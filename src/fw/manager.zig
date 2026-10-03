// Port of netbird client/firewall/iptables/{manager,family,chains}_linux.go
// init/teardown for one address family (v0.79.0), BSD-3-Clause.
// setup() mirrors family.init (minus statemanager persistence, firewalld,
// ipset and the raw table); reset() mirrors family.Reset.
// Static specs are recomputed at cleanup instead of persisted, so teardown
// also works after an unclean shutdown with no live state.
// Dynamic rules live in filter.zig (ACL) and nat.zig (routing); this file
// owns their tracking maps and the static create/delete paths.
const std = @import("std");
const model = @import("model.zig");
const chains = @import("chains.zig");
const iptables = @import("iptables.zig");

pub const Error = iptables.Error || model.Error;

pub const Manager = struct {
    alloc: std.mem.Allocator,
    io: std.Io,
    runner: iptables.Runner,
    /// WireGuard interface name, owned.
    iface: []u8,
    mtu: u16,
    /// True when the runner points at ip6tables (affects icmp mapping).
    /// One Manager covers one family; the engine owns two (v4 + v6).
    v6: bool,
    /// Filter rules by owned rule id (filter.zig).
    filters: std.StringHashMapUnmanaged(model.FilterRule) = .empty,
    /// NAT and legacy route rules by owned GenKey (nat.zig).
    tracked: std.StringHashMapUnmanaged(model.TrackedRule) = .empty,
    legacy_management: bool = false,

    pub fn init(
        alloc: std.mem.Allocator,
        io: std.Io,
        iptables_path: []const u8,
        iface: []const u8,
        mtu: u16,
        v6: bool,
    ) Error!Manager {
        const owned_iface = alloc.dupe(u8, iface) catch return Error.OutOfMemory;
        errdefer alloc.free(owned_iface);
        return .{
            .alloc = alloc,
            .io = io,
            .runner = .{ .path = iptables_path, .alloc = alloc, .io = io },
            .iface = owned_iface,
            .mtu = mtu,
            .v6 = v6,
        };
    }

    pub fn deinit(m: *Manager) void {
        m.forgetFilters();
        m.forgetTracked();
        m.runner.deinit();
        m.alloc.free(m.iface);
        m.* = undefined;
    }

    fn forgetFilters(m: *Manager) void {
        var it = m.filters.iterator();
        while (it.next()) |e| {
            m.alloc.free(e.key_ptr.*);
            e.value_ptr.free(m.alloc);
        }
        m.filters.deinit(m.alloc);
        m.filters = .empty;
    }

    fn forgetTracked(m: *Manager) void {
        var it = m.tracked.iterator();
        while (it.next()) |e| {
            m.alloc.free(e.key_ptr.*);
            e.value_ptr.free(m.alloc);
        }
        m.tracked.deinit(m.alloc);
        m.tracked = .empty;
    }

    /// Install all static state: route chains, established rules, jumps,
    /// data-plane marks, ACL chain and its INPUT/FORWARD/mangle seeds.
    /// Best-effort tears down previous static state first, so calling
    /// setup twice converges to the same kernel state. Tracked dynamic
    /// rules are dropped with the teardown (same as a process restart);
    /// callers re-add them afterwards.
    pub fn setup(m: *Manager) Error!void {
        m.reset() catch {};
        try m.createContainers();
        try m.setupDataplaneMarks();
        try m.createDefaultChains();
    }

    /// Remove every rule and chain owned by this manager (static and
    /// tracked) and forget the tracked maps. Continues past individual
    /// failures, returning the first error. ACL cleanup runs before
    /// route-chain cleanup: FORWARD still jumps into the route chains,
    /// and deleting a referenced chain trips EBUSY.
    pub fn reset(m: *Manager) Error!void {
        var first_err: ?Error = null;
        const note = struct {
            fn f(slot: *?Error, e: Error) void {
                if (slot.* == null) slot.* = e;
            }
        }.f;

        m.deleteTrackedFilters(&first_err);
        m.deleteTrackedRules(&first_err);
        m.cleanAclChains() catch |e| note(&first_err, e);
        m.cleanRouteChains() catch |e| note(&first_err, e);

        if (first_err) |e| return e;
    }

    fn deleteTrackedFilters(m: *Manager, first_err: *?Error) void {
        var keys: std.ArrayListUnmanaged([]const u8) = .empty;
        defer keys.deinit(m.alloc);
        var it = m.filters.iterator();
        while (it.next()) |e| keys.append(m.alloc, e.key_ptr.*) catch return;
        for (keys.items) |key| m.deleteFilterByID(key) catch |e| {
            if (first_err.* == null) first_err.* = e;
        };
    }

    fn deleteTrackedRules(m: *Manager, first_err: *?Error) void {
        var keys: std.ArrayListUnmanaged([]const u8) = .empty;
        defer keys.deinit(m.alloc);
        var it = m.tracked.iterator();
        while (it.next()) |e| keys.append(m.alloc, e.key_ptr.*) catch return;
        for (keys.items) |key| m.deleteTrackedByKey(key) catch |e| {
            if (first_err.* == null) first_err.* = e;
        };
    }

    /// Delete one tracked filter rule by id. No-op when unknown.
    /// Used by filter.zig and by reset().
    pub fn deleteFilterByID(m: *Manager, id: []const u8) Error!void {
        const kv = m.filters.fetchRemove(id) orelse return;
        defer m.alloc.free(kv.key);
        var rule = kv.value;
        defer rule.free(m.alloc);
        var ab: [40][]const u8 = undefined;
        try m.runner.deleteIfExists(chains.table_filter, rule.chain, model.constArgs(rule.specs, &ab));
        if (rule.mangle_specs) |ms| {
            try m.runner.deleteIfExists(chains.table_mangle, chains.rt_pre, model.constArgs(ms, &ab));
        }
        for (rule.extra) |e| {
            try m.runner.deleteIfExists(chains.table_filter, rule.chain, model.constArgs(e.specs, &ab));
            if (e.mangle_specs) |ms| {
                try m.runner.deleteIfExists(chains.table_mangle, chains.rt_pre, model.constArgs(ms, &ab));
            }
        }
    }

    /// Delete one tracked NAT/legacy rule by key. No-op when unknown.
    /// Used by nat.zig and by reset().
    pub fn deleteTrackedByKey(m: *Manager, key: []const u8) Error!void {
        const kv = m.tracked.fetchRemove(key) orelse return;
        defer m.alloc.free(kv.key);
        var rule = kv.value;
        defer rule.free(m.alloc);
        var ab: [40][]const u8 = undefined;
        try m.runner.deleteIfExists(rule.table, rule.chain, model.constArgs(rule.spec, &ab));
    }

    /// createContainers: route chains + established rules + jumps.
    /// (Static NAT and MSS rules are added by nat.setupRouting, step 3.)
    fn createContainers(m: *Manager) Error!void {
        const defs = [_][2][]const u8{
            .{ chains.table_filter, chains.rt_fwd_in },
            .{ chains.table_filter, chains.rt_fwd_out },
            .{ chains.table_mangle, chains.rt_pre },
            .{ chains.table_nat, chains.rt_nat },
            .{ chains.table_nat, chains.rt_rdr },
        };
        for (defs) |d| {
            // Fallback for an unclean shutdown: a surviving chain is
            // cleared first (same as upstream createContainers).
            if (try m.runner.chainExists(d[0], d[1])) {
                m.runner.flushChain(d[0], d[1]) catch {};
                m.runner.deleteChain(d[0], d[1]) catch {};
            }
            try m.runner.newChain(d[0], d[1]);
        }

        var eb: [8][]const u8 = undefined;
        try m.runner.insert(chains.table_filter, chains.rt_fwd_in, 1, chains.establishedBare(&eb));
        try m.runner.insert(chains.table_filter, chains.rt_fwd_out, 1, chains.establishedBare(&eb));

        try m.addJumpRules();
    }

    /// addJumpRules: POSTROUTING->RT-NAT, PREROUTING->RT-PRE, PREROUTING->RT-RDR.
    fn addJumpRules(m: *Manager) Error!void {
        var jb: [2][]const u8 = undefined;
        try m.runner.insert(chains.table_nat, chains.postrouting, 1, chains.jump(&jb, chains.rt_nat));
        try m.runner.insert(chains.table_mangle, chains.prerouting, 1, chains.jump(&jb, chains.rt_pre));
        try m.runner.insert(chains.table_nat, chains.prerouting, 1, chains.jump(&jb, chains.rt_rdr));
    }

    /// setupDataPlaneMark: CONNMARK rules on mangle PREROUTING/POSTROUTING.
    fn setupDataplaneMarks(m: *Manager) Error!void {
        var mb: [10][]const u8 = undefined;
        try m.runner.appendUnique(chains.table_mangle, chains.prerouting, chains.dataplaneMarkIn(&mb, m.iface));
        try m.runner.appendUnique(chains.table_mangle, chains.postrouting, chains.dataplaneMarkOut(&mb, m.iface));
    }

    /// createDefaultChains: ACL chain plus INPUT/FORWARD/mangle seeds.
    /// Each seed is inserted at position 1 in slice order, so the final
    /// head order is the reverse: INPUT gets [established, acl-jump, drop],
    /// FORWARD gets [in-jump, out-jump, drop], then the redirect accept
    /// lands at position 2.
    fn createDefaultChains(m: *Manager) Error!void {
        try m.runner.newChain(chains.table_filter, chains.acl_input);

        var sb: [13][]const u8 = undefined;
        try m.runner.insertUnique(chains.table_filter, chains.input, 1, chains.inputDrop(&sb, m.iface));
        try m.runner.insertUnique(chains.table_filter, chains.input, 1, chains.inputAclJump(&sb, m.iface));
        try m.runner.insertUnique(chains.table_filter, chains.input, 1, chains.established(&sb, m.iface));

        try m.runner.insertUnique(chains.table_filter, chains.forward, 1, chains.forwardDrop(&sb, m.iface));
        try m.runner.insertUnique(chains.table_filter, chains.forward, 1, chains.forwardOutJump(&sb, m.iface));
        try m.runner.insertUnique(chains.table_filter, chains.forward, 1, chains.forwardInJump(&sb, m.iface));

        try m.runner.insertUnique(chains.table_filter, chains.forward, 2, chains.forwardRedirectAccept(&sb));

        try m.runner.appendUnique(chains.table_mangle, chains.forward, chains.mangleGuardEst(&sb, m.iface));
        try m.runner.appendUnique(chains.table_mangle, chains.forward, chains.mangleGuardDnat(&sb, m.iface));
    }

    /// cleanAclChains: INPUT/FORWARD/mangle seeds plus the ACL chain.
    fn cleanAclChains(m: *Manager) Error!void {
        var first_err: ?Error = null;
        const note = struct {
            fn f(slot: *?Error, e: Error) void {
                if (slot.* == null) slot.* = e;
            }
        }.f;

        var sb: [13][]const u8 = undefined;
        m.runner.deleteIfExists(chains.table_filter, chains.input, chains.inputDrop(&sb, m.iface)) catch |e| note(&first_err, e);
        m.runner.deleteIfExists(chains.table_filter, chains.input, chains.inputAclJump(&sb, m.iface)) catch |e| note(&first_err, e);
        m.runner.deleteIfExists(chains.table_filter, chains.input, chains.established(&sb, m.iface)) catch |e| note(&first_err, e);

        m.runner.deleteIfExists(chains.table_filter, chains.forward, chains.forwardDrop(&sb, m.iface)) catch |e| note(&first_err, e);
        m.runner.deleteIfExists(chains.table_filter, chains.forward, chains.forwardOutJump(&sb, m.iface)) catch |e| note(&first_err, e);
        m.runner.deleteIfExists(chains.table_filter, chains.forward, chains.forwardInJump(&sb, m.iface)) catch |e| note(&first_err, e);
        m.runner.deleteIfExists(chains.table_filter, chains.forward, chains.forwardRedirectAccept(&sb)) catch |e| note(&first_err, e);

        m.runner.deleteIfExists(chains.table_mangle, chains.forward, chains.mangleGuardEst(&sb, m.iface)) catch |e| note(&first_err, e);
        m.runner.deleteIfExists(chains.table_mangle, chains.forward, chains.mangleGuardDnat(&sb, m.iface)) catch |e| note(&first_err, e);

        m.runner.clearAndDeleteChain(chains.table_filter, chains.acl_input) catch |e| note(&first_err, e);

        if (first_err) |e| return e;
    }

    /// cleanUpDefaultForwardRules + cleanJumpRules + cleanupDataPlaneMark:
    /// jumps, dataplane marks and the route chains.
    fn cleanRouteChains(m: *Manager) Error!void {
        var first_err: ?Error = null;
        const note = struct {
            fn f(slot: *?Error, e: Error) void {
                if (slot.* == null) slot.* = e;
            }
        }.f;

        var jb: [2][]const u8 = undefined;
        m.runner.deleteIfExists(chains.table_nat, chains.postrouting, chains.jump(&jb, chains.rt_nat)) catch |e| note(&first_err, e);
        m.runner.deleteIfExists(chains.table_mangle, chains.prerouting, chains.jump(&jb, chains.rt_pre)) catch |e| note(&first_err, e);
        m.runner.deleteIfExists(chains.table_nat, chains.prerouting, chains.jump(&jb, chains.rt_rdr)) catch |e| note(&first_err, e);

        var mb: [10][]const u8 = undefined;
        m.runner.deleteIfExists(chains.table_mangle, chains.prerouting, chains.dataplaneMarkIn(&mb, m.iface)) catch |e| note(&first_err, e);
        m.runner.deleteIfExists(chains.table_mangle, chains.postrouting, chains.dataplaneMarkOut(&mb, m.iface)) catch |e| note(&first_err, e);

        const defs = [_][2][]const u8{
            .{ chains.table_filter, chains.rt_fwd_in },
            .{ chains.table_filter, chains.rt_fwd_out },
            .{ chains.table_mangle, chains.rt_pre },
            .{ chains.table_nat, chains.rt_nat },
            .{ chains.table_nat, chains.rt_rdr },
        };
        for (defs) |d| {
            m.runner.clearAndDeleteChain(d[0], d[1]) catch |e| note(&first_err, e);
        }

        if (first_err) |e| return e;
    }
};
