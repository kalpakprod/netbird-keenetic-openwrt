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
    /// data-plane marks, ACL chain and its INPUT/FORWARD/mangle seeds,
    /// plus the static routing state (MSS clamp, MASQUERADE rules).
    /// Best-effort tears down previous state first, so calling setup
    /// twice converges to the same kernel state. Tracked dynamic rules
    /// are dropped with the teardown (same as a process restart, and
    /// airtight even when the teardown itself hit errors); callers
    /// re-add them afterwards.
    pub fn setup(m: *Manager) Error!void {
        m.reset() catch {};
        m.forgetFilters();
        m.forgetTracked();
        try m.createContainers();
        try m.setupDataplaneMarks();
        try m.createDefaultChains();
        try m.setupStaticRouting();
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
    /// Used by filter.zig and by reset(). Kernel rules go first: on a
    /// kernel failure the entry stays tracked so the caller can retry
    /// (upstream DeleteFilterRule keeps it tracked for the same reason).
    pub fn deleteFilterByID(m: *Manager, id: []const u8) Error!void {
        const found = m.filters.getPtr(id) orelse return;
        var ab: [40][]const u8 = undefined;
        try m.runner.deleteIfExists(chains.table_filter, found.chain, model.constArgs(found.specs, &ab));
        if (found.mangle_specs) |ms| {
            try m.runner.deleteIfExists(chains.table_mangle, chains.rt_pre, model.constArgs(ms, &ab));
        }
        for (found.extra) |e| {
            try m.runner.deleteIfExists(chains.table_filter, found.chain, model.constArgs(e.specs, &ab));
            if (e.mangle_specs) |ms| {
                try m.runner.deleteIfExists(chains.table_mangle, chains.rt_pre, model.constArgs(ms, &ab));
            }
        }
        var kv = m.filters.fetchRemove(id).?;
        m.alloc.free(kv.key);
        kv.value.free(m.alloc);
    }

    /// Delete one tracked NAT/legacy rule by key. No-op when unknown.
    /// Used by nat.zig and by reset(). Kernel-first, like deleteFilterByID.
    pub fn deleteTrackedByKey(m: *Manager, key: []const u8) Error!void {
        const found = m.tracked.getPtr(key) orelse return;
        var ab: [40][]const u8 = undefined;
        try m.runner.deleteIfExists(found.table, found.chain, model.constArgs(found.spec, &ab));
        var kv = m.tracked.fetchRemove(key).?;
        m.alloc.free(kv.key);
        kv.value.free(m.alloc);
    }

    /// setupStaticRouting: MSS clamp chain + FORWARD jump + clamp rule
    /// (addMSSClampingRules) and the two static MASQUERADE rules in
    /// NETBIRD-RT-NAT (addPostroutingRules). Runs after the seeds, but
    /// the final state matches upstream order: the MSS jump lands at
    /// FORWARD position 1 however the guards got there first.
    fn setupStaticRouting(m: *Manager) Error!void {
        if (try m.runner.chainExists(chains.table_mangle, chains.rt_mss_clamp)) {
            m.runner.flushChain(chains.table_mangle, chains.rt_mss_clamp) catch {};
            m.runner.deleteChain(chains.table_mangle, chains.rt_mss_clamp) catch {};
        }
        try m.runner.newChain(chains.table_mangle, chains.rt_mss_clamp);

        var jb: [2][]const u8 = undefined;
        try m.runner.insert(chains.table_mangle, chains.forward, 1, chains.jump(&jb, chains.rt_mss_clamp));

        var cb: [11][]const u8 = undefined;
        var val: [8]u8 = undefined;
        try m.runner.append(
            chains.table_mangle,
            chains.rt_mss_clamp,
            chains.mssClamp(&cb, &val, m.iface, m.mtu, m.v6),
        );

        var nb: [9][]const u8 = undefined;
        try m.runner.append(chains.table_nat, chains.rt_nat, chains.natMasqueradeOut(&nb));
        try m.runner.append(chains.table_nat, chains.rt_nat, chains.natMasqueradeReturn(&nb, m.iface));
    }

    /// createContainers: route chains + established rules + jumps.
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
        m.runner.deleteIfExists(chains.table_mangle, chains.forward, chains.jump(&jb, chains.rt_mss_clamp)) catch |e| note(&first_err, e);

        var mb: [10][]const u8 = undefined;
        m.runner.deleteIfExists(chains.table_mangle, chains.prerouting, chains.dataplaneMarkIn(&mb, m.iface)) catch |e| note(&first_err, e);
        m.runner.deleteIfExists(chains.table_mangle, chains.postrouting, chains.dataplaneMarkOut(&mb, m.iface)) catch |e| note(&first_err, e);

        const defs = [_][2][]const u8{
            .{ chains.table_filter, chains.rt_fwd_in },
            .{ chains.table_filter, chains.rt_fwd_out },
            .{ chains.table_mangle, chains.rt_pre },
            .{ chains.table_nat, chains.rt_nat },
            .{ chains.table_nat, chains.rt_rdr },
            .{ chains.table_mangle, chains.rt_mss_clamp },
        };
        for (defs) |d| {
            m.runner.clearAndDeleteChain(d[0], d[1]) catch |e| note(&first_err, e);
        }

        if (first_err) |e| return e;
    }
};
