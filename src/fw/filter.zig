// Port of netbird client/firewall/iptables/filter_linux.go (v0.79.0), BSD-3-Clause.
// ACL filter rules: peer rules (no destination) go to NETBIRD-ACL-INPUT
// with a paired mangle mark rule in NETBIRD-RT-PRE; route rules (with a
// destination) go to NETBIRD-RT-FWD-IN with no mangle pairing.
// Only the no-ipset behavior is ported (upstream's ipsetSupported=false
// path): multi-source rules expand to one iptables rule per prefix, and
// a destination set is rejected with IpsetRequired — the router has no
// ipset, and a set destination cannot be expressed without it.
// 1.4.21 deviation: port lists use "-m multiport --sports/--dports"
// (plural); 1.4.21's multiport has no singular --sport/--dport while
// upstream emits the singular form (accepted only by >=1.6-era iptables).
const std = @import("std");
const model = @import("model.zig");
const chains = @import("chains.zig");
const fwmark = @import("fwmark.zig");
const manager_mod = @import("manager.zig");

pub const Error = manager_mod.Error;

/// Assembled but not yet installed rule (unit-testable without iptables).
pub const BuiltRule = struct {
    id: []u8, // owned
    chain: []const u8, // static
    specs: model.Spec,
    mangle_specs: ?model.Spec,
    extra: []model.ExtraSpec, // owned, &.{} when none

    pub fn deinit(b: *BuiltRule, alloc: std.mem.Allocator) void {
        alloc.free(b.id);
        model.freeSpec(alloc, b.specs);
        if (b.mangle_specs) |s| model.freeSpec(alloc, s);
        for (b.extra) |*e| {
            model.freeSpec(alloc, e.specs);
            if (e.mangle_specs) |s| model.freeSpec(alloc, s);
        }
        if (b.extra.len > 0) alloc.free(b.extra);
        b.* = undefined;
    }
};

/// installFilterRule: assemble every iptables spec for one filter rule.
/// One rule per source prefix (no-ipset expansion); a single /0 source
/// becomes one rule with no source match.
pub fn buildFilterRule(
    alloc: std.mem.Allocator,
    iface: []const u8,
    v6: bool,
    sources: []const model.Prefix,
    destination: model.Network,
    proto: model.Protocol,
    s_port: ?model.Port,
    d_port: ?model.Port,
    action: model.Action,
) Error!BuiltRule {
    if (sources.len == 0) return Error.NoSources;
    const id = try model.generateRuleID(alloc, sources, destination, proto, s_port, d_port, action);
    errdefer alloc.free(id);

    const is_route = !destination.isZero();
    const chain = if (is_route) chains.rt_fwd_in else chains.acl_input;

    var dest_spec: ?model.Spec = null;
    defer if (dest_spec) |s| model.freeSpec(alloc, s);
    if (is_route) {
        var db = model.SpecBuilder.init(alloc);
        defer db.deinit();
        switch (destination) {
            .prefix => |p| {
                try db.arg("-d");
                try db.arg(p.text);
            },
            .set => return Error.IpsetRequired,
            .none => unreachable,
        }
        dest_spec = try db.build();
    }

    var mb = model.SpecBuilder.init(alloc);
    defer mb.deinit();
    if (proto != .all) {
        try mb.arg("-p");
        try mb.arg(proto.forFamily(v6));
    }
    try appendPortArgs(&mb, true, s_port);
    try appendPortArgs(&mb, false, d_port);
    const match_spec = try mb.build();
    defer model.freeSpec(alloc, match_spec);

    const primary_src: ?model.Prefix = if (sources.len == 1 and sources[0].isWildcard())
        null
    else
        sources[0];
    const primary = try buildOne(alloc, iface, primary_src, dest_spec, match_spec, !is_route, action);
    errdefer {
        model.freeSpec(alloc, primary.specs);
        if (primary.mangle_specs) |s| model.freeSpec(alloc, s);
    }

    var extra: []model.ExtraSpec = &.{};
    if (sources.len > 1) {
        extra = alloc.alloc(model.ExtraSpec, sources.len - 1) catch return Error.OutOfMemory;
        var n: usize = 0;
        errdefer {
            for (extra[0..n]) |*e| {
                model.freeSpec(alloc, e.specs);
                if (e.mangle_specs) |s| model.freeSpec(alloc, s);
            }
            alloc.free(extra);
        }
        for (sources[1..]) |s| {
            const one = try buildOne(alloc, iface, s, dest_spec, match_spec, !is_route, action);
            extra[n] = .{ .specs = one.specs, .mangle_specs = one.mangle_specs };
            n += 1;
        }
    }

    return .{
        .id = id,
        .chain = chain,
        .specs = primary.specs,
        .mangle_specs = primary.mangle_specs,
        .extra = extra,
    };
}

const OneRule = struct {
    specs: model.Spec,
    mangle_specs: ?model.Spec,
};

/// Assemble one filter spec plus (peer rules) the mangle redirect-mark pair:
/// <filter match> -i <iface> -m addrtype --dst-type LOCAL
/// -j MARK --set-xmark <redirected>.
fn buildOne(
    alloc: std.mem.Allocator,
    iface: []const u8,
    src: ?model.Prefix,
    dest: ?model.Spec,
    match: model.Spec,
    peer: bool,
    action: model.Action,
) Error!OneRule {
    var b = model.SpecBuilder.init(alloc);
    defer b.deinit();
    if (src) |s| {
        try b.arg("-s");
        try b.arg(s.text);
    }
    if (dest) |d| try b.appendOwned(d);
    try b.appendOwned(match);

    var mangle: ?model.Spec = null;
    if (peer) {
        var g = model.SpecBuilder.init(alloc);
        defer g.deinit();
        for (b.args.items) |a| try g.arg(a);
        try g.arg("-i");
        try g.arg(iface);
        try g.arg("-m");
        try g.arg("addrtype");
        try g.arg("--dst-type");
        try g.arg("LOCAL");
        try g.arg("-j");
        try g.arg("MARK");
        try g.arg("--set-xmark");
        try g.arg(fwmark.redirected_hex);
        mangle = try g.build();
    }

    try b.arg("-j");
    try b.arg(action.str());
    return .{ .specs = try b.build(), .mangle_specs = mangle };
}

/// applyPort: single port and range use the tcp/udp match's own
/// --sport/--dport; lists use the multiport module (plural flags).
/// An empty port value list is rejected (fail closed: silently dropping
/// the port match would widen the rule).
fn appendPortArgs(b: *model.SpecBuilder, sport: bool, port: ?model.Port) Error!void {
    const p = port orelse return;
    if (p.values.len == 0) return Error.InvalidPort;
    const single = if (sport) "--sport" else "--dport";
    if (p.is_range and p.values.len == 2) {
        try b.arg(single);
        try b.argf("{d}:{d}", .{ p.values[0], p.values[1] });
    } else if (p.values.len > 1) {
        try b.arg("-m");
        try b.arg("multiport");
        try b.arg(if (sport) "--sports" else "--dports");
        var joined: std.ArrayListUnmanaged(u8) = .empty;
        defer joined.deinit(b.alloc);
        for (p.values, 0..) |v, i| {
            if (i > 0) joined.append(b.alloc, ',') catch return Error.OutOfMemory;
            var tmp: [8]u8 = undefined;
            const s = std.fmt.bufPrint(&tmp, "{d}", .{v}) catch unreachable;
            joined.appendSlice(b.alloc, s) catch return Error.OutOfMemory;
        }
        try b.arg(joined.items);
    } else {
        try b.arg(single);
        try b.argf("{d}", .{p.values[0]});
    }
}

/// AddFilterRule: build, install and track one filter rule. Re-adding an
/// identical rule returns the existing id without touching iptables.
/// Returns the id borrowed from the tracking map (valid until delete/reset).
pub fn addFilterRule(
    m: *manager_mod.Manager,
    sources: []const model.Prefix,
    destination: model.Network,
    proto: model.Protocol,
    s_port: ?model.Port,
    d_port: ?model.Port,
    action: model.Action,
) Error![]const u8 {
    var built = try buildFilterRule(m.alloc, m.iface, m.v6, sources, destination, proto, s_port, d_port, action);
    if (m.filters.getKey(built.id)) |existing| {
        built.deinit(m.alloc);
        return existing;
    }
    errdefer built.deinit(m.alloc);

    // Install primary + extras. A filter-install failure removes what
    // was installed so far (upstream removeFilterSpecs).
    var primary_done = false;
    var installed_extra: usize = 0;
    errdefer {
        if (primary_done) deleteBuiltSpecs(m, built.chain, built.specs, built.mangle_specs);
        for (built.extra[0..installed_extra]) |e| deleteBuiltSpecs(m, built.chain, e.specs, e.mangle_specs);
    }

    try installOne(m, built.chain, action, built.specs, &built.mangle_specs);
    primary_done = true;
    for (built.extra) |*e| {
        try installOne(m, built.chain, action, e.specs, &e.mangle_specs);
        installed_extra += 1;
    }

    const key = built.id;
    const rule = model.FilterRule{
        .chain = built.chain,
        .specs = built.specs,
        .mangle_specs = built.mangle_specs,
        .extra = built.extra,
    };
    // On OOM the errdefers above roll back the kernel rules and free built.
    try m.filters.put(m.alloc, key, rule);
    return m.filters.getKey(key).?;
}

fn deleteBuiltSpecs(m: *manager_mod.Manager, chain: []const u8, specs: model.Spec, mangle: ?model.Spec) void {
    var ab: [40][]const u8 = undefined;
    m.runner.deleteIfExists(chains.table_filter, chain, model.constArgs(specs, &ab)) catch {};
    if (mangle) |ms| {
        m.runner.deleteIfExists(chains.table_mangle, chains.rt_pre, model.constArgs(ms, &ab)) catch {};
    }
}

/// insertFilterRule: peer drops at position 1, route drops at position 2
/// (right after the established accept), accepts appended. The mangle
/// pairing is best-effort like upstream: the filter rule enforces the
/// ACL, so a mangle failure must not undo it — the spec is dropped so
/// teardown skips a rule that was never added.
fn installOne(
    m: *manager_mod.Manager,
    chain: []const u8,
    action: model.Action,
    specs: model.Spec,
    mangle_specs: *?model.Spec,
) Error!void {
    var ab: [40][]const u8 = undefined;
    if (action == .drop) {
        const pos: u32 = if (std.mem.eql(u8, chain, chains.rt_fwd_in)) 2 else 1;
        try m.runner.insert(chains.table_filter, chain, pos, model.constArgs(specs, &ab));
    } else {
        try m.runner.append(chains.table_filter, chain, model.constArgs(specs, &ab));
    }
    if (mangle_specs.*) |ms| {
        m.runner.append(chains.table_mangle, chains.rt_pre, model.constArgs(ms, &ab)) catch {
            model.freeSpec(m.alloc, ms);
            mangle_specs.* = null;
        };
    }
}

/// DeleteFilterRule: remove a rule previously added via addFilterRule.
/// No-op for unknown ids.
pub fn deleteFilterRule(m: *manager_mod.Manager, id: []const u8) Error!void {
    try m.deleteFilterByID(id);
}
