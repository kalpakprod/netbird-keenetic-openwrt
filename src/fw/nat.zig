// Port of netbird client/firewall/iptables/routing_linux.go (v0.79.0), BSD-3-Clause.
// Routed-network NAT: mangle MARK rules select masqueraded flows, two
// static MASQUERADE rules in NETBIRD-RT-NAT act on the marks, legacy
// management mode adds plain forward ACCEPTs. Static state (MSS clamp,
// MASQUERADE rules) is installed by Manager.setup; this file owns the
// dynamic per-pair rules.
// No-ipset behavior only: a set source or destination is rejected with
// IpsetRequired (upstream fails the same way when the kernel lacks
// ip_set_hash_net, since the rule is inexpressible without it).
const std = @import("std");
const model = @import("model.zig");
const chains = @import("chains.zig");
const fwmark = @import("fwmark.zig");
const manager_mod = @import("manager.zig");

pub const Error = manager_mod.Error;

/// addNatRule's mark spec: [-i <iface> | ! -i <iface>]
/// -m conntrack --ctstate NEW [-s src] [-d dst] -j MARK --set-mark <mark>.
/// Forward pairs mark masquerade, inverse pairs masquerade_return.
/// Empty (none) networks match any, like upstream applyNetwork.
pub fn buildNatMarkRule(
    alloc: std.mem.Allocator,
    iface: []const u8,
    pair: model.RouterPair,
) Error!model.Spec {
    var b = model.SpecBuilder.init(alloc);
    defer b.deinit();
    if (pair.inverse) {
        try b.arg("!");
        try b.arg("-i");
    } else {
        try b.arg("-i");
    }
    try b.arg(iface);
    try b.arg("-m");
    try b.arg("conntrack");
    try b.arg("--ctstate");
    try b.arg("NEW");
    try appendNetwork(&b, "-s", pair.source);
    try appendNetwork(&b, "-d", pair.destination);
    try b.arg("-j");
    try b.arg("MARK");
    try b.arg("--set-mark");
    try b.arg(if (pair.inverse) fwmark.masquerade_return_hex else fwmark.masquerade_hex);
    return b.build();
}

/// addLegacyRouteRule's spec: [-s src] [-d dst] -j ACCEPT.
pub fn buildLegacyRule(
    alloc: std.mem.Allocator,
    pair: model.RouterPair,
) Error!model.Spec {
    var b = model.SpecBuilder.init(alloc);
    defer b.deinit();
    try appendNetwork(&b, "-s", pair.source);
    try appendNetwork(&b, "-d", pair.destination);
    try b.arg("-j");
    try b.arg("ACCEPT");
    return b.build();
}

/// applyNetwork for one direction. Sets need ipset; empty matches any.
fn appendNetwork(b: *model.SpecBuilder, flag: []const u8, net: model.Network) Error!void {
    switch (net) {
        .prefix => |p| {
            try b.arg(flag);
            try b.arg(p.text);
        },
        .set => return Error.IpsetRequired,
        .none => {},
    }
}

/// AddNatRule: legacy forward ACCEPT in legacy mode, plus the forward
/// and inverse mangle MARK rules when masquerading. Re-adding a pair
/// replaces its kernel rules. Like upstream, an inverse-install failure
/// leaves the forward rule installed and returns the error.
pub fn addNatRule(m: *manager_mod.Manager, pair: model.RouterPair) Error!void {
    if (m.legacy_management) try addLegacyRouteRule(m, pair);
    if (!pair.masquerade) return;
    try addOneNatMark(m, pair);
    try addOneNatMark(m, pair.inversePair());
}

/// RemoveNatRule: forward + inverse MARK rules, then the legacy rule.
/// Legacy removal always runs (upstream removes it unconditionally).
pub fn removeNatRule(m: *manager_mod.Manager, pair: model.RouterPair) Error!void {
    if (pair.masquerade) {
        const key = try pair.natKey(m.alloc);
        defer m.alloc.free(key);
        try m.deleteTrackedByKey(key);
        const inv = pair.inversePair();
        const ikey = try inv.natKey(m.alloc);
        defer m.alloc.free(ikey);
        try m.deleteTrackedByKey(ikey);
    }
    const fkey = try pair.fwdKey(m.alloc);
    defer m.alloc.free(fkey);
    try m.deleteTrackedByKey(fkey);
}

/// SetLegacyManagement: flip the mode; leaving legacy mode removes all
/// legacy forward rules (upstream firewall.SetLegacyManagement).
pub fn setLegacyManagement(m: *manager_mod.Manager, legacy: bool) Error!void {
    const old = m.legacy_management;
    m.legacy_management = legacy;
    if (!legacy and old) try removeAllLegacyRouteRules(m);
}

/// RemoveAllLegacyRouteRules: drop every tracked netbird-fwd-* rule,
/// continuing past individual failures like upstream's multierror loop.
pub fn removeAllLegacyRouteRules(m: *manager_mod.Manager) Error!void {
    var keys: std.ArrayListUnmanaged([]const u8) = .empty;
    defer keys.deinit(m.alloc);
    var it = m.tracked.iterator();
    while (it.next()) |e| {
        if (!std.mem.startsWith(u8, e.key_ptr.*, model.forwarding_format_prefix)) continue;
        keys.append(m.alloc, e.key_ptr.*) catch return Error.OutOfMemory;
    }
    var first_err: ?Error = null;
    for (keys.items) |key| {
        m.deleteTrackedByKey(key) catch |e| {
            if (first_err == null) first_err = e;
        };
    }
    if (first_err) |e| return e;
}

fn addOneNatMark(m: *manager_mod.Manager, pair: model.RouterPair) Error!void {
    const key = try pair.natKey(m.alloc);
    errdefer m.alloc.free(key);
    // Replace: drop the previous spec first (upstream deletes + drops
    // its set references; without ipset there is nothing to decrement).
    try m.deleteTrackedByKey(key);
    const spec = try buildNatMarkRule(m.alloc, m.iface, pair);
    errdefer model.freeSpec(m.alloc, spec);
    var ab: [40][]const u8 = undefined;
    // NAT marks go first so later rules can overwrite the mark.
    try m.runner.insert(chains.table_mangle, chains.rt_pre, 1, model.constArgs(spec, &ab));
    m.tracked.put(m.alloc, key, .{
        .table = chains.table_mangle,
        .chain = chains.rt_pre,
        .spec = spec,
    }) catch |e| {
        m.runner.deleteIfExists(chains.table_mangle, chains.rt_pre, model.constArgs(spec, &ab)) catch {};
        return e;
    };
}

fn addLegacyRouteRule(m: *manager_mod.Manager, pair: model.RouterPair) Error!void {
    const key = try pair.fwdKey(m.alloc);
    errdefer m.alloc.free(key);
    try m.deleteTrackedByKey(key);
    const spec = try buildLegacyRule(m.alloc, pair);
    errdefer model.freeSpec(m.alloc, spec);
    var ab: [40][]const u8 = undefined;
    try m.runner.append(chains.table_filter, chains.rt_fwd_in, model.constArgs(spec, &ab));
    m.tracked.put(m.alloc, key, .{
        .table = chains.table_filter,
        .chain = chains.rt_fwd_in,
        .spec = spec,
    }) catch |e| {
        m.runner.deleteIfExists(chains.table_filter, chains.rt_fwd_in, model.constArgs(spec, &ab)) catch {};
        return e;
    };
}
