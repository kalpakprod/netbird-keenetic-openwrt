// Tests for src/fw step 2: pure buildFilterRule spec tests (run
// everywhere) plus the netns integration test (install exact rules,
// duplicate add is a no-op, delete removes, reset cleans all).
const std = @import("std");
const builtin = @import("builtin");
const model = @import("model.zig");
const chains = @import("chains.zig");
const filter = @import("filter.zig");
const manager_mod = @import("manager.zig");
const lock_mod = @import("lock.zig");

const tio = std.testing.io;

fn expectSpec(actual: model.Spec, expected: []const []const u8) !void {
    try std.testing.expectEqual(expected.len, actual.len);
    for (expected, actual) |e, a| try std.testing.expectEqualStrings(e, a);
}

test "peer accept tcp dport builds filter plus mangle pair" {
    const alloc = std.testing.allocator;
    const src = [_]model.Prefix{try model.Prefix.parse("10.0.0.1/32")};
    const dport = model.Port{ .is_range = false, .values = &.{443} };
    var b = try filter.buildFilterRule(alloc, "wt0", false, &src, .none, .tcp, null, dport, .accept);
    defer b.deinit(alloc);
    try std.testing.expectEqualStrings(chains.acl_input, b.chain);
    try std.testing.expectEqual(@as(usize, 0), b.extra.len);
    try expectSpec(b.specs, &.{
        "-s", "10.0.0.1/32", "-p", "tcp", "--dport", "443", "-j", "ACCEPT",
    });
    try expectSpec(b.mangle_specs.?, &.{
        "-s", "10.0.0.1/32", "-p", "tcp", "--dport", "443",
        "-i",         "wt0", "-m", "addrtype", "--dst-type", "LOCAL",
        "-j",         "MARK", "--set-xmark", "0x1bd20",
    });
}

test "peer drop udp any-source has no source match" {
    const alloc = std.testing.allocator;
    const src = [_]model.Prefix{try model.Prefix.parse("0.0.0.0/0")};
    var b = try filter.buildFilterRule(alloc, "wt0", false, &src, .none, .udp, null, null, .drop);
    defer b.deinit(alloc);
    try expectSpec(b.specs, &.{ "-p", "udp", "-j", "DROP" });
    try std.testing.expect(b.mangle_specs != null);
}

test "route rule carries destination and no mangle pair" {
    const alloc = std.testing.allocator;
    const src = [_]model.Prefix{try model.Prefix.parse("10.0.0.0/24")};
    const dst = model.Network{ .prefix = try model.Prefix.parse("10.1.0.0/24") };
    var b = try filter.buildFilterRule(alloc, "wt0", false, &src, dst, .tcp, null, null, .accept);
    defer b.deinit(alloc);
    try std.testing.expectEqualStrings(chains.rt_fwd_in, b.chain);
    try expectSpec(b.specs, &.{
        "-s", "10.0.0.0/24", "-d", "10.1.0.0/24", "-p", "tcp", "-j", "ACCEPT",
    });
    try std.testing.expect(b.mangle_specs == null);
}

test "multi-source expands to one rule per prefix" {
    const alloc = std.testing.allocator;
    const src = [_]model.Prefix{
        try model.Prefix.parse("10.0.0.1/32"),
        try model.Prefix.parse("10.0.0.2/32"),
    };
    var b = try filter.buildFilterRule(alloc, "wt0", false, &src, .none, .all, null, null, .accept);
    defer b.deinit(alloc);
    try std.testing.expectEqual(@as(usize, 1), b.extra.len);
    try expectSpec(b.specs, &.{ "-s", "10.0.0.1/32", "-j", "ACCEPT" });
    try expectSpec(b.extra[0].specs, &.{ "-s", "10.0.0.2/32", "-j", "ACCEPT" });
    try std.testing.expect(b.extra[0].mangle_specs != null);
}

test "range and listed ports" {
    const alloc = std.testing.allocator;
    const src = [_]model.Prefix{try model.Prefix.parse("10.0.0.1/32")};
    const range = model.Port{ .is_range = true, .values = &.{ 80, 443 } };
    var r = try filter.buildFilterRule(alloc, "wt0", false, &src, .none, .tcp, null, range, .accept);
    defer r.deinit(alloc);
    try expectSpec(r.specs, &.{
        "-s", "10.0.0.1/32", "-p", "tcp", "--dport", "80:443", "-j", "ACCEPT",
    });
    const list = model.Port{ .is_range = false, .values = &.{ 80, 443 } };
    var l = try filter.buildFilterRule(alloc, "wt0", false, &src, .none, .tcp, null, list, .accept);
    defer l.deinit(alloc);
    try expectSpec(l.specs, &.{
        "-s", "10.0.0.1/32", "-p", "tcp", "-m", "multiport", "--dports", "80,443", "-j", "ACCEPT",
    });
}

test "icmp maps to ipv6-icmp for v6" {
    const alloc = std.testing.allocator;
    const src = [_]model.Prefix{try model.Prefix.parse("fd00::1/128")};
    var b = try filter.buildFilterRule(alloc, "wt0", true, &src, .none, .icmp, null, null, .accept);
    defer b.deinit(alloc);
    try expectSpec(b.specs, &.{ "-s", "fd00::1/128", "-p", "ipv6-icmp", "-j", "ACCEPT" });
}

test "filter build errors fail closed" {
    const alloc = std.testing.allocator;
    const src = [_]model.Prefix{try model.Prefix.parse("10.0.0.1/32")};
    try std.testing.expectError(
        model.Error.NoSources,
        filter.buildFilterRule(alloc, "wt0", false, &.{}, .none, .tcp, null, null, .accept),
    );
    const set = model.Network{ .set = .{ .name = "nb-acl-1234" } };
    try std.testing.expectError(
        model.Error.IpsetRequired,
        filter.buildFilterRule(alloc, "wt0", false, &src, set, .tcp, null, null, .accept),
    );
    const empty = model.Port{ .is_range = false, .values = &.{} };
    try std.testing.expectError(
        model.Error.InvalidPort,
        filter.buildFilterRule(alloc, "wt0", false, &src, .none, .tcp, empty, null, .accept),
    );
}

// --- integration test helpers ---

fn inUserNamespace() bool {
    var file = std.Io.Dir.openFileAbsolute(tio, "/proc/self/uid_map", .{ .mode = .read_only }) catch return false;
    defer file.close(tio);
    var buf: [128]u8 = undefined;
    const n = file.readPositionalAll(tio, &buf, 0) catch return false;
    const trimmed = std.mem.trim(u8, buf[0..n], " \t\n");
    return !std.mem.eql(u8, trimmed, "0          0 4294967295") and
        !std.mem.eql(u8, trimmed, "0 0 4294967295");
}

fn runList(alloc: std.mem.Allocator, table: []const u8, chain: []const u8) ![]u8 {
    const argv = [_][]const u8{ "iptables", "-t", table, "-S", chain };
    var res = try std.process.run(alloc, tio, .{ .argv = &argv });
    defer alloc.free(res.stderr);
    errdefer alloc.free(res.stdout);
    if (!res.term.success()) return error.ListFailed;
    return res.stdout;
}

test "filter install exact rules, duplicate no-op, delete, cleanup" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!inUserNamespace()) return error.SkipZigTest;
    const alloc = std.testing.allocator;

    var l = try lock_mod.Lock.acquire(lock_mod.lock_path);
    defer l.release();

    var m = try manager_mod.Manager.init(alloc, tio, "iptables", "wt0", 1280, false);
    defer m.deinit();
    defer m.reset() catch {};
    try m.setup();

    const peer_src = [_]model.Prefix{try model.Prefix.parse("10.0.0.1/32")};
    const dport = model.Port{ .is_range = false, .values = &.{443} };
    const peer_id = try filter.addFilterRule(&m, &peer_src, .none, .tcp, null, dport, .accept);

    const drop_src = [_]model.Prefix{try model.Prefix.parse("10.0.0.9/32")};
    const drop_id = try filter.addFilterRule(&m, &drop_src, .none, .udp, null, null, .drop);

    const route_src = [_]model.Prefix{try model.Prefix.parse("10.0.0.0/24")};
    const route_dst = model.Network{ .prefix = try model.Prefix.parse("10.1.0.0/24") };
    _ = try filter.addFilterRule(&m, &route_src, route_dst, .tcp, null, null, .accept);

    // Range and listed ports install (multiport plural form for 1.4.21).
    const range_src = [_]model.Prefix{try model.Prefix.parse("10.0.0.5/32")};
    const range = model.Port{ .is_range = true, .values = &.{ 8000, 8010 } };
    const range_id = try filter.addFilterRule(&m, &range_src, .none, .tcp, null, range, .accept);
    const list_src = [_]model.Prefix{try model.Prefix.parse("10.0.0.6/32")};
    const list = model.Port{ .is_range = false, .values = &.{ 80, 443 } };
    const list_id = try filter.addFilterRule(&m, &list_src, .none, .tcp, null, list, .accept);

    const acl = try runList(alloc, "filter", chains.acl_input);
    defer alloc.free(acl);
    try std.testing.expectEqualStrings(
        \\-N NETBIRD-ACL-INPUT
        \\-A NETBIRD-ACL-INPUT -s 10.0.0.9/32 -p udp -j DROP
        \\-A NETBIRD-ACL-INPUT -s 10.0.0.1/32 -p tcp -m tcp --dport 443 -j ACCEPT
        \\-A NETBIRD-ACL-INPUT -s 10.0.0.5/32 -p tcp -m tcp --dport 8000:8010 -j ACCEPT
        \\-A NETBIRD-ACL-INPUT -s 10.0.0.6/32 -p tcp -m multiport --dports 80,443 -j ACCEPT
        \\
    , acl);

    const fwd_in = try runList(alloc, "filter", chains.rt_fwd_in);
    defer alloc.free(fwd_in);
    try std.testing.expectEqualStrings(
        \\-N NETBIRD-RT-FWD-IN
        \\-A NETBIRD-RT-FWD-IN -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
        \\-A NETBIRD-RT-FWD-IN -s 10.0.0.0/24 -d 10.1.0.0/24 -p tcp -j ACCEPT
        \\
    , fwd_in);

    const pre = try runList(alloc, "mangle", chains.rt_pre);
    defer alloc.free(pre);
    try std.testing.expectEqualStrings(
        \\-N NETBIRD-RT-PRE
        \\-A NETBIRD-RT-PRE -s 10.0.0.1/32 -i wt0 -p tcp -m tcp --dport 443 -m addrtype --dst-type LOCAL -j MARK --set-xmark 0x1bd20/0xffffffff
        \\-A NETBIRD-RT-PRE -s 10.0.0.9/32 -i wt0 -p udp -m addrtype --dst-type LOCAL -j MARK --set-xmark 0x1bd20/0xffffffff
        \\-A NETBIRD-RT-PRE -s 10.0.0.5/32 -i wt0 -p tcp -m tcp --dport 8000:8010 -m addrtype --dst-type LOCAL -j MARK --set-xmark 0x1bd20/0xffffffff
        \\-A NETBIRD-RT-PRE -s 10.0.0.6/32 -i wt0 -p tcp -m multiport --dports 80,443 -m addrtype --dst-type LOCAL -j MARK --set-xmark 0x1bd20/0xffffffff
        \\
    , pre);

    // Duplicate add returns the same id and installs nothing new.
    const peer_id2 = try filter.addFilterRule(&m, &peer_src, .none, .tcp, null, dport, .accept);
    try std.testing.expectEqualStrings(peer_id, peer_id2);
    const acl2 = try runList(alloc, "filter", chains.acl_input);
    defer alloc.free(acl2);
    try std.testing.expectEqualStrings(acl, acl2);

    // Delete removes both the filter rule and its mangle pair.
    try filter.deleteFilterRule(&m, peer_id);
    const acl3 = try runList(alloc, "filter", chains.acl_input);
    defer alloc.free(acl3);
    try std.testing.expectEqualStrings(
        \\-N NETBIRD-ACL-INPUT
        \\-A NETBIRD-ACL-INPUT -s 10.0.0.9/32 -p udp -j DROP
        \\-A NETBIRD-ACL-INPUT -s 10.0.0.5/32 -p tcp -m tcp --dport 8000:8010 -j ACCEPT
        \\-A NETBIRD-ACL-INPUT -s 10.0.0.6/32 -p tcp -m multiport --dports 80,443 -j ACCEPT
        \\
    , acl3);
    const pre3 = try runList(alloc, "mangle", chains.rt_pre);
    defer alloc.free(pre3);
    try std.testing.expectEqualStrings(
        \\-N NETBIRD-RT-PRE
        \\-A NETBIRD-RT-PRE -s 10.0.0.9/32 -i wt0 -p udp -m addrtype --dst-type LOCAL -j MARK --set-xmark 0x1bd20/0xffffffff
        \\-A NETBIRD-RT-PRE -s 10.0.0.5/32 -i wt0 -p tcp -m tcp --dport 8000:8010 -m addrtype --dst-type LOCAL -j MARK --set-xmark 0x1bd20/0xffffffff
        \\-A NETBIRD-RT-PRE -s 10.0.0.6/32 -i wt0 -p tcp -m multiport --dports 80,443 -m addrtype --dst-type LOCAL -j MARK --set-xmark 0x1bd20/0xffffffff
        \\
    , pre3);

    // Unknown id is a no-op.
    try filter.deleteFilterRule(&m, "no-such-rule");

    // Range/list rules delete by their stored (plural multiport) specs.
    try filter.deleteFilterRule(&m, range_id);
    try filter.deleteFilterRule(&m, list_id);
    const acl4 = try runList(alloc, "filter", chains.acl_input);
    defer alloc.free(acl4);
    try std.testing.expectEqualStrings(
        \\-N NETBIRD-ACL-INPUT
        \\-A NETBIRD-ACL-INPUT -s 10.0.0.9/32 -p udp -j DROP
        \\
    , acl4);

    // reset() removes tracked rules and all static state.
    try filter.deleteFilterRule(&m, drop_id);
    try m.reset();
    try std.testing.expect(!try m.runner.chainExists("filter", chains.acl_input));
    try std.testing.expect(!try m.runner.chainExists("filter", chains.rt_fwd_in));
    try std.testing.expect(!try m.runner.chainExists("mangle", chains.rt_pre));
    const input = try runList(alloc, "filter", "INPUT");
    defer alloc.free(input);
    try std.testing.expect(std.mem.indexOf(u8, input, "wt0") == null);
}
