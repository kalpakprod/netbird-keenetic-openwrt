// Tests for src/fw step 3: pure NAT/legacy spec tests (run everywhere)
// plus the netns integration test (mark rules installed at head,
// legacy mode, removal, reset cleans all).
const std = @import("std");
const builtin = @import("builtin");
const model = @import("model.zig");
const chains = @import("chains.zig");
const nat = @import("nat.zig");
const manager_mod = @import("manager.zig");
const lock_mod = @import("lock.zig");

const tio = std.testing.io;

fn expectSpec(actual: model.Spec, expected: []const []const u8) !void {
    try std.testing.expectEqual(expected.len, actual.len);
    for (expected, actual) |e, a| try std.testing.expectEqualStrings(e, a);
}

fn testPair() !model.RouterPair {
    return .{
        .id = "route-1",
        .source = .{ .prefix = try model.Prefix.parse("10.0.0.0/24") },
        .destination = .{ .prefix = try model.Prefix.parse("10.1.0.0/24") },
        .masquerade = true,
        .inverse = false,
        .dynamic = false,
    };
}

test "forward mark rule selects masqueraded flows" {
    const alloc = std.testing.allocator;
    const pair = try testPair();
    const spec = try nat.buildNatMarkRule(alloc, "wt0", pair);
    defer model.freeSpec(alloc, spec);
    try expectSpec(spec, &.{
        "-i", "wt0", "-m", "conntrack", "--ctstate", "NEW",
        "-s", "10.0.0.0/24", "-d", "10.1.0.0/24",
        "-j", "MARK", "--set-mark", "0x1bd21",
    });
}

test "inverse mark rule matches off-interface return flows" {
    const alloc = std.testing.allocator;
    const pair = (try testPair()).inversePair();
    const spec = try nat.buildNatMarkRule(alloc, "wt0", pair);
    defer model.freeSpec(alloc, spec);
    try expectSpec(spec, &.{
        "!", "-i", "wt0", "-m", "conntrack", "--ctstate", "NEW",
        "-s", "10.1.0.0/24", "-d", "10.0.0.0/24",
        "-j", "MARK", "--set-mark", "0x1bd22",
    });
}

test "legacy rule is a plain forward accept" {
    const alloc = std.testing.allocator;
    const spec = try nat.buildLegacyRule(alloc, try testPair());
    defer model.freeSpec(alloc, spec);
    try expectSpec(spec, &.{
        "-s", "10.0.0.0/24", "-d", "10.1.0.0/24", "-j", "ACCEPT",
    });
}

test "set networks in NAT pairs need ipset" {
    const alloc = std.testing.allocator;
    var pair = try testPair();
    pair.destination = .{ .set = .{ .name = "nb-dom-1234" } };
    try std.testing.expectError(model.Error.IpsetRequired, nat.buildNatMarkRule(alloc, "wt0", pair));
    try std.testing.expectError(model.Error.IpsetRequired, nat.buildLegacyRule(alloc, pair));
    pair.destination = .{ .prefix = try model.Prefix.parse("10.1.0.0/24") };
    pair.source = .{ .set = .{ .name = "nb-dom-5678" } };
    try std.testing.expectError(model.Error.IpsetRequired, nat.buildNatMarkRule(alloc, "wt0", pair));
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

test "nat marks at head, legacy mode, removal, cleanup" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!inUserNamespace()) return error.SkipZigTest;
    const alloc = std.testing.allocator;

    var l = try lock_mod.Lock.acquire(lock_mod.lock_path);
    defer l.release();

    var m = try manager_mod.Manager.init(alloc, tio, "iptables", "wt0", 1280, false);
    defer m.deinit();
    defer m.reset() catch {};
    try m.setup();

    const pair = try testPair();
    try nat.addNatRule(&m, pair);

    // Both marks installed at head (inverse inserted last, so first).
    const pre = try runList(alloc, "mangle", chains.rt_pre);
    defer alloc.free(pre);
    try std.testing.expectEqualStrings(
        \\-N NETBIRD-RT-PRE
        \\-A NETBIRD-RT-PRE -s 10.1.0.0/24 -d 10.0.0.0/24 ! -i wt0 -m conntrack --ctstate NEW -j MARK --set-xmark 0x1bd22/0xffffffff
        \\-A NETBIRD-RT-PRE -s 10.0.0.0/24 -d 10.1.0.0/24 -i wt0 -m conntrack --ctstate NEW -j MARK --set-xmark 0x1bd21/0xffffffff
        \\
    , pre);

    // Re-adding replaces, not duplicates.
    try nat.addNatRule(&m, pair);
    const pre2 = try runList(alloc, "mangle", chains.rt_pre);
    defer alloc.free(pre2);
    try std.testing.expectEqualStrings(pre, pre2);

    // Removal drops both marks.
    try nat.removeNatRule(&m, pair);
    const pre3 = try runList(alloc, "mangle", chains.rt_pre);
    defer alloc.free(pre3);
    try std.testing.expectEqualStrings(
        \\-N NETBIRD-RT-PRE
        \\
    , pre3);

    // Legacy mode adds a plain forward ACCEPT next to the marks.
    try nat.setLegacyManagement(&m, true);
    try nat.addNatRule(&m, pair);
    const fwd = try runList(alloc, "filter", chains.rt_fwd_in);
    defer alloc.free(fwd);
    try std.testing.expectEqualStrings(
        \\-N NETBIRD-RT-FWD-IN
        \\-A NETBIRD-RT-FWD-IN -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
        \\-A NETBIRD-RT-FWD-IN -s 10.0.0.0/24 -d 10.1.0.0/24 -j ACCEPT
        \\
    , fwd);

    // Leaving legacy mode removes the ACCEPT but keeps the marks.
    try nat.setLegacyManagement(&m, false);
    const fwd2 = try runList(alloc, "filter", chains.rt_fwd_in);
    defer alloc.free(fwd2);
    try std.testing.expectEqualStrings(
        \\-N NETBIRD-RT-FWD-IN
        \\-A NETBIRD-RT-FWD-IN -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
        \\
    , fwd2);
    const pre4 = try runList(alloc, "mangle", chains.rt_pre);
    defer alloc.free(pre4);
    try std.testing.expectEqualStrings(pre, pre4);

    // reset() removes tracked marks, MSS state and all static state.
    try m.reset();
    try std.testing.expect(!try m.runner.chainExists("mangle", chains.rt_pre));
    try std.testing.expect(!try m.runner.chainExists("mangle", chains.rt_mss_clamp));
    try std.testing.expect(!try m.runner.chainExists("nat", chains.rt_nat));
    const fwd_out = try runList(alloc, "mangle", "FORWARD");
    defer alloc.free(fwd_out);
    try std.testing.expect(std.mem.indexOf(u8, fwd_out, "NETBIRD") == null);
}
