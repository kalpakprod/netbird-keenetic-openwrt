// Tests for src/fw step 1: pure unit tests (run everywhere) plus the
// netns integration test (setup exact rules, idempotent re-apply, full
// cleanup). Run under `unshare -Urn` for the integration part; the host
// tables are never touched (the netns has its own).
const std = @import("std");
const builtin = @import("builtin");
const fwmark = @import("fwmark.zig");
const model = @import("model.zig");
const chains = @import("chains.zig");
const manager_mod = @import("manager.zig");
const lock_mod = @import("lock.zig");

const tio = std.testing.io;

test "fwmark values match upstream fwmark_test golden" {
    try std.testing.expectEqual(@as(u32, 0x1bd00), fwmark.base);
    try std.testing.expectEqual(@as(u32, 0x1bd10), fwmark.data_plane_in);
    try std.testing.expectEqual(@as(u32, 0x1bd11), fwmark.data_plane_out);
    try std.testing.expectEqual(@as(u32, 0x1bd20), fwmark.redirected);
    try std.testing.expectEqual(@as(u32, 0x1bd21), fwmark.masquerade);
    try std.testing.expectEqual(@as(u32, 0x1bd22), fwmark.masquerade_return);
    try std.testing.expect(fwmark.isDataPlaneMark(0x1bd10));
    try std.testing.expect(fwmark.isDataPlaneMark(0x1bd22));
    try std.testing.expect(!fwmark.isDataPlaneMark(0x1bd00));
    try std.testing.expect(!fwmark.isDataPlaneMark(0x1bd0f));
}

test "prefix parse and wildcard" {
    const p = try model.Prefix.parse("10.98.0.1/24");
    try std.testing.expect(!p.is_v6);
    try std.testing.expectEqual(@as(u8, 24), p.bits);
    try std.testing.expectEqualSlices(u8, &.{ 10, 98, 0, 1 }, p.bytes[0..4]);
    try std.testing.expect(!p.isWildcard());

    const any4 = try model.Prefix.parse("0.0.0.0/0");
    try std.testing.expect(any4.isWildcard());

    const v6 = try model.Prefix.parse("fd00::1/64");
    try std.testing.expect(v6.is_v6);
    try std.testing.expectEqual(@as(u8, 64), v6.bits);

    try std.testing.expectError(model.Error.InvalidPrefix, model.Prefix.parse("10.0.0.1"));
    try std.testing.expectError(model.Error.InvalidPrefix, model.Prefix.parse("nope/24"));
    try std.testing.expectError(model.Error.InvalidBits, model.Prefix.parse("10.0.0.1/33"));
}

test "port hash text matches Go Port.String" {
    const alloc = std.testing.allocator;
    const single = model.Port{ .is_range = false, .values = &.{443} };
    const t1 = try single.hashText(alloc);
    defer alloc.free(t1);
    try std.testing.expectEqualStrings("443", t1);

    const range = model.Port{ .is_range = true, .values = &.{ 80, 443 } };
    const t2 = try range.hashText(alloc);
    defer alloc.free(t2);
    try std.testing.expectEqualStrings("range:80,443", t2);
}

test "rule id is deterministic and source-order independent" {
    const alloc = std.testing.allocator;
    const a = try model.Prefix.parse("10.0.0.1/32");
    const b = try model.Prefix.parse("10.0.0.2/32");
    const dst = model.Network{ .prefix = try model.Prefix.parse("10.1.0.0/24") };
    const s1 = [_]model.Prefix{ a, b };
    const s2 = [_]model.Prefix{ b, a };
    const id1 = try model.generateRuleID(alloc, &s1, dst, .tcp, null, null, .accept);
    defer alloc.free(id1);
    const id2 = try model.generateRuleID(alloc, &s2, dst, .tcp, null, null, .accept);
    defer alloc.free(id2);
    try std.testing.expectEqualStrings(id1, id2);
    try std.testing.expect(std.mem.startsWith(u8, id1, "10.1.0.0/24-"));
    try std.testing.expectEqual(@as(usize, "10.1.0.0/24-".len + 16), id1.len);

    const id3 = try model.generateRuleID(alloc, &s1, dst, .tcp, null, null, .drop);
    defer alloc.free(id3);
    try std.testing.expect(!std.mem.eql(u8, id1, id3));
}

test "router pair keys match Go GenKey" {
    const alloc = std.testing.allocator;
    const pair = model.RouterPair{
        .id = "abc",
        .source = .none,
        .destination = .none,
        .masquerade = true,
        .inverse = false,
        .dynamic = false,
    };
    const k = try pair.natKey(alloc);
    defer alloc.free(k);
    try std.testing.expectEqualStrings("netbird-nat-abc-false", k);
    const inv = pair.inversePair();
    try std.testing.expect(inv.inverse);
    const k2 = try inv.natKey(alloc);
    defer alloc.free(k2);
    try std.testing.expectEqualStrings("netbird-nat-abc-true", k2);
    const k3 = try pair.fwdKey(alloc);
    defer alloc.free(k3);
    try std.testing.expectEqualStrings("netbird-fwd-abc-false", k3);
}

test "static chain specs" {
    var b: [13][]const u8 = undefined;
    try std.testing.expectEqualSlices(
        []const u8,
        &.{ "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT" },
        chains.establishedBare(&b),
    );
    try std.testing.expectEqualSlices(
        []const u8,
        &.{ "-j", "NETBIRD-RT-NAT" },
        chains.jump(&b, chains.rt_nat),
    );
    try std.testing.expectEqualSlices(
        []const u8,
        &.{ "-i", "wt0", "-m", "conntrack", "--ctstate", "DNAT", "-m", "mark", "!", "--mark", "0x1bd20", "-j", "DROP" },
        chains.mangleGuardDnat(&b, "wt0"),
    );
    try std.testing.expectEqualSlices(
        []const u8,
        &.{ "-i", "wt0", "-m", "conntrack", "--ctstate", "NEW", "-j", "CONNMARK", "--set-mark", "0x1bd10" },
        chains.dataplaneMarkIn(&b, "wt0"),
    );
    try std.testing.expectEqualSlices(
        []const u8,
        &.{ "-m", "mark", "--mark", "0x1bd21", "!", "-o", "lo", "-j", "MASQUERADE" },
        chains.natMasqueradeOut(&b),
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

fn runSave(alloc: std.mem.Allocator, table: []const u8) ![]u8 {
    const argv = [_][]const u8{ "iptables-save", "-t", table };
    var res = try std.process.run(alloc, tio, .{ .argv = &argv });
    defer alloc.free(res.stderr);
    errdefer alloc.free(res.stdout);
    if (!res.term.success()) return error.SaveFailed;
    return res.stdout;
}

/// Normalize an iptables-save dump: drop comment lines, strip packet
/// counters from chain headers. Returns owned text.
fn normalize(alloc: std.mem.Allocator, save: []const u8) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(alloc);
    var lines = std.mem.splitScalar(u8, save, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        if (line[0] == '#') continue;
        var text = line;
        if (line[0] == ':') {
            if (std.mem.indexOf(u8, line, " [")) |sp| text = line[0..sp];
        }
        try out.appendSlice(alloc, text);
        try out.append(alloc, '\n');
    }
    return out.toOwnedSlice(alloc);
}

const expected_filter =
    \\*filter
    \\:INPUT ACCEPT
    \\:FORWARD ACCEPT
    \\:OUTPUT ACCEPT
    \\:NETBIRD-ACL-INPUT -
    \\:NETBIRD-RT-FWD-IN -
    \\:NETBIRD-RT-FWD-OUT -
    \\-A INPUT -i wt0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    \\-A INPUT -i wt0 -j NETBIRD-ACL-INPUT
    \\-A INPUT -i wt0 -j DROP
    \\-A FORWARD -i wt0 -j NETBIRD-RT-FWD-IN
    \\-A FORWARD -m mark --mark 0x1bd20 -j ACCEPT
    \\-A FORWARD -o wt0 -j NETBIRD-RT-FWD-OUT
    \\-A FORWARD -i wt0 -j DROP
    \\-A NETBIRD-RT-FWD-IN -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    \\-A NETBIRD-RT-FWD-OUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    \\COMMIT
    \\
;

const expected_mangle =
    \\*mangle
    \\:PREROUTING ACCEPT
    \\:INPUT ACCEPT
    \\:FORWARD ACCEPT
    \\:OUTPUT ACCEPT
    \\:POSTROUTING ACCEPT
    \\:NETBIRD-RT-PRE -
    \\-A PREROUTING -j NETBIRD-RT-PRE
    \\-A PREROUTING -i wt0 -m conntrack --ctstate NEW -j CONNMARK --set-xmark 0x1bd10/0xffffffff
    \\-A FORWARD -i wt0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    \\-A FORWARD -i wt0 -m conntrack --ctstate DNAT -m mark ! --mark 0x1bd20 -j DROP
    \\-A POSTROUTING -o wt0 -m conntrack --ctstate NEW -j CONNMARK --set-xmark 0x1bd11/0xffffffff
    \\COMMIT
    \\
;

const expected_nat =
    \\*nat
    \\:PREROUTING ACCEPT
    \\:INPUT ACCEPT
    \\:OUTPUT ACCEPT
    \\:POSTROUTING ACCEPT
    \\:NETBIRD-RT-NAT -
    \\:NETBIRD-RT-RDR -
    \\-A PREROUTING -j NETBIRD-RT-RDR
    \\-A POSTROUTING -j NETBIRD-RT-NAT
    \\COMMIT
    \\
;

test "chains setup exact rules, idempotent re-apply, full cleanup" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!inUserNamespace()) return error.SkipZigTest;
    const alloc = std.testing.allocator;

    var l = try lock_mod.Lock.acquire(lock_mod.lock_path);
    defer l.release();

    const pristine_filter = try runSave(alloc, "filter");
    defer alloc.free(pristine_filter);
    const pristine_mangle = try runSave(alloc, "mangle");
    defer alloc.free(pristine_mangle);
    const pristine_nat = try runSave(alloc, "nat");
    defer alloc.free(pristine_nat);

    var m = try manager_mod.Manager.init(alloc, tio, "iptables", "wt0", 1280);
    defer m.deinit();
    defer m.reset() catch {};

    try m.setup();

    const f1 = try runSave(alloc, "filter");
    defer alloc.free(f1);
    const n1 = try normalize(alloc, f1);
    defer alloc.free(n1);
    try std.testing.expectEqualStrings(expected_filter, n1);

    const mg1 = try runSave(alloc, "mangle");
    defer alloc.free(mg1);
    const nm1 = try normalize(alloc, mg1);
    defer alloc.free(nm1);
    try std.testing.expectEqualStrings(expected_mangle, nm1);

    const t1 = try runSave(alloc, "nat");
    defer alloc.free(t1);
    const nt1 = try normalize(alloc, t1);
    defer alloc.free(nt1);
    try std.testing.expectEqualStrings(expected_nat, nt1);

    // Re-apply converges to the identical state.
    try m.setup();
    const f2 = try runSave(alloc, "filter");
    defer alloc.free(f2);
    const n2 = try normalize(alloc, f2);
    defer alloc.free(n2);
    try std.testing.expectEqualStrings(expected_filter, n2);

    // Full cleanup restores the pristine tables (normalized: raw saves
    // carry a timestamp comment).
    try m.reset();
    const f3 = try runSave(alloc, "filter");
    defer alloc.free(f3);
    const n3 = try normalize(alloc, f3);
    defer alloc.free(n3);
    const pn = try normalize(alloc, pristine_filter);
    defer alloc.free(pn);
    try std.testing.expectEqualStrings(pn, n3);
    const mg3 = try runSave(alloc, "mangle");
    defer alloc.free(mg3);
    const nm3 = try normalize(alloc, mg3);
    defer alloc.free(nm3);
    const pnm = try normalize(alloc, pristine_mangle);
    defer alloc.free(pnm);
    try std.testing.expectEqualStrings(pnm, nm3);
    const t3 = try runSave(alloc, "nat");
    defer alloc.free(t3);
    const nt3 = try normalize(alloc, t3);
    defer alloc.free(nt3);
    const pnt = try normalize(alloc, pristine_nat);
    defer alloc.free(pnt);
    try std.testing.expectEqualStrings(pnt, nt3);
}
