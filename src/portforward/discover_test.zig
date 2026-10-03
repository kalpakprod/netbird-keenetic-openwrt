// Tests for go-nat discovery order. Live tests run only in a namespace
// (PF_TEST_NS=<mode>); modes select the fake combo, one combo per run:
//   full   - fakegw (FAKEGW_V6=1) + fakeigd
//   upnp   - fakeigd only
//   natpmp - fakegw with FAKEGW_PCP_OFF=1, no fakeigd
// Never run live discovery on the host: it would probe the real gateway.
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const discover = @import("discover.zig");

test "unit shortService maps URNs" {
    try std.testing.expectEqualStrings("IP2", discover.shortService("urn:schemas-upnp-org:service:WANIPConnection:2"));
    try std.testing.expectEqualStrings("IP1", discover.shortService("urn:schemas-upnp-org:service:WANIPConnection:1"));
    try std.testing.expectEqualStrings("PPP1", discover.shortService("urn:schemas-upnp-org:service:WANPPPConnection:1"));
}

fn testMode(out: []u8) ?[]u8 {
    const path = "/proc/self/environ";
    const rc = linux.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (rc > 0xfffffffffffff000 or rc == 0) return null;
    const fd: linux.fd_t = @intCast(rc);
    defer _ = linux.close(fd);
    var ebuf: [65536]u8 = undefined;
    const n = linux.read(fd, &ebuf, ebuf.len);
    if (n > 0xfffffffffffff000 or n == 0) return null;
    var entries = std.mem.splitScalar(u8, ebuf[0..n], 0);
    const name = "PF_TEST_NS";
    while (entries.next()) |e| {
        if (e.len > name.len and std.mem.eql(u8, e[0..name.len], name) and e[name.len] == '=') {
            const v = e[name.len + 1 ..];
            if (v.len == 0 or v.len > out.len) return null;
            @memcpy(out[0..v.len], v);
            return out[0..v.len];
        }
    }
    return null;
}

fn wantMode(mode: []const u8) bool {
    var buf: [16]u8 = undefined;
    const m = testMode(&buf) orelse return false;
    return std.mem.eql(u8, m, mode);
}

fn nowMs() i64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return ts.sec * 1000 + @divTrunc(ts.nsec, 1_000_000);
}

const gw4: [4]u8 = .{ 127, 0, 0, 1 };
const v6loop = discover.V6Pair{
    .gateway = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
    .local = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
};

test "live PCP preferred over UPnP and NAT-PMP" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!wantMode("full")) return error.SkipZigTest;
    var g = try discover.discoverWithGateways(gw4, gw4, null, nowMs() + 10000);
    defer g.close();
    try std.testing.expect(g == .pcp);
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("PCP", try g.typeString(&buf));
}

test "live UPnP unicast wins without PCP and NAT-PMP" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!wantMode("upnp")) return error.SkipZigTest;
    var g = try discover.discoverWithGateways(gw4, gw4, null, nowMs() + 15000);
    defer g.close();
    try std.testing.expect(g == .upnp);
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("UPnP unicast (IP2)", try g.typeString(&buf));
}

test "live NAT-PMP wins without PCP and UPnP" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!wantMode("natpmp")) return error.SkipZigTest;
    var g = try discover.discoverWithGateways(gw4, gw4, null, nowMs() + 10000);
    defer g.close();
    try std.testing.expect(g == .natpmp);
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("NAT-PMP", try g.typeString(&buf));
}

test "live dual attaches PCPv6 pinhole" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!wantMode("full")) return error.SkipZigTest;
    var g = try discover.discoverWithGateways(gw4, gw4, v6loop, nowMs() + 10000);
    defer g.close();
    try std.testing.expect(g == .dual);
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("PCP+PCPv6", try g.typeString(&buf));
}

test "live IPv6 pinhole alone without IPv4" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!wantMode("full")) return error.SkipZigTest;
    const unroutable: [4]u8 = .{ 192, 0, 2, 1 };
    var g = try discover.discoverWithGateways(unroutable, gw4, v6loop, nowMs() + 4000);
    defer g.close();
    try std.testing.expect(g == .pcp6only);
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("PCP", try g.typeString(&buf));
}

test "live no gateway anywhere" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!wantMode("full")) return error.SkipZigTest;
    const unroutable: [4]u8 = .{ 192, 0, 2, 1 };
    const r = discover.discoverWithGateways(unroutable, gw4, null, nowMs() + 2000);
    try std.testing.expectError(discover.Error.NoGateway, r);
}

test "live full discover without route fails fast" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!wantMode("full")) return error.SkipZigTest;
    // The namespace has no default route, so this sends no packets.
    const t0 = nowMs();
    const r = discover.discover(t0 + 10000);
    try std.testing.expectError(discover.Error.NoGateway, r);
    try std.testing.expect(nowMs() - t0 < 2000);
}
