// Tests for natpmp.zig. Oracles: testdata/natpmp_vectors.txt (requests
// produced by jackpal/go-nat-pmp, responses accepted by it — see
// gen/nat/cmd/natvecs + cmd/fakegw), and a live run against the fake
// gateway via NATPMP_TEST_ADDR=127.0.0.1:5351.

const std = @import("std");
const builtin = @import("builtin");
const natpmp = @import("natpmp.zig");
const linux = std.os.linux;

const vectors_text = @embedFile("testdata/natpmp_vectors.txt");

fn vecHex(name: []const u8, out: []u8) []u8 {
    var lines = std.mem.splitScalar(u8, vectors_text, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var parts = std.mem.splitScalar(u8, line, ' ');
        const n = parts.next() orelse continue;
        if (!std.mem.eql(u8, n, name)) continue;
        const h = parts.next() orelse continue;
        const blen = h.len / 2;
        std.debug.assert(blen <= out.len);
        for (0..blen) |i| {
            out[i] = std.fmt.parseInt(u8, h[i * 2 .. i * 2 + 2], 16) catch unreachable;
        }
        return out[0..blen];
    }
    unreachable;
}

test "external address vector" {
    var buf: [64]u8 = undefined;
    var buf2: [64]u8 = undefined;
    const req = vecHex("ext_req", &buf);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0 }, req);
    // Separate buffer: vecHex slices alias the output buffer.
    const resp = vecHex("ext_resp", &buf2);
    const r = try natpmp.decodeExtResponse(resp);
    try std.testing.expectEqual(@as(u16, 0), r.result);
    try std.testing.expectEqual(@as(u32, 1000), r.epoch_s);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 203, 0, 113, 9 }, &r.external);
    // Re-encode matches the Go client's request bytes.
    var enc: [2]u8 = undefined;
    try std.testing.expectEqualSlices(u8, req, natpmp.encodeExternalRequest(&enc));
}

test "map vector" {
    var buf: [64]u8 = undefined;
    const req = vecHex("map_req", &buf);
    // jackpal asked udp 51820 -> 51820 for 3600s.
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 1, 0, 0, 0xca, 0x6c, 0xca, 0x6c, 0, 0, 0x0e, 0x10 }, req);
    var enc: [12]u8 = undefined;
    try std.testing.expectEqualSlices(
        u8,
        req,
        natpmp.encodeMapRequest(&enc, .udp, 51820, 51820, 3600),
    );
    const resp = vecHex("map_resp", &buf);
    const m = try natpmp.decodeMapResponse(resp, .udp);
    try std.testing.expectEqual(@as(u16, 0), m.result);
    try std.testing.expectEqual(@as(u32, 1000), m.epoch_s);
    try std.testing.expectEqual(@as(u16, 51820), m.internal_port);
    try std.testing.expectEqual(@as(u16, 51820), m.external_port);
    try std.testing.expectEqual(@as(u32, 3600), m.lifetime_s);
}

test "delete vector" {
    var buf: [64]u8 = undefined;
    const req = vecHex("del_req", &buf);
    var enc: [12]u8 = undefined;
    try std.testing.expectEqualSlices(u8, req, natpmp.encodeMapRequest(&enc, .udp, 51820, 0, 0));
    const resp = vecHex("del_resp", &buf);
    const m = try natpmp.decodeMapResponse(resp, .udp);
    try std.testing.expectEqual(@as(u32, 0), m.lifetime_s);
}

test "malformed responses rejected" {
    var buf: [64]u8 = undefined;
    const resp = vecHex("ext_resp", &buf);
    try std.testing.expectError(natpmp.Error.BadResponse, natpmp.decodeExtResponse(resp[0..11]));
    var bad: [12]u8 = undefined;
    @memcpy(&bad, resp[0..12]);
    bad[0] = 1;
    try std.testing.expectError(natpmp.Error.BadVersion, natpmp.decodeExtResponse(&bad));
    bad[0] = 0;
    bad[1] = 129;
    try std.testing.expectError(natpmp.Error.BadResponse, natpmp.decodeExtResponse(&bad));
    const mresp = vecHex("map_resp", &buf);
    // UDP response must not parse as TCP.
    try std.testing.expectError(natpmp.Error.BadResponse, natpmp.decodeMapResponse(mresp, .tcp));
}

const tio = std.testing.io;

fn testAddrFromEnviron(out: []u8) ?[]u8 {
    var file = std.Io.Dir.openFileAbsolute(tio, "/proc/self/environ", .{ .mode = .read_only }) catch return null;
    defer file.close(tio);
    var ebuf: [65536]u8 = undefined;
    const n = file.readPositionalAll(tio, &ebuf, 0) catch return null;
    var entries = std.mem.splitScalar(u8, ebuf[0..n], 0);
    const prefix = "NATPMP_TEST_ADDR=";
    while (entries.next()) |e| {
        if (std.mem.startsWith(u8, e, prefix)) {
            const v = e[prefix.len..];
            if (v.len == 0 or v.len > out.len) return null;
            @memcpy(out[0..v.len], v);
            return out[0..v.len];
        }
    }
    return null;
}

test "live exchange with fake gateway" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var env_buf: [64]u8 = undefined;
    const env = testAddrFromEnviron(&env_buf) orelse return error.SkipZigTest;
    var it = std.mem.splitScalar(u8, env, ':');
    const host = it.next() orelse return error.SkipZigTest;
    var gw: [4]u8 = undefined;
    var oit = std.mem.splitScalar(u8, host, '.');
    for (0..4) |i| gw[i] = std.fmt.parseInt(u8, oit.next() orelse return error.SkipZigTest, 10) catch return error.SkipZigTest;

    var c = try natpmp.open(gw);
    defer c.close();
    const ext = try c.externalAddress();
    try std.testing.expectEqualSlices(u8, &[_]u8{ 203, 0, 113, 9 }, &ext);
    const m = try c.addPortMapping(.udp, 51820, 51820, 3600);
    try std.testing.expectEqual(@as(u16, 51820), m.external_port);
    try std.testing.expectEqual(@as(u32, 3600), m.lifetime_s);
    try c.deletePortMapping(.udp, 51820);
    // TCP opcode path works too.
    const t = try c.addPortMapping(.tcp, 51821, 0, 100);
    try std.testing.expect(t.external_port != 0);
    try c.deletePortMapping(.tcp, 51821);
}

test "timeout against silent listener" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    // Occupy 127.0.0.1:5351 with a socket that never answers; skip when a
    // fake gateway already holds it (the live test covers that case).
    const sfd = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    if (sfd > 0xfffffffffffff000) return error.SkipZigTest;
    const fd: linux.fd_t = @intCast(sfd);
    defer _ = linux.close(fd);
    var sa = linux.sockaddr.in{
        .family = linux.AF.INET,
        .port = std.mem.nativeToBig(u16, natpmp.port),
        .addr = 0x0100007f,
    };
    if (linux.bind(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in)) > 0xfffffffffffff000)
        return error.SkipZigTest;
    var c = try natpmp.open(.{ 127, 0, 0, 1 });
    defer c.close();
    c.timeout_ms = 300;
    try std.testing.expectError(natpmp.Error.Timeout, c.externalAddress());
}
