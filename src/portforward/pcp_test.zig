// Tests for pcp.zig. Oracles: testdata/pcp_vectors.txt (requests produced
// by netbirdio/go-nat/pcp, responses accepted by it — see gen/nat/cmd/natvecs
// + cmd/fakegw), and a live run against the fake gateway via
// PCP_TEST_ADDR=127.0.0.1:5351.

const std = @import("std");
const builtin = @import("builtin");
const pcp = @import("pcp.zig");
const linux = std.os.linux;

const vectors_text = @embedFile("testdata/pcp_vectors.txt");

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

const loopback_mapped: [16]u8 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1 };

test "announce vector" {
    var buf: [128]u8 = undefined;
    const req = vecHex("announce_req", &buf);
    try std.testing.expectEqual(@as(usize, 24), req.len);
    try std.testing.expectEqualSlices(u8, &loopback_mapped, req[8..24]);
    var enc: [24]u8 = undefined;
    try std.testing.expectEqualSlices(u8, req, pcp.encodeAnnounceRequest(&enc, loopback_mapped));
    const resp = vecHex("announce_resp", &buf);
    const h = try pcp.decodeHeader(resp);
    try std.testing.expectEqual(@as(u8, 0), h.result);
    try std.testing.expectEqual(@as(u32, 2000), h.epoch);
}

test "map vector" {
    var buf: [256]u8 = undefined;
    const req = vecHex("map_req", &buf);
    try std.testing.expectEqual(@as(usize, 60), req.len);
    try std.testing.expectEqual(@as(u32, 3600), std.mem.readInt(u32, req[4..8], .big));
    try std.testing.expectEqualSlices(u8, &loopback_mapped, req[8..24]);
    try std.testing.expectEqual(@as(u8, 17), req[36]);
    try std.testing.expectEqual(@as(u16, 51820), std.mem.readInt(u16, req[40..42], .big));
    try std.testing.expectEqual(@as(u16, 51820), std.mem.readInt(u16, req[42..44], .big));
    // Re-encode from parsed fields matches the Go client's bytes.
    var enc: [60]u8 = undefined;
    var want_ip: [16]u8 = undefined;
    @memcpy(&want_ip, req[44..60]);
    try std.testing.expectEqualSlices(
        u8,
        req,
        pcp.encodeMapRequest(&enc, loopback_mapped, req[24..36].*, 17, 51820, 51820, want_ip, 3600),
    );
    const resp = vecHex("map_resp", &buf);
    const m = try pcp.decodeMapResponse(resp);
    try std.testing.expectEqual(@as(u8, 0), m.result);
    try std.testing.expectEqual(@as(u32, 3600), m.lifetime_s);
    try std.testing.expectEqual(@as(u32, 2000), m.epoch);
    try std.testing.expectEqualSlices(u8, req[24..36], &m.nonce);
    try std.testing.expectEqual(@as(u8, 17), m.proto);
    try std.testing.expectEqual(@as(u16, 51820), m.internal_port);
    try std.testing.expectEqual(@as(u16, 51820), m.external_port);
    try std.testing.expectEqualSlices(
        u8,
        &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 203, 0, 113, 9 },
        &m.external_ip16,
    );
}

test "delete vector reuses the map nonce" {
    var buf: [256]u8 = undefined;
    const map_req = vecHex("map_req", &buf);
    var map_nonce: [12]u8 = undefined;
    @memcpy(&map_nonce, map_req[24..36]);
    const del_req = vecHex("del_req", &buf);
    // Lifetime 0, suggested port 0, same nonce as the mapping (RFC 6887 §11.3).
    try std.testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, del_req[4..8], .big));
    try std.testing.expectEqualSlices(u8, &map_nonce, del_req[24..36]);
    var enc: [60]u8 = undefined;
    var want_ip: [16]u8 = undefined;
    @memcpy(&want_ip, del_req[44..60]);
    try std.testing.expectEqualSlices(
        u8,
        del_req,
        pcp.encodeMapRequest(&enc, loopback_mapped, map_nonce, 17, 51820, 0, want_ip, 0),
    );
    const resp = vecHex("del_resp", &buf);
    const m = try pcp.decodeMapResponse(resp);
    try std.testing.expectEqual(@as(u32, 0), m.lifetime_s);
}

test "malformed responses rejected" {
    var buf: [256]u8 = undefined;
    const resp = vecHex("map_resp", &buf);
    try std.testing.expectError(pcp.Error.BadResponse, pcp.decodeMapResponse(resp[0..59]));
    var bad: [60]u8 = undefined;
    @memcpy(&bad, resp[0..60]);
    bad[0] = 1;
    try std.testing.expectError(pcp.Error.BadVersion, pcp.decodeMapResponse(&bad));
    bad[0] = 2;
    bad[1] = 0x01;
    try std.testing.expectError(pcp.Error.MissingReply, pcp.decodeMapResponse(&bad));
}

const tio = std.testing.io;

fn testEnvFromEnviron(out: []u8, prefix: []const u8) ?[]u8 {
    var file = std.Io.Dir.openFileAbsolute(tio, "/proc/self/environ", .{ .mode = .read_only }) catch return null;
    defer file.close(tio);
    var ebuf: [65536]u8 = undefined;
    const n = file.readPositionalAll(tio, &ebuf, 0) catch return null;
    var entries = std.mem.splitScalar(u8, ebuf[0..n], 0);
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

fn testAddrFromEnviron(out: []u8) ?[]u8 {
    return testEnvFromEnviron(out, "PCP_TEST_ADDR=");
}

fn nowMsLocal() i64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return ts.sec * 1000 + @divTrunc(ts.nsec, 1_000_000);
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

    var c = pcp.Client{};
    c.setGateway4(gw);
    c.setLocal4(gw);
    c.timeout_ms = 1000;
    c.retries = 2;
    const epoch = try c.announce();
    try std.testing.expectEqual(@as(u32, 2000), epoch);
    try std.testing.expect(!c.epochStateLost());
    const m = try c.addPortMapping(pcp.proto_udp, 61820, 3600);
    try std.testing.expectEqual(@as(u16, 61820), m.external_port);
    try std.testing.expectEqualSlices(
        u8,
        &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 203, 0, 113, 9 },
        &m.external_ip16,
    );
    try c.deletePortMapping(pcp.proto_udp, 61820);
    const ext = try c.externalAddress();
    try std.testing.expect(pcp.isMappedV4(ext));
    try std.testing.expectEqualSlices(u8, &[_]u8{ 203, 0, 113, 9 }, ext[12..16]);
}

test "no gateway and no local are errors" {
    var c = pcp.Client{};
    try std.testing.expectError(pcp.Error.NoLocalIP, c.announce());
    c.setLocal4(.{ 127, 0, 0, 1 });
    try std.testing.expectError(pcp.Error.NoGateway, c.announce());
}

test "dead gateway fails within the total budget" {
    // Namespace only (PF_TEST_NS set): 192.0.2.1 is unroutable there, so no
    // packet leaves and the retry sleeps prove the deadline bound.
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var mbuf: [16]u8 = undefined;
    if (testEnvFromEnviron(&mbuf, "PF_TEST_NS=") == null) return error.SkipZigTest;
    var c = pcp.Client{};
    c.setGateway4(.{ 192, 0, 2, 1 });
    c.setLocal4(.{ 127, 0, 0, 1 });
    c.timeout_ms = 1500;
    const t0 = nowMsLocal();
    if (c.announce()) |_| return error.ExpectedFailure else |_| {}
    const dt = nowMsLocal() - t0;
    try std.testing.expect(dt >= 1400 and dt < 3000);
}
