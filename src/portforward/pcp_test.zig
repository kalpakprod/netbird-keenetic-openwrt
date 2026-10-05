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

fn testAddrFromEnviron(out: []u8) ?[]u8 {
    var file = std.Io.Dir.openFileAbsolute(tio, "/proc/self/environ", .{ .mode = .read_only }) catch return null;
    defer file.close(tio);
    var ebuf: [65536]u8 = undefined;
    const n = file.readPositionalAll(tio, &ebuf, 0) catch return null;
    var entries = std.mem.splitScalar(u8, ebuf[0..n], 0);
    const prefix = "PCP_TEST_ADDR=";
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

test "link local gateway sockaddr preserves interface scope" {
    var c = pcp.Client{};
    const link_local = [_]u8{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    c.setGateway6Scoped(link_local, 5);
    const sa = c.gatewaySockaddr6();
    try std.testing.expectEqual(@as(u32, 5), sa.scope_id);
    try std.testing.expectEqual(linux.AF.INET6, sa.family);
    try std.testing.expectEqual(std.mem.nativeToBig(u16, pcp.port), sa.port);
    try std.testing.expectEqualSlices(u8, &link_local, &sa.addr);
    try std.testing.expect(c.gatewaySource6Matches(&sa));
    var wrong = sa;
    wrong.scope_id = 6;
    try std.testing.expect(!c.gatewaySource6Matches(&wrong));
    c.setGateway6(.{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 });
    try std.testing.expectEqual(@as(u32, 0), c.gatewaySockaddr6().scope_id);
    c.setGateway6Scoped(link_local, 5);
    c.setGateway4(.{ 127, 0, 0, 1 });
    try std.testing.expectEqual(@as(u32, 0), c.gateway_scope_id);
}

// Real UDP lifecycle fixture adapted from the saved R40 regression harness.
fn failed(rc: usize) bool {
    return rc > 0xfffffffffffff000;
}

fn gatewaySocket() !linux.fd_t {
    const rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    if (failed(rc)) return error.SocketFailed;
    const fd: linux.fd_t = @intCast(rc);
    errdefer _ = linux.close(fd);
    var sa = linux.sockaddr.in{ .family = linux.AF.INET, .port = std.mem.nativeToBig(u16, pcp.port), .addr = @bitCast([_]u8{ 127, 0, 0, 2 }) };
    if (failed(linux.bind(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in)))) return error.BindFailed;
    return fd;
}

const Fixture = struct {
    fd: linux.fd_t,
    addresses: [2][16]u8,
    temporary: bool = false,
    expected_nonce: ?pcp.Nonce = null,
    requests: usize = 0,
    nonce_reused: bool = false,
    err: ?anyerror = null,

    fn run(f: *@This()) void {
        f.respond() catch |err| { f.err = err; };
    }

    fn respond(f: *@This()) !void {
        var first_nonce: pcp.Nonce = undefined;
        for (0..2) |i| {
            var pfds = [_]linux.pollfd{.{ .fd = f.fd, .events = linux.POLL.IN }};
            if (linux.poll(&pfds, 1, 2000) != 1) return error.NoRequest;
            var req: [128]u8 = undefined;
            var peer: linux.sockaddr.in = undefined;
            var peer_len: linux.socklen_t = @sizeOf(linux.sockaddr.in);
            if (linux.recvfrom(f.fd, &req, req.len, 0, @ptrCast(&peer), &peer_len) != 60) return error.BadFixtureRequest;
            if (req[0] != 2 or req[1] != 1 or req[36] != 17) return error.BadFixtureRequest;
            const lifetime = std.mem.readInt(u32, req[4..8], .big);
            if (!f.temporary) {
                if ((i == 0 and lifetime != 3600) or (i == 1 and lifetime != 0)) return error.BadFixtureRequest;
            } else if (lifetime != (if (i == 0) @as(u32, 1) else 0)) return error.BadFixtureRequest;
            if (lifetime == 0 and std.mem.readInt(u16, req[42..44], .big) != 0) return error.BadFixtureRequest;
            if (i == 0) first_nonce = req[24..36].* else f.nonce_reused = std.mem.eql(u8, &first_nonce, req[24..36]);
            if (f.expected_nonce) |nonce| {
                if (!std.mem.eql(u8, &nonce, req[24..36])) return error.BadFixtureNonce;
            }
            var response: [60]u8 = undefined;
            @memset(&response, 0);
            response[0] = 2;
            response[1] = 0x81;
            response[3] = 0;
            @memcpy(response[4..8], req[4..8]);
            std.mem.writeInt(u32, response[8..12], 2000, .big);
            @memcpy(response[24..36], req[24..36]);
            response[36] = req[36];
            @memcpy(response[40..44], req[40..44]);
            @memcpy(response[44..60], &f.addresses[i]);
            if (linux.sendto(f.fd, &response, response.len, 0, @ptrCast(&peer), peer_len) != response.len) return error.SendFailed;
            f.requests += 1;
        }
    }
};


const learned_v4 = pcp.mapV4(.{ 203, 0, 113, 9 });
const learned_v6 = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9 };
const unspecified_v6 = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
const unspecified_v4 = pcp.mapV4(.{ 0, 0, 0, 0 });

fn cacheLifecycle(learned: [16]u8, deleted: [16]u8) !void {
    const gateway = try gatewaySocket();
    defer _ = linux.close(gateway);
    var c = pcp.Client{ .timeout_ms = 500, .retries = 1 };
    c.setGateway4(.{ 127, 0, 0, 2 });
    c.setLocal4(.{ 127, 0, 0, 1 });
    var f = Fixture{ .fd = gateway, .addresses = .{ learned, deleted } };
    const thread = try std.Thread.spawn(.{}, Fixture.run, .{&f});
    const created = c.addPortMapping(pcp.proto_udp, 61824, 3600);
    const removed = c.mapPort(pcp.proto_udp, 61824, 0, null, 0);
    thread.join();
    if (f.err) |err| return err;
    try std.testing.expectEqualSlices(u8, &learned, &(try created).external_ip16);
    try std.testing.expectEqualSlices(u8, &deleted, &(try removed).external_ip16);
    try std.testing.expectEqual(@as(usize, 2), f.requests);
    try std.testing.expect(f.nonce_reused);
    try std.testing.expectEqual(@as(usize, 0), c.n_nonces);
    const cached = try c.externalAddress();
    try std.testing.expectEqualSlices(u8, &learned, &cached);
}

test "cache lifecycle preserves learned IPv4 after mapped unspecified delete" {
    try cacheLifecycle(learned_v4, unspecified_v4);
}

test "cache lifecycle preserves learned IPv6 after plain unspecified delete" {
    try cacheLifecycle(learned_v6, unspecified_v6);
}

test "temporary external address returns raw response without caching unspecified" {
    for ([_][16]u8{ unspecified_v6, unspecified_v4, learned_v6 }) |address| {
        const gateway = try gatewaySocket();
        defer _ = linux.close(gateway);
        var c = pcp.Client{ .timeout_ms = 500, .retries = 1 };
        c.setGateway4(.{ 127, 0, 0, 2 });
        c.setLocal4(.{ 127, 0, 0, 1 });
        var f = Fixture{ .fd = gateway, .temporary = true, .addresses = .{ address, unspecified_v4 } };
        const thread = try std.Thread.spawn(.{}, Fixture.run, .{&f});
        const result = c.externalAddress();
        thread.join();
        if (f.err) |err| return err;
        const actual = try result;
        try std.testing.expectEqualSlices(u8, &address, &actual);
        try std.testing.expectEqual(!std.mem.eql(u8, &address, &unspecified_v6) and !std.mem.eql(u8, &address, &unspecified_v4), c.has_external);
        try std.testing.expect(f.nonce_reused);
        try std.testing.expectEqual(@as(usize, 0), c.n_nonces);
        if (c.has_external) {
            const cached = try c.externalAddress();
            try std.testing.expectEqualSlices(u8, &address, &cached);
        }
    }
}
