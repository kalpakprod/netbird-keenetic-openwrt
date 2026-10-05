// Tests for stun.zig. Oracles: testdata/vectors.txt (built by pion/stun/v3,
// gen/ice/cmd/vecs), a forked loopback responder for the client socket path,
// and an optional pion-based server via STUN_TEST_ADDR=127.0.0.1:port.

const std = @import("std");
const builtin = @import("builtin");
const stun = @import("stun.zig");
const linux = std.os.linux;

const vectors_text = @embedFile("testdata/vectors.txt");

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

test "type codec incl TURN methods" {
    const cases = [_]struct { t: stun.MessageType, wire: u16 }{
        .{ .t = .binding_request, .wire = 0x0001 },
        .{ .t = .binding_success, .wire = 0x0101 },
        .{ .t = .binding_error, .wire = 0x0111 },
        .{ .t = .{ .method = .allocate, .class = .request }, .wire = 0x0003 },
        .{ .t = .{ .method = .allocate, .class = .success }, .wire = 0x0103 },
        .{ .t = .{ .method = .refresh, .class = .request }, .wire = 0x0004 },
        .{ .t = .{ .method = .send, .class = .indication }, .wire = 0x0016 },
        .{ .t = .{ .method = .data, .class = .indication }, .wire = 0x0017 },
        .{ .t = .{ .method = .create_permission, .class = .request }, .wire = 0x0008 },
        .{ .t = .{ .method = .channel_bind, .class = .success }, .wire = 0x0109 },
    };
    for (cases) |c| {
        try std.testing.expectEqual(c.wire, c.t.encode());
        const back = stun.MessageType.decode(c.wire);
        try std.testing.expectEqual(c.t.method, back.method);
        try std.testing.expectEqual(c.t.class, back.class);
    }
}

test "decode bare request and software padding" {
    var buf: [512]u8 = undefined;
    const bare = vecHex("binding_req_bare", &buf);
    const d = try stun.decode(bare);
    try std.testing.expectEqual(stun.Method.binding, d.msg_type.method);
    try std.testing.expectEqual(stun.Class.request, d.msg_type.class);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 }, &d.trid);
    try std.testing.expectEqual(@as(usize, 0), d.count);

    const sw = vecHex("binding_req_software", &buf);
    const ds = try stun.decode(sw);
    try std.testing.expectEqual(@as(usize, 1), ds.count);
    try std.testing.expectEqualSlices(u8, "nb-zig-test", try ds.get(stun.Attr.software));
}

test "xor-mapped v4 and v6" {
    var buf: [512]u8 = undefined;
    const v4 = vecHex("binding_success_xor_v4", &buf);
    const d4 = try stun.decode(v4);
    try std.testing.expectEqual(stun.Class.success, d4.msg_type.class);
    const a4 = try stun.XorAddr.decode(&d4, stun.Attr.xor_mapped_address, d4.trid);
    try std.testing.expectEqual(@as(u16, 32853), a4.port);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 192, 0, 2, 1 }, &a4.ip.ip4.bytes);

    const v6 = vecHex("binding_success_xor_v6", &buf);
    const d6 = try stun.decode(v6);
    const a6 = try stun.XorAddr.decode(&d6, stun.Attr.xor_mapped_address, d6.trid);
    try std.testing.expectEqual(@as(u16, 32853), a6.port);
    var want6: [16]u8 = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    try std.testing.expectEqualSlices(u8, &want6, &a6.ip.ip6.bytes);
}

test "error 401 fields" {
    var buf: [512]u8 = undefined;
    const raw = vecHex("binding_error_401", &buf);
    const d = try stun.decode(raw);
    try std.testing.expectEqual(stun.Class.err, d.msg_type.class);
    const ec = try stun.ErrorCode.decode(&d);
    try std.testing.expectEqual(@as(u16, 401), ec.code);
    try std.testing.expectEqualSlices(u8, "Unauthorized", ec.reason);
    try std.testing.expectEqualSlices(u8, "example.org", try d.get(stun.Attr.realm));
    try std.testing.expectEqualSlices(u8, "nonce1234", try d.get(stun.Attr.nonce));
}

test "full ICE check fields" {
    var buf: [1024]u8 = undefined;
    const raw = vecHex("ice_check_full", &buf);
    const d = try stun.decode(raw);
    try std.testing.expectEqualSlices(u8, "remoteUfragA1B2:localUfragC3D4", try d.get(stun.Attr.username));
    const prio = try d.get(stun.Attr.priority);
    try std.testing.expectEqual(@as(u32, 2130706431), std.mem.readInt(u32, prio[0..4], .big));
    const tb = try d.get(stun.Attr.ice_controlling);
    try std.testing.expectEqual(@as(u64, 0x123456789abcdef0), std.mem.readInt(u64, tb[0..8], .big));
    try std.testing.expect(d.contains(stun.Attr.message_integrity));
    try std.testing.expect(d.contains(stun.Attr.fingerprint));
    // Short-term key is the remote password; wrong key must fail.
    try stun.checkIntegrity(raw, &d, "remotePwd0123456789abcdef01234567");
    try std.testing.expectError(stun.Error.IntegrityMismatch, stun.checkIntegrity(raw, &d, "wrongpassword"));
    try stun.checkFingerprint(raw, &d);
}

test "success with integrity and role conflict" {
    var buf: [1024]u8 = undefined;
    const raw = vecHex("ice_success_full", &buf);
    const d = try stun.decode(raw);
    const a = try stun.XorAddr.decode(&d, stun.Attr.xor_mapped_address, d.trid);
    try std.testing.expectEqual(@as(u16, 54321), a.port);
    try stun.checkIntegrity(raw, &d, "localPwd0123456789abcdef01234567");
    try stun.checkFingerprint(raw, &d);

    const e487 = vecHex("binding_error_487", &buf);
    const d487 = try stun.decode(e487);
    const ec = try stun.ErrorCode.decode(&d487);
    try std.testing.expectEqual(@as(u16, 487), ec.code);
}

test "long-term integrity" {
    var buf: [1024]u8 = undefined;
    const raw = vecHex("longterm_integrity", &buf);
    const d = try stun.decode(raw);
    var key: [16]u8 = undefined;
    stun.longTermKey("turnuser", "turnrealm", "turnpass", &key);
    try stun.checkIntegrity(raw, &d, &key);
    var bad: [16]u8 = undefined;
    stun.longTermKey("turnuser", "turnrealm", "wrong", &bad);
    try std.testing.expectError(stun.Error.IntegrityMismatch, stun.checkIntegrity(raw, &d, &bad));
    try stun.checkFingerprint(raw, &d);
}

test "encode matches pion bytes" {
    var buf: [1024]u8 = undefined;
    var out: [1024]u8 = undefined;
    // Bare request.
    const bare = vecHex("binding_req_bare", &buf);
    const d = try stun.decode(bare);
    var e = try stun.Encoder.init(&out, d.msg_type, d.trid);
    try std.testing.expectEqualSlices(u8, bare, e.bytes());
    // Full ICE check rebuilt field by field.
    const full = vecHex("ice_check_full", &buf);
    const df = try stun.decode(full);
    var e2 = try stun.Encoder.init(&out, df.msg_type, df.trid);
    try e2.add(stun.Attr.username, try df.get(stun.Attr.username));
    try e2.add(stun.Attr.priority, try df.get(stun.Attr.priority));
    try e2.add(stun.Attr.ice_controlling, try df.get(stun.Attr.ice_controlling));
    try e2.addIntegrity("remotePwd0123456789abcdef01234567");
    try e2.addFingerprint();
    try std.testing.expectEqualSlices(u8, full, e2.bytes());
    // Long-term vector rebuilt.
    const lt = vecHex("longterm_integrity", &buf);
    const dl = try stun.decode(lt);
    var e3 = try stun.Encoder.init(&out, dl.msg_type, dl.trid);
    try e3.add(stun.Attr.username, try dl.get(stun.Attr.username));
    try e3.add(stun.Attr.realm, try dl.get(stun.Attr.realm));
    try e3.add(stun.Attr.nonce, try dl.get(stun.Attr.nonce));
    var key: [16]u8 = undefined;
    stun.longTermKey("turnuser", "turnrealm", "turnpass", &key);
    try e3.addIntegrity(&key);
    try e3.addFingerprint();
    try std.testing.expectEqualSlices(u8, lt, e3.bytes());
    // Error 401 rebuilt.
    const e401 = vecHex("binding_error_401", &buf);
    const d401 = try stun.decode(e401);
    var e4 = try stun.Encoder.init(&out, d401.msg_type, d401.trid);
    const ec = try stun.ErrorCode.decode(&d401);
    try stun.ErrorCode.encode(&e4, ec.code, ec.reason);
    try e4.add(stun.Attr.realm, try d401.get(stun.Attr.realm));
    try e4.add(stun.Attr.nonce, try d401.get(stun.Attr.nonce));
    try std.testing.expectEqualSlices(u8, e401, e4.bytes());
}

test "isMessage and malformed inputs" {
    var buf: [512]u8 = undefined;
    const bare = vecHex("binding_req_bare", &buf);
    try std.testing.expect(stun.isMessage(bare));
    try std.testing.expect(!stun.isMessage(bare[0..10]));
    // TURN ChannelData shape must not look like STUN.
    const chandata = [_]u8{ 0x40, 0x00, 0x00, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    try std.testing.expect(!stun.isMessage(&chandata));
    // Bad cookie.
    var bad_buf: [512]u8 = undefined;
    @memcpy(bad_buf[0..bare.len], bare);
    const bad = bad_buf[0..bare.len];
    bad[4] = 0x00;
    try std.testing.expect(!stun.isMessage(bad));
    try std.testing.expectError(stun.Error.BadCookie, stun.decode(bad));
    // Truncated attribute.
    try std.testing.expectError(stun.Error.Truncated, stun.decode(bare[0 .. bare.len - 1]));
    // Legacy 0x8020 decodes as XOR-MAPPED-ADDRESS.
    const v4 = vecHex("binding_success_xor_v4", &buf);
    var compat_buf: [512]u8 = undefined;
    @memcpy(compat_buf[0..v4.len], v4);
    const compat = compat_buf[0..v4.len];
    compat[20] = 0x80;
    const dc = try stun.decode(compat);
    const ac = try stun.XorAddr.decode(&dc, stun.Attr.xor_mapped_address, dc.trid);
    try std.testing.expectEqual(@as(u16, 32853), ac.port);
}

test "binding timeout with no server" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const srv = stun.ip4(.{ 127, 0, 0, 1 }, 9);
    var resp: [2048]u8 = undefined;
    const t: stun.Trid = .{ 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9 };
    const err = stun.bindingRequest(srv, t, .{ .rto_ms = 20, .attempts = 2 }, &resp);
    try std.testing.expectError(stun.Error.Timeout, err);
}

test "binding against forked loopback responder" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    // Parent binds the server socket so the port is known before fork.
    const sfd_usize = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    if (sfd_usize > 0xfffffffffffff000) return error.SkipZigTest;
    const sfd: linux.fd_t = @intCast(sfd_usize);
    defer _ = linux.close(sfd);
    var sa = linux.sockaddr.in{
        .family = linux.AF.INET,
        .port = std.mem.nativeToBig(u16, 0),
        .addr = 0x0100007f, // 127.0.0.1
    };
    const brc = linux.bind(sfd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in));
    if (brc > 0xfffffffffffff000) return error.SkipZigTest;
    var got: linux.sockaddr.in = undefined;
    var got_len: linux.socklen_t = @sizeOf(linux.sockaddr.in);
    const grc = linux.getsockname(sfd, @ptrCast(&got), &got_len);
    if (grc > 0xfffffffffffff000) return error.SkipZigTest;
    const port: u16 = std.mem.bigToNative(u16, got.port);

    const pid = linux.fork();
    if (pid == 0) {
        // Child: answer one binding request, then exit.
        var rbuf: [1500]u8 = undefined;
        var from: linux.sockaddr.in = undefined;
        var from_len: linux.socklen_t = @sizeOf(linux.sockaddr.in);
        const n = linux.recvfrom(sfd, &rbuf, rbuf.len, 0, @ptrCast(&from), &from_len);
        if (n > 0xfffffffffffff000 or n == 0) linux.exit(1);
        const req = stun.decode(rbuf[0..n]) catch linux.exit(1);
        var sbuf: [256]u8 = undefined;
        var enc = stun.Encoder.init(&sbuf, stun.MessageType.binding_success, req.trid) catch linux.exit(1);
        const from_bytes: [4]u8 = @bitCast(from.addr);
        const cli_ip = stun.ip4(from_bytes, 0);
        stun.XorAddr.encode(&enc, stun.Attr.xor_mapped_address, req.trid, cli_ip, std.mem.bigToNative(u16, from.port)) catch linux.exit(1);
        const out = enc.bytes();
        const w = linux.sendto(sfd, out.ptr, out.len, 0, @ptrCast(&from), from_len);
        linux.exit(if (w == out.len) 0 else 1);
    }
    if (pid < 0) return error.SkipZigTest;
    const srv = stun.ip4(.{ 127, 0, 0, 1 }, port);
    var resp: [2048]u8 = undefined;
    const t = stun.randomTrid();
    const n = try stun.bindingRequest(srv, t, .{ .rto_ms = 100, .attempts = 5 }, &resp);
    const d = try stun.decode(resp[0..n]);
    try std.testing.expectEqual(stun.Class.success, d.msg_type.class);
    try std.testing.expectEqualSlices(u8, &t, &d.trid);
    const mapped = try stun.XorAddr.decode(&d, stun.Attr.xor_mapped_address, d.trid);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 127, 0, 0, 1 }, &mapped.ip.ip4.bytes);
    try std.testing.expect(mapped.port != 0);
    var status: i32 = 0;
    _ = linux.waitpid(@intCast(pid), &status, 0);
    try std.testing.expectEqual(@as(u8, 0), linux.W.EXITSTATUS(@bitCast(status)));
}

const tio = std.testing.io;

/// Reads STUN_TEST_ADDR from /proc/self/environ (no getenv in std 0.17).
fn testAddrFromEnviron(out: []u8) ?[]u8 {
    var file = std.Io.Dir.openFileAbsolute(tio, "/proc/self/environ", .{ .mode = .read_only }) catch return null;
    defer file.close(tio);
    var buf: [65536]u8 = undefined;
    const n = file.readPositionalAll(tio, &buf, 0) catch return null;
    var entries = std.mem.splitScalar(u8, buf[0..n], 0);
    const prefix = "STUN_TEST_ADDR=";
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

test "binding against pion-based server via STUN_TEST_ADDR" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var env_buf: [64]u8 = undefined;
    const env = testAddrFromEnviron(&env_buf) orelse return error.SkipZigTest;
    var it = std.mem.splitScalar(u8, env, ':');
    const host = it.next() orelse return error.SkipZigTest;
    const port_s = it.next() orelse return error.SkipZigTest;
    const port = std.fmt.parseInt(u16, port_s, 10) catch return error.SkipZigTest;
    var host4: [4]u8 = undefined;
    var oit = std.mem.splitScalar(u8, host, '.');
    for (0..4) |i| host4[i] = std.fmt.parseInt(u8, oit.next() orelse return error.SkipZigTest, 10) catch return error.SkipZigTest;
    const srv = stun.ip4(host4, port);
    var resp: [2048]u8 = undefined;
    const n = try stun.bindingRequest(srv, stun.randomTrid(), .{ .rto_ms = 200, .attempts = 5 }, &resp);
    const d = try stun.decode(resp[0..n]);
    try std.testing.expectEqual(stun.Class.success, d.msg_type.class);
    const mapped = try stun.XorAddr.decode(&d, stun.Attr.xor_mapped_address, d.trid);
    try std.testing.expect(mapped.port != 0);
}
