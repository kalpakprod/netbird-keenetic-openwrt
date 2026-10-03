// Tests for turn.zig: attr codecs, ChannelData framing, and a live run
// against a pion/turn server (TURN_TEST_ADDR=127.0.0.1:port, user/pass
// "zigtest"/"zigtestpass" as served by gen/ice/cmd/turnserver): two
// allocations exchange data both via channels and via Send indications.

const std = @import("std");
const builtin = @import("builtin");
const turn = @import("turn.zig");
const stun = @import("stun.zig");
const ice = @import("ice.zig");
const linux = std.os.linux;

test "turn attr codecs round-trip" {
    var buf: [256]u8 = undefined;
    const t: stun.Trid = .{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
    var enc = try stun.Encoder.init(&buf, .{ .method = .allocate, .class = .request }, t);
    try turn.encodeRequestedTransport(&enc, turn.proto_udp);
    try turn.encodeLifetime(&enc, 600);
    try turn.encodeChannelNumber(&enc, 0x4000);
    // XOR-PEER-ADDRESS with a fixed trid has a known encoding.
    try stun.XorAddr.encode(&enc, stun.Attr.xor_peer_address, t, stun.ip4(.{ 192, 0, 2, 1 }, 0), 32853);
    const raw = enc.bytes();
    const d = try stun.decode(raw);
    try std.testing.expectEqual(@as(u8, 17), try turn.decodeRequestedTransport(&d));
    try std.testing.expectEqual(@as(u32, 600), try turn.decodeLifetime(&d));
    try std.testing.expectEqual(@as(u16, 0x4000), try turn.decodeChannelNumber(&d));
    const peer = try stun.XorAddr.decode(&d, stun.Attr.xor_peer_address, t);
    try std.testing.expectEqual(@as(u16, 32853), peer.port);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 192, 0, 2, 1 }, &peer.ip.ip4.bytes);
    // Bad channel numbers rejected.
    var buf2: [64]u8 = undefined;
    var enc2 = try stun.Encoder.init(&buf2, .{ .method = .channel_bind, .class = .request }, t);
    try std.testing.expectError(turn.Error.BadChannel, turn.encodeChannelNumber(&enc2, 0x3FFF));
    try std.testing.expectError(turn.Error.BadChannel, turn.encodeChannelNumber(&enc2, 0x8000));
}

test "channel data framing" {
    var buf: [64]u8 = undefined;
    // 3-byte payload pads to 4 on the wire, length stays 3.
    const n = try turn.encodeChannelData(&buf, 0x4001, "abc");
    try std.testing.expectEqual(@as(usize, 8), n);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x40, 0x01, 0x00, 0x03, 'a', 'b', 'c', 0 }, buf[0..n]);
    const cd = try turn.decodeChannelData(buf[0..n]);
    try std.testing.expectEqual(@as(u16, 0x4001), cd.number);
    try std.testing.expectEqualSlices(u8, "abc", cd.data);
    try std.testing.expect(turn.isChannelData(buf[0..n]));
    // Not STUN and STUN is not ChannelData.
    try std.testing.expect(!stun.isMessage(buf[0..n]));
    var sbuf: [32]u8 = undefined;
    const t: stun.Trid = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    var enc = try stun.Encoder.init(&sbuf, stun.MessageType.binding_request, t);
    try std.testing.expect(!turn.isChannelData(enc.bytes()));
    // Truncated length field rejected.
    try std.testing.expect(!turn.isChannelData(buf[0..3]));
    try std.testing.expectError(turn.Error.NotChannelData, turn.decodeChannelData(buf[0..3]));
}

const tio = std.testing.io;

fn testAddrFromEnviron(out: []u8) ?[]u8 {
    var file = std.Io.Dir.openFileAbsolute(tio, "/proc/self/environ", .{ .mode = .read_only }) catch return null;
    defer file.close(tio);
    var ebuf: [65536]u8 = undefined;
    const n = file.readPositionalAll(tio, &ebuf, 0) catch return null;
    var entries = std.mem.splitScalar(u8, ebuf[0..n], 0);
    const prefix = "TURN_TEST_ADDR=";
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

fn parseTestAddr() ?stun.IpAddress {
    var env_buf: [64]u8 = undefined;
    const env = testAddrFromEnviron(&env_buf) orelse return null;
    var it = std.mem.splitScalar(u8, env, ':');
    const host = it.next() orelse return null;
    const port = std.fmt.parseInt(u16, it.next() orelse return null, 10) catch return null;
    return ice.parseIp(host, port) catch null;
}

fn expectAddrEq(a: stun.IpAddress, b: stun.IpAddress) !void {
    try std.testing.expect(std.meta.activeTag(a) == std.meta.activeTag(b));
    switch (a) {
        .ip4 => |x| {
            try std.testing.expectEqualSlices(u8, &x.bytes, &b.ip4.bytes);
            try std.testing.expectEqual(x.port, b.ip4.port);
        },
        .ip6 => |x| {
            try std.testing.expectEqualSlices(u8, &x.bytes, &b.ip6.bytes);
            try std.testing.expectEqual(x.port, b.ip6.port);
        },
    }
}

test "allocate permission channel and relay via pion server" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const srv = parseTestAddr() orelse return error.SkipZigTest;

    var a = try turn.allocate(srv, "zigtest", "zigtestpass", .{});
    defer a.close();
    var b = try turn.allocate(srv, "zigtest", "zigtestpass", .{});
    defer b.close();
    try std.testing.expect(a.lifetime_s > 0);
    // Relayed addresses are real loopback endpoints.
    try std.testing.expect(a.relayed.ip4.port != 0);
    try std.testing.expect(b.relayed.ip4.port != 0);

    // Relay-to-relay like real ICE relay candidates: permissions and
    // channels target the peer's RELAYED address, not its socket address.
    // Channel path both directions.
    const ch_a = try turn.channelBind(&a, b.relayed);
    try std.testing.expect(ch_a >= 0x4000);
    const ch_b = try turn.channelBind(&b, a.relayed);
    try std.testing.expect(ch_b >= 0x4000);
    // Re-binding the same peer returns the same channel, no new request storm.
    try std.testing.expectEqual(ch_a, try turn.channelBind(&a, b.relayed));

    try turn.sendTo(&a, b.relayed, "msg-a-to-b");
    var buf: [1500]u8 = undefined;
    const rb = try turn.recvFrom(&b, &buf, 5000);
    try std.testing.expectEqualStrings("msg-a-to-b", buf[0..rb.len]);
    // B sees A's relayed address as the source.
    try expectAddrEq(a.relayed, rb.from);

    try turn.sendTo(&b, a.relayed, "msg-b-to-a");
    const ra = try turn.recvFrom(&a, &buf, 5000);
    try std.testing.expectEqualStrings("msg-b-to-a", buf[0..ra.len]);
    try expectAddrEq(b.relayed, ra.from);
}

test "send indication path via pion server" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const srv = parseTestAddr() orelse return error.SkipZigTest;

    var a = try turn.allocate(srv, "zigtest", "zigtestpass", .{});
    defer a.close();

    // Raw UDP peer (no TURN client): gets an indication, replies to the
    // relayed address, A reads it back as a Data indication.
    const b = try ice.bindUdp(stun.ip4(.{ 127, 0, 0, 1 }, 0));
    defer _ = linux.close(b.fd);
    const peer = stun.ip4(.{ 127, 0, 0, 1 }, b.port);

    try turn.sendTo(&a, peer, "via-indication");
    var pfd = [_]linux.pollfd{.{ .fd = b.fd, .events = linux.POLL.IN }};
    const prc = linux.poll(&pfd, 1, 5000);
    try std.testing.expect(prc == 1);
    var pbuf: [1500]u8 = undefined;
    var sab = ice.SockAddrBuf{};
    var slen: linux.socklen_t = @sizeOf(linux.sockaddr.in6);
    const n = linux.recvfrom(b.fd, &pbuf, pbuf.len, 0, @ptrCast(@alignCast(&sab.buf)), &slen);
    try std.testing.expect(n == "via-indication".len);
    const src = try sab.toIp(slen);
    try expectAddrEq(a.relayed, src);

    // Reply to the relayed address; A must get a Data indication from peer.
    try ice.sendTo(b.fd, a.relayed, "echo-back");
    var abuf: [1500]u8 = undefined;
    const ra = try turn.recvFrom(&a, &abuf, 5000);
    try std.testing.expectEqualStrings("echo-back", abuf[0..ra.len]);
    try expectAddrEq(peer, ra.from);
}
