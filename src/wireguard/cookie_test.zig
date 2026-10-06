// Tests for the cookie.go port. MACs don't depend on handshake validity,
// so fixed buffers stand in for initiation/response packets.

const std = @import("std");
const noise = @import("noise.zig");
const cookie = @import("cookie.zig");

const local_pk: noise.PublicKey = @splat(@as(u8, 0x11));
const other_pk: noise.PublicKey = @splat(@as(u8, 0x22));

test "mac1 round trip, both handshake sizes" {
    var checker = cookie.CookieChecker.init(&local_pk);
    var gen = cookie.CookieGenerator.init(&local_pk);
    var init: [noise.message_initiation_size]u8 = undefined;
    var resp: [noise.message_response_size]u8 = undefined;
    for (&init, 0..) |*b, i| b.* = @truncate(i);
    for (&resp, 0..) |*b, i| b.* = @truncate(3 * i);
    std.mem.writeInt(u32, init[0..4], noise.message_initiation_type, .little);
    std.mem.writeInt(u32, resp[0..4], noise.message_response_type, .little);

    gen.addMacs(&init, 1_000);
    gen.addMacs(&resp, 1_000);
    try std.testing.expect(checker.checkMac1(&init));
    try std.testing.expect(checker.checkMac1(&resp));
    // mac2 is zero without a cookie
    try std.testing.expectEqual(@as([16]u8, @splat(0)), init[132..148].*);
    try std.testing.expectEqual(@as([16]u8, @splat(0)), resp[76..92].*);
    // tampering breaks mac1
    init[50] ^= 0x01;
    try std.testing.expect(!checker.checkMac1(&init));
}

test "mac1 rejects wrong key and wrong sizes" {
    var gen = cookie.CookieGenerator.init(&local_pk);
    var other = cookie.CookieChecker.init(&other_pk);
    var pkt: [noise.message_initiation_size]u8 = undefined;
    @memset(&pkt, 0x5a);
    gen.addMacs(&pkt, 0);
    try std.testing.expect(!other.checkMac1(&pkt));
    try std.testing.expect(!other.checkMac1(pkt[0..100]));
}

test "cookie reply round trip enables mac2" {
    const src = [_]u8{ 127, 0, 0, 1, 0x23, 0x45 }; // endpoint bytes stand-in
    var checker = cookie.CookieChecker.init(&local_pk);
    var gen = cookie.CookieGenerator.init(&local_pk);
    var pkt: [noise.message_initiation_size]u8 = undefined;
    @memset(&pkt, 0x33);
    std.mem.writeInt(u32, pkt[0..4], noise.message_initiation_type, .little);
    std.mem.writeInt(u32, pkt[4..8], 0xdeadbeef, .little);
    gen.addMacs(&pkt, 1_000);

    const reply = checker.createReply(std.testing.io, &pkt, 0xdeadbeef, &src, 2_000);
    try std.testing.expectEqual(@as(u32, 0xdeadbeef), reply.receiver);
    var wire: [cookie.message_cookie_reply_size]u8 = undefined;
    reply.marshal(&wire);
    const back = cookie.CookieReply.unmarshal(&wire).?;
    try std.testing.expect(gen.consumeReply(&back, 3_000));

    // fresh cookie -> mac2 verifies
    gen.addMacs(&pkt, 4_000);
    try std.testing.expect(checker.checkMac1(&pkt));
    try std.testing.expect(checker.checkMac2(&pkt, &src, 5_000));
    // wrong source address fails mac2
    const wrong = [_]u8{ 10, 0, 0, 2, 0x23, 0x45 };
    try std.testing.expect(!checker.checkMac2(&pkt, &wrong, 5_000));
}

test "consume reply without mac1 fails" {
    var gen = cookie.CookieGenerator.init(&local_pk);
    const reply: cookie.CookieReply = .{ .receiver = 1, .nonce = @as([24]u8, @splat(0)), .cookie = @as([32]u8, @splat(0)) };
    try std.testing.expect(!gen.consumeReply(&reply, 0));
}

test "stale cookie is not used" {
    const src = [_]u8{ 127, 0, 0, 1, 1, 2 };
    var checker = cookie.CookieChecker.init(&local_pk);
    var gen = cookie.CookieGenerator.init(&local_pk);
    var pkt: [noise.message_initiation_size]u8 = undefined;
    @memset(&pkt, 0x77);
    gen.addMacs(&pkt, 0);
    const reply = checker.createReply(std.testing.io, &pkt, 9, &src, 0);
    try std.testing.expect(gen.consumeReply(&reply, 0));
    // 121s later the cookie is stale: mac2 left zero
    gen.addMacs(&pkt, 121 * std.time.ns_per_s);
    try std.testing.expectEqual(@as([16]u8, @splat(0)), pkt[132..148].*);
    // and an old mac2 does not verify past refresh time
    gen.addMacs(&pkt, 1_000);
    try std.testing.expect(!checker.checkMac2(&pkt, &src, 121 * std.time.ns_per_s));
}

test "reply marshal rejects bad type" {
    var wire: [cookie.message_cookie_reply_size]u8 = undefined;
    @memset(&wire, 0);
    try std.testing.expect(cookie.CookieReply.unmarshal(&wire) == null);
}
