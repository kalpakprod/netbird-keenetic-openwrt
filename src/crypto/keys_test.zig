// Port of wireguard-go wgctrl/wgtypes (MIT) — tests.
// Pubkey vectors cross-checked against the Go helper in gen/cryptovecs.

const std = @import("std");
const keys = @import("keys.zig");

test "base64 round trip and known encoding" {
    const k: keys.Key = @splat(@as(u8, 0x11));
    var s: [keys.key_base64_len]u8 = undefined;
    const str = keys.toString(k, &s);
    // produced by Go base64.StdEncoding of 32x 0x11 (see report command)
    try std.testing.expectEqualStrings("ERERERERERERERERERERERERERERERERERERERERERE=", str);
    try std.testing.expectEqual(k, try keys.parseKey(str));
}

test "parse rejects bad input" {
    try std.testing.expectError(keys.Error.InvalidBase64, keys.parseKey("!!!not-base64!!!"));
    try std.testing.expectError(keys.Error.IncorrectKeySize, keys.parseKey("aGk=")); // "hi", 2 bytes
    const short: [31]u8 = @splat(1);
    try std.testing.expectError(keys.Error.IncorrectKeySize, keys.newKey(&short));
}

test "public key matches Go X25519" {
    // alice_priv 0x11*32 -> alice_pub from gen/cryptovecs vectors.json
    const priv: keys.Key = @splat(@as(u8, 0x11));
    const want_hex = "7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13";
    var want: keys.Key = undefined;
    _ = try std.fmt.hexToBytes(&want, want_hex);
    try std.testing.expectEqual(want, keys.publicKey(priv));
}

test "generated keys have the right shape" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const psk = keys.generateKey(io);
    try std.testing.expect(!keys.isZero(psk));
    const priv = keys.generatePrivateKey(io);
    try std.testing.expectEqual(@as(u8, 0), priv[0] & 7);
    try std.testing.expectEqual(@as(u8, 0), priv[31] & 128);
    try std.testing.expectEqual(@as(u8, 64), priv[31] & 64);
    try std.testing.expect(!keys.isZero(keys.publicKey(priv)));
}
