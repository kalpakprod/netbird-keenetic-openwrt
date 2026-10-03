// Port of netbird encryption/encryption.go (v0.79.0), BSD-3-Clause — tests.
// Vectors: testdata/vectors.json from gen/cryptovecs (real upstream package).

const std = @import("std");
const box = @import("box.zig");
const keys = @import("keys.zig");

const Vectors = struct {
    alice_priv: []const u8,
    alice_pub: []const u8,
    bob_priv: []const u8,
    bob_pub: []const u8,
    msg: []const u8,
    ciphertext: []const u8,
    nonce: []const u8,
    ciphertext_fixed_nonce: []const u8,
};

const vectors_raw = @embedFile("testdata/vectors.json");

fn loadVectors(allocator: std.mem.Allocator) !std.json.Parsed(Vectors) {
    return std.json.parseFromSlice(Vectors, allocator, vectors_raw, .{});
}

fn hexToArray(comptime N: usize, s: []const u8) [N]u8 {
    var out: [N]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "decrypt Go ciphertext in Zig" {
    var parsed = try loadVectors(std.testing.allocator);
    defer parsed.deinit();
    const v = parsed.value;

    const ct_len = v.ciphertext.len / 2;
    const ct = try std.testing.allocator.alloc(u8, ct_len);
    defer std.testing.allocator.free(ct);
    _ = try std.fmt.hexToBytes(ct, v.ciphertext);

    const pt_len = ct_len - box.nonce_size - box.tag_size;
    const pt = try std.testing.allocator.alloc(u8, pt_len);
    defer std.testing.allocator.free(pt);

    try box.decrypt(
        pt,
        ct,
        hexToArray(32, v.alice_pub),
        hexToArray(32, v.bob_priv),
    );
    const want = try std.testing.allocator.alloc(u8, v.msg.len / 2);
    defer std.testing.allocator.free(want);
    _ = try std.fmt.hexToBytes(want, v.msg);
    try std.testing.expectEqualSlices(u8, want, pt);
}

test "encrypt with fixed nonce matches Go" {
    var parsed = try loadVectors(std.testing.allocator);
    defer parsed.deinit();
    const v = parsed.value;

    const msg = try std.testing.allocator.alloc(u8, v.msg.len / 2);
    defer std.testing.allocator.free(msg);
    _ = try std.fmt.hexToBytes(msg, v.msg);

    var out: [22 + box.nonce_size + box.tag_size]u8 = undefined;
    try box.encryptWithNonce(
        &out,
        msg,
        hexToArray(32, v.bob_pub),
        hexToArray(32, v.alice_priv),
        hexToArray(24, v.nonce),
    );
    const want = hexToArray(22 + box.nonce_size + box.tag_size, v.ciphertext_fixed_nonce);
    try std.testing.expectEqual(want, out);
}

test "random-nonce round trip and tamper rejection" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const alice_priv: keys.Key = @splat(0x11);
    const bob_priv: keys.Key = @splat(0x22);
    const alice_pub = keys.publicKey(alice_priv);
    const bob_pub = keys.publicKey(bob_priv);

    const msg = "round-trip-message";
    var ct: [msg.len + box.nonce_size + box.tag_size]u8 = undefined;
    try box.encrypt(&ct, msg, bob_pub, alice_priv, io);

    var pt: [msg.len]u8 = undefined;
    try box.decrypt(&pt, &ct, alice_pub, bob_priv);
    try std.testing.expectEqualStrings(msg, &pt);

    // tampered byte fails authentication
    var bad = ct;
    bad[bad.len - 1] ^= 0x01;
    try std.testing.expectError(box.Error.AuthenticationFailed, box.decrypt(&pt, &bad, alice_pub, bob_priv));

    // truncated input rejected
    try std.testing.expectError(box.Error.MessageTooShort, box.decrypt(&pt, ct[0..10], alice_pub, bob_priv));

    // Go checks only len < 24, then box.Open fails: 24..39 is auth failure,
    // not short input (and must not underflow the length math)
    var short: [30]u8 = undefined;
    @memcpy(short[0..24], ct[0..24]);
    @memset(short[24..30], 0);
    var pt_any: [1]u8 = undefined;
    try std.testing.expectError(box.Error.AuthenticationFailed, box.decrypt(&pt_any, &short, alice_pub, bob_priv));
    // exact boundary: 24 bytes, empty box
    try std.testing.expectError(box.Error.AuthenticationFailed, box.decrypt(&pt_any, ct[0..24], alice_pub, bob_priv));
    // 23 bytes stays short
    try std.testing.expectError(box.Error.MessageTooShort, box.decrypt(&pt_any, ct[0..23], alice_pub, bob_priv));
}
