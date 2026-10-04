// Port of netbird shared/relay/auth (v0.79.0), BSD-3-Clause.
// Token format from shared/relay/auth/hmac/v2: algo byte, HMAC-SHA256
// signature, ASCII unix expiry payload. The client signs with the SHA-256 of
// the server's auth secret (server/relay/auth/hmac/validator.go).

const std = @import("std");

pub const AuthAlgo = enum(u8) {
    hmac_sha256 = 1,
    _,
};

pub const signature_size = 32;

pub const Error = error{PayloadTooBig};

/// Maximum token size: 1 algo byte + 32-byte signature + ASCII expiry.
pub const max_token_size = 1 + signature_size + 20;

/// Token binary layout: algo byte || HMAC-SHA256 signature || payload.
pub const Token = struct {
    algo: AuthAlgo,
    signature: [signature_size]u8,
    payload: []const u8,

    pub fn marshal(t: *const Token, buf: []u8) []u8 {
        buf[0] = @backingInt(t.algo);
        @memcpy(buf[1..][0..signature_size], &t.signature);
        // copyForwards: generateToken builds the payload inside buf, so src
        // and dst overlap there.
        std.mem.copyForwards(u8, buf[1 + signature_size ..][0..t.payload.len], t.payload);
        return buf[0 .. 1 + signature_size + t.payload.len];
    }
};

/// Generates a token valid for `ttl_secs`, mirroring
/// v2.Generator.GenerateToken: HMAC-SHA256 over the ASCII unix expiry, keyed
/// with the SHA-256 of the secret.
pub fn generateToken(
    secret: []const u8,
    ttl_secs: u64,
    now_unix: u64,
    buf: *[max_token_size]u8,
) Error![]u8 {
    const payload = std.fmt.bufPrint(buf[1 + signature_size ..], "{d}", .{now_unix + ttl_secs}) catch
        return Error.PayloadTooBig;

    var key: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(secret, &key, .{});

    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    var sig: [signature_size]u8 = undefined;
    HmacSha256.create(&sig, payload, &key);

    const token = Token{ .algo = .hmac_sha256, .signature = sig, .payload = payload };
    return token.marshal(buf);
}

test "token: algo byte, hmac over payload keyed with sha256(secret)" {
    var buf: [max_token_size]u8 = undefined;
    const token = try generateToken("test-secret", 24 * 3600, 1_700_000_000, &buf);

    try std.testing.expectEqual(@as(u8, 1), token[0]);
    const payload = token[1 + signature_size ..];
    try std.testing.expectEqualStrings("1700086400", payload);

    var key: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("test-secret", &key, .{});
    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    var expected_sig: [signature_size]u8 = undefined;
    HmacSha256.create(&expected_sig, payload, &key);
    try std.testing.expectEqualSlices(u8, &expected_sig, token[1 .. 1 + signature_size]);
}

test "token: payload fits expiry digits" {
    var buf: [max_token_size]u8 = undefined;
    const token = try generateToken("s", 0, 253_402_300_799, &buf);
    try std.testing.expectEqualStrings("253402300799", token[1 + signature_size ..]);
}
