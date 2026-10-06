// Port of wireguard-go wgctrl/wgtypes key functions (MIT), vendored in netbird v0.79.0.
// Reference: upstream/netbird/vendor/golang.zx2c4.com/wireguard/wgctrl/wgtypes/types.go
// Scope: Key type, generation, base64 parse/format, public-from-private.
// Device/Peer/Config structs are device-layer and out of scope.

const std = @import("std");
const X25519 = std.crypto.dh.X25519;

pub const Key = [32]u8;
pub const key_len = 32;
pub const key_base64_len = 44;

pub const Error = error{
    IncorrectKeySize,
    InvalidBase64,
};

/// Random 32 bytes, NOT clamped. For pre-shared keys only (GenerateKey).
pub fn generateKey(io: std.Io) Key {
    var k: Key = undefined;
    io.random(&k);
    return k;
}

/// Random clamped private key (GeneratePrivateKey).
pub fn generatePrivateKey(io: std.Io) Key {
    var k = generateKey(io);
    clamp(&k);
    return k;
}

pub fn clamp(k: *Key) void {
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
}

/// Key from exactly 32 bytes (NewKey).
pub fn newKey(b: []const u8) Error!Key {
    if (b.len != key_len) {
        return Error.IncorrectKeySize;
    }
    var k: Key = undefined;
    @memcpy(&k, b);
    return k;
}

/// base64.StdEncoding string (Key.String).
pub fn toString(k: Key, out: *[key_base64_len]u8) []const u8 {
    return std.base64.standard.Encoder.encode(out, &k);
}

/// Parse base64 string produced by toString (ParseKey).
/// Same order as Go: base64 decode first, then the 32-byte size check.
pub fn parseKey(s: []const u8) Error!Key {
    var tmp: [64]u8 = undefined;
    std.base64.standard.Decoder.decode(&tmp, s) catch |err| {
        return if (err == error.NoSpaceLeft) Error.IncorrectKeySize else Error.InvalidBase64;
    };
    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(s) catch {
        return Error.InvalidBase64;
    };
    if (decoded_len != key_len) {
        return Error.IncorrectKeySize;
    }
    var k: Key = undefined;
    @memcpy(&k, tmp[0..key_len]);
    return k;
}

/// Public key from private key (Key.PublicKey via X25519 base mult).
/// Both Go (crypto/ecdh) and Zig clamp the scalar internally, so no
/// explicit clamp here — same behavior for any input.
pub fn publicKey(priv: Key) Key {
    return X25519.recoverPublicKey(priv);
}

pub fn isZero(k: Key) bool {
    return std.mem.allEqual(u8, &k, 0);
}
