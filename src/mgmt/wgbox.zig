//! WireGuard keys + NaCl-box glue for the management/signal clients.
//! Mirrors src/crypto/{keys,box}.zig on main (port of wgtypes + NaCl box),
//! kept local because this branch stacks on feat/h2-conn, which predates
//! src/crypto on main. TODO: unify (delete this file, import src/crypto)
//! once the branches converge. Interop with Go is proven by the mgmt/signal
//! tests against Go fakes (real nacl/box on the other end).

const std = @import("std");
const X25519 = std.crypto.dh.X25519;
const Box = std.crypto.nacl.Box;

pub const Key = [32]u8;
pub const key_base64_len = 44;
pub const nonce_size = 24;
pub const tag_size = 16;

pub const Error = error{
    IncorrectKeySize,
    InvalidBase64,
    MessageTooShort,
    AuthenticationFailed,
    InvalidPublicKey,
    OutOfMemory,
};

/// Random clamped private key (GeneratePrivateKey).
pub fn generatePrivateKey(io: std.Io) Key {
    var k: Key = undefined;
    io.random(&k);
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    return k;
}

/// Public key from private key (X25519 base mult).
pub fn publicKey(priv: Key) Key {
    return X25519.recoverPublicKey(priv);
}

/// base64.StdEncoding string (Key.String), caller frees.
pub fn allocString(alloc: std.mem.Allocator, k: Key) Error![]u8 {
    const out = try alloc.alloc(u8, key_base64_len);
    _ = std.base64.standard.Encoder.encode(out, &k);
    return out;
}

/// Parse base64 string produced by allocString (ParseKey).
pub fn parseKey(s: []const u8) Error!Key {
    var tmp: [64]u8 = undefined;
    std.base64.standard.Decoder.decode(&tmp, s) catch |err| {
        return if (err == error.NoSpaceLeft) Error.IncorrectKeySize else Error.InvalidBase64;
    };
    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(s) catch {
        return Error.InvalidBase64;
    };
    if (decoded_len != 32) return Error.IncorrectKeySize;
    var k: Key = undefined;
    @memcpy(&k, tmp[0..32]);
    return k;
}

/// Encrypt: random 24-byte nonce || box(msg). Mirrors encryption.Encrypt.
pub fn encrypt(
    alloc: std.mem.Allocator,
    msg: []const u8,
    peer_public: Key,
    private: Key,
    io: std.Io,
) Error![]u8 {
    var nonce: [nonce_size]u8 = undefined;
    io.random(&nonce);
    return encryptWithNonce(alloc, msg, peer_public, private, nonce);
}

pub fn encryptWithNonce(
    alloc: std.mem.Allocator,
    msg: []const u8,
    peer_public: Key,
    private: Key,
    nonce: [nonce_size]u8,
) Error![]u8 {
    const out = try alloc.alloc(u8, msg.len + nonce_size + tag_size);
    @memcpy(out[0..nonce_size], &nonce);
    Box.seal(out[nonce_size..], msg, nonce, peer_public, private) catch {
        alloc.free(out);
        return Error.InvalidPublicKey;
    };
    return out;
}

/// Decrypt: split nonce || box, open. Mirrors encryption.Decrypt.
pub fn decrypt(
    alloc: std.mem.Allocator,
    encrypted: []const u8,
    peer_public: Key,
    private: Key,
) Error![]u8 {
    if (encrypted.len < nonce_size + tag_size) return Error.MessageTooShort;
    const out = try alloc.alloc(u8, encrypted.len - nonce_size - tag_size);
    errdefer alloc.free(out);
    const nonce: [nonce_size]u8 = encrypted[0..nonce_size].*;
    Box.open(out, encrypted[nonce_size..], nonce, peer_public, private) catch {
        return Error.AuthenticationFailed;
    };
    return out;
}
