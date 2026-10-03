// Port of netbird encryption/encryption.go (v0.79.0), BSD-3-Clause.
// Reference: upstream/netbird/encryption/encryption.go (Encrypt/Decrypt).
// Scope: byte-level NaCl-box encrypt/decrypt with the exact nonce layout
// (nonce || box). EncryptMessage/DecryptMessage protobuf marshal/unmarshal
// belongs to M1 codecs; message.go cert/letsencrypt/route53 helpers are
// server-side and out of scope.

const std = @import("std");
const Box = std.crypto.nacl.Box;
const keys = @import("keys.zig");

pub const nonce_size = 24;
pub const tag_size = 16;

pub const Error = error{
    MessageTooShort,
    AuthenticationFailed,
    InvalidPublicKey,
};

/// Encrypt: random 24-byte nonce || box(msg). Mirrors Encrypt().
/// Randomness comes from the caller's Io; out must be msg.len + 36.
pub fn encrypt(
    out: []u8,
    msg: []const u8,
    peer_public: keys.Key,
    private: keys.Key,
    io: std.Io,
) Error!void {
    if (out.len != msg.len + nonce_size + tag_size) {
        return Error.MessageTooShort;
    }
    var nonce: [nonce_size]u8 = undefined;
    io.random(&nonce);
    try encryptWithNonce(out, msg, peer_public, private, nonce);
}

/// Encrypt with an explicit nonce (same layout; used by tests/vectors).
pub fn encryptWithNonce(
    out: []u8,
    msg: []const u8,
    peer_public: keys.Key,
    private: keys.Key,
    nonce: [nonce_size]u8,
) Error!void {
    if (out.len != msg.len + nonce_size + tag_size) {
        return Error.MessageTooShort;
    }
    @memcpy(out[0..nonce_size], &nonce);
    Box.seal(out[nonce_size..], msg, nonce, peer_public, private) catch {
        return Error.InvalidPublicKey;
    };
}

/// Decrypt: split nonce || box, open. Mirrors Decrypt().
pub fn decrypt(
    out: []u8,
    encrypted: []const u8,
    peer_public: keys.Key,
    private: keys.Key,
) Error!void {
    if (encrypted.len < nonce_size + tag_size) {
        return Error.MessageTooShort;
    }
    if (out.len != encrypted.len - nonce_size - tag_size) {
        return Error.MessageTooShort;
    }
    const nonce: [nonce_size]u8 = encrypted[0..nonce_size].*;
    Box.open(out, encrypted[nonce_size..], nonce, peer_public, private) catch {
        return Error.AuthenticationFailed;
    };
}
