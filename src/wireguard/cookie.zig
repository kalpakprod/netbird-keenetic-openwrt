// Port of wireguard-go device/cookie.go (MIT).
// Reference: upstream/netbird/vendor/golang.zx2c4.com/wireguard/device/cookie.go.
// MAC1/MAC2 for handshake messages and the under-load cookie reply.
// Single-threaded: clocks are caller-supplied nanoseconds, randomness comes
// from std.Io.

const std = @import("std");
const noise = @import("noise.zig");

const Blake2s256 = std.crypto.hash.blake2.Blake2s256;
const Blake2s128 = std.crypto.hash.blake2.Blake2s128;
const XChaCha20Poly1305 = std.crypto.aead.chacha_poly.XChaCha20Poly1305;

pub const label_mac1 = "mac1----";
pub const label_cookie = "cookie--";
pub const cookie_refresh_time_ns: i64 = 120 * std.time.ns_per_s;
pub const message_cookie_reply_type: u32 = 3;
pub const message_cookie_reply_size = 64;
pub const nonce_size_x = 24;

fn mac1Key(out: *[32]u8, pk: *const noise.PublicKey) void {
    var h = Blake2s256.init(.{});
    h.update(label_mac1);
    h.update(pk);
    h.final(out);
}

fn cookieEncryptionKey(out: *[32]u8, pk: *const noise.PublicKey) void {
    var h = Blake2s256.init(.{});
    h.update(label_cookie);
    h.update(pk);
    h.final(out);
}

fn constantTimeEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var diff: u8 = 0;
    for (a, b) |x, y| diff |= x ^ y;
    return diff == 0;
}

fn mac128(out: *[16]u8, key: []const u8, msg: []const u8) void {
    var h = Blake2s128.init(.{ .key = key });
    h.update(msg);
    h.final(out);
}

pub const CookieReply = struct {
    receiver: u32,
    nonce: [nonce_size_x]u8,
    cookie: [32]u8, // sealed cookie: 16 bytes + 16 tag

    pub fn marshal(self: *const CookieReply, out: *[message_cookie_reply_size]u8) void {
        std.mem.writeInt(u32, out[0..4], message_cookie_reply_type, .little);
        std.mem.writeInt(u32, out[4..8], self.receiver, .little);
        @memcpy(out[8..32], &self.nonce);
        @memcpy(out[32..64], &self.cookie);
    }

    pub fn unmarshal(buf: *const [message_cookie_reply_size]u8) ?CookieReply {
        if (std.mem.readInt(u32, buf[0..4], .little) != message_cookie_reply_type) return null;
        var r: CookieReply = undefined;
        r.receiver = std.mem.readInt(u32, buf[4..8], .little);
        @memcpy(&r.nonce, buf[8..32]);
        @memcpy(&r.cookie, buf[32..64]);
        return r;
    }
};

/// Receiver side: verifies MAC1 always, MAC2 under load, mints replies.
pub const CookieChecker = struct {
    mac1_key: [32]u8,
    secret: [32]u8 = std.mem.zeroes([32]u8),
    secret_set_ns: i64 = 0,
    secret_valid: bool = false,
    encryption_key: [32]u8,

    pub fn init(local_static_public: *const noise.PublicKey) CookieChecker {
        var c: CookieChecker = undefined;
        mac1Key(&c.mac1_key, local_static_public);
        cookieEncryptionKey(&c.encryption_key, local_static_public);
        c.secret = std.mem.zeroes([32]u8);
        c.secret_set_ns = 0;
        c.secret_valid = false;
        return c;
    }

    /// CheckMAC1 over a full handshake packet (initiation or response).
    pub fn checkMac1(c: *const CookieChecker, msg: []const u8) bool {
        if (msg.len != noise.message_initiation_size and
            msg.len != noise.message_response_size) return false;
        const smac1 = msg.len - 32;
        var mac1: [16]u8 = undefined;
        mac128(&mac1, &c.mac1_key, msg[0..smac1]);
        return constantTimeEqual(&mac1, msg[smac1 .. smac1 + 16]);
    }

    /// CheckMAC2. src is the endpoint address bytes (DstToBytes).
    pub fn checkMac2(c: *const CookieChecker, msg: []const u8, src: []const u8, now_ns: i64) bool {
        if (msg.len != noise.message_initiation_size and
            msg.len != noise.message_response_size) return false;
        if (!c.secret_valid or now_ns - c.secret_set_ns > cookie_refresh_time_ns) return false;
        var cookie: [16]u8 = undefined;
        mac128(&cookie, &c.secret, src);
        const smac2 = msg.len - 16;
        var mac2: [16]u8 = undefined;
        mac128(&mac2, &cookie, msg[0..smac2]);
        return constantTimeEqual(&mac2, msg[smac2..][0..16]);
    }

    /// CreateReply, refreshing the secret when stale. msg is the offending
    /// handshake packet, recv its sender index, src the endpoint bytes.
    pub fn createReply(
        c: *CookieChecker,
        io: std.Io,
        msg: []const u8,
        recv: u32,
        src: []const u8,
        now_ns: i64,
    ) CookieReply {
        if (!c.secret_valid or now_ns - c.secret_set_ns > cookie_refresh_time_ns) {
            io.random(&c.secret);
            c.secret_set_ns = now_ns;
            c.secret_valid = true;
        }
        var cookie: [16]u8 = undefined;
        mac128(&cookie, &c.secret, src);
        const smac1 = msg.len - 32;
        var reply: CookieReply = .{
            .receiver = recv,
            .nonce = undefined,
            .cookie = undefined,
        };
        io.random(&reply.nonce);
        var tag: [16]u8 = undefined;
        XChaCha20Poly1305.encrypt(
            reply.cookie[0..16],
            &tag,
            &cookie,
            msg[smac1 .. smac1 + 16],
            reply.nonce,
            c.encryption_key,
        );
        @memcpy(reply.cookie[16..32], &tag);
        noise.wipe(&cookie);
        return reply;
    }
};

/// Sender side: stamps MAC1/MAC2, consumes cookie replies.
pub const CookieGenerator = struct {
    mac1_key: [32]u8,
    cookie: [16]u8 = std.mem.zeroes([16]u8),
    cookie_set_ns: i64 = 0,
    cookie_valid: bool = false,
    has_last_mac1: bool = false,
    last_mac1: [16]u8 = std.mem.zeroes([16]u8),
    encryption_key: [32]u8,

    pub fn init(remote_static_public: *const noise.PublicKey) CookieGenerator {
        var g: CookieGenerator = undefined;
        mac1Key(&g.mac1_key, remote_static_public);
        cookieEncryptionKey(&g.encryption_key, remote_static_public);
        g.cookie = std.mem.zeroes([16]u8);
        g.cookie_set_ns = 0;
        g.cookie_valid = false;
        g.has_last_mac1 = false;
        g.last_mac1 = std.mem.zeroes([16]u8);
        return g;
    }

    /// AddMacs: MAC1 always, MAC2 only with a fresh cookie (else zeroes).
    pub fn addMacs(g: *CookieGenerator, msg: []u8, now_ns: i64) void {
        std.debug.assert(msg.len == noise.message_initiation_size or
            msg.len == noise.message_response_size);
        const smac2 = msg.len - 16;
        const smac1 = smac2 - 16;
        var mac1: [16]u8 = undefined;
        mac128(&mac1, &g.mac1_key, msg[0..smac1]);
        @memcpy(msg[smac1..smac2], &mac1);
        g.last_mac1 = mac1;
        g.has_last_mac1 = true;
        @memset(msg[smac2..], 0);
        if (!g.cookie_valid or now_ns - g.cookie_set_ns > cookie_refresh_time_ns) return;
        var mac2: [16]u8 = undefined;
        mac128(&mac2, &g.cookie, msg[0..smac2]);
        @memcpy(msg[smac2..], &mac2);
    }

    /// ConsumeReply: decrypts the cookie against our last MAC1.
    pub fn consumeReply(g: *CookieGenerator, reply: *const CookieReply, now_ns: i64) bool {
        if (!g.has_last_mac1) return false;
        var cookie: [16]u8 = undefined;
        XChaCha20Poly1305.decrypt(
            &cookie,
            reply.cookie[0..16],
            reply.cookie[16..32].*,
            &g.last_mac1,
            reply.nonce,
            g.encryption_key,
        ) catch {
            return false;
        };
        g.cookie = cookie;
        g.cookie_set_ns = now_ns;
        g.cookie_valid = true;
        noise.wipe(&cookie);
        return true;
    }
};
