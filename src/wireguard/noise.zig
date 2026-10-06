// Port of wireguard-go device/noise-*.go (MIT)
// Reference: upstream/netbird/vendor/golang.zx2c4.com/wireguard/device/
// noise-protocol.go, noise-helpers.go, noise-types.go, ../replay/replay.go,
// ../tai64n/tai64n.go and the transport seal/open paths in device/send.go
// (RoutineEncryption) and device/receive.go (RoutineDecryption).
//
// Scope: Noise_IKpsk2 handshake (cookie-less path, no MAC1/MAC2, no cookie
// reply), transport AEAD and the RFC 6479 replay filter. Device concerns
// (index table, timers, queues, padding, rate limiting) are out of scope:
// sender indices and timestamps are caller-supplied parameters.

const std = @import("std");
const Blake2s256 = std.crypto.hash.blake2.Blake2s256;
const HmacBlake2s = std.crypto.auth.hmac.Hmac(Blake2s256);
const X25519 = std.crypto.dh.X25519;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

pub const NoiseConstruction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
pub const wg_identifier = "WireGuard v1 zx2c4 Jason@zx2c4.com";

pub const PublicKey = [32]u8;
pub const PrivateKey = [32]u8;
pub const PresharedKey = [32]u8;
pub const Timestamp = [12]u8;
pub const Hash = [32]u8;

pub const message_initiation_type: u32 = 1;
pub const message_response_type: u32 = 2;
pub const message_transport_type: u32 = 4;

pub const message_initiation_size = 148;
pub const message_response_size = 92;
pub const message_transport_header_size = 16;
pub const tag_size = 16;

pub const message_transport_offset_receiver = 4;
pub const message_transport_offset_counter = 8;
pub const message_transport_offset_content = 16;

pub const rekey_after_messages: u64 = 1 << 60;
pub const reject_after_messages: u64 = (1 << 64) - (1 << 13) - 1;

pub const tai64n_base: u64 = 0x400000000000000a;
pub const tai64n_whitener_mask: u32 = 0x1000000 - 1;

pub const zero_nonce: [12]u8 = std.mem.zeroes([12]u8);

pub const Error = error{
    InvalidState,
    AuthenticationFailed,
    InvalidPublicKey,
    Replay,
    MessageLengthMismatch,
    CounterExhausted,
};

fn hmac1(out: *Hash, key: []const u8, in0: []const u8) void {
    var ctx = HmacBlake2s.init(key);
    ctx.update(in0);
    ctx.final(out);
}

fn hmac2(out: *Hash, key: []const u8, in0: []const u8, in1: []const u8) void {
    var ctx = HmacBlake2s.init(key);
    ctx.update(in0);
    ctx.update(in1);
    ctx.final(out);
}

/// HKDF-Expand for one output (noise-helpers.go KDF1).
pub fn kdf1(t0: *Hash, key: []const u8, input: []const u8) void {
    hmac1(t0, key, input);
    const one = [_]u8{0x1};
    var tmp: Hash = t0.*;
    hmac1(t0, &tmp, &one);
    wipe(&tmp);
}

/// HKDF for two outputs (noise-helpers.go KDF2).
pub fn kdf2(t0: *Hash, t1: *Hash, key: []const u8, input: []const u8) void {
    var prk: Hash = undefined;
    hmac1(&prk, key, input);
    const one = [_]u8{0x1};
    hmac1(t0, &prk, &one);
    const two = [_]u8{0x2};
    hmac2(t1, &prk, t0, &two);
    wipe(&prk);
}

/// HKDF for three outputs (noise-helpers.go KDF3).
pub fn kdf3(t0: *Hash, t1: *Hash, t2: *Hash, key: []const u8, input: []const u8) void {
    var prk: Hash = undefined;
    hmac1(&prk, key, input);
    const one = [_]u8{0x1};
    hmac1(t0, &prk, &one);
    const two = [_]u8{0x2};
    hmac2(t1, &prk, t0, &two);
    const three = [_]u8{0x3};
    hmac2(t2, &prk, t1, &three);
    wipe(&prk);
}

pub fn wipe(buf: []u8) void {
    @memset(buf, 0);
}

fn isZero(val: []const u8) bool {
    var acc: u8 = 1;
    for (val) |b| {
        acc &= @intFromBool(b == 0);
    }
    return acc == 1;
}

fn constantTimeEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var diff: u8 = 0;
    for (a, b) |x, y| {
        diff |= x ^ y;
    }
    return diff == 0;
}

pub fn clamp(sk: *PrivateKey) void {
    sk[0] &= 248;
    sk[31] = (sk[31] & 127) | 64;
}

/// Random clamped private key. Randomness comes from the caller's Io.
pub fn generatePrivateKey(io: std.Io) PrivateKey {
    var sk: PrivateKey = undefined;
    io.random(&sk);
    clamp(&sk);
    return sk;
}

pub fn publicKeyFromPrivate(sk: PrivateKey) PublicKey {
    var clamped = sk;
    clamp(&clamped);
    return X25519.recoverPublicKey(clamped);
}

/// X25519 shared secret; rejects the all-zero secret like Go's sharedSecret.
pub fn sharedSecret(sk: PrivateKey, pk: PublicKey) Error![32]u8 {
    var clamped = sk;
    clamp(&clamped);
    const ss = X25519.scalarmult(clamped, pk) catch {
        return Error.InvalidPublicKey;
    };
    if (isZero(&ss)) {
        return Error.InvalidPublicKey;
    }
    return ss;
}

fn mixHash(dst: *Hash, h: *const Hash, data: []const u8) void {
    var hasher = Blake2s256.init(.{});
    hasher.update(h);
    hasher.update(data);
    hasher.final(dst);
}

fn mixKey(dst: *Hash, c: *const Hash, data: []const u8) void {
    var tmp: Hash = c.*;
    kdf1(dst, &tmp, data);
    wipe(&tmp);
}

pub const InitialKeys = struct {
    chain_key: Hash,
    hash: Hash,
};

/// Precomputations from noise-protocol.go init(): chainKey = H(construction),
/// hash = H(chainKey || identifier).
pub fn initialKeys() InitialKeys {
    var chain_key: Hash = undefined;
    Blake2s256.hash(NoiseConstruction, &chain_key, .{});
    var hash: Hash = undefined;
    mixHash(&hash, &chain_key, wg_identifier);
    return .{ .chain_key = chain_key, .hash = hash };
}

/// TAI64N stamp (tai64n.go stamp): BE64(base + unix secs) || BE32(nanos, low
/// 24 bits cleared).
pub fn tai64nStamp(unix_secs: i64, nanos: u32) Timestamp {
    var out: Timestamp = undefined;
    const secs: u64 = tai64n_base +% @as(u64, @bitCast(unix_secs));
    std.mem.writeInt(u64, out[0..8], secs, .big);
    std.mem.writeInt(u32, out[8..12], nanos & ~tai64n_whitener_mask, .big);
    return out;
}

pub fn timestampAfter(t1: Timestamp, t2: Timestamp) bool {
    return std.mem.order(u8, &t1, &t2) == .gt;
}

pub const Initiation = struct {
    sender: u32,
    ephemeral: PublicKey,
    static: [48]u8,
    timestamp: [28]u8,
    mac1: [16]u8 = std.mem.zeroes([16]u8),
    mac2: [16]u8 = std.mem.zeroes([16]u8),

    pub fn marshal(self: *const Initiation, out: *[message_initiation_size]u8) void {
        std.mem.writeInt(u32, out[0..4], message_initiation_type, .little);
        std.mem.writeInt(u32, out[4..8], self.sender, .little);
        @memcpy(out[8..40], &self.ephemeral);
        @memcpy(out[40..88], &self.static);
        @memcpy(out[88..116], &self.timestamp);
        @memcpy(out[116..132], &self.mac1);
        @memcpy(out[132..148], &self.mac2);
    }

    pub fn unmarshal(buf: *const [message_initiation_size]u8) Error!Initiation {
        if (std.mem.readInt(u32, buf[0..4], .little) != message_initiation_type) {
            return Error.MessageLengthMismatch;
        }
        var msg: Initiation = undefined;
        msg.sender = std.mem.readInt(u32, buf[4..8], .little);
        @memcpy(&msg.ephemeral, buf[8..40]);
        @memcpy(&msg.static, buf[40..88]);
        @memcpy(&msg.timestamp, buf[88..116]);
        @memcpy(&msg.mac1, buf[116..132]);
        @memcpy(&msg.mac2, buf[132..148]);
        return msg;
    }
};

pub const Response = struct {
    sender: u32,
    receiver: u32,
    ephemeral: PublicKey,
    empty: [16]u8,
    mac1: [16]u8 = std.mem.zeroes([16]u8),
    mac2: [16]u8 = std.mem.zeroes([16]u8),

    pub fn marshal(self: *const Response, out: *[message_response_size]u8) void {
        std.mem.writeInt(u32, out[0..4], message_response_type, .little);
        std.mem.writeInt(u32, out[4..8], self.sender, .little);
        std.mem.writeInt(u32, out[8..12], self.receiver, .little);
        @memcpy(out[12..44], &self.ephemeral);
        @memcpy(out[44..60], &self.empty);
        @memcpy(out[60..76], &self.mac1);
        @memcpy(out[76..92], &self.mac2);
    }

    pub fn unmarshal(buf: *const [message_response_size]u8) Error!Response {
        if (std.mem.readInt(u32, buf[0..4], .little) != message_response_type) {
            return Error.MessageLengthMismatch;
        }
        var msg: Response = undefined;
        msg.sender = std.mem.readInt(u32, buf[4..8], .little);
        msg.receiver = std.mem.readInt(u32, buf[8..12], .little);
        @memcpy(&msg.ephemeral, buf[12..44]);
        @memcpy(&msg.empty, buf[44..60]);
        @memcpy(&msg.mac1, buf[60..76]);
        @memcpy(&msg.mac2, buf[76..92]);
        return msg;
    }
};

pub const HandshakeState = enum {
    zeroed,
    initiation_created,
    initiation_consumed,
    response_created,
    response_consumed,
};

/// Single-peer Noise_IKpsk2 handshake. Mirrors device.Handshake fields minus
/// device coupling (no mutex, no index table, no timers).
pub const Handshake = struct {
    state: HandshakeState = .zeroed,
    hash: Hash = std.mem.zeroes([32]u8),
    chain_key: Hash = std.mem.zeroes([32]u8),
    preshared_key: PresharedKey,
    local_static_private: PrivateKey,
    local_static_public: PublicKey,
    local_ephemeral: PrivateKey = std.mem.zeroes([32]u8),
    local_index: u32 = 0,
    remote_index: u32 = 0,
    remote_static: PublicKey,
    remote_ephemeral: PublicKey = std.mem.zeroes([32]u8),
    precomputed_static_static: [32]u8,
    last_timestamp: Timestamp = std.mem.zeroes([12]u8),

    pub fn init(
        local_private: PrivateKey,
        remote_static: PublicKey,
        psk: PresharedKey,
    ) Error!Handshake {
        const ss = try sharedSecret(local_private, remote_static);
        return .{
            .preshared_key = psk,
            .local_static_private = local_private,
            .local_static_public = publicKeyFromPrivate(local_private),
            .remote_static = remote_static,
            .precomputed_static_static = ss,
        };
    }

    pub fn clear(self: *Handshake) void {
        wipe(&self.local_ephemeral);
        wipe(&self.remote_ephemeral);
        wipe(&self.chain_key);
        wipe(&self.hash);
        self.local_index = 0;
        self.state = .zeroed;
    }

    fn mixHashState(self: *Handshake, data: []const u8) void {
        var out: Hash = undefined;
        mixHash(&out, &self.hash, data);
        self.hash = out;
    }

    fn mixKeyState(self: *Handshake, data: []const u8) void {
        var out: Hash = undefined;
        mixKey(&out, &self.chain_key, data);
        self.chain_key = out;
    }

    /// Port of CreateMessageInitiation. Caller supplies the ephemeral key, the
    /// sender index (index table lives in the device layer) and the timestamp.
    pub fn createInitiation(
        self: *Handshake,
        ephemeral_private: PrivateKey,
        sender_index: u32,
        stamp: Timestamp,
    ) Error!Initiation {
        const initial = initialKeys();
        self.hash = initial.hash;
        self.chain_key = initial.chain_key;
        self.local_ephemeral = ephemeral_private;

        self.mixHashState(&self.remote_static);

        var msg: Initiation = .{
            .sender = sender_index,
            .ephemeral = publicKeyFromPrivate(ephemeral_private),
            .static = undefined,
            .timestamp = undefined,
        };

        self.mixKeyState(&msg.ephemeral);
        self.mixHashState(&msg.ephemeral);

        // encrypt static key
        var ss = try sharedSecret(self.local_ephemeral, self.remote_static);
        defer wipe(&ss);
        var key: [32]u8 = undefined;
        {
            var ck = self.chain_key;
            kdf2(&self.chain_key, &key, &ck, &ss);
            wipe(&ck);
        }
        {
            var tag: [tag_size]u8 = undefined;
            ChaCha20Poly1305.encrypt(
                msg.static[0..32],
                &tag,
                &self.local_static_public,
                &self.hash,
                zero_nonce,
                key,
            );
            @memcpy(msg.static[32..48], &tag);
        }
        wipe(&key);
        self.mixHashState(&msg.static);

        // encrypt timestamp
        if (isZero(&self.precomputed_static_static)) {
            return Error.InvalidPublicKey;
        }
        {
            var ck = self.chain_key;
            kdf2(&self.chain_key, &key, &ck, &self.precomputed_static_static);
            wipe(&ck);
        }
        {
            var tag: [tag_size]u8 = undefined;
            ChaCha20Poly1305.encrypt(
                msg.timestamp[0..12],
                &tag,
                &stamp,
                &self.hash,
                zero_nonce,
                key,
            );
            @memcpy(msg.timestamp[12..28], &tag);
        }
        wipe(&key);

        self.local_index = sender_index;
        self.mixHashState(&msg.timestamp);
        self.state = .initiation_created;
        return msg;
    }

    /// Port of ConsumeMessageInitiation. The decrypted static key must equal
    /// the bound remote static (this replaces the device peer-table lookup).
    /// Flood rate limiting stays in the device layer.
    pub fn consumeInitiation(
        self: *Handshake,
        msg: *const Initiation,
        stamp_out: ?*Timestamp,
    ) Error!void {
        const initial = initialKeys();
        var hash: Hash = undefined;
        var chain_key: Hash = undefined;
        mixHash(&hash, &initial.hash, &self.local_static_public);
        mixHash(&hash, &hash, &msg.ephemeral);
        mixKey(&chain_key, &initial.chain_key, &msg.ephemeral);

        // decrypt static key
        var peer_pk: PublicKey = undefined;
        var key: [32]u8 = undefined;
        var ss = sharedSecret(self.local_static_private, msg.ephemeral) catch {
            return Error.AuthenticationFailed;
        };
        defer wipe(&ss);
        kdf2(&chain_key, &key, &chain_key, &ss);
        {
            const tag: [tag_size]u8 = msg.static[32..48].*;
            ChaCha20Poly1305.decrypt(
                &peer_pk,
                msg.static[0..32],
                tag,
                &hash,
                zero_nonce,
                key,
            ) catch {
                return Error.AuthenticationFailed;
            };
        }
        mixHash(&hash, &hash, &msg.static);

        // peer lookup by static key
        if (!constantTimeEqual(&peer_pk, &self.remote_static)) {
            return Error.AuthenticationFailed;
        }

        // decrypt timestamp
        var ts: Timestamp = undefined;
        if (isZero(&self.precomputed_static_static)) {
            return Error.AuthenticationFailed;
        }
        kdf2(&chain_key, &key, &chain_key, &self.precomputed_static_static);
        {
            const tag: [tag_size]u8 = msg.timestamp[12..28].*;
            ChaCha20Poly1305.decrypt(
                &ts,
                msg.timestamp[0..12],
                tag,
                &hash,
                zero_nonce,
                key,
            ) catch {
                return Error.AuthenticationFailed;
            };
        }
        wipe(&key);
        mixHash(&hash, &hash, &msg.timestamp);

        // replay protection
        if (!timestampAfter(ts, self.last_timestamp)) {
            return Error.Replay;
        }

        self.hash = hash;
        self.chain_key = chain_key;
        self.remote_index = msg.sender;
        self.remote_ephemeral = msg.ephemeral;
        self.last_timestamp = ts;
        self.state = .initiation_consumed;
        if (stamp_out) |out| {
            out.* = ts;
        }
    }

    /// Port of CreateMessageResponse.
    pub fn createResponse(
        self: *Handshake,
        ephemeral_private: PrivateKey,
        sender_index: u32,
    ) Error!Response {
        if (self.state != .initiation_consumed) {
            return Error.InvalidState;
        }
        self.local_index = sender_index;
        self.local_ephemeral = ephemeral_private;

        var msg: Response = .{
            .sender = sender_index,
            .receiver = self.remote_index,
            .ephemeral = publicKeyFromPrivate(ephemeral_private),
            .empty = undefined,
        };
        self.mixHashState(&msg.ephemeral);
        self.mixKeyState(&msg.ephemeral);

        var ss = try sharedSecret(self.local_ephemeral, self.remote_ephemeral);
        self.mixKeyState(&ss);
        wipe(&ss);
        ss = try sharedSecret(self.local_ephemeral, self.remote_static);
        self.mixKeyState(&ss);
        wipe(&ss);

        // add preshared key
        var tau: Hash = undefined;
        var key: [32]u8 = undefined;
        {
            var ck = self.chain_key;
            kdf3(&self.chain_key, &tau, &key, &ck, &self.preshared_key);
            wipe(&ck);
        }
        self.mixHashState(&tau);
        wipe(&tau);

        {
            var no_content: [0]u8 = .{};
            ChaCha20Poly1305.encrypt(no_content[0..], &msg.empty, &.{}, &self.hash, zero_nonce, key);
        }
        wipe(&key);
        self.mixHashState(&msg.empty);

        self.state = .response_created;
        return msg;
    }

    /// Port of ConsumeMessageResponse.
    pub fn consumeResponse(self: *Handshake, msg: *const Response) Error!void {
        if (self.state != .initiation_created) {
            return Error.InvalidState;
        }

        var hash: Hash = undefined;
        var chain_key: Hash = undefined;
        mixHash(&hash, &self.hash, &msg.ephemeral);
        mixKey(&chain_key, &self.chain_key, &msg.ephemeral);

        var ss = sharedSecret(self.local_ephemeral, msg.ephemeral) catch {
            return Error.AuthenticationFailed;
        };
        {
            var out: Hash = undefined;
            mixKey(&out, &chain_key, &ss);
            chain_key = out;
        }
        wipe(&ss);

        ss = sharedSecret(self.local_static_private, msg.ephemeral) catch {
            return Error.AuthenticationFailed;
        };
        {
            var out: Hash = undefined;
            mixKey(&out, &chain_key, &ss);
            chain_key = out;
        }
        wipe(&ss);

        var tau: Hash = undefined;
        var key: [32]u8 = undefined;
        kdf3(&chain_key, &tau, &key, &chain_key, &self.preshared_key);
        mixHash(&hash, &hash, &tau);
        wipe(&tau);

        var empty_plain: [0]u8 = .{};
        ChaCha20Poly1305.decrypt(&empty_plain, &.{}, msg.empty, &hash, zero_nonce, key) catch {
            return Error.AuthenticationFailed;
        };
        wipe(&key);
        mixHash(&hash, &hash, &msg.empty);

        self.hash = hash;
        self.chain_key = chain_key;
        self.remote_index = msg.sender;
        self.state = .response_consumed;
    }

    pub const SessionKeys = struct {
        send_key: [32]u8,
        receive_key: [32]u8,
        is_initiator: bool,
        local_index: u32,
        remote_index: u32,
    };

    /// Port of BeginSymmetricSession (key derivation half). Zeroes the
    /// handshake; keypair bookkeeping stays in the device layer.
    pub fn beginSymmetricSession(self: *Handshake) Error!SessionKeys {
        var send_key: [32]u8 = undefined;
        var recv_key: [32]u8 = undefined;
        const is_initiator: bool = switch (self.state) {
            .response_consumed => blk: {
                const empty: [0]u8 = .{};
                kdf2(&send_key, &recv_key, &self.chain_key, &empty);
                break :blk true;
            },
            .response_created => blk: {
                const empty: [0]u8 = .{};
                kdf2(&recv_key, &send_key, &self.chain_key, &empty);
                break :blk false;
            },
            else => return Error.InvalidState,
        };
        const keys = SessionKeys{
            .send_key = send_key,
            .receive_key = recv_key,
            .is_initiator = is_initiator,
            .local_index = self.local_index,
            .remote_index = self.remote_index,
        };
        self.clear();
        return keys;
    }
};

/// Sliding-window anti-replay filter, port of replay/replay.go (RFC 6479).
pub const ReplayFilter = struct {
    const block_bit_log = 6;
    const block_bits = 1 << block_bit_log;
    const ring_blocks = 1 << 7;
    const window_size = (ring_blocks - 1) * block_bits;
    const block_mask = ring_blocks - 1;
    const bit_mask = block_bits - 1;

    last: u64 = 0,
    ring: [ring_blocks]u64 = std.mem.zeroes([ring_blocks]u64),

    pub fn reset(self: *ReplayFilter) void {
        self.last = 0;
        self.ring[0] = 0;
    }

    /// Returns true once per counter inside the window and below limit.
    pub fn validateCounter(self: *ReplayFilter, counter: u64, limit: u64) bool {
        if (counter >= limit) {
            return false;
        }
        var index_block = counter >> block_bit_log;
        if (counter > self.last) {
            const current = self.last >> block_bit_log;
            var diff = index_block - current;
            if (diff > ring_blocks) {
                diff = ring_blocks;
            }
            var i: u64 = current + 1;
            while (i <= current + diff) : (i += 1) {
                self.ring[i & block_mask] = 0;
            }
            self.last = counter;
        } else if (self.last - counter > window_size) {
            return false;
        }
        index_block &= block_mask;
        const index_bit: u6 = @intCast(counter & bit_mask);
        const old = self.ring[index_block];
        const new = old | (@as(u64, 1) << index_bit);
        self.ring[index_block] = new;
        return old != new;
    }
};

/// Transport AEAD endpoint. Mirrors RoutineEncryption/RoutineDecryption:
/// header = type(4) || receiver LE32 || counter LE64, nonce = 4 zero bytes ||
/// LE64(counter), empty additional data. Padding (send.go) is the caller's job.
pub const Transport = struct {
    send_key: [32]u8,
    receive_key: [32]u8,
    send_nonce: u64 = 0,
    remote_index: u32,
    replay: ReplayFilter = .{},

    pub fn init(keys: Handshake.SessionKeys) Transport {
        return .{
            .send_key = keys.send_key,
            .receive_key = keys.receive_key,
            .remote_index = keys.remote_index,
        };
    }

    /// Seal one transport packet. Returns the counter used.
    pub fn seal(
        self: *Transport,
        out_header: *[message_transport_header_size]u8,
        out_ciphertext: []u8,
        plaintext: []const u8,
    ) Error!u64 {
        if (self.send_nonce >= reject_after_messages) {
            return Error.CounterExhausted;
        }
        if (out_ciphertext.len != plaintext.len + tag_size) {
            return Error.MessageLengthMismatch;
        }
        const counter = self.send_nonce;
        self.send_nonce += 1;

        std.mem.writeInt(u32, out_header[0..4], message_transport_type, .little);
        std.mem.writeInt(u32, out_header[4..8], self.remote_index, .little);
        std.mem.writeInt(u64, out_header[8..16], counter, .little);

        var nonce = zero_nonce;
        std.mem.writeInt(u64, nonce[4..12], counter, .little);
        var tag: [tag_size]u8 = undefined;
        ChaCha20Poly1305.encrypt(
            out_ciphertext[0..plaintext.len],
            &tag,
            plaintext,
            &.{},
            nonce,
            self.send_key,
        );
        @memcpy(out_ciphertext[plaintext.len..][0..tag_size], &tag);
        return counter;
    }

    /// Open one transport packet. Validates the replay window first.
    pub fn open(
        self: *Transport,
        plaintext_out: []u8,
        header: *const [message_transport_header_size]u8,
        ciphertext_with_tag: []const u8,
    ) Error!u64 {
        if (std.mem.readInt(u32, header[0..4], .little) != message_transport_type) {
            return Error.MessageLengthMismatch;
        }
        if (ciphertext_with_tag.len < tag_size) {
            return Error.MessageLengthMismatch;
        }
        if (plaintext_out.len != ciphertext_with_tag.len - tag_size) {
            return Error.MessageLengthMismatch;
        }
        const counter = std.mem.readInt(u64, header[8..16], .little);
        var replay = self.replay;
        if (!replay.validateCounter(counter, reject_after_messages)) {
            return Error.Replay;
        }
        var nonce = zero_nonce;
        std.mem.writeInt(u64, nonce[4..12], counter, .little);
        const body_len = ciphertext_with_tag.len - tag_size;
        const tag: [tag_size]u8 = ciphertext_with_tag[body_len..][0..tag_size].*;
        ChaCha20Poly1305.decrypt(
            plaintext_out,
            ciphertext_with_tag[0..body_len],
            tag,
            &.{},
            nonce,
            self.receive_key,
        ) catch {
            return Error.AuthenticationFailed;
        };
        self.replay = replay;
        return counter;
    }
};
