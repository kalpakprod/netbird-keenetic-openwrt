// Port of wireguard-go device/noise-*.go (MIT) — tests.
// Fixed vectors come from gen/wgnoise (real wireguard-go handshake between two
// in-process devices with fixed static keys + PSK); see vectors.txt there.

const std = @import("std");
const noise = @import("noise.zig");

const INIT_PRIV = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
const RESP_PRIV = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf";
const PSK_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const INIT_PUB = "07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c";
const RESP_PUB = "dc2cca31e8e43bbd91dff7e475cca3347eb478107d5bd765aba4ae4a30c35d44";
const INITIATION_HEX = "01000000460de87b66c88e23df92c946c349d90449afaa3c07c61ae9f58e3232ef68e2e6dc9bd4064da0bf271857aa06c279722cb75891c9693d936c8350c2040750355dfc5e6543616f0fc5cc055c06affc3812c42fde392a871b8b9e7278b58b29acba530362955654e79ff6e7ee1d58da041c0000000000000000000000000000000000000000000000000000000000000000";
const RESPONSE_HEX = "02000000a2688a3e460de87b26d1d83971056f9f39a89276660dd387bb1aaf88ef46193177d2ffa648a412150cf816a0469969b332a6bbc07e81c2e80000000000000000000000000000000000000000000000000000000000000000";
const INIT_EPHEMERAL = "66c88e23df92c946c349d90449afaa3c07c61ae9f58e3232ef68e2e6dc9bd406";
const RESP_EPHEMERAL = "26d1d83971056f9f39a89276660dd387bb1aaf88ef46193177d2ffa648a41215";
const INITIAL_CHAINKEY = "60e26daef327efc02ec335e2a025d2d016eb4206f87277f52d38d1988b78cd36";
const INITIAL_HASH = "2211b361081ac566691243db458ad5322d9c6c662293e8b70ee19c65ba079ef3";
const T_KEY = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
const T_CTR: u64 = 72623859790382856;
const T_PLAIN = "7769726567756172642d7472616e73706f72742d766563746f72";
const T_CIPHERTEXT = "4b6d6557fde1ac60a4bbd5b4bb9c51eb1a784bdad7906cd9db6be42cd26904c29a86b9fd5a266a593dd5";

fn hexToArray(comptime N: usize, s: []const u8) [N]u8 {
    var out: [N]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "initial keys match wireguard-go" {
    const initial = noise.initialKeys();
    try std.testing.expectEqual(hexToArray(32, INITIAL_CHAINKEY), initial.chain_key);
    try std.testing.expectEqual(hexToArray(32, INITIAL_HASH), initial.hash);
}

test "static public keys match wireguard-go" {
    try std.testing.expectEqual(
        hexToArray(32, INIT_PUB),
        noise.publicKeyFromPrivate(hexToArray(32, INIT_PRIV)),
    );
    try std.testing.expectEqual(
        hexToArray(32, RESP_PUB),
        noise.publicKeyFromPrivate(hexToArray(32, RESP_PRIV)),
    );
}

test "unmarshal Go initiation" {
    const bytes = hexToArray(noise.message_initiation_size, INITIATION_HEX);
    const msg = try noise.Initiation.unmarshal(&bytes);
    try std.testing.expectEqual(@as(u32, 2078805318), msg.sender);
    try std.testing.expectEqual(hexToArray(32, INIT_EPHEMERAL), msg.ephemeral);
    var roundtrip: [noise.message_initiation_size]u8 = undefined;
    msg.marshal(&roundtrip);
    try std.testing.expectEqual(bytes, roundtrip);
}

test "unmarshal Go response" {
    const bytes = hexToArray(noise.message_response_size, RESPONSE_HEX);
    const msg = try noise.Response.unmarshal(&bytes);
    try std.testing.expectEqual(@as(u32, 1049258146), msg.sender);
    try std.testing.expectEqual(@as(u32, 2078805318), msg.receiver);
    try std.testing.expectEqual(hexToArray(32, RESP_EPHEMERAL), msg.ephemeral);
}

test "consume Go initiation as responder" {
    var hs = try noise.Handshake.init(
        hexToArray(32, RESP_PRIV),
        hexToArray(32, INIT_PUB),
        hexToArray(32, PSK_HEX),
    );
    const bytes = hexToArray(noise.message_initiation_size, INITIATION_HEX);
    const msg = try noise.Initiation.unmarshal(&bytes);
    var stamp: noise.Timestamp = undefined;
    try hs.consumeInitiation(&msg, &stamp);
    // timestamp decrypted and sane (TAI64N base + recent unix time)
    const secs = std.mem.readInt(u64, stamp[0..8], .big);
    try std.testing.expect(secs > noise.tai64n_base);
    try std.testing.expectEqual(@as(u32, 2078805318), hs.remote_index);
    // same initiation twice is a replay
    try std.testing.expectError(noise.Error.Replay, hs.consumeInitiation(&msg, null));
}

test "consume Go initiation rejects wrong static and tampering" {
    // PSK is not used in the initiation at all (Go touches presharedKey only
    // in Create/ConsumeMessageResponse); the initiation binds the static key.
    var wrong_static = hexToArray(32, INIT_PUB);
    wrong_static[0] ^= 0xff;
    var hs = try noise.Handshake.init(
        hexToArray(32, RESP_PRIV),
        wrong_static,
        hexToArray(32, PSK_HEX),
    );
    const bytes = hexToArray(noise.message_initiation_size, INITIATION_HEX);
    const msg = try noise.Initiation.unmarshal(&bytes);
    try std.testing.expectError(noise.Error.AuthenticationFailed, hs.consumeInitiation(&msg, null));

    var hs2 = try noise.Handshake.init(
        hexToArray(32, RESP_PRIV),
        hexToArray(32, INIT_PUB),
        hexToArray(32, PSK_HEX),
    );
    var tampered = bytes;
    tampered[50] ^= 0x01;
    const msg2 = try noise.Initiation.unmarshal(&tampered);
    try std.testing.expectError(noise.Error.AuthenticationFailed, hs2.consumeInitiation(&msg2, null));
}

test "full handshake in memory produces matching transport keys" {
    const eph_i = hexToArray(32, "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f");
    const eph_r = hexToArray(32, "505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f");
    var init_hs = try noise.Handshake.init(
        hexToArray(32, INIT_PRIV),
        hexToArray(32, RESP_PUB),
        hexToArray(32, PSK_HEX),
    );
    var resp_hs = try noise.Handshake.init(
        hexToArray(32, RESP_PRIV),
        hexToArray(32, INIT_PUB),
        hexToArray(32, PSK_HEX),
    );

    const stamp = noise.tai64nStamp(1_757_000_000, 0);
    const initiation = try init_hs.createInitiation(eph_i, 0x11111111, stamp);
    var init_bytes: [noise.message_initiation_size]u8 = undefined;
    initiation.marshal(&init_bytes);
    const initiation2 = try noise.Initiation.unmarshal(&init_bytes);
    try resp_hs.consumeInitiation(&initiation2, null);

    const response = try resp_hs.createResponse(eph_r, 0x22222222);
    var resp_bytes: [noise.message_response_size]u8 = undefined;
    response.marshal(&resp_bytes);
    const response2 = try noise.Response.unmarshal(&resp_bytes);
    try std.testing.expectEqual(@as(u32, 0x11111111), response2.receiver);
    try init_hs.consumeResponse(&response2);

    const init_keys = try init_hs.beginSymmetricSession();
    const resp_keys = try resp_hs.beginSymmetricSession();
    try std.testing.expect(init_keys.is_initiator);
    try std.testing.expect(!resp_keys.is_initiator);
    try std.testing.expectEqual(init_keys.send_key, resp_keys.receive_key);
    try std.testing.expectEqual(init_keys.receive_key, resp_keys.send_key);
    try std.testing.expectEqual(init_keys.remote_index, resp_keys.local_index);
    try std.testing.expectEqual(resp_keys.remote_index, init_keys.local_index);
    // handshake material is zeroed after derivation
    try std.testing.expectEqual(noise.HandshakeState.zeroed, init_hs.state);
}

test "transport round trip both directions with replay rejection" {
    const eph_i = hexToArray(32, "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f");
    const eph_r = hexToArray(32, "909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
    var init_hs = try noise.Handshake.init(
        hexToArray(32, INIT_PRIV),
        hexToArray(32, RESP_PUB),
        hexToArray(32, PSK_HEX),
    );
    var resp_hs = try noise.Handshake.init(
        hexToArray(32, RESP_PRIV),
        hexToArray(32, INIT_PUB),
        hexToArray(32, PSK_HEX),
    );
    const stamp = noise.tai64nStamp(1_757_000_001, 0);
    const initiation = try init_hs.createInitiation(eph_i, 1, stamp);
    try resp_hs.consumeInitiation(&initiation, null);
    const response = try resp_hs.createResponse(eph_r, 2);
    try init_hs.consumeResponse(&response);
    var init_tp = noise.Transport.init(try init_hs.beginSymmetricSession());
    var resp_tp = noise.Transport.init(try resp_hs.beginSymmetricSession());

    const plaintext = "hello from initiator";
    var header: [noise.message_transport_header_size]u8 = undefined;
    var ciphertext: [plaintext.len + noise.tag_size]u8 = undefined;
    const counter = try init_tp.seal(&header, &ciphertext, plaintext);
    try std.testing.expectEqual(@as(u64, 0), counter);

    var opened: [plaintext.len]u8 = undefined;
    const got = try resp_tp.open(&opened, &header, &ciphertext);
    try std.testing.expectEqual(@as(u64, 0), got);
    try std.testing.expectEqualStrings(plaintext, &opened);

    // replay of the same packet is rejected
    try std.testing.expectError(noise.Error.Replay, resp_tp.open(&opened, &header, &ciphertext));

    // reverse direction works
    const back = "hello back";
    var header2: [noise.message_transport_header_size]u8 = undefined;
    var ciphertext2: [back.len + noise.tag_size]u8 = undefined;
    _ = try resp_tp.seal(&header2, &ciphertext2, back);
    var opened2: [back.len]u8 = undefined;
    _ = try init_tp.open(&opened2, &header2, &ciphertext2);
    try std.testing.expectEqualStrings(back, &opened2);

    // tampered tag fails authentication (fresh counter so replay is not the cause)
    var header3: [noise.message_transport_header_size]u8 = undefined;
    var ciphertext3: [back.len + noise.tag_size]u8 = undefined;
    _ = try resp_tp.seal(&header3, &ciphertext3, back);
    ciphertext3[ciphertext3.len - 1] ^= 0x01;
    try std.testing.expectError(
        noise.Error.AuthenticationFailed,
        init_tp.open(&opened2, &header3, &ciphertext3),
    );
}

test "transport construction matches Go x/crypto vector" {
    var tp = noise.Transport{
        .send_key = hexToArray(32, T_KEY),
        .receive_key = hexToArray(32, T_KEY),
        .send_nonce = T_CTR,
        .remote_index = 0,
    };
    const plain = hexToArray(26, T_PLAIN);
    var header: [noise.message_transport_header_size]u8 = undefined;
    var ciphertext: [26 + noise.tag_size]u8 = undefined;
    const counter = try tp.seal(&header, &ciphertext, &plain);
    try std.testing.expectEqual(T_CTR, counter);
    try std.testing.expectEqual(hexToArray(42, T_CIPHERTEXT), ciphertext);

    // and back: decrypt the Go-produced ciphertext
    const go_ct = hexToArray(42, T_CIPHERTEXT);
    var tp2 = noise.Transport{
        .send_key = hexToArray(32, T_KEY),
        .receive_key = hexToArray(32, T_KEY),
        .remote_index = 0,
    };
    // force the replay window past the large counter first
    tp2.replay.last = T_CTR;
    var header2: [noise.message_transport_header_size]u8 = undefined;
    std.mem.writeInt(u32, header2[0..4], noise.message_transport_type, .little);
    std.mem.writeInt(u32, header2[4..8], 0, .little);
    std.mem.writeInt(u64, header2[8..16], T_CTR, .little);
    var opened: [26]u8 = undefined;
    _ = try tp2.open(&opened, &header2, &go_ct);
    try std.testing.expectEqual(plain, opened);
}

test "replay window behavior matches RFC 6479 port" {
    var f = noise.ReplayFilter{};
    // in-order counters accepted once
    try std.testing.expect(f.validateCounter(0, noise.reject_after_messages));
    try std.testing.expect(!f.validateCounter(0, noise.reject_after_messages));
    try std.testing.expect(f.validateCounter(1, noise.reject_after_messages));
    // large jump clears the ring; old counter behind the window is rejected
    try std.testing.expect(f.validateCounter(100_000, noise.reject_after_messages));
    try std.testing.expect(!f.validateCounter(1, noise.reject_after_messages));
    // over-limit counter always rejected
    try std.testing.expect(!f.validateCounter(noise.reject_after_messages, noise.reject_after_messages));
    // sender refuses to seal past the limit
    var tp = noise.Transport{
        .send_key = std.mem.zeroes([32]u8),
        .receive_key = std.mem.zeroes([32]u8),
        .send_nonce = noise.reject_after_messages,
        .remote_index = 0,
    };
    var header: [noise.message_transport_header_size]u8 = undefined;
    var ct: [noise.tag_size]u8 = undefined;
    try std.testing.expectError(noise.Error.CounterExhausted, tp.seal(&header, &ct, &.{}));
}

test "psk mismatch fails at response consumption" {
    const eph_i = hexToArray(32, INIT_PRIV);
    const eph_r = hexToArray(32, RESP_PRIV);
    var bad_psk = hexToArray(32, PSK_HEX);
    bad_psk[31] ^= 0x01;
    var init_hs = try noise.Handshake.init(
        hexToArray(32, INIT_PRIV),
        hexToArray(32, RESP_PUB),
        hexToArray(32, PSK_HEX),
    );
    var resp_hs = try noise.Handshake.init(
        hexToArray(32, RESP_PRIV),
        hexToArray(32, INIT_PUB),
        bad_psk,
    );
    const initiation = try init_hs.createInitiation(eph_i, 1, noise.tai64nStamp(1_757_000_002, 0));
    try resp_hs.consumeInitiation(&initiation, null);
    const response = try resp_hs.createResponse(eph_r, 2);
    try std.testing.expectError(noise.Error.AuthenticationFailed, init_hs.consumeResponse(&response));
}

test "handshake state machine rejects out-of-order calls" {
    var hs = try noise.Handshake.init(
        hexToArray(32, INIT_PRIV),
        hexToArray(32, RESP_PUB),
        hexToArray(32, PSK_HEX),
    );
    const eph = hexToArray(32, INIT_PRIV);
    try std.testing.expectError(
        noise.Error.InvalidState,
        hs.createResponse(eph, 1),
    );
    try std.testing.expectError(noise.Error.InvalidState, hs.beginSymmetricSession());
    // zero remote static -> invalid public key at init
    try std.testing.expectError(
        noise.Error.InvalidPublicKey,
        noise.Handshake.init(hexToArray(32, INIT_PRIV), std.mem.zeroes([32]u8), hexToArray(32, PSK_HEX)),
    );
}
