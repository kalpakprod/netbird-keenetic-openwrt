// Port of netbird shared/relay/messages (v0.79.0) — tests.
// Vectors: src/relay/testdata/msgs.txt from gen/relayvecs (real upstream
// package): every message type, encoded by Go; Zig must decode, re-encode
// byte-identically, and reproduce the encoder output.

const std = @import("std");
const messages = @import("messages.zig");

const vectors_raw = @embedFile("testdata/msgs.txt");

fn hexOf(name: []const u8) []const u8 {
    var it = std.mem.splitScalar(u8, vectors_raw, '\n');
    while (it.next()) |line| {
        if (line.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, line, '=').?;
        if (std.mem.eql(u8, line[0..eq], name)) return line[eq + 1 ..];
    }
    unreachable;
}

fn bytesOf(allocator: std.mem.Allocator, name: []const u8) ![]u8 {
    const hx = hexOf(name);
    const out = try allocator.alloc(u8, hx.len / 2);
    _ = try std.fmt.hexToBytes(out, hx);
    return out;
}

fn bytesFixed(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

test "hash id matches go vectors" {
    var raw: [messages.peer_id_size]u8 = undefined;
    _ = try std.fmt.hexToBytes(&raw, hexOf("hash_id_alpha"));
    try std.testing.expectEqualSlices(u8, &raw, &messages.hashID("peer-alpha"));
    _ = try std.fmt.hexToBytes(&raw, hexOf("hash_id_beta"));
    try std.testing.expectEqualSlices(u8, &raw, &messages.hashID("peer-beta"));
}

test "auth msg decodes and re-encodes like go" {
    const raw = try bytesOf(std.testing.allocator, "auth");
    defer std.testing.allocator.free(raw);

    try std.testing.expectEqual(messages.MsgType.auth, try messages.determineClientMessageType(raw));
    const parsed = try messages.unmarshalAuthMsg(raw);
    const alpha = messages.hashID("peer-alpha");
    try std.testing.expectEqualSlices(u8, &alpha, &parsed.peer_id);
    // token binary: algo byte 1 (HMAC-SHA256), 32-byte signature, ascii payload
    try std.testing.expectEqual(@as(u8, 1), parsed.payload[0]);
    try std.testing.expectEqualStrings("4102444800", parsed.payload[33..]);

    var buf: [messages.max_handshake_size]u8 = undefined;
    const out = try messages.marshalAuthMsg(&buf, parsed.peer_id, parsed.payload);
    try std.testing.expectEqualSlices(u8, raw, out);
}

test "auth msg at max handshake size" {
    const raw = try bytesOf(std.testing.allocator, "auth_max");
    defer std.testing.allocator.free(raw);
    try std.testing.expectEqual(messages.max_handshake_size, raw.len);

    const parsed = try messages.unmarshalAuthMsg(raw);
    try std.testing.expectEqual(messages.max_auth_payload_size, parsed.payload.len);
    var buf: [messages.max_handshake_size]u8 = undefined;
    const out = try messages.marshalAuthMsg(&buf, parsed.peer_id, parsed.payload);
    try std.testing.expectEqualSlices(u8, raw, out);

    var too_long_payload: [messages.max_auth_payload_size + 1]u8 = @splat('a');
    try std.testing.expectError(messages.Error.AuthPayloadTooLarge, messages.marshalAuthMsg(&buf, parsed.peer_id, &too_long_payload));
}

test "auth response carries the instance url" {
    const raw = try bytesOf(std.testing.allocator, "authresp");
    defer std.testing.allocator.free(raw);
    try std.testing.expectEqual(messages.MsgType.auth_response, try messages.determineServerMessageType(raw));
    try std.testing.expectEqualStrings("rels://127.0.0.1:33073", try messages.unmarshalAuthResponse(raw));

    var buf: [messages.max_handshake_resp_size]u8 = undefined;
    const out = try messages.marshalAuthResponse(&buf, "rels://127.0.0.1:33073");
    try std.testing.expectEqualSlices(u8, raw, out);

    try std.testing.expectError(messages.Error.InvalidMessageLength, messages.unmarshalAuthResponse(raw[0..2]));
    const too_long: [messages.max_handshake_resp_size - 1]u8 = @splat('x');
    try std.testing.expectError(messages.Error.AuthResponseTooLarge, messages.marshalAuthResponse(&buf, &too_long));
    const max_addr: [messages.max_handshake_resp_size - 2]u8 = @splat('x');
    _ = try messages.marshalAuthResponse(&buf, &max_addr);
}

test "close and healthcheck are two-byte headers" {
    const close_bytes = bytesFixed("0104");
    try std.testing.expectEqualSlices(u8, &close_bytes, &messages.marshalCloseMsg());
    const hc_bytes = bytesFixed("0105");
    try std.testing.expectEqualSlices(u8, &hc_bytes, &messages.marshalHealthcheck());
    try std.testing.expectEqual(messages.MsgType.close, try messages.determineServerMessageType(&messages.marshalCloseMsg()));
    try std.testing.expectEqual(messages.MsgType.health_check, try messages.determineClientMessageType(&messages.marshalHealthcheck()));
}

test "transport msg decodes and re-encodes like go" {
    inline for (.{ "transport", "transport_empty" }) |name| {
        const raw = try bytesOf(std.testing.allocator, name);
        defer std.testing.allocator.free(raw);
        try std.testing.expectEqual(messages.MsgType.transport, try messages.determineClientMessageType(raw));
        const parsed = try messages.unmarshalTransportMsg(raw);
        const beta = messages.hashID("peer-beta");
        try std.testing.expectEqualSlices(u8, &beta, &parsed.peer_id);
        if (comptime std.mem.eql(u8, name, "transport")) {
            try std.testing.expectEqualStrings("hello-relay", parsed.payload);
        } else {
            try std.testing.expectEqual(@as(usize, 0), parsed.payload.len);
        }
        var buf: [messages.max_message_size]u8 = undefined;
        const out = try messages.marshalTransportMsg(&buf, parsed.peer_id, parsed.payload);
        try std.testing.expectEqualSlices(u8, raw, out);
        try std.testing.expectEqual(parsed.peer_id, try messages.unmarshalTransportID(raw));
    }
}

test "transport msg id rewrite in place" {
    var buf: [64]u8 = undefined;
    const beta = messages.hashID("peer-beta");
    const out = try messages.marshalTransportMsg(&buf, beta, "x");
    const alpha = messages.hashID("peer-alpha");
    try messages.updateTransportMsg(out, alpha);
    try std.testing.expectEqual(alpha, try messages.unmarshalTransportID(out));
    try std.testing.expectError(messages.Error.InvalidMessageLength, messages.updateTransportMsg(out[0..10], beta));
}

test "peer state messages round trip through go vectors" {
    const alpha = messages.hashID("peer-alpha");
    const beta = messages.hashID("peer-beta");

    inline for (.{
        .{ "sub1", messages.MsgType.subscribe_peer_state, [_]messages.PeerID{alpha} },
        .{ "online2", messages.MsgType.peers_online, [_]messages.PeerID{ alpha, beta } },
        .{ "offline1", messages.MsgType.peers_went_offline, [_]messages.PeerID{beta} },
    }) |case| {
        const raw = try bytesOf(std.testing.allocator, case[0]);
        defer std.testing.allocator.free(raw);
        var ids: [2]messages.PeerID = undefined;
        const n = try messages.unmarshalPeerIDs(raw, &ids);
        try std.testing.expectEqual(case[2].len, n);
        for (case[2][0..n], 0..) |want, i| try std.testing.expectEqualSlices(u8, &want, &ids[i]);
        var buf: [messages.max_message_size]u8 = undefined;
        const out = try messages.marshalPeerIDs(&buf, ids[0..n], case[1]);
        try std.testing.expectEqualSlices(u8, raw, out);
    }

    // sub245: go chunked 245 ids into max-per-message + remainder
    var many: [245]messages.PeerID = undefined;
    var name_buf: [16]u8 = undefined;
    for (&many, 0..) |*id, i| {
        id.* = messages.hashID(try std.fmt.bufPrint(&name_buf, "peer-{d}", .{i}));
    }
    const raw0 = try bytesOf(std.testing.allocator, "sub245_0");
    defer std.testing.allocator.free(raw0);
    const raw1 = try bytesOf(std.testing.allocator, "sub245_1");
    defer std.testing.allocator.free(raw1);
    try std.testing.expectEqual(@as(usize, 244), messages.max_peers_per_message);
    try std.testing.expectEqual(2 + 244 * messages.peer_id_size, raw0.len);

    var buf: [messages.max_message_size]u8 = undefined;
    const out0 = try messages.marshalPeerIDs(&buf, many[0..244], .subscribe_peer_state);
    try std.testing.expectEqualSlices(u8, raw0, out0);
    const out1 = try messages.marshalPeerIDs(&buf, many[244..], .subscribe_peer_state);
    try std.testing.expectEqualSlices(u8, raw1, out1);

    var ids: [245]messages.PeerID = undefined;
    try std.testing.expectEqual(@as(usize, 244), try messages.unmarshalPeerIDs(raw0, &ids));
    try std.testing.expectEqualSlices(u8, &many[243], &ids[243]);
}

test "peer state marshal rejects empty and oversize lists" {
    var buf: [messages.max_message_size]u8 = undefined;
    try std.testing.expectError(messages.Error.NoPeerIDs, messages.marshalPeerIDs(&buf, &[_]messages.PeerID{}, .peers_online));
    const alpha = messages.hashID("peer-alpha");
    var many: [245]messages.PeerID = @splat(alpha);
try std.testing.expectError(messages.Error.InvalidPeerListSize, messages.marshalPeerIDs(&buf, &many, .peers_online));
}

test "unmarshal rejects bad peer list sizes" {
    try std.testing.expectError(messages.Error.InvalidMessageLength, messages.unmarshalPeerIDs(bytesFixed("0108")[0..1], &[_]messages.PeerID{}));
    const raw = try bytesOf(std.testing.allocator, "sub1");
    defer std.testing.allocator.free(raw);
    try std.testing.expectError(messages.Error.InvalidPeerListSize, messages.unmarshalPeerIDs(raw[0 .. raw.len - 1], &[_]messages.PeerID{}));
    var ids: [1]messages.PeerID = undefined;
    try std.testing.expectEqual(@as(usize, 1), try messages.unmarshalPeerIDs(raw, &ids));
    try std.testing.expectError(messages.Error.BufferTooSmall, messages.unmarshalPeerIDs(raw, ids[0..0]));
}

test "version and type validation" {
    try std.testing.expectEqual(@as(u8, 1), try messages.validateVersion(bytesFixed("0103")[0..]));
    try std.testing.expectError(messages.Error.InvalidMessageLength, messages.validateVersion(bytesFixed("0103")[0..1]));
    try std.testing.expectError(messages.Error.UnsupportedVersion, messages.validateVersion(bytesFixed("0203")[0..]));

    // client set: auth 6, transport 3, close 4, health 5, sub 8, unsub 9
    try std.testing.expectEqual(messages.MsgType.auth, try messages.determineClientMessageType(bytesFixed("0106")[0..]));
    try std.testing.expectEqual(messages.MsgType.unsubscribe_peer_state, try messages.determineClientMessageType(bytesFixed("0109")[0..]));
    // server set: auth_response 7, transport 3, close 4, health 5, online 10, offline 11
    try std.testing.expectEqual(messages.MsgType.auth_response, try messages.determineServerMessageType(bytesFixed("0107")[0..]));
    try std.testing.expectEqual(messages.MsgType.peers_went_offline, try messages.determineServerMessageType(bytesFixed("010b")[0..]));
    // reserved legacy values are rejected on both sides
    try std.testing.expectError(messages.Error.InvalidMessageType, messages.determineClientMessageType(bytesFixed("0101")[0..]));
    try std.testing.expectError(messages.Error.InvalidMessageType, messages.determineServerMessageType(bytesFixed("0102")[0..]));
    try std.testing.expectError(messages.Error.InvalidMessageType, messages.determineServerMessageType(bytesFixed("0106")[0..]));
    try std.testing.expectError(messages.Error.InvalidMessageType, messages.determineClientMessageType(bytesFixed("010a")[0..]));
    try std.testing.expectError(messages.Error.InvalidMessageLength, messages.determineClientMessageType(bytesFixed("0106")[0..1]));
}

test "auth msg magic header and length checks" {
    try std.testing.expectError(messages.Error.InvalidMessageLength, messages.unmarshalAuthMsg(bytesFixed("01062112a442")[0..]));
    const raw = try bytesOf(std.testing.allocator, "auth");
    defer std.testing.allocator.free(raw);
    raw[2] ^= 0xff;
    try std.testing.expectError(messages.Error.InvalidMagicHeader, messages.unmarshalAuthMsg(raw));
}

test "msg type names match go" {
    try std.testing.expectEqualStrings("auth", messages.MsgType.auth.string());
    try std.testing.expectEqualStrings("auth response", messages.MsgType.auth_response.string());
    try std.testing.expectEqualStrings("transport", messages.MsgType.transport.string());
    try std.testing.expectEqualStrings("close", messages.MsgType.close.string());
    try std.testing.expectEqualStrings("health check", messages.MsgType.health_check.string());
    try std.testing.expectEqualStrings("subscribe peer state", messages.MsgType.subscribe_peer_state.string());
    try std.testing.expectEqualStrings("unsubscribe peer state", messages.MsgType.unsubscribe_peer_state.string());
    try std.testing.expectEqualStrings("peers online", messages.MsgType.peers_online.string());
    try std.testing.expectEqualStrings("peers went offline", messages.MsgType.peers_went_offline.string());
    try std.testing.expectEqualStrings("hello", messages.MsgType.hello.string());
    try std.testing.expectEqualStrings("hello response", messages.MsgType.hello_response.string());
    try std.testing.expectEqualStrings("unknown", @as(messages.MsgType, @enumFromInt(42)).string());
}

test "peer id string is prefix plus base64" {
    const alpha = messages.hashID("peer-alpha");
    var buf: [48]u8 = undefined;
    const s = messages.formatPeerID(&buf, alpha);
    try std.testing.expect(std.mem.startsWith(u8, s, "sha-"));
    var hash: [32]u8 = undefined;
    try std.base64.standard.Decoder.decode(&hash, s[4..]);
    try std.testing.expectEqualSlices(u8, alpha[4..], &hash);
}
