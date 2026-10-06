// Port of netbird shared/relay/messages (v0.79.0), BSD-3-Clause.
// Reference: upstream/netbird/shared/relay/messages/{message,id,peer_state}.go
// and upstream/netbird/shared/relay/constants.go (WebSocketURLPath).
//
// Differences from Go: marshal functions write into a caller buffer and
// return the written slice (no allocator); the [][]byte chunking of the
// peer-state marshals becomes one call per message with max_peers_per_message
// exported for the caller to chunk. Wire behavior is unchanged.

const std = @import("std");

pub const max_handshake_size = 212;
pub const max_handshake_resp_size = 8192;
pub const max_message_size = 8820;

pub const current_protocol_version: u8 = 1;

pub const websocket_url_path = "/relay";

pub const MsgType = enum(u8) {
    unknown = 0,
    // Removed legacy handshake types; wire values reserved, server rejects both.
    hello = 1,
    hello_response = 2,
    transport = 3,
    close = 4,
    health_check = 5,
    auth = 6,
    auth_response = 7,
    subscribe_peer_state = 8,
    unsubscribe_peer_state = 9,
    peers_online = 10,
    peers_went_offline = 11,
    _,

    pub fn string(m: MsgType) []const u8 {
        return switch (m) {
            .unknown => "unknown",
            .hello => "hello",
            .hello_response => "hello response",
            .auth => "auth",
            .auth_response => "auth response",
            .transport => "transport",
            .close => "close",
            .health_check => "health check",
            .subscribe_peer_state => "subscribe peer state",
            .unsubscribe_peer_state => "unsubscribe peer state",
            .peers_online => "peers online",
            .peers_went_offline => "peers went offline",
            _ => "unknown",
        };
    }
};

pub const Error = error{
    // Go ErrInvalidMessageLength
    InvalidMessageLength,
    // Go ErrUnsupportedVersion (offending version is in the message byte)
    UnsupportedVersion,
    // Go DetermineClientMessageType/DetermineServerMessageType errors
    InvalidMessageType,
    // Go "invalid magic header"
    InvalidMagicHeader,
    // Go "too large auth payload"
    AuthPayloadTooLarge,
    // Go MarshalAuthResponse "invalid message length"
    AuthResponseTooLarge,
    // Go "no list of peer ids provided"
    NoPeerIDs,
    // Go "invalid peer list size"
    InvalidPeerListSize,
    // Zig-only: caller buffer too small for the marshalled message
    BufferTooSmall,
};

pub const magic_header = [4]u8{ 0x21, 0x12, 0xA4, 0x42 };

pub const size_of_proto_header = 2;

// PeerID: "sha-" prefix + sha256 hash (messages/id.go).
pub const peer_id_prefix = "sha-";
pub const peer_id_size = peer_id_prefix.len + 32;
pub const PeerID = [peer_id_size]u8;

pub fn hashID(peer_id: []const u8) PeerID {
    var out: PeerID = undefined;
    @memcpy(out[0..peer_id_prefix.len], peer_id_prefix);
    std.crypto.hash.sha2.Sha256.hash(peer_id, out[peer_id_prefix.len..], .{});
    return out;
}

/// PeerID.String(): "sha-" + base64 of the hash; needs a 48-byte buffer.
pub fn formatPeerID(buf: *[48]u8, id: PeerID) []const u8 {
    @memcpy(buf[0..peer_id_prefix.len], peer_id_prefix);
    const enc = std.base64.standard.Encoder;
    _ = enc.encode(buf[peer_id_prefix.len..], id[peer_id_prefix.len..]);
    return buf;
}

// Auth message layout (message.go): header + magic + peerID + payload.
pub const size_of_magic_byte = 4;
pub const header_size_auth = size_of_magic_byte + peer_id_size;
pub const offset_magic_byte = size_of_proto_header;
pub const offset_auth_peer_id = size_of_proto_header + size_of_magic_byte;
pub const header_total_size_auth = size_of_proto_header + header_size_auth;
/// Go MaxHandshakeSize caps the whole auth message.
pub const max_auth_payload_size = max_handshake_size - header_total_size_auth;

pub const AuthMsg = struct {
    peer_id: PeerID,
    payload: []const u8,
};

pub fn marshalAuthMsg(buf: []u8, peer_id: PeerID, auth_payload: []const u8) Error![]u8 {
    const total = header_total_size_auth + auth_payload.len;
    if (total > max_handshake_size) return Error.AuthPayloadTooLarge;
    if (buf.len < total) return Error.BufferTooSmall;
    buf[0] = current_protocol_version;
    buf[1] = @intFromEnum(MsgType.auth);
    @memcpy(buf[size_of_proto_header..][0..magic_header.len], &magic_header);
    @memcpy(buf[offset_auth_peer_id..][0..peer_id_size], &peer_id);
    @memcpy(buf[header_total_size_auth..total], auth_payload);
    return buf[0..total];
}

pub fn unmarshalAuthMsg(msg: []const u8) Error!AuthMsg {
    if (msg.len < header_total_size_auth) return Error.InvalidMessageLength;
    if (!std.mem.eql(u8, msg[offset_magic_byte..][0..size_of_magic_byte], &magic_header)) {
        return Error.InvalidMagicHeader;
    }
    var peer_id: PeerID = undefined;
    @memcpy(&peer_id, msg[offset_auth_peer_id..header_total_size_auth]);
    return .{ .peer_id = peer_id, .payload = msg[header_total_size_auth..] };
}

pub fn marshalAuthResponse(buf: []u8, address: []const u8) Error![]u8 {
    const total = size_of_proto_header + address.len;
    if (total > max_handshake_resp_size) return Error.AuthResponseTooLarge;
    if (buf.len < total) return Error.BufferTooSmall;
    buf[0] = current_protocol_version;
    buf[1] = @intFromEnum(MsgType.auth_response);
    @memcpy(buf[size_of_proto_header..total], address);
    return buf[0..total];
}

/// Go requires len(msg) >= sizeOfProtoHeader+1, so an empty address is invalid.
pub fn unmarshalAuthResponse(msg: []const u8) Error![]const u8 {
    if (msg.len < size_of_proto_header + 1) return Error.InvalidMessageLength;
    return msg[size_of_proto_header..];
}

pub fn marshalCloseMsg() [2]u8 {
    return .{ current_protocol_version, @intFromEnum(MsgType.close) };
}

pub fn marshalHealthcheck() [2]u8 {
    return .{ current_protocol_version, @intFromEnum(MsgType.health_check) };
}

// Transport message layout: header + peerID + payload.
pub const header_size_transport = peer_id_size;
pub const offset_transport_id = size_of_proto_header;
pub const header_total_size_transport = size_of_proto_header + header_size_transport;

pub const TransportMsg = struct {
    peer_id: PeerID,
    payload: []const u8,
};

/// Go has no size validation here yet ("todo validate size"); MTU enforcement
/// lives above the codec.
pub fn marshalTransportMsg(buf: []u8, peer_id: PeerID, payload: []const u8) Error![]u8 {
    const total = header_total_size_transport + payload.len;
    if (buf.len < total) return Error.BufferTooSmall;
    buf[0] = current_protocol_version;
    buf[1] = @intFromEnum(MsgType.transport);
    @memcpy(buf[offset_transport_id..][0..peer_id_size], &peer_id);
    @memcpy(buf[header_total_size_transport..total], payload);
    return buf[0..total];
}

pub fn unmarshalTransportMsg(buf: []const u8) Error!TransportMsg {
    if (buf.len < header_total_size_transport) return Error.InvalidMessageLength;
    var peer_id: PeerID = undefined;
    @memcpy(&peer_id, buf[offset_transport_id..header_total_size_transport]);
    return .{ .peer_id = peer_id, .payload = buf[header_total_size_transport..] };
}

pub fn unmarshalTransportID(buf: []const u8) Error!PeerID {
    if (buf.len < header_total_size_transport) return Error.InvalidMessageLength;
    var id: PeerID = undefined;
    @memcpy(&id, buf[offset_transport_id..header_total_size_transport]);
    return id;
}

pub fn updateTransportMsg(msg: []u8, peer_id: PeerID) Error!void {
    if (msg.len < offset_transport_id + peer_id_size) return Error.InvalidMessageLength;
    @memcpy(msg[offset_transport_id..][0..peer_id_size], &peer_id);
}

// Peer state messages (peer_state.go): header + N*peerID.
/// Go maxPeersPerMessage = (MaxMessageSize - sizeOfProtoHeader) / peerIDSize.
pub const max_peers_per_message = (max_message_size - size_of_proto_header) / peer_id_size;

/// Marshals ONE peer-state message (up to max_peers_per_message ids). Callers
/// chunk id lists like Go's marshalPeerIDs does.
pub fn marshalPeerIDs(buf: []u8, ids: []const PeerID, msg_type: MsgType) Error![]u8 {
    if (ids.len == 0) return Error.NoPeerIDs;
    if (ids.len > max_peers_per_message) return Error.InvalidPeerListSize;
    const total = size_of_proto_header + ids.len * peer_id_size;
    if (buf.len < total) return Error.BufferTooSmall;
    buf[0] = current_protocol_version;
    buf[1] = @intFromEnum(msg_type);
    var offset: usize = size_of_proto_header;
    for (ids) |id| {
        @memcpy(buf[offset..][0..peer_id_size], &id);
        offset += peer_id_size;
    }
    return buf[0..total];
}

pub fn unmarshalPeerIDs(buf: []const u8, out: []PeerID) Error!usize {
    if (buf.len < size_of_proto_header) return Error.InvalidMessageLength;
    const rest = buf.len - size_of_proto_header;
    if (rest % peer_id_size != 0) return Error.InvalidPeerListSize;
    const num_ids = rest / peer_id_size;
    if (out.len < num_ids) return Error.BufferTooSmall;
    var offset: usize = size_of_proto_header;
    for (out[0..num_ids]) |*id| {
        @memcpy(id, buf[offset..][0..peer_id_size]);
        offset += peer_id_size;
    }
    return num_ids;
}

/// Go ValidateVersion: returns the protocol version of the message.
pub fn validateVersion(msg: []const u8) Error!u8 {
    if (msg.len < size_of_proto_header) return Error.InvalidMessageLength;
    const version = msg[0];
    if (version != current_protocol_version) return Error.UnsupportedVersion;
    return version;
}

pub fn determineClientMessageType(msg: []const u8) Error!MsgType {
    if (msg.len < size_of_proto_header) return Error.InvalidMessageLength;
    const msg_type: MsgType = @enumFromInt(msg[1]);
    return switch (msg_type) {
        .auth, .transport, .close, .health_check, .subscribe_peer_state, .unsubscribe_peer_state => msg_type,
        else => Error.InvalidMessageType,
    };
}

pub fn determineServerMessageType(msg: []const u8) Error!MsgType {
    if (msg.len < size_of_proto_header) return Error.InvalidMessageLength;
    const msg_type: MsgType = @enumFromInt(msg[1]);
    return switch (msg_type) {
        .auth_response, .transport, .close, .health_check, .peers_online, .peers_went_offline => msg_type,
        else => Error.InvalidMessageType,
    };
}

test {
    _ = @import("messages_test.zig");
}
