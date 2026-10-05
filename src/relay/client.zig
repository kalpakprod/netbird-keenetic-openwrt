// Port of netbird shared/relay/client (v0.79.0), BSD-3-Clause.
// The client is transport-agnostic like upstream: it works on anything with
// the conn surface of the WebSocket dialer (writeMessage/readMessage), so the
// dialer lives with the caller (src/net/ws). One writer per message like
// upstream's writeMsg; the read side drives state via waitPeerOnline/recv.

const std = @import("std");
const Allocator = std.mem.Allocator;
const msgs = @import("messages.zig");

// Re-exported so callers (the live helper) reach token generation and peer
// hashing through this module.
pub const messages = msgs;
pub const auth = @import("auth.zig");

pub const Error = error{
    Timeout,
    DeadlineUnsupported,
    HandshakeFailed,
    UnexpectedMessage,
    PeerNotOnline,
    ConnectionClosed,
    /// Transport-level failures (the conn surface of the websocket dialer).
    ReadFailed,
    EndOfStream,
    WriteFailed,
    ProtocolError,
    MessageTooBig,
    CloseReceived,
    BadAcceptKey,
} || msgs.Error || Allocator.Error;

/// The client over a concrete connection type. The conn must provide:
///   writeMessage(.binary, payload) — one binary frame per call
///   readMessage(buf) -> Message{ .data }
pub fn Client(comptime Conn: type) type {
    return struct {
        gpa: Allocator,
        conn: Conn,
        own_id: msgs.PeerID,
        wbuf: []u8,

        const Self = @This();

        /// Performs the auth handshake on an already-connected websocket:
        /// sends Auth and consumes the AuthResponse (client.go handShake).
        pub fn connect(gpa: Allocator, conn: Conn, opts: AuthOptions) Error!*Self {
            errdefer conn.destroy();

            const c = try gpa.create(Self);
            errdefer gpa.destroy(c);
            c.* = .{
                .gpa = gpa,
                .conn = conn,
                .own_id = msgs.hashID(opts.peer_id),
                .wbuf = undefined,
            };
            c.wbuf = try gpa.alloc(u8, msgs.max_message_size);
            errdefer gpa.free(c.wbuf);

            const msg = try msgs.marshalAuthMsg(c.wbuf, c.own_id, opts.token);
            try c.conn.writeMessage(.binary, msg);
            try c.expectAuthResponse(opts.deadline_ms);
            return c;
        }

        pub fn destroy(c: *Self) void {
            c.conn.close(.normal);
            c.conn.destroy();
            c.gpa.free(c.wbuf);
            c.gpa.destroy(c);
        }

        fn expectAuthResponse(c: *Self, deadline_ms: ?i64) Error!void {
            var rbuf: [msgs.max_handshake_resp_size]u8 = undefined;
            const msg = try c.readMessage(&rbuf, deadline_ms);
            _ = try msgs.validateVersion(msg.data);
            const t = try msgs.determineServerMessageType(msg.data);
            if (t != .auth_response) return Error.UnexpectedMessage;
            _ = try msgs.unmarshalAuthResponse(msg.data);
        }

        /// Subscribes to the peer's state; the server answers with PeersOnline
        /// once the peer is connected (immediately if it already is).
        pub fn subscribe(c: *Self, dst: msgs.PeerID) Error!void {
            const msg = try msgs.marshalPeerIDs(c.wbuf, &.{dst}, .subscribe_peer_state);
            try c.conn.writeMessage(.binary, msg);
        }

        /// Reads until a PeersOnline message lists `dst`; replies to health
        /// checks on the way.
        pub fn waitPeerOnline(c: *Self, dst: msgs.PeerID) Error!void {
            return c.waitPeerOnlineDeadline(dst, null);
        }

        pub fn waitPeerOnlineDeadline(c: *Self, dst: msgs.PeerID, deadline_ms: ?i64) Error!void {
            var rbuf: [msgs.max_message_size]u8 = undefined;
            var peers: [msgs.max_peers_per_message]msgs.PeerID = undefined;
            while (true) {
                const msg = try c.readMessage(&rbuf, deadline_ms);
                _ = try msgs.validateVersion(msg.data);
                const t = try msgs.determineServerMessageType(msg.data);
                switch (t) {
                    .peers_online => {
                        const n = try msgs.unmarshalPeerIDs(msg.data, peers[0..]);
                        for (peers[0..n]) |p| {
                            if (std.mem.eql(u8, &p, &dst)) return;
                        }
                    },
                    .health_check => try c.writeHealthcheck(),
                    .close => return Error.ConnectionClosed,
                    else => {},
                }
            }
        }

        /// Sends a payload to the peer (the server stamps the sender id).
        pub fn sendTo(c: *Self, dst: msgs.PeerID, payload: []const u8) Error!void {
            const msg = try msgs.marshalTransportMsg(c.wbuf, dst, payload);
            try c.conn.writeMessage(.binary, msg);
        }

        /// Reads the next transport message from any peer, replying to health
        /// checks and skipping state messages.
        pub fn recv(c: *Self, out: []u8) Error!msgs.TransportMsg {
            return c.recvDeadline(out, null);
        }

        pub fn recvDeadline(c: *Self, out: []u8, deadline_ms: ?i64) Error!msgs.TransportMsg {
            var rbuf: [msgs.max_message_size]u8 = undefined;
            while (true) {
                const msg = try c.readMessage(&rbuf, deadline_ms);
                _ = try msgs.validateVersion(msg.data);
                const t = try msgs.determineServerMessageType(msg.data);
                switch (t) {
                    .transport => {
                        var tm = try msgs.unmarshalTransportMsg(msg.data);
                        if (tm.payload.len > out.len) return msgs.Error.BufferTooSmall;
                        @memcpy(out[0..tm.payload.len], tm.payload);
                        tm.payload = out[0..tm.payload.len];
                        return tm;
                    },
                    .health_check => try c.writeHealthcheck(),
                    .close => return Error.ConnectionClosed,
                    else => {},
                }
            }
        }

        // Absolute monotonic milliseconds in the transport's clock domain.
        // readMessageDeadline must bound the entire message read, including
        // partial frames. Timeout preserves framing and leaves the stream usable.
        // A transport unable to preserve framing must close itself on timeout.
        fn readMessage(c: *Self, out: []u8, deadline_ms: ?i64) Error!struct { data: []const u8 } {
            if (deadline_ms) |deadline| {
                const T = switch (@typeInfo(Conn)) { .pointer => |p| p.child, else => Conn };
                if (@hasDecl(T, "readMessageDeadline")) {
                    const msg = try c.conn.readMessageDeadline(out, deadline);
                    return .{ .data = msg.data };
                }
                return error.DeadlineUnsupported;
            }
            const msg = try c.conn.readMessage(out);
            return .{ .data = msg.data };
        }

        fn writeHealthcheck(c: *Self) Error!void {
            try c.conn.writeMessage(.binary, &msgs.marshalHealthcheck());
        }
    };
}

pub const AuthOptions = struct {
    /// Raw peer identity; hashed to the PeerID the protocol carries.
    peer_id: []const u8,
    /// Optional absolute monotonic deadline, enforced by readMessageDeadline.
    /// Ownership transfers even on failure. Auth timeout destroys the transport.
    deadline_ms: ?i64 = null,
    /// Token binary from auth.generateToken, keyed with sha256(secret).
    token: []const u8,
};

test "client: module compiles" {
    try std.testing.expect(true);
}

test {
    _ = auth;
    std.testing.refAllDecls(@This());
}
