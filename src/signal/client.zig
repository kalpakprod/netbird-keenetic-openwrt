// Port of netbird shared/signal/client/grpc.go (v0.79.0), BSD-3-Clause.
// SignalExchange client: unary Send and bidi ConnectStream, both with
// NaCl-boxed bodies (peer-to-peer keys, the server only routes opaque
// messages). Covers only what step 4 needs: no retry loop, no conn-state
// listeners, no idle watchdog (engine layers add those).

const std = @import("std");
const h2 = @import("../net/h2/conn.zig");
const grpc = @import("../net/grpc/client.zig");
const messages = @import("messages.zig");
const wgbox = @import("../mgmt/wgbox.zig");

pub const Error = grpc.Error || messages.Error || wgbox.Error || error{ SignalStatus, SignalNotRegistered };

pub const header_id = "x-wiretrustee-peer-id";
pub const header_registered = "x-wiretrustee-peer-registered";

/// Upstream send timeout (client.ConnectTimeout); ConnectStream has none.
pub const send_timeout_ns: i64 = 10 * std.time.ns_per_s;

pub const Client = struct {
    conn: *h2.Conn,
    alloc: std.mem.Allocator,
    authority: []const u8,
    io: std.Io,
    key: wgbox.Key,
    last_status_code: u32 = 0,
    last_status_msg: std.ArrayList(u8) = .empty,

    pub fn deinit(c: *Client) void {
        c.last_status_msg.deinit(c.alloc);
    }

    fn setStatus(c: *Client, code: u32, msg: []const u8) Error!void {
        c.last_status_code = code;
        c.last_status_msg.clearRetainingCapacity();
        try c.last_status_msg.appendSlice(c.alloc, msg);
    }

    fn myPubStr(c: *Client) Error![]u8 {
        return try wgbox.allocString(c.alloc, wgbox.publicKey(c.key));
    }

    /// Box a local Message into an EncryptedMessage (remote = recipient).
    fn encryptMessage(c: *Client, msg: *const messages.Message) Error![]u8 {
        const remote = try wgbox.parseKey(msg.remote_key);
        const plain = try msg.body.encode(c.alloc);
        defer c.alloc.free(plain);
        const enc_body = try wgbox.encrypt(c.alloc, plain, remote, c.key, c.io);
        defer c.alloc.free(enc_body);
        const my_pub = try c.myPubStr();
        defer c.alloc.free(my_pub);
        const env = messages.EncryptedMessage{
            .key = my_pub,
            .remote_key = msg.remote_key,
            .body = enc_body,
        };
        return try env.encode(c.alloc);
    }

    /// Unbox an EncryptedMessage into a local Message (remote = sender).
    fn decryptMessage(c: *Client, env_bytes: []const u8) Error!messages.Message {
        var env = try messages.EncryptedMessage.decode(c.alloc, env_bytes);
        defer env.deinit(c.alloc);
        const remote = try wgbox.parseKey(env.key);
        const dec = try wgbox.decrypt(c.alloc, env.body, remote, c.key);
        defer c.alloc.free(dec);
        var body = try messages.Body.decode(c.alloc, dec);
        errdefer body.deinit(c.alloc);
        const key = try c.alloc.dupe(u8, env.key);
        errdefer c.alloc.free(key);
        return .{
            .key = key,
            .remote_key = try c.alloc.dupe(u8, env.remote_key),
            .body = body,
            .owned = true,
        };
    }

    /// Send: unary RPC; the server routes to the peer's stream and replies
    /// with an empty message (upstream discards the response too).
    pub fn send(c: *Client, msg: *const messages.Message) Error!void {
        try c.setStatus(0, "");
        const body = try c.encryptMessage(msg);
        defer c.alloc.free(body);
        var res = try grpc.unary(
            c.conn,
            c.alloc,
            "/signalexchange.SignalExchange/Send",
            c.authority,
            send_timeout_ns,
            body,
            c.io,
        );
        defer res.deinit(c.alloc);
        if (res.status != 0) {
            try c.setStatus(res.status, res.message);
            return Error.SignalStatus;
        }
    }

    /// ConnectStream: open the bidi stream, registering our key in the
    /// request headers. Fails fast unless the server answers registered.
    pub fn connectStream(c: *Client) Error!Stream {
        try c.setStatus(0, "");
        const my_pub = try c.myPubStr();
        defer c.alloc.free(my_pub);
        var call = try grpc.startCallWithHeaders(
            c.conn,
            c.alloc,
            "/signalexchange.SignalExchange/ConnectStream",
            c.authority,
            null,
            c.io,
            &.{.{ .name = header_id, .value = my_pub }},
        );
        errdefer call.deinit();
        try grpc.awaitHeaders(&call);
        if (call.done) {
            const code = call.status() orelse 0;
            if (code != 0) {
                try c.setStatus(code, call.statusMessage());
                return Error.SignalStatus;
            }
            return Error.SignalNotRegistered;
        }
        if (call.responseHeader(header_registered) == null) {
            return Error.SignalNotRegistered;
        }
        return .{
            .call = call,
            .alloc = c.alloc,
            .parent = c,
        };
    }
};

/// One ConnectStream bidi stream.
pub const Stream = struct {
    call: grpc.Call,
    alloc: std.mem.Allocator,
    parent: *Client,

    pub fn deinit(s: *Stream) void {
        s.call.deinit();
    }

    pub fn registered(s: *const Stream) bool {
        return s.call.responseHeader(header_registered) != null;
    }

    /// Send one message to the peer through our stream (mirrors upstream
    /// SendToStream; the server never reads stream messages, so use unary
    /// Send for actual delivery).
    pub fn send(s: *Stream, msg: *const messages.Message) Error!void {
        const body = try s.parent.encryptMessage(msg);
        defer s.alloc.free(body);
        try grpc.sendMessage(&s.call, body, false);
    }

    /// Receive the next routed message, or null at server close.
    pub fn recv(s: *Stream) Error!?messages.Message {
        const bytes = try grpc.recvMessage(&s.call) orelse {
            const code = s.call.status() orelse 0;
            if (code != 0) {
                try s.parent.setStatus(code, s.call.statusMessage());
                return Error.SignalStatus;
            }
            return null;
        };
        return try s.parent.decryptMessage(bytes);
    }
};
