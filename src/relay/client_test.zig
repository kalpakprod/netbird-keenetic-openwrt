// Relay client tests. Unit tests drive the client over an in-memory fake
// conn with hand-rolled websocket frames. The live orchestration (upstream
// relay server, two clients, the Go client helper) lives in
// ~/.cache/netbird-zig-context/gen/relay_live.zig — the build system roots
// each test suite in its own directory, so a cross-directory live test cannot
// import src/net/ws from here.

const std = @import("std");
const testing = std.testing;
const msgs = @import("messages.zig");
const auth = @import("auth.zig");
const client = @import("client.zig");

/// Encodes one server-side (unmasked) websocket frame, mirroring what a real
/// server sends.
fn serverFrame(out: []u8, fin: bool, opcode_u4: u4, payload: []const u8) []u8 {
    var i: usize = 0;
    out[i] = (if (fin) @as(u8, 0x80) else 0) | opcode_u4;
    i += 1;
    if (payload.len < 126) {
        out[i] = @intCast(payload.len);
        i += 1;
    } else if (payload.len <= 0xffff) {
        out[i] = 126;
        std.mem.writeInt(u16, out[i + 1 ..][0..2], @intCast(payload.len), .big);
        i += 3;
    } else {
        out[i] = 127;
        std.mem.writeInt(u64, out[i + 1 ..][0..8], @intCast(payload.len), .big);
        i += 9;
    }
    @memcpy(out[i..][0..payload.len], payload);
    return out[0 .. i + payload.len];
}

const Opcode = struct {
    const binary: u4 = 0x2;
    const ping: u4 = 0x9;
};

/// In-memory conn: the "server" stream is preloaded bytes; client writes are
/// collected. Implements the readMessage/writeMessage surface of ws.Conn.
const FakeConn = struct {
    gpa: std.mem.Allocator,
    server_stream: std.Io.Reader,
    server_buf: [8192]u8 = undefined,
    written: std.ArrayListUnmanaged(u8) = .empty,
    // ws.Conn surface bits the client calls
    destroyed: bool = false,

    fn initInPlace(c: *FakeConn, gpa: std.mem.Allocator, server_frames: []const u8) void {
        c.* = .{ .gpa = gpa, .server_stream = undefined };
        c.server_stream = .fixed(&c.server_buf);
        @memcpy(c.server_buf[0..server_frames.len], server_frames);
        c.server_stream.end = server_frames.len;
    }

    fn deinit(c: *FakeConn) void {
        c.written.deinit(c.gpa);
    }

    // --- ws.Conn-compatible surface (values; client uses c.conn.* where
    // conn is a *ws.Conn, so pass &fake here) ---
    pub fn writeMessage(c: *FakeConn, opcode: anytype, payload: []const u8) !void {
        _ = opcode;
        try c.written.appendSlice(c.gpa, payload);
    }

    pub fn readMessage(c: *FakeConn, out: []u8) !struct { data: []const u8 } {
        // decode one frame from server_stream
        const hdr = try c.server_stream.takeArray(2);
        const fin = hdr[0] & 0x80 != 0;
        _ = fin;
        const len7: u8 = hdr[1] & 0x7f;
        var len: usize = len7;
        switch (len7) {
            126 => {
                const ext = try c.server_stream.takeArray(2);
                len = std.mem.readInt(u16, ext, .big);
            },
            127 => {
                const ext = try c.server_stream.takeArray(8);
                len = @intCast(std.mem.readInt(u64, ext, .big));
            },
            else => {},
        }
        try c.server_stream.readSliceAll(out[0..len]);
        return .{ .data = out[0..len] };
    }

    pub fn close(c: *FakeConn, code: anytype) void {
        _ = c;
        _ = code;
    }

    pub fn destroy(c: *FakeConn) void {
        c.destroyed = true;
    }
};

const FakeClient = client.Client(*FakeConn);

fn authResponseFrame(buf: []u8, address: []const u8) []u8 {
    var body: [msgs.max_handshake_resp_size]u8 = undefined;
    const resp = msgs.marshalAuthResponse(&body, address) catch unreachable;
    return serverFrame(buf, true, Opcode.binary, resp);
}

test "client: auth handshake sends auth msg and consumes authresponse" {
    const gpa = testing.allocator;
    var frame_buf: [9000]u8 = undefined;
    const resp_frame = authResponseFrame(&frame_buf, "rel://127.0.0.1:33073");

    var fake: FakeConn = undefined;
    fake.initInPlace(gpa, resp_frame);
    defer fake.deinit();

    var token_buf: [auth.max_token_size]u8 = undefined;
    const token = try auth.generateToken("secret", 3600, 1_700_000_000, &token_buf);

    const c = try FakeClient.connect(gpa, &fake, .{ .peer_id = "peer-one", .token = token });
    defer c.destroy();

    // The client must have written exactly the auth message.
    const sent = fake.written.items;
    _ = try msgs.validateVersion(sent);
    const t = try msgs.determineClientMessageType(sent);
    try testing.expectEqual(.auth, t);
    const am = try msgs.unmarshalAuthMsg(sent);
    try testing.expectEqual(msgs.hashID("peer-one"), am.peer_id);
    try testing.expectEqualSlices(u8, token, am.payload);
}

test "client: subscribe, wait online, transport both ways, healthcheck" {
    const gpa = testing.allocator;
    var fbs_buf: [9000]u8 = undefined;
    var fbs = std.Io.Writer.fixed(&fbs_buf);

    const id2 = msgs.hashID("peer-two");
    // server script: authresp, peers_online(peer-two), transport from peer-two,
    // healthcheck, transport from peer-two
    var body: [9000]u8 = undefined;
    _ = try fbs.write(authResponseFrame(&body, "rel://127.0.0.1:1"));
    var ids_buf: [msgs.max_message_size]u8 = undefined;
    const online = try msgs.marshalPeerIDs(&ids_buf, &.{id2}, .peers_online);
    var f2: [9000]u8 = undefined;
    _ = try fbs.write(serverFrame(&f2, true, Opcode.binary, online));
    const transport = try msgs.marshalTransportMsg(&ids_buf, msgs.hashID("peer-one"), "from-peer-two");
    var f3: [9000]u8 = undefined;
    _ = try fbs.write(serverFrame(&f3, true, Opcode.binary, transport));
    var f4: [9000]u8 = undefined;
    _ = try fbs.write(serverFrame(&f4, true, Opcode.binary, &msgs.marshalHealthcheck()));
    var f5: [9000]u8 = undefined;
    _ = try fbs.write(serverFrame(&f5, true, Opcode.binary, transport));

    var fake: FakeConn = undefined;
    fake.initInPlace(gpa, fbs.buffered());
    defer fake.deinit();

    var token_buf: [auth.max_token_size]u8 = undefined;
    const token = try auth.generateToken("secret", 3600, 1_700_000_000, &token_buf);

    const c = try FakeClient.connect(gpa, &fake, .{ .peer_id = "peer-one", .token = token });
    defer c.destroy();
    fake.written.clearRetainingCapacity(); // drop the auth msg

    try c.subscribe(id2);
    const sub = fake.written.items;
    try testing.expectEqual(.subscribe_peer_state, try msgs.determineClientMessageType(sub));
    var ids_out: [msgs.max_peers_per_message]msgs.PeerID = undefined;
    const n = try msgs.unmarshalPeerIDs(sub, ids_out[0..]);
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expectEqual(id2, ids_out[0]);
    fake.written.clearRetainingCapacity();

    try c.waitPeerOnline(id2);

    var out: [128]u8 = undefined;
    const got = try c.recv(&out);
    try testing.expectEqualStrings("from-peer-two", got.payload);
    try testing.expectEqual(msgs.hashID("peer-one"), got.peer_id);

    fake.written.clearRetainingCapacity();

    // second recv processes the healthcheck frame, then the second transport
    const got2 = try c.recv(&out);
    try testing.expectEqualStrings("from-peer-two", got2.payload);

    // the healthcheck must have been answered with the 2-byte reply
    try testing.expectEqualSlices(u8, &msgs.marshalHealthcheck(), fake.written.items);

    fake.written.clearRetainingCapacity();
    try c.sendTo(id2, "to-peer-two");
    const tm = try msgs.unmarshalTransportMsg(fake.written.items);
    try testing.expectEqualStrings("to-peer-two", tm.payload);
    try testing.expectEqual(id2, tm.peer_id);
}
