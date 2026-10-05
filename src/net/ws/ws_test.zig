// RFC 6455 client — tests.
// Pure-Zig frame tests use in-memory reader/writer pairs; the live interop
// (echo, fragmentation from the server, ping, TLS) runs against a Go server
// built from the vendored coder/websocket (the one the relay uses).

const std = @import("std");
const ws = @import("ws.zig");

const tio = std.testing.io;

// Builds frames the way an RFC 6455 server would send them. Server frames
// are unmasked; set masked_client=true to synthesize client-side frames.
fn serverFrame(out: []u8, fin: bool, opcode: ws.Opcode, payload: []const u8) []u8 {
    var i: usize = 0;
    out[i] = (if (fin) @as(u8, 0x80) else 0) | @backingInt(opcode);
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

fn makeConn(gpa: std.mem.Allocator, input: *std.Io.Reader, output: *std.Io.Writer) !*ws.Conn {
    const c = try gpa.create(ws.Conn);
    const scratch = try gpa.alloc(u8, 4096);
    c.* = .{
        .io = tio,
        .gpa = gpa,
        .input = input,
        .output = output,
        .send = output,
        .net = null,
        .scratch = scratch,
    };
    return c;
}

fn dropConn(c: *ws.Conn) void {
    const gpa = std.testing.allocator;
    gpa.free(c.scratch);
    gpa.destroy(c);
}

const TestConn = struct {
    c: *ws.Conn,
    out: std.Io.Writer.Allocating,
    reader: std.Io.Reader,
    in: []u8,

    fn init(t: *TestConn, server_bytes: []const u8) !void {
        const gpa = std.testing.allocator;
        t.* = .{
            .c = undefined,
            .out = try std.Io.Writer.Allocating.initCapacity(gpa, 4096),
            .reader = undefined,
            .in = try gpa.dupe(u8, server_bytes),
        };
        t.reader = std.Io.Reader.fixed(t.in);
        t.c = try makeConn(gpa, &t.reader, &t.out.writer);
    }
    fn deinit(t: *TestConn) void {
        t.out.deinit();
        dropConn(t.c);
        std.testing.allocator.free(t.in);
    }
};

test "single binary frame" {
    var raw: [64]u8 = undefined;
    const frame = serverFrame(&raw, true, .binary, "hello");
    var t: TestConn = undefined;
    try t.init(frame);
    defer t.deinit();

    var buf: [100]u8 = undefined;
    const msg = try t.c.readMessage(&buf);
    try std.testing.expectEqual(ws.Opcode.binary, msg.opcode);
    try std.testing.expectEqualStrings("hello", msg.data);
    try std.testing.expectEqual(@as(usize, 0), t.out.written().len);
}

test "16-bit frame length" {
    var payload: [300]u8 = @splat('x');
    payload[42] = '!';
    var raw: [400]u8 = undefined;
    const frame = serverFrame(&raw, true, .binary, &payload);
    var t: TestConn = undefined;
    try t.init(frame);
    defer t.deinit();

    var buf: [1000]u8 = undefined;
    const msg = try t.c.readMessage(&buf);
    try std.testing.expectEqual(@as(usize, 300), msg.data.len);
    try std.testing.expectEqual(@as(u8, '!'), msg.data[42]);
}

test "fragmented message with interleaved ping" {
    var f1: [16]u8 = undefined;
    var f2: [16]u8 = undefined;
    var f3: [16]u8 = undefined;
    var fping: [16]u8 = undefined;
    var stream_buf: [128]u8 = undefined;
    var off: usize = 0;
    const parts = [_][]u8{
        serverFrame(&f1, false, .binary, "aa"),
        serverFrame(&fping, true, .ping, "whop"),
        serverFrame(&f2, false, .continuation, "bb"),
        serverFrame(&f3, true, .continuation, "cc"),
    };
    for (parts) |part| {
        @memcpy(stream_buf[off..][0..part.len], part);
        off += part.len;
    }
    var t: TestConn = undefined;
    try t.init(stream_buf[0..off]);
    defer t.deinit();

    var buf: [100]u8 = undefined;
    const msg = try t.c.readMessage(&buf);
    try std.testing.expectEqual(ws.Opcode.binary, msg.opcode);
    try std.testing.expectEqualStrings("aabbcc", msg.data);
    // the ping got answered with a masked pong carrying the same payload
    const written = t.out.written();
    try std.testing.expectEqual(@as(u8, 0x8a), written[0]); // fin + pong
    try std.testing.expectEqual(@as(u8, 0x80 | 4), written[1]);
    const mask = written[2..6];
    var pong_payload: [4]u8 = undefined;
    @memcpy(&pong_payload, written[6..10]);
    for (&pong_payload, 0..) |*b, i| b.* ^= mask[i % 4];
    try std.testing.expectEqualStrings("whop", &pong_payload);
}

test "close frame is echoed and reported" {
    var raw: [4]u8 = undefined;
    raw[0] = @as(u8, 0x80) | @as(u8, @backingInt(ws.Opcode.close));
    raw[1] = 2;
    std.mem.writeInt(u16, raw[2..4], 1000, .big);
    var t: TestConn = undefined;
    try t.init(&raw);
    defer t.deinit();

    var buf: [100]u8 = undefined;
    try std.testing.expectError(ws.Error.CloseReceived, t.c.readMessage(&buf));
    const written = t.out.written();
    try std.testing.expectEqual(@as(u8, 0x88), written[0]);
    try std.testing.expectEqual(@as(u8, 0x80 | 2), written[1]);
    const mask = written[2..6];
    var echoed: [2]u8 = undefined;
    @memcpy(&echoed, written[6..8]);
    for (&echoed, 0..) |*b, i| b.* ^= mask[i % 4];
    try std.testing.expectEqual(@as(u16, 1000), std.mem.readInt(u16, &echoed, .big));
}

test "server mask and reserved bits are rejected" {
    var raw: [4]u8 = undefined;
    raw[0] = @as(u8, 0x80) | @as(u8, @backingInt(ws.Opcode.binary));
    raw[1] = 0x80; // masked server frame
    var t1: TestConn = undefined;
    try t1.init(&raw);
    defer t1.deinit();
    var buf: [100]u8 = undefined;
    try std.testing.expectError(ws.Error.ProtocolError, t1.c.readMessage(&buf));

    var raw2: [2]u8 = undefined;
    raw2[0] = @as(u8, 0x40 | 0x80) | @as(u8, @backingInt(ws.Opcode.binary)); // rsv1 set // rsv1 set
    raw2[1] = 0;
    var t2: TestConn = undefined;
    try t2.init(&raw2);
    defer t2.deinit();
    try std.testing.expectError(ws.Error.ProtocolError, t2.c.readMessage(&buf));
}

test "message too big" {
    var raw: [4]u8 = undefined;
    raw[0] = @as(u8, 0x80) | @as(u8, @backingInt(ws.Opcode.binary));
    raw[1] = 126;
    std.mem.writeInt(u16, raw[2..4], 200, .big); // payload never needed: size check first
    var t: TestConn = undefined;
    try t.init(&raw);
    defer t.deinit();
    var buf: [100]u8 = undefined;
    try std.testing.expectError(ws.Error.MessageTooBig, t.c.readMessage(&buf));
}

test "continuation without start is rejected" {
    var raw: [8]u8 = undefined;
    _ = serverFrame(&raw, true, .continuation, "orphan");
    var t: TestConn = undefined;
    try t.init(&raw);
    defer t.deinit();
    var buf: [100]u8 = undefined;
    try std.testing.expectError(ws.Error.ProtocolError, t.c.readMessage(&buf));
}

test "client writes masked binary frames" {
    const gpa = std.testing.allocator;
    var out = try std.Io.Writer.Allocating.initCapacity(gpa, 4096);
    defer out.deinit();
    var in = std.Io.Reader.fixed("");
    const c = try makeConn(gpa, &in, &out.writer);
    defer dropConn(c);

    try c.writeMessage(.binary, "abcdabcdabcdabcdabcdabcdabcdabcdabcd"); // 36 bytes: 7-bit length
    const written = out.written();
    try std.testing.expectEqual(2 + 4 + 36, written.len);
    try std.testing.expectEqual(@as(u8, 0x82), written[0]); // fin + binary
    try std.testing.expectEqual(@as(u8, 0x80 | 36), written[1]);
    try std.testing.expect(!std.mem.eql(u8, "abcdabcdabcdabcdabcdabcdabcdabcdabcd", written[6..]));
    const mask = written[2..6];
    for (written[6..], 0..) |*b, i| b.* ^= mask[i % 4];
    try std.testing.expectEqualStrings("abcdabcdabcdabcdabcdabcdabcdabcdabcd", written[6..]);
}

test "handshake accept key derivation" {
    // RFC 6455 §1.3 example
    const key = "dGhlIHNhbXBsZSBub25jZQ==";
    var sha = std.crypto.hash.Sha1.init(.{});
    sha.update(key);
    sha.update(ws.websocket_guid);
    var accept: [28]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&accept, &sha.finalResult());
    try std.testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", &accept);
}

// ------------------------------------------------- live Go interop tests --
// Run with NB_WS_GO_ECHO=<path to gen/wstest/wstest> [NB_WS_TEST_TLS=<dir with
// localhost.crt+localhost.key>]; without it these tests skip.

const GoServer = struct {
    child: std.process.Child,
    reader: std.Io.File.Reader,
    buf: [4096]u8 = undefined,
    port: u16,

    fn start(s: *GoServer, bin: []const u8, mode: []const u8, tls_dir: ?[]const u8) !void {
        const gpa = std.testing.allocator;
        var argv: std.ArrayListUnmanaged([]const u8) = .empty;
        defer argv.deinit(gpa);
        try argv.append(gpa, bin);
        try argv.append(gpa, "serve");
        try argv.append(gpa, mode);
        var owned: [2][]u8 = .{ &.{}, &.{} };
        var owned_n: usize = 0;
        defer {
            for (owned[0..owned_n]) |a| gpa.free(a);
        }
        if (tls_dir) |dir| {
            owned[0] = try std.fmt.allocPrint(gpa, "{s}/localhost.crt", .{dir});
            owned[1] = try std.fmt.allocPrint(gpa, "{s}/localhost.key", .{dir});
            owned_n = 2;
            try argv.append(gpa, owned[0]);
            try argv.append(gpa, owned[1]);
        }
        try argv.append(gpa, "0");

        const child = try std.process.spawn(tio, .{
            .argv = argv.items,
            .stdin = .pipe,
            .stdout = .pipe,
            .stderr = .inherit,
        });
        s.* = .{ .child = child, .reader = undefined, .port = 0 };
        s.reader = child.stdout.?.readerStreaming(tio, &s.buf);
        const line = (try s.reader.interface.takeDelimiter('\n')) orelse return error.NoReady;
        if (!std.mem.startsWith(u8, line, "READY ")) return error.NoReady;
        s.port = try std.fmt.parseInt(u16, std.mem.trim(u8, line["READY ".len..], " \r"), 10);
    }

    fn stop(s: *GoServer) !void {
        s.child.stdin.?.close(tio);
        s.child.stdin = null;
        const term = try s.child.wait(tio);
        try std.testing.expect(term.success());
    }
};

fn goHelperPath() ![]u8 {
    return (try getenv(std.testing.allocator, "NB_WS_GO_ECHO")) orelse error.SkipZigTest;
}

fn getenv(allocator: std.mem.Allocator, key: []const u8) !?[]u8 {
    var file = std.Io.Dir.openFileAbsolute(tio, "/proc/self/environ", .{ .mode = .read_only }) catch return null;
    defer file.close(tio);
    var buf: [16384]u8 = undefined;
    const n = file.readPositionalAll(tio, &buf, 0) catch return null;
    var rest = buf[0..n];
    while (rest.len > 0) {
        const end = std.mem.indexOfScalar(u8, rest, 0) orelse break;
        const entry = rest[0..end];
        rest = rest[end + 1 ..];
        const eq = std.mem.indexOfScalar(u8, entry, '=') orelse continue;
        if (std.mem.eql(u8, entry[0..eq], key)) return try allocator.dupe(u8, entry[eq + 1 ..]);
    }
    return null;
}

test "live: plain echo against vendored coder/websocket (with server ping)" {
    const bin = try goHelperPath();
    defer std.testing.allocator.free(bin);
    var server: GoServer = undefined;
    try server.start(bin, "plain", null);
    defer server.stop() catch {};

    const conn = try ws.connect(std.testing.allocator, tio, .{ .host = "127.0.0.1", .port = server.port, .path = "/relay" });
    defer conn.destroy();
    // the server pings before echoing; readMessage answers the ping itself
    try conn.writeMessage(.binary, "hello-ws-interop");
    var buf: [4096]u8 = undefined;
    const msg = try conn.readMessage(&buf);
    try std.testing.expectEqualStrings("hello-ws-interop", msg.data);
    conn.close(.normal);
}

test "live: fragmented message from go server" {
    const bin = try goHelperPath();
    defer std.testing.allocator.free(bin);
    var server: GoServer = undefined;
    try server.start(bin, "frag", null);
    defer server.stop() catch {};

    const conn = try ws.connect(std.testing.allocator, tio, .{ .host = "127.0.0.1", .port = server.port, .path = "/relay" });
    defer conn.destroy();
    var buf: [4096]u8 = undefined;
    const msg = try conn.readMessage(&buf);
    try std.testing.expectEqualStrings("frag-mented", msg.data);
    // and a normal echo round trip after it
    try conn.writeMessage(.binary, "zig-echo");
    const echo = try conn.readMessage(&buf);
    try std.testing.expectEqualStrings("zig-echo", echo.data);
    conn.close(.normal);
}

test "live: tls with self-signed ip-san cert" {
    const bin = try goHelperPath();
    defer std.testing.allocator.free(bin);
    const tls_dir = (try getenv(std.testing.allocator, "NB_WS_TEST_TLS")) orelse {
        std.testing.allocator.free(bin);
        return error.SkipZigTest;
    };
    defer std.testing.allocator.free(tls_dir);
    var server: GoServer = undefined;
    try server.start(bin, "tls", tls_dir);
    defer server.stop() catch {};

    const conn = try ws.connect(std.testing.allocator, tio, .{
        .host = "127.0.0.1",
        .port = server.port,
        .path = "/relay",
        .tls = .self_signed,
    });
    defer conn.destroy();
    // bigger than one TLS record to cross record boundaries
    var payload: [9000]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = 'a' + @as(u8, @intCast(i % 26));
    try conn.writeMessage(.binary, &payload);
    var buf: [16384]u8 = undefined;
    const msg = try conn.readMessage(&buf);
    try std.testing.expectEqualSlices(u8, &payload, msg.data);
    conn.close(.normal);
}

test "one-byte close payload is a protocol error" {
    var t: TestConn = undefined;
    try t.init(&.{0x88, 1, 0});
    defer t.deinit();
    var buf: [16]u8 = undefined;
    try std.testing.expectError(ws.Error.ProtocolError, t.c.readMessage(&buf));
    try std.testing.expectEqual(@as(usize, 0), t.out.written().len);
}
