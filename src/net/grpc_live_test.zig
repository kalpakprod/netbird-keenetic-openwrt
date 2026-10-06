// Live gRPC tests against a Go grpc server (gen/grpc_echo).
// Sits at src/net/ (not src/net/grpc/) because build.zig discovery gives
// each suite no named imports: only relative imports work, and only within
// the suite file's own directory. GRPC_HELPER env or
// $HOME/.cache/netbird-zig-context/gen/grpc_echo/grpc_echo; missing helper
// skips. Uses the real h2 conn over plaintext TCP (grpc-go h2c).

const std = @import("std");
const builtin = @import("builtin");
const grpc = @import("grpc/client.zig");
const h2 = @import("h2/conn.zig");

const tio = std.testing.io;

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
        if (std.mem.eql(u8, entry[0..eq], key)) {
            return try allocator.dupe(u8, entry[eq + 1 ..]);
        }
    }
    return null;
}

fn helperPath(allocator: std.mem.Allocator) ![]u8 {
    if (try getenv(allocator, "GRPC_HELPER")) |p| return p;
    const home = (try getenv(allocator, "HOME")) orelse return error.SkipZigTest;
    defer allocator.free(home);
    const def = try std.fmt.allocPrint(allocator, "{s}/.cache/netbird-zig-context/gen/grpc_echo/grpc_echo", .{home});
    errdefer allocator.free(def);
    var f = std.Io.Dir.openFileAbsolute(tio, def, .{ .mode = .read_only }) catch return error.SkipZigTest;
    f.close(tio);
    return def;
}

const Live = struct {
    child: std.process.Child,
    stream: std.Io.net.Stream,
    rdr: std.Io.net.Stream.Reader,
    wtr: std.Io.net.Stream.Writer,
    rx_buf: [16384]u8,
    tx_buf: [16384]u8,
    conn: h2.Conn,
    tctx: Ctx,

    const Ctx = struct {
        reader: *std.Io.Reader,
        writer: *std.Io.Writer,
    };

    fn readFn(ctx: *anyopaque, buf: []u8) h2.Transport.ReadError!usize {
        const c: *Ctx = @ptrCast(@alignCast(ctx));
        c.reader.readSliceAll(buf) catch return error.Closed;
        return buf.len;
    }

    fn writeFn(ctx: *anyopaque, buf: []const u8) h2.Transport.WriteError!void {
        const c: *Ctx = @ptrCast(@alignCast(ctx));
        c.writer.writeAll(buf) catch return error.Closed;
        c.writer.flush() catch return error.Closed;
    }

    fn connect(allocator: std.mem.Allocator, port: u16) !*Live {
        const self = try allocator.create(Live);
        errdefer allocator.destroy(self);
        const helper = try helperPath(allocator);
        defer allocator.free(helper);
        const addr_str = try std.fmt.allocPrint(allocator, "127.0.0.1:{d}", .{port});
        defer allocator.free(addr_str);
        const argv = [_][]const u8{ helper, addr_str };
        // Ignore stdio: an orphaned server must never hold our pipes open.
        self.child = try std.process.spawn(tio, .{
            .argv = &argv,
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .ignore,
        });
        errdefer self.child.kill(tio);
        var addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(port) };
        var i: usize = 0;
        const stream = while (i < 200000) : (i += 1) {
            if (addr.connect(tio, .{ .mode = .stream })) |s| break s else |_| {}
        } else return error.ConnectTimeout;
        self.stream = stream;
        self.rdr = std.Io.net.Stream.Reader.init(stream, tio, &self.rx_buf);
        self.wtr = stream.writer(tio, &self.tx_buf);
        self.tctx = .{ .reader = &self.rdr.interface, .writer = &self.wtr.interface };
        self.conn = h2.Conn.init(.{ .ctx = &self.tctx, .readFn = readFn, .writeFn = writeFn });
        try self.conn.handshake();
        return self;
    }

    fn close(self: *Live, allocator: std.mem.Allocator) void {
        self.stream.close(tio);
        self.child.kill(tio);
        allocator.destroy(self);
    }
};

/// Hand-encode echo.Payload{body}: field 1, wire type 2.
fn encodePayload(allocator: std.mem.Allocator, body: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, 2 + body.len);
    out[0] = 0x0a;
    out[1] = @intCast(body.len);
    @memcpy(out[2..], body);
    return out;
}

/// Hand-decode echo.Payload.body.
fn decodeBody(msg: []const u8) ![]const u8 {
    if (msg.len < 2 or msg[0] != 0x0a) return error.BadPayload;
    const len = msg[1];
    if (msg.len != 2 + len) return error.BadPayload;
    return msg[2..];
}

test "grpc unary echo" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    const live = try Live.connect(alloc, 18562);
    defer live.close(alloc);
    const req = try encodePayload(alloc, "hello");
    defer alloc.free(req);
    var res = try grpc.unary(&live.conn, alloc, "/echo.Echo/Unary", "127.0.0.1:18562", null, req, tio);
    defer res.deinit(alloc);
    try std.testing.expectEqual(@as(u32, 0), res.status);
    try std.testing.expectEqualStrings("echo:hello", try decodeBody(res.body.?));
}

test "grpc server stream collects three" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    const live = try Live.connect(alloc, 18563);
    defer live.close(alloc);
    var c = try grpc.startCall(&live.conn, alloc, "/echo.Echo/ServerStream", "127.0.0.1:18563", null, tio);
    defer c.deinit();
    const req = try encodePayload(alloc, "s");
    defer alloc.free(req);
    try grpc.sendMessage(&c, req, true);
    var bodies: [3][]u8 = undefined;
    var n: usize = 0;
    while (try grpc.recvMessage(&c)) |m| {
        bodies[n] = try alloc.dupe(u8, try decodeBody(m));
        n += 1;
    }
    defer for (bodies[0..n]) |b| alloc.free(b);
    try std.testing.expectEqual(@as(usize, 3), n);
    try std.testing.expectEqualStrings("s0", bodies[0]);
    try std.testing.expectEqualStrings("s1", bodies[1]);
    try std.testing.expectEqualStrings("s2", bodies[2]);
    try std.testing.expectEqual(@as(u32, 0), c.status().?);
}

test "grpc bidi echo interleaved" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    const live = try Live.connect(alloc, 18564);
    defer live.close(alloc);
    var c = try grpc.startCall(&live.conn, alloc, "/echo.Echo/Bidi", "127.0.0.1:18564", null, tio);
    defer c.deinit();
    const ra = try encodePayload(alloc, "a");
    defer alloc.free(ra);
    try grpc.sendMessage(&c, ra, false);
    const ma = try grpc.recvMessage(&c);
    try std.testing.expectEqualStrings("b:a", try decodeBody(ma.?));
    const rb = try encodePayload(alloc, "b");
    defer alloc.free(rb);
    try grpc.sendMessage(&c, rb, false);
    const mb = try grpc.recvMessage(&c);
    try std.testing.expectEqualStrings("b:b", try decodeBody(mb.?));
    try grpc.closeSend(&c);
    try std.testing.expect(try grpc.recvMessage(&c) == null);
    try std.testing.expectEqual(@as(u32, 0), c.status().?);
}

test "grpc error maps status and message" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    const live = try Live.connect(alloc, 18565);
    defer live.close(alloc);
    const req = try encodePayload(alloc, "x");
    defer alloc.free(req);
    var res = try grpc.unary(&live.conn, alloc, "/echo.Echo/Fail", "127.0.0.1:18565", null, req, tio);
    defer res.deinit(alloc);
    try std.testing.expectEqual(@as(u32, 5), res.status); // NotFound
    try std.testing.expectEqualStrings("no such thing", res.message);
    try std.testing.expect(res.body == null);
}

test "grpc timeout enforced by server" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    const live = try Live.connect(alloc, 18566);
    defer live.close(alloc);
    const req = try encodePayload(alloc, "slow");
    defer alloc.free(req);
    var res = try grpc.unary(&live.conn, alloc, "/echo.Echo/Slow", "127.0.0.1:18566", 50 * std.time.ns_per_ms, req, tio);
    defer res.deinit(alloc);
    try std.testing.expectEqual(@as(u32, 4), res.status); // DeadlineExceeded
}
