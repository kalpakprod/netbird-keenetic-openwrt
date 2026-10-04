// Live HTTP/2 interop against a real Go h2c server (gen/h2interop).
// H2_HELPER env or $HOME/.cache/netbird-zig-context/gen/h2interop/h2interop;
// missing helper skips explicitly instead of passing.

const std = @import("std");
const builtin = @import("builtin");
const h2 = @import("conn.zig");
const hpack = @import("hpack.zig");

const tio = std.testing.io;
const port: u16 = 18631;

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
    if (try getenv(allocator, "H2_HELPER")) |p| {
        errdefer allocator.free(p);
        var f = std.Io.Dir.openFileAbsolute(tio, p, .{ .mode = .read_only }) catch return error.SkipZigTest;
        f.close(tio);
        return p;
    }
    const home = (try getenv(allocator, "HOME")) orelse return error.SkipZigTest;
    defer allocator.free(home);
    const def = try std.fmt.allocPrint(allocator, "{s}/.cache/netbird-zig-context/gen/h2interop/h2interop", .{home});
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

    fn connect(allocator: std.mem.Allocator) !*Live {
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

fn findField(fields: []const h2.HeaderField, name: []const u8) ?[]const u8 {
    for (fields) |f| {
        if (std.mem.eql(u8, f.name, name)) return f.value;
    }
    return null;
}

test "h2 interop echo with Go server" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    const live = try Live.connect(alloc);
    defer live.close(alloc);

    const sid = try live.conn.writeHeaders(&[_]hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/echo" },
        .{ .name = ":authority", .value = "127.0.0.1:18631" },
        .{ .name = "x-ping", .value = "42" },
    }, true);
    try std.testing.expectEqual(@as(u32, 1), sid);

    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(alloc);
    var status: ?[]const u8 = null;
    var echo: ?[]const u8 = null;
    var done = false;
    while (!done) {
        const ev = try live.conn.readNext() orelse continue;
        switch (ev) {
            .response_headers => |h| {
                try std.testing.expectEqual(@as(u32, 1), h.stream_id);
                try std.testing.expect(!h.end_stream);
                status = findField(h.fields, ":status");
                echo = findField(h.fields, "x-echo");
            },
            .data => |d| {
                try std.testing.expectEqual(@as(u32, 1), d.stream_id);
                try body.appendSlice(alloc, d.bytes);
                try live.conn.sendWindowUpdate(d.stream_id, @intCast(d.bytes.len));
                try live.conn.sendWindowUpdate(0, @intCast(d.bytes.len));
                if (d.end_stream) done = true;
            },
            .trailers => |t| {
                try std.testing.expectEqual(@as(u32, 1), t.stream_id);
                done = true;
            },
            .rst => return error.UnexpectedRst,
            .goaway => return error.UnexpectedGoaway,
            .settings_applied, .ping_acked, .window_update => {},
        }
    }
    try std.testing.expectEqualStrings("200", status.?);
    try std.testing.expectEqualStrings("42", echo.?);
    try std.testing.expectEqualStrings("hello h2:/echo", body.items);
}
