// Port of netbird shared/signal/client/grpc.go (v0.80.0), BSD-3-Clause
// Real local Go server interop. Compile via the harness root to keep src imports
// in one module. No production credentials or external endpoints are accepted.
const std = @import("std");
const h2 = @import("../net/h2/conn.zig");
const signal = @import("client.zig");
const messages = @import("messages.zig");
const wgbox = @import("../mgmt/wgbox.zig");
const tio = std.testing.io;

fn getenv(allocator: std.mem.Allocator, key: []const u8) !?[]u8 {
    var file = std.Io.Dir.openFileAbsolute(tio, "/proc/self/environ", .{ .mode = .read_only }) catch return error.EnvironmentReadFailed;
    defer file.close(tio);
    var data: std.ArrayList(u8) = .empty;
    defer data.deinit(allocator);
    var chunk: [4096]u8 = undefined;
    while (true) {
        const n = try file.readPositionalAll(tio, &chunk, data.items.len);
        try data.appendSlice(allocator, chunk[0..n]);
        if (n < chunk.len) break;
    }
    var rest = data.items;
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

const Live = struct {
    stream: std.Io.net.Stream,
    transport_open: bool = true,
    rdr: std.Io.net.Stream.Reader,
    wtr: std.Io.net.Stream.Writer,
    rx_buf: [16384]u8,
    tx_buf: [16384]u8,
    conn: h2.Conn,
    tctx: Ctx,
    authority: []u8,

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
        const addr_str = try std.fmt.allocPrint(allocator, "127.0.0.1:{d}", .{port});
        errdefer allocator.free(addr_str);
        var addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(port) };
        const stream = try addr.connect(tio, .{ .mode = .stream });
        errdefer stream.close(tio);
        self.stream = stream;
        self.transport_open = true;
        self.authority = addr_str;
        self.rdr = std.Io.net.Stream.Reader.init(stream, tio, &self.rx_buf);
        self.wtr = stream.writer(tio, &self.tx_buf);
        self.tctx = .{ .reader = &self.rdr.interface, .writer = &self.wtr.interface };
        self.conn = h2.Conn.init(.{ .ctx = &self.tctx, .readFn = readFn, .writeFn = writeFn });
        try self.conn.handshake();
        return self;
    }

    fn close(self: *Live, allocator: std.mem.Allocator) void {
        if (self.transport_open) self.stream.close(tio);
        allocator.free(self.authority);
        allocator.destroy(self);
    }
};


fn exchange(sender: *signal.Client, receiver: *signal.Stream, from: []const u8, to: []const u8, body: messages.Body) !void {
    const msg = messages.Message{ .key = from, .remote_key = to, .body = body };
    try sender.send(&msg);
    var got = (try receiver.recv()) orelse return error.MissingMessage;
    defer got.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings(from, got.key);
    try std.testing.expectEqualStrings(to, got.remote_key);
    const expected = try body.encode(std.testing.allocator);
    defer std.testing.allocator.free(expected);
    const actual = try got.body.encode(std.testing.allocator);
    defer std.testing.allocator.free(actual);
    try std.testing.expectEqualSlices(u8, expected, actual);
}

fn activePeers(port: u16) !u64 {
    var address: std.Io.net.IpAddress = .{ .ip4 = .loopback(port) };
    const stream = try address.connect(tio, .{ .mode = .stream });
    defer stream.close(tio);
    var tx: [256]u8 = undefined;
    var writer = stream.writer(tio, &tx);
    try writer.interface.writeAll("GET /metrics HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    try writer.interface.flush();
    var rx: [4096]u8 = undefined;
    var reader = stream.reader(tio, &rx);
    var data: std.ArrayList(u8) = .empty;
    defer data.deinit(std.testing.allocator);
    var chunk: [4096]u8 = undefined;
    while (true) {
        const n = try reader.interface.readSliceShort(&chunk);
        try data.appendSlice(std.testing.allocator, chunk[0..n]);
        if (n < chunk.len) break;
    }
    if (!std.mem.startsWith(u8, data.items, "HTTP/1.0 200") and
        !std.mem.startsWith(u8, data.items, "HTTP/1.1 200")) return error.MetricsHttpFailed;
    var lines = std.mem.splitScalar(u8, data.items, '\n');
    var count: u64 = 0;
    var found = false;
    while (lines.next()) |line| {
        if (line.len == 0 or line[0] == '#') continue;
        const end = std.mem.indexOfScalar(u8, line, ' ') orelse continue;
        const metric = line[0..end];
        if (!std.mem.startsWith(u8, metric, "active_peers") and
            !std.mem.startsWith(u8, metric, "netbird_signal_active_peers")) continue;
        var values = std.mem.tokenizeAny(u8, line[end..], " \r\t");
        count += try std.fmt.parseInt(u64, values.next() orelse return error.MissingMetricValue, 10);
        found = true;
    }
    if (!found) return error.ActivePeersMetricMissing;
    return count;
}

fn waitActivePeers(port: u16, expected: u64) !void {
    for (0..40) |_| {
        const count = try activePeers(port);
        if (count == expected) {
            std.debug.print("SERVER_ACTIVE_PEERS={d}\n", .{count});
            return;
        }
        try std.Io.sleep(tio, .fromMilliseconds(50), .awake);
    }
    return error.ServerDidNotObserveClose;
}

test "signal Go v0.80 boxed bidirectional exchange and stream isolation" {
    const alloc = std.testing.allocator;
    const addr = (try getenv(alloc, "NB_SIGNAL_ADDR")) orelse {
        std.debug.print("SKIP: NB_SIGNAL_ADDR required\n", .{});
        return error.SkipZigTest;
    };
    defer alloc.free(addr);
    const prefix = "127.0.0.1:";
    if (!std.mem.startsWith(u8, addr, prefix)) return error.LocalH2cRequired;
    const port = try std.fmt.parseInt(u16, addr[prefix.len..], 10);
    const la = try Live.connect(alloc, port);
    defer la.close(alloc);
    const lb = try Live.connect(alloc, port);
    defer lb.close(alloc);
    var a = signal.Client{ .conn = &la.conn, .alloc = alloc, .authority = addr, .io = tio, .key = wgbox.generatePrivateKey(tio) };
    defer a.deinit();
    var b = signal.Client{ .conn = &lb.conn, .alloc = alloc, .authority = addr, .io = tio, .key = wgbox.generatePrivateKey(tio) };
    defer b.deinit();
    const ap = try wgbox.allocString(alloc, wgbox.publicKey(a.key));
    defer alloc.free(ap);
    const bp = try wgbox.allocString(alloc, wgbox.publicKey(b.key));
    defer alloc.free(bp);
    std.debug.print("stage register A and B\n", .{});
    var sa = try a.connectStream();
    var a_open = true;
    defer if (a_open) sa.deinit();
    var sb = try b.connectStream();
    defer sb.deinit();
    try std.testing.expect(sa.registered() and sb.registered());
    std.debug.print("stage offer A -> B\n", .{});
    try exchange(&a, &sb, ap, bp, .{ .msg_type = .offer, .payload = "local-offer", .wg_listen_port = 51820, .netbird_version = "0.80.0-zig-e2e", .session_id = "local-session" });
    std.debug.print("stage answer B -> A\n", .{});
    try exchange(&b, &sa, bp, ap, .{ .msg_type = .answer, .payload = "local-answer", .mode = .{ .direct = true } });
    const unknown = try wgbox.allocString(alloc, wgbox.publicKey(wgbox.generatePrivateKey(tio)));
    defer alloc.free(unknown);
    std.debug.print("stage unknown recipient accepted and dropped\n", .{});
    // v0.80 Send delegates unknown peers to the vendored dispatcher, which
    // returns an empty successful response when no listener exists.
    try b.send(&.{ .remote_key = unknown, .body = .{ .msg_type = .candidate, .payload = "unknown" } });
    try std.testing.expectEqual(@as(u32, 0), b.last_status_code);
    std.debug.print("stage close A stream, retain B stream\n", .{});
    // Buffer deinit is not cancellation. Close the owned socket and wait for
    // the server's active-peer gauge to fall before exercising B again.
    const metrics_addr = (try getenv(alloc, "STACK_SIGNAL_METRICS_PORT")) orelse return error.MetricsPortRequired;
    defer alloc.free(metrics_addr);
    const metrics_port = try std.fmt.parseInt(u16, metrics_addr, 10);
    try waitActivePeers(metrics_port, 2);
    la.stream.close(tio);
    la.transport_open = false;
    sa.deinit();
    a_open = false;
    try waitActivePeers(metrics_port, 1);
    // A's transport is gone. Use a separate unary connection with the same
    // ephemeral identity, without creating a new receiving stream.
    const lc = try Live.connect(alloc, port);
    defer lc.close(alloc);
    var sender = signal.Client{ .conn = &lc.conn, .alloc = alloc, .authority = addr, .io = tio, .key = a.key };
    defer sender.deinit();
    try exchange(&sender, &sb, ap, bp, .{ .msg_type = .candidate, .payload = "after-close" });
    std.debug.print("interop complete: boxed bodies match and B survives A close\n", .{});
}
