// Port of netbird shared/management/client/grpc.go (v0.80.0), BSD-3-Clause
// Real local Go server interop. Compile via the harness root to keep src imports
// in one module. No production credentials or external endpoints are accepted.
const std = @import("std");
const h2 = @import("../net/h2/conn.zig");
const mgmt = @import("client.zig");
const messages = @import("messages.zig");
const wgbox = @import("wgbox.zig");
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
        self.authority = addr_str;
        self.rdr = std.Io.net.Stream.Reader.init(stream, tio, &self.rx_buf);
        self.wtr = stream.writer(tio, &self.tx_buf);
        self.tctx = .{ .reader = &self.rdr.interface, .writer = &self.wtr.interface };
        self.conn = h2.Conn.init(.{ .ctx = &self.tctx, .readFn = readFn, .writeFn = writeFn });
        try self.conn.handshake();
        return self;
    }

    fn close(self: *Live, allocator: std.mem.Allocator) void {
        self.stream.close(tio);
        allocator.free(self.authority);
        allocator.destroy(self);
    }
};


test "management Go v0.80 registration login and first sync" {
    const alloc = std.testing.allocator;
    const url = (try getenv(alloc, "NB_MANAGEMENT_URL")) orelse {
        std.debug.print("SKIP: NB_MANAGEMENT_URL and NB_SETUP_KEY_FILE required\n", .{});
        return error.SkipZigTest;
    };
    defer alloc.free(url);
    const path = (try getenv(alloc, "NB_SETUP_KEY_FILE")) orelse {
        std.debug.print("SKIP: NB_SETUP_KEY_FILE required\n", .{});
        return error.SkipZigTest;
    };
    defer alloc.free(path);
    const prefix = "http://127.0.0.1:";
    if (!std.mem.startsWith(u8, url, prefix)) return error.LocalH2cRequired;
    const port = try std.fmt.parseInt(u16, url[prefix.len..], 10);
    var file = try std.Io.Dir.openFileAbsolute(tio, path, .{ .mode = .read_only });
    defer file.close(tio);
    var key_buf: [128]u8 = undefined;
    const n = try file.readPositionalAll(tio, &key_buf, 0);
    const setup_key = std.mem.trim(u8, key_buf[0..n], "\r\n");
    try std.testing.expectEqual(@as(usize, 36), setup_key.len);
    std.debug.print("setup key ********************************{s}\n", .{setup_key[32..]});
    const live = try Live.connect(alloc, port);
    defer live.close(alloc);
    var c = mgmt.Client{ .conn = &live.conn, .alloc = alloc,
        .authority = live.authority, .io = tio, .key = wgbox.generatePrivateKey(tio) };
    defer c.deinit();
    std.debug.print("stage GetServerKey\n", .{});
    const server_key = try c.getServerKey();
    const encoded = try wgbox.allocString(alloc, server_key);
    defer alloc.free(encoded);
    try std.testing.expectEqual(@as(usize, 44), encoded.len);
    const parsed = try wgbox.parseKey(encoded);
    try std.testing.expectEqualSlices(u8, &server_key, &parsed);
    const meta = messages.PeerSystemMeta{ .hostname = "zig-local-e2e", .go_os = "linux",
        .kernel = "Linux", .core = "arm64", .os = "OpenWrt", .platform = "router",
        .kernel_version = "4.9", .netbird_version = "0.80.0-zig-e2e" };
    std.debug.print("stage Login registration\n", .{});
    var registered = try c.register(setup_key, "", meta, "", &.{});
    defer registered.deinit(alloc);
    const pc = registered.peer_config orelse return error.NoPeerConfig;
    try std.testing.expect(pc.address.len > 0);
    std.debug.print("stage second Login same WireGuard identity\n", .{});
    var logged_in = try c.login(meta, "", &.{});
    defer logged_in.deinit(alloc);
    const second = logged_in.peer_config orelse return error.NoPeerConfig;
    try std.testing.expectEqualStrings(pc.address, second.address);
    try std.testing.expectEqualStrings(pc.fqdn, second.fqdn);
    std.debug.print("stage Sync\n", .{});
    var stream = try c.sync(meta);
    defer stream.deinit();
    var response = (try stream.next()) orelse return error.NoSyncResponse;
    defer response.deinit(alloc);
    const map = response.network_map orelse return error.NoNetworkMap;
    const synced = map.peer_config orelse return error.NoPeerConfig;
    try std.testing.expectEqualStrings(pc.address, synced.address);
    try std.testing.expect(map.serial > 0);
    std.debug.print("interop complete: consistent peer config, serial={d}\n", .{map.serial});
}
