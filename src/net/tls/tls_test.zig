// Tests for the vendored TLS client with ALPN.
// Live tests spawn gen/tlsserver (TLS_HELPER env or
// $HOME/.cache/netbird-zig-context/gen/tlsserver/tlsserver); missing helper
// skips. Linux-only (procfs env scan + /dev/net namespaces elsewhere).

const std = @import("std");
const builtin = @import("builtin");
const client = @import("client.zig");
const ca = @import("ca.zig");

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
    if (try getenv(allocator, "TLS_HELPER")) |p| return p;
    const home = (try getenv(allocator, "HOME")) orelse return error.SkipZigTest;
    defer allocator.free(home);
    const def = try std.fmt.allocPrint(allocator, "{s}/.cache/netbird-zig-context/gen/tlsserver/tlsserver", .{home});
    errdefer allocator.free(def);
    var f = std.Io.Dir.openFileAbsolute(tio, def, .{ .mode = .read_only }) catch return error.SkipZigTest;
    f.close(tio);
    return def;
}

fn fixedEntropy() [client.Options.entropy_len]u8 {
    var e: [client.Options.entropy_len]u8 = undefined;
    for (&e, 0..) |*b, i| b.* = @truncate(i * 7 + 1);
    return e;
}

/// Connect to a just-spawned server, spinning until it listens.
fn connectLoop(addr: *std.Io.net.IpAddress, io: std.Io) !std.Io.net.Stream {
    var i: usize = 0;
    while (i < 200000) : (i += 1) {
        if (addr.connect(io, .{ .mode = .stream })) |s| return s else |_| {}
    }
    return error.ConnectTimeout;
}

fn handshakeCase(
    allocator: std.mem.Allocator,
    mode: []const u8,
    port: u16,
    comptime offer: []const []const u8,
    expect_alpn: ?[]const u8,
    expect_reply: []const u8,
) !void {
    const helper = try helperPath(allocator);
    defer allocator.free(helper);
    const addr_str = try std.fmt.allocPrint(allocator, "127.0.0.1:{d}", .{port});
    defer allocator.free(addr_str);
    const argv = [_][]const u8{ helper, mode, addr_str };
    var child = try std.process.spawn(tio, .{ .argv = &argv });
    // kill-only: the server exits after one connection; kill reaps it and
    // wait() after kill asserts (id already null).
    defer child.kill(tio);

    var addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(port) };
    const stream = try connectLoop(&addr, tio);
    defer stream.close(tio);

    var rx_buf: [client.min_buffer_len]u8 = undefined;
    var tx_buf: [client.min_buffer_len]u8 = undefined;
    var rdr = std.Io.net.Stream.Reader.init(stream, tio, &rx_buf);
    var wtr = stream.writer(tio, &tx_buf);
    var entropy = fixedEntropy();
    var read_buf: [client.min_buffer_len]u8 = undefined;
    var write_buf: [client.min_buffer_len]u8 = undefined;
    var c = try client.init(&rdr.interface, &wtr.interface, .{
        .host = .{ .explicit = "127.0.0.1" },
        .ca = .self_signed,
        .write_buffer = &write_buf,
        .read_buffer = &read_buf,
        .entropy = &entropy,
        .realtime_now = std.Io.Clock.real.now(tio),
    }, offer);

    if (expect_alpn) |exp| {
        const got = c.negotiatedAlpn() orelse return error.AlpnMissing;
        try std.testing.expectEqualStrings(exp, got);
    } else {
        try std.testing.expect(c.negotiatedAlpn() == null);
    }
    try c.writer.writeAll("ping\n");
    // The TLS flush only advances the transport buffer; the transport flush
    // pushes bytes to the socket (same contract as std: init flushes output
    // explicitly after every flight).
    try c.writer.flush();
    try wtr.interface.flush();
    var reply: [16]u8 = undefined;
    try c.reader.readSliceAll(reply[0..expect_reply.len]);
    try std.testing.expectEqualStrings(expect_reply, reply[0..expect_reply.len]);
}

test "tls negotiates h2 alpn with Go server" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    try handshakeCase(std.testing.allocator, "h2", 18543, &.{"h2"}, "h2", "proto=h2!\n");
}

test "tls reports null alpn when server disables it" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    try handshakeCase(std.testing.allocator, "none", 18544, &.{"h2"}, null, "proto=!\n");
}

test "tls without alpn offer completes" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    try handshakeCase(std.testing.allocator, "h2", 18545, &.{}, null, "proto=!\n");
}

test "system ca bundle loads without statx" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(std.testing.allocator);
    try ca.loadSystem(&bundle, std.testing.allocator, tio, std.Io.Clock.real.now(tio));
}
