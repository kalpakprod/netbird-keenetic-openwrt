// Port of netbird client/grpc/dialer.go (v0.80.0), BSD-3-Clause
// Run: zig test --dep net -Mroot=src/net/grpc/reuse_test.zig -Mnet=<bindings importing h2/conn.zig and grpc/client.zig>
const std = @import("std");
const net = @import("net");
const h2 = net.h2;
const grpc = net.grpc;

const Pipe = struct {
    inbound: []const u8 = &.{},
    in_pos: usize = 0,
    outbound: [4096]u8 = undefined,
    out_len: usize = 0,

    fn read(ctx: *anyopaque, buf: []u8) h2.Transport.ReadError!usize {
        const p: *Pipe = @ptrCast(@alignCast(ctx));
        if (p.in_pos == p.inbound.len) return 0;
        const n = @min(buf.len, p.inbound.len - p.in_pos);
        @memcpy(buf[0..n], p.inbound[p.in_pos..][0..n]);
        p.in_pos += n;
        return n;
    }

    fn write(ctx: *anyopaque, bytes: []const u8) h2.Transport.WriteError!void {
        const p: *Pipe = @ptrCast(@alignCast(ctx));
        std.debug.assert(p.out_len + bytes.len <= p.outbound.len);
        @memcpy(p.outbound[p.out_len..][0..bytes.len], bytes);
        p.out_len += bytes.len;
    }

    fn transport(p: *Pipe) h2.Transport {
        return .{ .ctx = p, .readFn = read, .writeFn = write };
    }
};

fn appendFrame(out: []u8, pos: *usize, ty: u8, flags: u8, id: u32, payload: []const u8) void {
    const buf = out[pos.*..];
    buf[0] = @truncate(payload.len >> 16);
    buf[1] = @truncate(payload.len >> 8);
    buf[2] = @truncate(payload.len);
    buf[3] = ty;
    buf[4] = flags;
    std.mem.writeInt(u32, buf[5..9], id, .big);
    @memcpy(buf[9..][0..payload.len], payload);
    pos.* += 9 + payload.len;
}

fn nextCallReceivesTrailers(late: u8, await_headers: bool) !void {
    const alloc = std.testing.allocator;
    // Independent HPACK: indexed status 200, content-type static name with
    // application/grpc literal, grpc-status literal zero. END_STREAM makes
    // this a valid trailers-only successful gRPC response on stream 3.
    const response = [_]u8{
        0x88, 0x0f, 0x10, 16,
        'a',  'p',  'p',  'l',
        'i',  'c',  'a',  't',
        'i',  'o',  'n',  '/',
        'g',  'r',  'p',  'c',
        0,    11,   'g',  'r',
        'p',  'c',  '-',  's',
        't',  'a',  't',  'u',
        's',  1,    '0',
    };
    var wire: [256]u8 = undefined;
    var n: usize = 0;
    switch (late) {
        0 => {},
        1 => appendFrame(&wire, &n, 0, 0, 1, "late"),
        2 => appendFrame(&wire, &n, 1, 4, 1, &.{0x88}),
        3 => appendFrame(&wire, &n, 6, 1, 0, "12345678"),
        4 => appendFrame(&wire, &n, 0xff, 0, 0, "extension"),
        else => unreachable,
    }
    appendFrame(&wire, &n, 1, 5, 3, &response);
    var p = Pipe{ .inbound = wire[0..n] };
    var c = h2.Conn.init(p.transport());
    var canceled = try grpc.startCall(&c, alloc, "/svc/Stream", "localhost", null, std.testing.io);
    canceled.deinit();
    var next = try grpc.startCall(&c, alloc, "/svc/Next", "localhost", null, std.testing.io);
    defer next.deinit();
    try grpc.closeSend(&next);
    if (await_headers) try grpc.awaitHeaders(&next);
    const msg = grpc.recvMessage(&next) catch |err| {
        std.debug.print("late-type={d}: recvMessage={s}, consumed={d}/{d} bytes, status={any}\n", .{ late, @errorName(err), p.in_pos, n, next.status() });
        return err;
    };
    try std.testing.expect(msg == null);
    try std.testing.expectEqual(@as(?u32, 0), next.status());
    try std.testing.expectEqual(n, p.in_pos);
}

test "control before recvMessage" {
    try nextCallReceivesTrailers(0, false);
}
test "control before awaitHeaders" {
    try nextCallReceivesTrailers(0, true);
}
test "late DATA before recvMessage" {
    try nextCallReceivesTrailers(1, false);
}
test "late DATA before awaitHeaders" {
    try nextCallReceivesTrailers(1, true);
}
test "late HEADERS before recvMessage" {
    try nextCallReceivesTrailers(2, false);
}
test "late HEADERS before awaitHeaders" {
    try nextCallReceivesTrailers(2, true);
}
test "PING ACK before recvMessage" {
    try nextCallReceivesTrailers(3, false);
}
test "PING ACK before awaitHeaders" {
    try nextCallReceivesTrailers(3, true);
}
test "unknown extension before recvMessage" {
    try nextCallReceivesTrailers(4, false);
}
test "unknown extension before awaitHeaders" {
    try nextCallReceivesTrailers(4, true);
}

test "nine canceled calls release slots" {
    var p = Pipe{};
    var conn = h2.Conn.init(p.transport());
    for (0..12) |_| {
        var call = try grpc.startCall(&conn, std.testing.allocator, "/svc/Cancel", "localhost", null, std.testing.io);
        call.deinit();
    }
}
test "twelve trailers-only calls release open send slots" {
    const response = [_]u8{ 0x88, 0x0f, 0x10, 16, 'a', 'p', 'p', 'l', 'i', 'c', 'a', 't', 'i', 'o', 'n', '/', 'g', 'r', 'p', 'c', 0, 11, 'g', 'r', 'p', 'c', '-', 's', 't', 'a', 't', 'u', 's', 1, '7' };
    var wire: [1024]u8 = undefined;
    var n: usize = 0;
    for (0..12) |i| appendFrame(&wire, &n, 1, 5, @intCast(2 * i + 1), &response);
    var p = Pipe{ .inbound = wire[0..n] };
    var conn = h2.Conn.init(p.transport());
    for (0..12) |_| {
        var call = try grpc.startCall(&conn, std.testing.allocator, "/svc/Error", "localhost", null, std.testing.io);
        defer call.deinit();
        try std.testing.expect(try grpc.recvMessage(&call) == null);
        try std.testing.expectEqual(@as(?u32, 7), call.status());
    }
}

test "empty DATA before valid message and trailers" {
    var wire: [256]u8 = undefined;
    var n: usize = 0;
    const headers = [_]u8{ 0x88, 0x0f, 0x10, 16, 'a', 'p', 'p', 'l', 'i', 'c', 'a', 't', 'i', 'o', 'n', '/', 'g', 'r', 'p', 'c' };
    const trailers = [_]u8{ 0, 11, 'g', 'r', 'p', 'c', '-', 's', 't', 'a', 't', 'u', 's', 1, '0' };
    appendFrame(&wire, &n, 1, 4, 1, &headers);
    appendFrame(&wire, &n, 0, 0, 1, "");
    appendFrame(&wire, &n, 0, 0, 1, &.{ 0, 0, 0, 0, 1, 'x' });
    appendFrame(&wire, &n, 1, 5, 1, &trailers);
    var p = Pipe{ .inbound = wire[0..n] };
    var conn = h2.Conn.init(p.transport());
    var call = try grpc.startCall(&conn, std.testing.allocator, "/svc/Empty", "localhost", null, std.testing.io);
    defer call.deinit();
    try grpc.closeSend(&call);
    try std.testing.expectEqualStrings("x", (try grpc.recvMessage(&call)).?);
    try std.testing.expect(try grpc.recvMessage(&call) == null);
    try std.testing.expectEqual(@as(?u32, 0), call.status());
}
test "DATA END_STREAM requires trailers" {
    var wire: [256]u8 = undefined;
    var n: usize = 0;
    const headers = [_]u8{ 0x88, 0x0f, 0x10, 16, 'a', 'p', 'p', 'l', 'i', 'c', 'a', 't', 'i', 'o', 'n', '/', 'g', 'r', 'p', 'c' };
    appendFrame(&wire, &n, 1, 4, 1, &headers);
    appendFrame(&wire, &n, 0, 1, 1, "");
    var p = Pipe{ .inbound = wire[0..n] };
    var conn = h2.Conn.init(p.transport());
    var call = try grpc.startCall(&conn, std.testing.allocator, "/svc/Empty", "localhost", null, std.testing.io);
    defer call.deinit();
    try grpc.closeSend(&call);
    try std.testing.expect(try grpc.recvMessage(&call) == null);
    try std.testing.expectEqual(@as(?u32, 13), call.status());
    try std.testing.expectEqualStrings("server closed the stream without sending trailers", call.statusMessage());
}
