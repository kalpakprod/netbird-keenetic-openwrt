// Port of netbird client/grpc/dialer.go (v0.80.0), BSD-3-Clause
// Regression probes recovered from the independent R32 review.
const std = @import("std");
const net = @import("net");
const h2 = net.h2;
const grpc = net.grpc;

const headers = [_]u8{ 0x88, 0x0f, 0x10, 16, 'a', 'p', 'p', 'l', 'i', 'c', 'a', 't', 'i', 'o', 'n', '/', 'g', 'r', 'p', 'c' };
const trailers = [_]u8{ 0, 11, 'g', 'r', 'p', 'c', '-', 's', 't', 'a', 't', 'u', 's', 1, '0' };

const Pipe = struct {
    inbound: []const u8 = &.{},
    pos: usize = 0,
    out: [65536]u8 = undefined,
    out_len: usize = 0,
    fail_writes: bool = false,
    fn read(ctx: *anyopaque, buf: []u8) h2.Transport.ReadError!usize {
        const p: *Pipe = @ptrCast(@alignCast(ctx));
        if (p.pos == p.inbound.len) return 0;
        const n = @min(buf.len, p.inbound.len - p.pos);
        @memcpy(buf[0..n], p.inbound[p.pos..][0..n]);
        p.pos += n;
        return n;
    }
    fn write(ctx: *anyopaque, data: []const u8) h2.Transport.WriteError!void {
        const p: *Pipe = @ptrCast(@alignCast(ctx));
        if (p.fail_writes) return error.Reset;
        std.debug.assert(p.out_len + data.len <= p.out.len);
        @memcpy(p.out[p.out_len..][0..data.len], data);
        p.out_len += data.len;
    }
    fn transport(p: *Pipe) h2.Transport {
        return .{ .ctx = p, .readFn = read, .writeFn = write };
    }
};

fn appendFrame(out: []u8, pos: *usize, typ: u8, flags: u8, sid: u32, payload: []const u8) void {
    const b = out[pos.*..];
    b[0] = @truncate(payload.len >> 16);
    b[1] = @truncate(payload.len >> 8);
    b[2] = @truncate(payload.len);
    b[3] = typ;
    b[4] = flags;
    std.mem.writeInt(u32, b[5..9], sid, .big);
    @memcpy(b[9..][0..payload.len], payload);
    pos.* += 9 + payload.len;
}

fn twoMessageFlow(end_stream: bool) !void {
    var wire: [256]u8 = undefined;
    var n: usize = 0;
    const messages = [_]u8{ 0, 0, 0, 0, 1, 'a', 0, 0, 0, 0, 1, 'b' };
    appendFrame(&wire, &n, 1, 4, 1, &headers);
    appendFrame(&wire, &n, 0, if (end_stream) 1 else 0, 1, &messages);
    if (!end_stream) appendFrame(&wire, &n, 1, 5, 1, &trailers);
    var p = Pipe{ .inbound = wire[0..n] };
    var conn = h2.Conn.init(p.transport());
    var call = try grpc.startCall(&conn, std.testing.allocator, "/svc/Stream", "localhost", null, std.testing.io);
    defer call.deinit();
    try grpc.closeSend(&call);
    try std.testing.expectEqualStrings("a", (try grpc.recvMessage(&call)).?);
    const second = try grpc.recvMessage(&call);
    if (second == null) std.debug.print("second message=null, done={any}, status={any}, buffered_remaining={d}\n", .{ call.done, call.status(), call.rx.items.len - call.rx_off });
    try std.testing.expect(second != null);
    try std.testing.expectEqualStrings("b", second.?);
    try std.testing.expect((try grpc.recvMessage(&call)) == null);
    try std.testing.expectEqual(@as(?u32, if (end_stream) 13 else 0), call.status());
}

test "control two buffered messages followed by success trailers" {
    try twoMessageFlow(false);
}
test "END_STREAM DATA preserves every buffered message before Internal" {
    try twoMessageFlow(true);
}

test "deinit releases capacity after reset write failure without touching another call" {
    var p = Pipe{};
    var conn = h2.Conn.init(p.transport());
    conn.peer_max_concurrent = 1;
    var call = try grpc.startCall(&conn, std.testing.allocator, "/svc/Cancel", "localhost", null, std.testing.io);
    const before = p.out_len;
    p.fail_writes = true;
    call.deinit();
    try std.testing.expectEqual(h2.StreamState.closed, conn.streams[0].state);
    try std.testing.expectEqual(before, p.out_len);
    p.fail_writes = false;
    var next = try grpc.startCall(&conn, std.testing.allocator, "/svc/Next", "localhost", null, std.testing.io);
    defer next.deinit();
    try std.testing.expectEqual(@as(u32, 3), next.stream_id);
    try std.testing.expectEqual(h2.StreamState.open, conn.streams[0].state);
}

test "Call cleanup after external reset does not reset the reused slot twice" {
    var p = Pipe{};
    var conn = h2.Conn.init(p.transport());
    var old = try grpc.startCall(&conn, std.testing.allocator, "/svc/Cancel", "localhost", null, std.testing.io);
    try conn.resetStream(old.stream_id, .cancel);
    var next = try grpc.startCall(&conn, std.testing.allocator, "/svc/Next", "localhost", null, std.testing.io);
    defer next.deinit();
    const before = p.out_len;
    old.deinit();
    try std.testing.expectEqual(before, p.out_len);
    try std.testing.expectEqual(@as(u32, 3), conn.streams[0].id);
    try std.testing.expectEqual(h2.StreamState.open, conn.streams[0].state);
}

test "both-directions-closed Call deinit emits no reset" {
    var wire: [256]u8 = undefined;
    var n: usize = 0;
    var response: [64]u8 = undefined;
    @memcpy(response[0..headers.len], &headers);
    @memcpy(response[headers.len..][0..trailers.len], &trailers);
    appendFrame(&wire, &n, 1, 5, 1, response[0 .. headers.len + trailers.len]);
    var p = Pipe{ .inbound = wire[0..n] };
    var conn = h2.Conn.init(p.transport());
    var call = try grpc.startCall(&conn, std.testing.allocator, "/svc/Done", "localhost", null, std.testing.io);
    try grpc.closeSend(&call);
    try std.testing.expect((try grpc.recvMessage(&call)) == null);
    const before = p.out_len;
    call.deinit();
    try std.testing.expectEqual(before, p.out_len);
    try std.testing.expectEqual(h2.StreamState.closed, conn.streams[0].state);
}

test "padded empty DATA credits only H2-owned padding and never zero application bytes" {
    var wire: [256]u8 = undefined;
    var n: usize = 0;
    appendFrame(&wire, &n, 1, 4, 1, &headers);
    appendFrame(&wire, &n, 0, 8, 1, &.{ 3, 0, 0, 0 });
    appendFrame(&wire, &n, 0, 0, 1, &.{ 0, 0, 0, 0, 1, 'x' });
    appendFrame(&wire, &n, 1, 5, 1, &trailers);
    var p = Pipe{ .inbound = wire[0..n] };
    var conn = h2.Conn.init(p.transport());
    var call = try grpc.startCall(&conn, std.testing.allocator, "/svc/Empty", "localhost", null, std.testing.io);
    defer call.deinit();
    try grpc.closeSend(&call);
    const before = p.out_len;
    try std.testing.expectEqualStrings("x", (try grpc.recvMessage(&call)).?);
    try std.testing.expect((try grpc.recvMessage(&call)) == null);
    var off = before;
    var stream_credit: u32 = 0;
    var conn_credit: u32 = 0;
    while (off < p.out_len) {
        const h_len = (@as(u32, p.out[off]) << 16) | (@as(u32, p.out[off + 1]) << 8) | p.out[off + 2];
        try std.testing.expectEqual(@as(u8, 8), p.out[off + 3]);
        const sid = std.mem.readInt(u32, p.out[off + 5 ..][0..4], .big) & 0x7fffffff;
        const credit = std.mem.readInt(u32, p.out[off + 9 ..][0..4], .big);
        try std.testing.expect(credit > 0);
        if (sid == 0) conn_credit += credit else stream_credit += credit;
        off += 9 + h_len;
    }
    try std.testing.expectEqual(@as(u32, 10), stream_credit);
    try std.testing.expectEqual(@as(u32, 10), conn_credit);
}

fn endStreamAllocationFlow(alloc: std.mem.Allocator) !void {
    var wire: [256]u8 = undefined;
    var n: usize = 0;
    appendFrame(&wire, &n, 1, 4, 1, &headers);
    appendFrame(&wire, &n, 0, 1, 1, "");
    var p = Pipe{ .inbound = wire[0..n] };
    var conn = h2.Conn.init(p.transport());
    var call = try grpc.startCall(&conn, alloc, "/svc/Empty", "localhost", null, std.testing.io);
    defer call.deinit();
    try grpc.closeSend(&call);
    try std.testing.expect((try grpc.recvMessage(&call)) == null);
    try std.testing.expectEqual(@as(?u32, 13), call.status());
}
test "END_STREAM status/header ownership survives all allocation failures" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, endStreamAllocationFlow, .{});
}

test "malformed trailers error then Call deinit frees the still-open local direction" {
    var wire: [256]u8 = undefined;
    var n: usize = 0;
    appendFrame(&wire, &n, 1, 4, 1, &headers);
    appendFrame(&wire, &n, 1, 5, 1, &.{});
    var p = Pipe{ .inbound = wire[0..n] };
    var conn = h2.Conn.init(p.transport());
    conn.peer_max_concurrent = 1;
    var call = try grpc.startCall(&conn, std.testing.allocator, "/svc/Bad", "localhost", null, std.testing.io);
    try std.testing.expectError(error.GrpcStatusMissing, grpc.recvMessage(&call));
    call.deinit();
    var next = try grpc.startCall(&conn, std.testing.allocator, "/svc/Next", "localhost", null, std.testing.io);
    defer next.deinit();
    try std.testing.expectEqual(@as(u32, 3), next.stream_id);
}

test "terminal trailers release stream before result storage deinit" {
    var wire: [256]u8 = undefined;
    var n: usize = 0;
    const denied = [_]u8{ 0, 11, 'g', 'r', 'p', 'c', '-', 's', 't', 'a', 't', 'u', 's', 1, '7' };
    var response: [64]u8 = undefined;
    @memcpy(response[0..headers.len], &headers);
    @memcpy(response[headers.len..][0..denied.len], &denied);
    appendFrame(&wire, &n, 1, 5, 1, response[0 .. headers.len + denied.len]);
    var p = Pipe{ .inbound = wire[0..n] };
    var conn = h2.Conn.init(p.transport());
    conn.peer_max_concurrent = 1;
    var call = try grpc.startCall(&conn, std.testing.allocator, "/svc/Denied", "localhost", null, std.testing.io);
    defer call.deinit();
    try std.testing.expect((try grpc.recvMessage(&call)) == null);
    try std.testing.expect(call.done);
    try std.testing.expectEqual(@as(?u32, 7), call.status());
    std.debug.print("terminal status=7 done=true, slot_state={s} before deinit\n", .{@tagName(conn.streams[0].state)});
    // Completed Call result storage is still owned, but no active call remains.
    var next = try grpc.startCall(&conn, std.testing.allocator, "/svc/Next", "localhost", null, std.testing.io);
    defer next.deinit();
    try std.testing.expectEqual(@as(u32, 3), next.stream_id);
    try std.testing.expectEqualStrings("application/grpc", call.responseHeader("content-type").?);
    try std.testing.expectEqual(@as(?u32, 7), call.status());
}

test "terminal trailers cleanup uses upstream NO_ERROR not cancellation" {
    var wire: [256]u8 = undefined;
    var n: usize = 0;
    var response: [64]u8 = undefined;
    @memcpy(response[0..headers.len], &headers);
    @memcpy(response[headers.len..][0..trailers.len], &trailers);
    appendFrame(&wire, &n, 1, 5, 1, response[0 .. headers.len + trailers.len]);
    var p = Pipe{ .inbound = wire[0..n] };
    var conn = h2.Conn.init(p.transport());
    var call = try grpc.startCall(&conn, std.testing.allocator, "/svc/Done", "localhost", null, std.testing.io);
    const before = p.out_len;
    try std.testing.expect((try grpc.recvMessage(&call)) == null);
    try std.testing.expectEqual(@as(?u32, 0), call.status());
    defer call.deinit();
    try std.testing.expectEqual(@as(usize, 13), p.out_len - before);
    try std.testing.expectEqual(@as(u8, 3), p.out[before + 3]);
    const code = std.mem.readInt(u32, p.out[before + 9 ..][0..4], .big);
    std.debug.print("terminal trailers deinit RST_STREAM code={d}, upstream expected=0\n", .{code});
    try std.testing.expectEqual(@as(u32, 0), code);
}
