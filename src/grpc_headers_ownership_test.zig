// gRPC response-header ownership: captureHeaders must not leak a duped
// name/value when a later allocation fails. In-memory H2 transport with
// scripted server bytes; public API only (startCallWithHeaders,
// awaitHeaders, responseHeader).

const std = @import("std");
const grpc = @import("net/grpc/client.zig");
const h2 = @import("net/h2/conn.zig");
const hpack = @import("net/h2/hpack.zig");
const frame = @import("net/h2/frame.zig");

const tio = std.testing.io;

/// In-memory full-duplex pipe: inbound feeds reads, outbound records writes.
const Pipe = struct {
    inbound: []const u8,
    in_pos: usize = 0,
    outbound: [65536]u8 = undefined,
    out_len: usize = 0,

    fn read(ctx: *anyopaque, buf: []u8) h2.Transport.ReadError!usize {
        const self: *Pipe = @ptrCast(@alignCast(ctx));
        if (self.in_pos >= self.inbound.len) return 0;
        const n = @min(buf.len, self.inbound.len - self.in_pos);
        @memcpy(buf[0..n], self.inbound[self.in_pos..][0..n]);
        self.in_pos += n;
        return n;
    }

    fn write(ctx: *anyopaque, buf: []const u8) h2.Transport.WriteError!void {
        const self: *Pipe = @ptrCast(@alignCast(ctx));
        @memcpy(self.outbound[self.out_len..][0..buf.len], buf);
        self.out_len += buf.len;
    }

    fn transport(p: *Pipe) h2.Transport {
        return .{ .ctx = p, .readFn = read, .writeFn = write };
    }
};

fn encodeFrame(out: []u8, t: frame.FrameType, flags: frame.Flags, id: u32, payload: []const u8) []u8 {
    out[0] = @truncate(payload.len >> 16);
    out[1] = @truncate(payload.len >> 8);
    out[2] = @truncate(payload.len);
    out[3] = @intFromEnum(t);
    out[4] = flags;
    std.mem.writeInt(u32, out[5..9], id, .big);
    @memcpy(out[9..][0..payload.len], payload);
    return out[0 .. 9 + payload.len];
}

fn run(allocator: std.mem.Allocator) !void {
    var enc = hpack.Encoder.init();
    var block: [512]u8 = undefined;
    var blen: usize = 0;
    for ([_]hpack.HeaderField{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "application/grpc" },
        .{ .name = "x-echo", .value = "yes" },
    }) |f| {
        blen += try enc.writeField(block[blen..], f);
    }

    var inbound: [2048]u8 = undefined;
    var ilen: usize = 0;
    ilen += encodeFrame(inbound[ilen..], .settings, 0, 0, &.{}).len;
    ilen += encodeFrame(inbound[ilen..], .headers, frame.flag_headers_end_headers, 1, block[0..blen]).len;

    var pipe = Pipe{ .inbound = inbound[0..ilen] };
    var conn = h2.Conn.init(pipe.transport());
    try conn.handshake();
    var c = try grpc.startCallWithHeaders(&conn, allocator, "/svc/Method", "auth", null, tio, &.{
        .{ .name = "x-meta", .value = "m" },
    });
    defer c.deinit();
    try grpc.awaitHeaders(&c);
    try std.testing.expectEqualStrings("yes", c.responseHeader("x-echo").?);
    try std.testing.expectEqualStrings("application/grpc", c.responseHeader("content-type").?);
}

test "grpc response headers captured without leaks" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, run, .{});
}
