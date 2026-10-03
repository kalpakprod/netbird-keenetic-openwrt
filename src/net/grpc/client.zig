// gRPC-minimum client over src/net/h2 (prior-knowledge HTTP/2, no TLS here;
// steps 3-4 wrap the transport in TLS). Covers what the NetBird clients
// call: unary, server-streaming and bidi calls, length-prefixed messages,
// grpc-status/grpc-message trailers, grpc-timeout. Single-threaded blocking.
// One outstanding call per Conn: events for other streams are an error
// (open a second Conn for concurrent calls). No compression, no local
// deadline enforcement (the server enforces grpc-timeout; close to cancel).

const std = @import("std");
const h2 = @import("h2");

pub const Error = error{
    GrpcProtocol,
    GrpcStatusMissing,
    GrpcCompressed,
    GrpcTruncated,
    GrpcHttpStatus,
    GrpcContentType,
    GrpcUnexpectedStream,
    GrpcTimeout,
    OutOfMemory,
} || h2.Error;

/// Format nanoseconds as a grpc-timeout value ("50M", "5S", ...).
pub fn formatTimeout(ns: i64, out: *[32]u8) []u8 {
    const units = [_]struct { div: i64, suf: u8 }{
        .{ .div = 3600 * std.time.ns_per_s, .suf = 'H' },
        .{ .div = 60 * std.time.ns_per_s, .suf = 'M' },
        .{ .div = std.time.ns_per_s, .suf = 'S' },
        .{ .div = std.time.ns_per_ms, .suf = 'm' },
        .{ .div = std.time.ns_per_us, .suf = 'u' },
        .{ .div = 1, .suf = 'n' },
    };
    for (units) |u| {
        if (@rem(ns, u.div) == 0) {
            return std.fmt.bufPrint(out, "{d}{c}", .{ @divTrunc(ns, u.div), u.suf }) catch unreachable;
        }
    }
    unreachable;
}

/// Percent-decode a grpc-message value into out (out must fit the decoded
/// form, which never exceeds src.len).
pub fn decodeMessage(src: []const u8, out: []u8) Error![]u8 {
    var i: usize = 0;
    var o: usize = 0;
    while (i < src.len) {
        if (src[i] == '%') {
            if (i + 2 >= src.len) return Error.GrpcProtocol;
            const hi = std.fmt.charToDigit(src[i + 1], 16) catch return Error.GrpcProtocol;
            const lo = std.fmt.charToDigit(src[i + 2], 16) catch return Error.GrpcProtocol;
            out[o] = hi * 16 + lo;
            o += 1;
            i += 3;
        } else {
            out[o] = src[i];
            o += 1;
            i += 1;
        }
    }
    return out[0..o];
}

pub const Call = struct {
    conn: *h2.Conn,
    alloc: std.mem.Allocator,
    stream_id: u32,
    rx: std.ArrayList(u8),
    rx_off: usize = 0,
    status_code: ?u32 = null,
    status_msg: std.ArrayList(u8),
    io: std.Io,
    deadline: ?std.Io.Clock.Timestamp = null,
    done: bool = false,

    pub fn deinit(c: *Call) void {
        c.rx.deinit(c.alloc);
        c.status_msg.deinit(c.alloc);
    }

    pub fn status(c: *const Call) ?u32 {
        return c.status_code;
    }

    pub fn statusMessage(c: *const Call) []const u8 {
        return c.status_msg.items;
    }

    /// Pop a complete buffered message, if any. The slice aliases the
    /// receive buffer: valid until the next recvMessage on this call.
    fn popMessage(c: *Call) Error!?[]const u8 {
        const buf = c.rx.items[c.rx_off..];
        if (buf.len < 5) return null;
        if (buf[0] != 0) return Error.GrpcCompressed;
        const len = std.mem.readInt(u32, buf[1..5], .big);
        if (buf.len < 5 + len) return null;
        c.rx_off += 5 + len;
        return buf[5 .. 5 + len];
    }

    /// Make room for n more bytes, compacting consumed prefix first.
    fn rxReserve(c: *Call, n: usize) Error!void {
        if (c.rx_off > 0) {
            const items = c.rx.items;
            const rest = items.len - c.rx_off;
            std.mem.copyForwards(u8, items[0..rest], items[c.rx_off..]);
            c.rx.shrinkRetainingCapacity(rest);
            c.rx_off = 0;
        }
        try c.rx.ensureTotalCapacity(c.alloc, c.rx.items.len + n);
    }

    fn takeTrailers(c: *Call, fields: []const h2.HeaderField) Error!void {
        const st = findField(fields, "grpc-status") orelse return Error.GrpcStatusMissing;
        c.status_code = std.fmt.parseInt(u32, st, 10) catch return Error.GrpcProtocol;
        c.status_msg.clearRetainingCapacity();
        if (findField(fields, "grpc-message")) |m| {
            const tmp = try c.status_msg.addManyAsSlice(c.alloc, m.len);
            const dec = try decodeMessage(m, tmp);
            c.status_msg.shrinkRetainingCapacity(dec.len);
        }
    }
};

/// Open a call: POST headers without END_STREAM. timeout_ns formats the
/// grpc-timeout header (server-side enforcement); io reads the monotonic
/// clock to tell an expired local deadline from an early server abort.
pub fn startCall(
    conn: *h2.Conn,
    alloc: std.mem.Allocator,
    path: []const u8,
    authority: []const u8,
    timeout_ns: ?i64,
    io: std.Io,
) Error!Call {
    // Anonymous literals: they coerce to hpack.HeaderField without importing
    // hpack (a second import would be a distinct module instance with
    // distinct types from the one conn.zig uses).
    var timeout_buf: [32]u8 = undefined;
    const id = if (timeout_ns) |ns| blk: {
        const tv = formatTimeout(ns, &timeout_buf);
        break :blk try conn.writeHeaders(&.{
            .{ .name = ":method", .value = "POST" },
            .{ .name = ":scheme", .value = "http" },
            .{ .name = ":path", .value = path },
            .{ .name = ":authority", .value = authority },
            .{ .name = "content-type", .value = "application/grpc" },
            .{ .name = "te", .value = "trailers" },
            .{ .name = "grpc-timeout", .value = tv },
        }, false);
    } else try conn.writeHeaders(&.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = path },
        .{ .name = ":authority", .value = authority },
        .{ .name = "content-type", .value = "application/grpc" },
        .{ .name = "te", .value = "trailers" },
    }, false);
    return .{
        .conn = conn,
        .alloc = alloc,
        .stream_id = id,
        .rx = .empty,
        .status_msg = .empty,
        .io = io,
        .deadline = if (timeout_ns) |ns|
            std.Io.Clock.Timestamp.now(io, .awake).addDuration(.{
                .raw = .fromNanoseconds(ns),
                .clock = .awake,
            })
        else
            null,
    };
}

/// Send one length-prefixed message (flag 0, never compressed).
pub fn sendMessage(c: *Call, payload: []const u8, end_stream: bool) Error!void {
    var hdr: [5]u8 = .{ 0, 0, 0, 0, 0 };
    std.mem.writeInt(u32, hdr[1..5], @intCast(payload.len), .big);
    try c.conn.writeData(c.stream_id, &hdr, payload.len == 0 and end_stream);
    if (payload.len > 0) try c.conn.writeData(c.stream_id, payload, end_stream);
}

/// Half-close the request stream (bidi done sending).
pub fn closeSend(c: *Call) Error!void {
    try c.conn.writeData(c.stream_id, "", true);
}

fn findField(fields: []const h2.HeaderField, name: []const u8) ?[]const u8 {
    for (fields) |f| {
        if (std.mem.eql(u8, f.name, name)) return f.value;
    }
    return null;
}

/// Receive the next message, driving the connection. Borrowed: valid until
/// the next recvMessage or deinit. Returns null at trailers (then status()
/// is set). Copies everything out of the conn's reused buffers immediately.
pub fn recvMessage(c: *Call) Error!?[]const u8 {
    if (c.done) return null;
    while (true) {
        if (try c.popMessage()) |msg| return msg;
        const ev = try c.conn.readNext() orelse return Error.GrpcTruncated;
        switch (ev) {
            .response_headers => |h| {
                if (h.stream_id != c.stream_id) return Error.GrpcUnexpectedStream;
                const hs = findField(h.fields, ":status") orelse return Error.GrpcProtocol;
                if (!std.mem.eql(u8, hs, "200")) return Error.GrpcHttpStatus;
                const ct = findField(h.fields, "content-type") orelse return Error.GrpcContentType;
                if (!std.mem.startsWith(u8, ct, "application/grpc")) return Error.GrpcContentType;
                if (h.end_stream) {
                    // Trailers-only response.
                    try c.takeTrailers(h.fields);
                    c.done = true;
                    if (c.rx_off != c.rx.items.len) return Error.GrpcTruncated;
                    return null;
                }
            },
            .data => |d| {
                if (d.stream_id != c.stream_id) return Error.GrpcUnexpectedStream;
                try c.rxReserve(d.bytes.len);
                try c.rx.appendSlice(c.alloc, d.bytes);
                try c.conn.sendWindowUpdate(c.stream_id, @intCast(d.bytes.len));
                try c.conn.sendWindowUpdate(0, @intCast(d.bytes.len));
            },
            .trailers => |t| {
                if (t.stream_id != c.stream_id) return Error.GrpcUnexpectedStream;
                try c.takeTrailers(t.fields);
                c.done = true;
                if (c.rx_off != c.rx.items.len) return Error.GrpcTruncated;
                return null;
            },
            .rst => |r| {
                if (r.stream_id != c.stream_id) return Error.GrpcUnexpectedStream;
                // grpc-go never sends trailers for a timed-out call: it closes
                // the stream with RST CANCEL (http2_server.go closeStream).
                // Like a grpc-go client, an expired local deadline surfaces as
                // DeadlineExceeded, an early abort as Canceled.
                if (r.code == .cancel) {
                    c.status_msg.clearRetainingCapacity();
                    if (c.deadline) |dl| {
                        const now = std.Io.Clock.Timestamp.now(c.io, .awake);
                        if (now.compare(.gte, dl)) {
                            try c.status_msg.appendSlice(c.alloc, "context deadline exceeded");
                            c.status_code = 4;
                            c.done = true;
                            return null;
                        }
                    }
                    try c.status_msg.appendSlice(c.alloc, "canceled");
                    c.status_code = 1;
                    c.done = true;
                    return null;
                }
                return Error.GrpcProtocol;
            },
            .goaway => return Error.GrpcProtocol,
            .settings_applied, .ping_acked, .window_update => {},
        }
    }
}

pub const UnaryResult = struct {
    status: u32,
    message: []u8,
    body: ?[]u8,

    pub fn deinit(r: *UnaryResult, alloc: std.mem.Allocator) void {
        alloc.free(r.message);
        if (r.body) |b| alloc.free(b);
    }
};

/// Full unary exchange: one request message, exactly one response message
/// (or trailers-only on error). All outputs owned by the caller.
pub fn unary(
    conn: *h2.Conn,
    alloc: std.mem.Allocator,
    path: []const u8,
    authority: []const u8,
    timeout_ns: ?i64,
    req: []const u8,
    io: std.Io,
) Error!UnaryResult {
    var c = try startCall(conn, alloc, path, authority, timeout_ns, io);
    defer c.deinit();
    try sendMessage(&c, req, true);
    const body = try recvMessage(&c);
    // Drain to trailers; a second message on a unary call violates the spec.
    if (try recvMessage(&c) != null) return Error.GrpcProtocol;
    const st = c.status() orelse return Error.GrpcStatusMissing;
    return .{
        .status = st,
        .message = try alloc.dupe(u8, c.statusMessage()),
        .body = if (body) |b| try alloc.dupe(u8, b) else null,
    };
}
