// gRPC-minimum client over src/net/h2 (prior-knowledge HTTP/2, no TLS here;
// steps 3-4 wrap the transport in TLS). Covers what the NetBird clients
// call: unary, server-streaming and bidi calls, length-prefixed messages,
// grpc-status/grpc-message trailers, grpc-timeout. Single-threaded blocking.
// One outstanding call per Conn: events for other streams are an error
// (open a second Conn for concurrent calls). No compression, no local
// deadline enforcement (the server enforces grpc-timeout; close to cancel).

const std = @import("std");
const h2 = @import("../h2/conn.zig");
const hpack = @import("../h2/hpack.zig");
const frame = @import("../h2/frame.zig");
const format = @import("format.zig");

/// Extra request header (gRPC metadata), e.g. the signal peer id.
pub const Metadata = struct {
    name: []const u8,
    value: []const u8,
};

/// Captured response header field (owned by the Call).
pub const Header = struct {
    name: []u8,
    value: []u8,
};

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
    resp_headers: std.ArrayList(Header),
    headers_seen: bool = false,
    done: bool = false,

    pub fn deinit(c: *Call) void {
        // resetStream closes locally before attempting the best-effort write.
        c.conn.resetStream(c.stream_id, .cancel) catch {};
        for (c.resp_headers.items) |h| {
            c.alloc.free(h.name);
            c.alloc.free(h.value);
        }
        c.resp_headers.deinit(c.alloc);
        c.rx.deinit(c.alloc);
        c.status_msg.deinit(c.alloc);
    }

    pub fn status(c: *const Call) ?u32 {
        return c.status_code;
    }

    pub fn statusMessage(c: *const Call) []const u8 {
        return c.status_msg.items;
    }

    /// First captured response header value, or null. Valid after the
    /// server's response headers arrive (awaitHeaders, or the first
    /// recvMessage that drives past them).
    pub fn responseHeader(c: *const Call, name: []const u8) ?[]const u8 {
        for (c.resp_headers.items) |h| {
            if (std.mem.eql(u8, h.name, name)) return h.value;
        }
        return null;
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
            const dec = try format.decodeMessage(m, tmp);
            c.status_msg.shrinkRetainingCapacity(dec.len);
        }
    }

    fn captureHeaders(c: *Call, fields: []const h2.HeaderField) Error!void {
        for (fields) |f| {
            const name = try c.alloc.dupe(u8, f.name);
            errdefer c.alloc.free(name);
            const value = try c.alloc.dupe(u8, f.value);
            errdefer c.alloc.free(value);
            try c.resp_headers.append(c.alloc, .{ .name = name, .value = value });
        }
        c.headers_seen = true;
    }

    /// Shared response-headers arm (recvMessage and awaitHeaders).
    fn handleHeaders(c: *Call, stream_id: u32, end_stream: bool, fields: []const h2.HeaderField) Error!void {
        if (stream_id != c.stream_id) return Error.GrpcUnexpectedStream;
        const hs = findField(fields, ":status") orelse return Error.GrpcProtocol;
        if (!std.mem.eql(u8, hs, "200")) return Error.GrpcHttpStatus;
        const ct = findField(fields, "content-type") orelse return Error.GrpcContentType;
        if (!std.mem.startsWith(u8, ct, "application/grpc")) return Error.GrpcContentType;
        try c.captureHeaders(fields);
        if (end_stream) {
            // Trailers-only response.
            try c.takeTrailers(fields);
            c.done = true;
            if (c.rx_off != c.rx.items.len) return Error.GrpcTruncated;
        }
    }

    /// Shared trailers arm.
    fn handleTrailers(c: *Call, stream_id: u32, fields: []const h2.HeaderField) Error!void {
        if (stream_id != c.stream_id) return Error.GrpcUnexpectedStream;
        try c.takeTrailers(fields);
        c.done = true;
        if (c.rx_off != c.rx.items.len) return Error.GrpcTruncated;
    }

    /// Shared reset arm.
    fn handleRst(c: *Call, stream_id: u32, code: frame.ErrCode) Error!void {
        if (stream_id != c.stream_id) return Error.GrpcUnexpectedStream;
        // grpc-go never sends trailers for a timed-out call: it closes
        // the stream with RST CANCEL (http2_server.go closeStream).
        // Like a grpc-go client, an expired local deadline surfaces as
        // DeadlineExceeded, an early abort as Canceled.
        if (code == .cancel) {
            c.status_msg.clearRetainingCapacity();
            if (c.deadline) |dl| {
                const now = std.Io.Clock.Timestamp.now(c.io, .awake);
                if (now.compare(.gte, dl)) {
                    try c.status_msg.appendSlice(c.alloc, "context deadline exceeded");
                    c.status_code = 4;
                    c.done = true;
                    return;
                }
            }
            try c.status_msg.appendSlice(c.alloc, "canceled");
            c.status_code = 1;
            c.done = true;
            return;
        }
        return Error.GrpcProtocol;
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
    return startCallWithHeaders(conn, alloc, path, authority, timeout_ns, io, &.{});
}

/// Open a call with extra request headers (gRPC metadata).
pub fn startCallWithHeaders(
    conn: *h2.Conn,
    alloc: std.mem.Allocator,
    path: []const u8,
    authority: []const u8,
    timeout_ns: ?i64,
    io: std.Io,
    extra: []const Metadata,
) Error!Call {
    var timeout_buf: [32]u8 = undefined;
    const base_n: usize = if (timeout_ns != null) 7 else 6;
    const fields = try alloc.alloc(hpack.HeaderField, base_n + extra.len);
    defer alloc.free(fields);
    fields[0] = .{ .name = ":method", .value = "POST" };
    fields[1] = .{ .name = ":scheme", .value = "http" };
    fields[2] = .{ .name = ":path", .value = path };
    fields[3] = .{ .name = ":authority", .value = authority };
    fields[4] = .{ .name = "content-type", .value = "application/grpc" };
    fields[5] = .{ .name = "te", .value = "trailers" };
    if (timeout_ns) |ns| {
        fields[6] = .{ .name = "grpc-timeout", .value = format.formatTimeout(ns, &timeout_buf) };
    }
    for (extra, 0..) |m, i| {
        fields[base_n + i] = .{ .name = m.name, .value = m.value };
    }
    const id = try conn.writeHeaders(fields, false);
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
        .resp_headers = .empty,
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
        const ev = try c.conn.readNext() orelse continue;
        switch (ev) {
            .response_headers => |h| {
                try c.handleHeaders(h.stream_id, h.end_stream, h.fields);
                if (c.done) return null;
            },
            .data => |d| {
                if (d.stream_id != c.stream_id) return Error.GrpcUnexpectedStream;
                try c.rxReserve(d.bytes.len);
                try c.rx.appendSlice(c.alloc, d.bytes);
                try c.conn.sendWindowUpdate(c.stream_id, @intCast(d.bytes.len));
                try c.conn.sendWindowUpdate(0, @intCast(d.bytes.len));
            },
            .trailers => |t| {
                try c.handleTrailers(t.stream_id, t.fields);
                return null;
            },
            .rst => |r| {
                try c.handleRst(r.stream_id, r.code);
                return null;
            },
            .goaway => return Error.GrpcProtocol,
            .settings_applied, .ping_acked, .window_update => {},
        }
    }
}

/// Drive the connection until the server's response headers arrive (then
/// responseHeader() is valid) or the call ends terminally first.
pub fn awaitHeaders(c: *Call) Error!void {
    while (!c.headers_seen and !c.done) {
        const ev = try c.conn.readNext() orelse continue;
        switch (ev) {
            .response_headers => |h| try c.handleHeaders(h.stream_id, h.end_stream, h.fields),
            .trailers => |t| try c.handleTrailers(t.stream_id, t.fields),
            .rst => |r| try c.handleRst(r.stream_id, r.code),
            .data => return Error.GrpcProtocol,
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
