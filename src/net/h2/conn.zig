// Port of golang.org/x/net/http2 client connection behavior (v0.79.0 vendored copy, BSD-3-Clause).
// Reference: upstream/netbird/vendor/golang.org/x/net/http2/transport.go
// (handshake, readLoop), frame.go (sequencing).
// Scope: single-threaded blocking H2 client: preface + SETTINGS handshake,
// CONTINUATION reassembly with sequencing checks, HPACK decode of response
// and trailer blocks, connection/stream flow-control accounting, PING ack,
// GOAWAY/RST handling. No server push, no priority, no padding on write.
// Receive DATA top-up is manual (caller sends WINDOW_UPDATE explicitly);
// only DATA padding is refunded automatically like Go (transport.go:2335),
// since the app never sees those bytes.

const std = @import("std");
const frame = @import("frame.zig");
const hpack = @import("hpack.zig");

/// Byte transport (TCP stream, in-memory pipe in tests).
pub const Transport = struct {
    ctx: *anyopaque,
    readFn: *const fn (*anyopaque, []u8) ReadError!usize,
    writeFn: *const fn (*anyopaque, []const u8) WriteError!void,

    pub const ReadError = error{ Closed, Reset };
    pub const WriteError = error{ Closed, Reset };

    pub fn readFull(t: *const Transport, buf: []u8) ReadError!void {
        var off: usize = 0;
        while (off < buf.len) {
            const n = try t.readFn(t.ctx, buf[off..]);
            if (n == 0) return ReadError.Closed;
            off += n;
        }
    }

    pub fn writeAll(t: *const Transport, buf: []const u8) WriteError!void {
        try t.writeFn(t.ctx, buf);
    }
};

pub const Error = error{
    Protocol,
    FlowControl,
    FrameSize,
    Compression,
    StreamClosed,
    RefusedStream,
    NoStreamsLeft,
    BadState,
    NoSpaceLeft,
    Truncated,
    InvalidIndex,
    VarintOverflow,
    StringTooLong,
    InvalidHuffman,
    TableSizeUpdateNotAtStart,
    TableSizeTooLarge,
    TooManyEntries,
    MessageTooLong,
} || Transport.ReadError || Transport.WriteError || frame.Error || hpack.Error;

pub const max_streams = 8;
pub const default_max_frame_read: u32 = 1 << 20;
pub const max_header_block: usize = 64 * 1024;

pub const StreamState = enum {
    idle,
    open,
    half_closed_remote,
    half_closed_local,
    closed,
};

pub const Stream = struct {
    id: u32 = 0,
    state: StreamState = .idle,
    recv_window: i64 = 0,
    send_window: i64 = 0,
    headers_received: bool = false,
};

pub const HeadersEvent = struct {
    stream_id: u32,
    end_stream: bool,
    fields: []HeaderField,
};

pub const HeaderField = struct {
    name: []const u8,
    value: []const u8,
};

pub const Event = union(enum) {
    response_headers: HeadersEvent,
    trailers: HeadersEvent,
    data: struct {
        stream_id: u32,
        end_stream: bool,
        bytes: []const u8,
    },
    rst: struct {
        stream_id: u32,
        code: frame.ErrCode,
    },
    goaway: struct {
        last_stream_id: u32,
        code: frame.ErrCode,
    },
    settings_applied,
    ping_acked: [8]u8,
    window_update: struct {
        stream_id: u32,
        increment: u32,
    },
};

pub const Conn = struct {
    transport: Transport,
    decoder: hpack.Decoder = hpack.Decoder.init(4096),
    encoder: hpack.Encoder = hpack.Encoder.init(),
    write_buf: [default_max_frame_read + frame.header_len]u8 = undefined,

    peer_header_table_size: u32 = 4096,
    peer_max_frame_size: u32 = frame.initial_max_frame_size,
    peer_max_concurrent: u32 = std.math.maxInt(u32),
    peer_initial_window: u32 = frame.initial_window_size,

    conn_recv_window: i64 = frame.initial_window_size,
    conn_send_window: i64 = frame.initial_window_size,
    max_frame_read: u32 = default_max_frame_read,

    streams: [max_streams]Stream = std.mem.zeroes([max_streams]Stream),
    next_stream_id: u32 = 1,
    last_header_stream: u32 = 0,
    frag_buf: [max_header_block]u8 = undefined,
    frag_len: usize = 0,
    frag_end_stream: bool = false,
    fields_buf: [64]HeaderField = undefined,
    goaway_seen: bool = false,
    goaway_code: frame.ErrCode = .no,

    pub fn init(transport: Transport) Conn {
        return .{ .transport = transport };
    }

    fn writeRaw(c: *Conn, bytes: []const u8) Error!void {
        try c.transport.writeAll(bytes);
    }

    /// Client connection preface: magic + SETTINGS, like transport.go
    /// newClientConn (without the extra upload-buffer WINDOW_UPDATE).
    pub fn writePreface(c: *Conn) Error!void {
        try c.writeRaw(frame.client_preface);
        var w = frame.Writer.init(&c.write_buf);
        try w.writeSettings(&[_]frame.Setting{
            .{ .id = .enable_push, .val = 0 },
            .{ .id = .initial_window_size, .val = frame.initial_window_size },
            .{ .id = .max_frame_size, .val = frame.initial_max_frame_size },
        });
        try c.writeRaw(w.bytes());
    }

    /// Read frames until the server SETTINGS; the first frame MUST be
    /// SETTINGS (RFC 7540 3.5). Applies peer settings, sends the ack.
    pub fn readHandshake(c: *Conn) Error!void {
        var first = true;
        while (true) {
            const h = try c.readHeader();
            const payload = try c.readPayload(h);
            if (first) {
                first = false;
                if (h.type != .settings) return Error.Protocol;
            }
            switch (frame.parse(h, payload)) {
                .err => |e| return fail(e),
                .ok => |f| switch (f) {
                    .settings => |s| {
                        if (s.isAck()) continue;
                        try c.applyPeerSettings(&s);
                        try c.writeSettingsAck();
                        return;
                    },
                    .window_update => |wu| try c.onWindowUpdate(wu),
                    .ping => |p| try c.ackPing(p),
                    .goaway => |g| {
                        c.goaway_seen = true;
                        c.goaway_code = g.err_code;
                        return Error.RefusedStream;
                    },
                    else => return Error.Protocol,
                },
            }
        }
    }

    pub fn handshake(c: *Conn) Error!void {
        try c.writePreface();
        try c.readHandshake();
    }

    fn applyPeerSettings(c: *Conn, s: *const frame.Settings) Error!void {
        var i: usize = 0;
        while (i < s.numSettings()) : (i += 1) {
            const st = s.setting(i);
            switch (st.id) {
                .header_table_size => {
                    // Go transport.go:2518-2519: the public setter schedules
                    // the HPACK Dynamic Table Size Update on the next block.
                    c.peer_header_table_size = st.val;
                    c.encoder.setMaxDynamicTableSize(st.val);
                },
                .enable_push => {
                    if (st.val != 0) return Error.Protocol;
                },
                .max_concurrent_streams => c.peer_max_concurrent = st.val,
                .initial_window_size => {
                    if (st.val > (1 << 31) - 1) return Error.FlowControl;
                    const delta: i64 = @as(i64, st.val) - c.peer_initial_window;
                    c.peer_initial_window = st.val;
                    for (&c.streams) |*sm| {
                        if (sm.state == .open or sm.state == .half_closed_remote or
                            sm.state == .half_closed_local)
                        {
                            sm.send_window += delta;
                        }
                    }
                },
                .max_frame_size => {
                    if (st.val < 16384 or st.val > (1 << 24) - 1) return Error.Protocol;
                    c.peer_max_frame_size = st.val;
                },
                .max_header_list_size => {},
                _ => {},
            }
        }
    }

    fn writeSettingsAck(c: *Conn) Error!void {
        var w = frame.Writer.init(&c.write_buf);
        try w.writeSettingsAck();
        try c.writeRaw(w.bytes());
    }

    fn ackPing(c: *Conn, p: frame.Ping) Error!void {
        if (p.isAck()) return;
        var w = frame.Writer.init(&c.write_buf);
        try w.writePing(true, p.data);
        try c.writeRaw(w.bytes());
    }

    fn activeCount(c: *Conn) u32 {
        var n: u32 = 0;
        for (&c.streams) |*sm| {
            if (sm.state != .idle and sm.state != .closed) n += 1;
        }
        return n;
    }

    fn allocStream(c: *Conn) Error!*Stream {
        if (c.activeCount() >= c.peer_max_concurrent) return Error.NoStreamsLeft;
        for (&c.streams) |*sm| {
            if (sm.state == .idle or sm.state == .closed) {
                sm.* = .{
                    .id = c.next_stream_id,
                    .state = .open,
                    .recv_window = frame.initial_window_size,
                    .send_window = c.peer_initial_window,
                };
                c.next_stream_id += 2;
                return sm;
            }
        }
        return Error.NoStreamsLeft;
    }

    fn findStream(c: *Conn, id: u32) ?*Stream {
        for (&c.streams) |*sm| {
            if (sm.state != .idle and sm.state != .closed and sm.id == id) {
                return sm;
            }
        }
        return null;
    }

    /// Release locally even when the peer does not echo RST_STREAM.
    pub fn resetStream(c: *Conn, id: u32, code: frame.ErrCode) Error!void {
        const sm = c.findStream(id) orelse return Error.StreamClosed;
        sm.state = .closed;
        var w = frame.Writer.init(&c.write_buf);
        try w.writeRstStream(id, code);
        try c.transport.writeAll(w.bytes());
    }

    /// Local END_STREAM sent: open -> half_closed_local, remote already
    /// done -> closed (RFC 7540 5.1).
    fn localEnd(sm: *Stream) void {
        sm.state = if (sm.state == .half_closed_remote) .closed else .half_closed_local;
    }

    /// Remote END_STREAM received: mirror direction.
    fn remoteEnd(sm: *Stream) void {
        sm.state = if (sm.state == .half_closed_local) .closed else .half_closed_remote;
    }

    /// Open a stream and send request headers, fragmenting the HPACK
    /// block by peer_max_frame_size (HEADERS + CONTINUATIONs).
    pub fn writeHeaders(
        c: *Conn,
        fields: []const hpack.HeaderField,
        end_stream: bool,
    ) Error!u32 {
        if (c.goaway_seen) return Error.RefusedStream;
        const sm = try c.allocStream();
        var block: [max_header_block]u8 = undefined;
        var blen: usize = 0;
        for (fields) |f| {
            blen += try c.encoder.writeField(block[blen..], f);
        }
        var off: usize = 0;
        var first = true;
        while (true) {
            const chunk_len: usize = @min(c.peer_max_frame_size, blen - off);
            const last = off + chunk_len == blen;
            var w = frame.Writer.init(&c.write_buf);
            if (first) {
                // Go transport.go:1423: END_STREAM rides the first HEADERS
                // even when CONTINUATIONs follow (RFC 7540 6.2).
                try w.writeHeaders(sm.id, block[off..][0..chunk_len], end_stream, last, 0);
            } else {
                try w.writeContinuation(sm.id, last, block[off..][0..chunk_len]);
            }
            try c.writeRaw(w.bytes());
            off += chunk_len;
            first = false;
            if (last) break;
        }
        if (end_stream) localEnd(sm);
        return sm.id;
    }

    /// Send DATA on a stream, honoring both flow-control windows.
    pub fn writeData(c: *Conn, stream_id: u32, data: []const u8, end_stream: bool) Error!void {
        const sm = c.findStream(stream_id) orelse return Error.StreamClosed;
        // Remote END_STREAM does not block local sends (RFC 7540 5.1
        // half-closed(remote)); only our own END_STREAM does.
        if (sm.state != .open and sm.state != .half_closed_remote) {
            return Error.StreamClosed;
        }
        // All-or-nothing: refuse before writing a partial frame.
        if (@as(i64, @intCast(data.len)) > sm.send_window) return Error.FlowControl;
        if (@as(i64, @intCast(data.len)) > c.conn_send_window) return Error.FlowControl;
        var off: usize = 0;
        while (off < data.len or (data.len == 0 and end_stream)) {
            const chunk: usize = @min(@min(c.peer_max_frame_size, data.len - off), @as(usize, 1024 * 1024));
            if (@as(i64, @intCast(chunk)) > sm.send_window) return Error.FlowControl;
            if (@as(i64, @intCast(chunk)) > c.conn_send_window) return Error.FlowControl;
            const last = off + chunk == data.len;
            var w = frame.Writer.init(&c.write_buf);
            try w.writeData(stream_id, end_stream and last, data[off..][0..chunk]);
            try c.writeRaw(w.bytes());
            sm.send_window -= @intCast(chunk);
            c.conn_send_window -= @intCast(chunk);
            off += chunk;
            if (data.len == 0) break;
        }
        if (end_stream) localEnd(sm);
    }

    /// Explicitly grow the receive windows (no automatic top-up).
    pub fn sendWindowUpdate(c: *Conn, stream_id: u32, increment: u32) Error!void {
        var w = frame.Writer.init(&c.write_buf);
        try w.writeWindowUpdate(stream_id, increment);
        try c.writeRaw(w.bytes());
        if (stream_id == 0) {
            c.conn_recv_window += increment;
        } else if (c.findStream(stream_id)) |sm| {
            sm.recv_window += increment;
        }
    }

    pub fn readHeader(c: *Conn) Error!frame.Header {
        var raw: [frame.header_len]u8 = undefined;
        try c.transport.readFull(&raw);
        const h = frame.Header.parse(&raw);
        if (h.length > c.max_frame_read) return Error.FrameSize;
        return h;
    }

    fn readPayload(c: *Conn, h: frame.Header) Error![]u8 {
        // Payload lands in the shared write buffer (never live across calls).
        if (h.length > c.write_buf.len) return Error.FrameSize;
        const out = c.write_buf[0..h.length];
        try c.transport.readFull(out);
        return out;
    }

    /// Read and dispatch one frame; returns the resulting event, or null
    /// for frames fully absorbed (settings-ack absorbed into
    /// settings_applied; use the event to observe them).
    pub fn readNext(c: *Conn) Error!?Event {
        const h = try c.readHeader();
        const payload = try c.readPayload(h);
        try c.checkSequence(h);
        switch (frame.parse(h, payload)) {
            .err => |e| return fail(e),
            .ok => |f| return switch (f) {
                .settings => |s| try c.onSettings(s),
                .window_update => |wu| blk: {
                    try c.onWindowUpdate(wu);
                    break :blk Event{ .window_update = .{ .stream_id = h.stream_id, .increment = wu.increment } };
                },
                .ping => |p| blk: {
                    try c.ackPing(p);
                    break :blk if (p.isAck()) null else Event{ .ping_acked = p.data };
                },
                .data => |d| try c.onData(d),
                .headers => |hd| try c.onHeaders(hd, h.stream_id),
                .continuation => |cc| try c.onContinuation(cc, h.stream_id),
                .rst_stream => |r| blk: {
                    if (c.findStream(h.stream_id)) |sm| sm.state = .closed;
                    break :blk Event{ .rst = .{ .stream_id = h.stream_id, .code = r.err_code } };
                },
                .goaway => |g| blk: {
                    c.goaway_seen = true;
                    c.goaway_code = g.err_code;
                    break :blk Event{ .goaway = .{ .last_stream_id = g.last_stream_id, .code = g.err_code } };
                },
                .unknown => null,
            },
        }
    }

    fn checkSequence(c: *Conn, h: frame.Header) Error!void {
        if (c.last_header_stream != 0) {
            if (h.type != .continuation) return Error.Protocol;
            if (h.stream_id != c.last_header_stream) return Error.Protocol;
        } else if (h.type == .continuation) {
            return Error.Protocol;
        }
        switch (h.type) {
            .headers, .continuation => {
                if (h.hasFlags(frame.flag_headers_end_headers)) {
                    c.last_header_stream = 0;
                } else {
                    c.last_header_stream = h.stream_id;
                }
            },
            else => {},
        }
    }

    fn onSettings(c: *Conn, s: frame.Settings) Error!?Event {
        if (s.isAck()) return Event{ .settings_applied = {} };
        try c.applyPeerSettings(&s);
        try c.writeSettingsAck();
        return Event{ .settings_applied = {} };
    }

    fn onWindowUpdate(c: *Conn, wu: frame.WindowUpdate) Error!void {
        if (wu.header.stream_id == 0) {
            c.conn_send_window += wu.increment;
            if (c.conn_send_window > (1 << 31) - 1) return Error.FlowControl;
        } else {
            const sm = c.findStream(wu.header.stream_id) orelse return;
            sm.send_window += wu.increment;
            if (sm.send_window > (1 << 31) - 1) return Error.FlowControl;
        }
    }

    fn onData(c: *Conn, d: frame.Data) Error!?Event {
        const sm = c.findStream(d.header.stream_id) orelse {
            if (d.header.stream_id >= c.next_stream_id) return Error.StreamClosed;
            if (d.header.length > c.conn_recv_window) return Error.FlowControl;
            c.conn_recv_window -= d.header.length;
            if (d.header.length > 0) try c.sendWindowUpdate(0, d.header.length);
            return null;
        };
        if (sm.state == .half_closed_remote) return Error.StreamClosed;
        // Flow control counts the whole payload incl. padding (RFC 7540
        // 6.9, Go transport.go:2328 takeInflows(f.Length)).
        const full: i64 = d.header.length;
        if (full > sm.recv_window) return Error.FlowControl;
        if (full > c.conn_recv_window) return Error.FlowControl;
        sm.recv_window -= full;
        c.conn_recv_window -= full;
        const end = d.header.hasFlags(frame.flag_data_end_stream);
        if (end) remoteEnd(sm);
        // Copy out of the shared buffer: the event must survive the call.
        const kept = c.frag_buf[0..d.data.len];
        @memcpy(kept, d.data);
        const sid = d.header.stream_id;
        // Go transport.go:2335 refunds padding immediately: the app never
        // sees those bytes, so DATA top-up stays fully manual. Credit the
        // stream window directly: the frame may have closed the stream,
        // and sendWindowUpdate skips unknown streams.
        const pad: u32 = d.header.length - @as(u32, @intCast(d.data.len));
        if (pad > 0) {
            var w = frame.Writer.init(&c.write_buf);
            try w.writeWindowUpdate(sid, pad);
            try c.writeRaw(w.bytes());
            sm.recv_window += pad;
            try c.sendWindowUpdate(0, pad);
        }
        return Event{ .data = .{ .stream_id = sid, .end_stream = end, .bytes = kept } };
    }

    fn onHeaders(c: *Conn, hd: frame.Headers, stream_id: u32) Error!?Event {
        // Response HEADERS on a stream we never opened (or push, which we
        // disabled) is a connection error.
        if (c.findStream(stream_id) == null and stream_id >= c.next_stream_id) return Error.Protocol;
        if (hd.headersEnded()) {
            return c.decodeBlock(stream_id, hd.fragment, hd.streamEnded());
        }
        if (hd.fragment.len > c.frag_buf.len) return Error.MessageTooLong;
        @memcpy(c.frag_buf[0..hd.fragment.len], hd.fragment);
        c.frag_len = hd.fragment.len;
        c.frag_end_stream = hd.streamEnded();
        return null;
    }

    fn onContinuation(c: *Conn, cc: frame.Continuation, stream_id: u32) Error!?Event {
        if (c.frag_len + cc.fragment.len > c.frag_buf.len) return Error.MessageTooLong;
        @memcpy(c.frag_buf[c.frag_len..][0..cc.fragment.len], cc.fragment);
        c.frag_len += cc.fragment.len;
        if (!cc.headersEnded()) return null;
        const end_stream = c.frag_end_stream;
        const ev = try c.decodeBlock(stream_id, c.frag_buf[0..c.frag_len], end_stream);
        c.frag_len = 0;
        c.frag_end_stream = false;
        return ev;
    }

    fn decodeBlock(c: *Conn, stream_id: u32, block: []const u8, end_stream: bool) Error!?Event {
        var discarded: Stream = .{};
        const active = c.findStream(stream_id);
        const sm = active orelse &discarded;
        const is_trailers = sm.headers_received;
        sm.headers_received = true;
        const Ctx = struct {
            fields: []HeaderField,
            len: usize,
            dropped: bool,
        };
        var ctx = Ctx{ .fields = &c.fields_buf, .len = 0, .dropped = false };
        const emit = struct {
            fn f(ctx_ptr: ?*anyopaque, hf: hpack.HeaderField) void {
                const cx: *Ctx = @ptrCast(@alignCast(ctx_ptr.?));
                if (cx.len < cx.fields.len) {
                    cx.fields[cx.len] = .{ .name = hf.name, .value = hf.value };
                    cx.len += 1;
                } else {
                    cx.dropped = true;
                }
            }
        }.f;
        c.decoder.decodeBlock(block, &ctx, emit) catch |err| {
            return switch (err) {
                error.Truncated, error.InvalidIndex, error.VarintOverflow, error.StringTooLong, error.InvalidHuffman, error.TableSizeUpdateNotAtStart, error.TableSizeTooLarge, error.TooManyEntries, error.InvalidEncoding => Error.Compression,
                else => err,
            };
        };
        if (active == null) return null;
        if (ctx.dropped) return Error.MessageTooLong;
        if (end_stream) remoteEnd(sm);
        const fields = c.fields_buf[0..ctx.len];
        if (is_trailers) {
            return Event{ .trailers = .{ .stream_id = stream_id, .end_stream = end_stream, .fields = fields } };
        }
        return Event{ .response_headers = .{ .stream_id = stream_id, .end_stream = end_stream, .fields = fields } };
    }
};

fn fail(e: frame.ParseError) Error {
    return switch (e.err) {
        error.Protocol => Error.Protocol,
        error.FlowControl => Error.FlowControl,
        error.FrameSize => Error.FrameSize,
        else => Error.Protocol,
    };
}
