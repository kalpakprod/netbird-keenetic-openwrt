// Port of golang.org/x/net/http2 frame codec (BSD-3-Clause).
// Reference: upstream/netbird/vendor/golang.org/x/net/http2/frame.go,
// errors.go (ErrCode), http2.go (SettingID, defaults).
// Scope: frame reader/writer over caller slices for DATA, HEADERS,
// CONTINUATION, SETTINGS, PING, GOAWAY, RST_STREAM, WINDOW_UPDATE.
// PRIORITY, PUSH_PROMISE and unknown types parse as Unknown (payload
// retained). Frame sequencing (CONTINUATION order) lives in conn.zig.

const std = @import("std");

pub const header_len = 9;
pub const max_frame_len: u32 = (1 << 24) - 1;
pub const initial_max_frame_size: u32 = 16384;
pub const initial_window_size: u32 = 65535;
pub const default_max_read_frame_size: u32 = 1 << 20;
pub const client_preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

pub const FrameType = enum(u8) {
    data = 0x0,
    headers = 0x1,
    priority = 0x2,
    rst_stream = 0x3,
    settings = 0x4,
    push_promise = 0x5,
    ping = 0x6,
    goaway = 0x7,
    window_update = 0x8,
    continuation = 0x9,
    _,
};

pub const Flags = u8;
pub const flag_data_end_stream: Flags = 0x1;
pub const flag_data_padded: Flags = 0x8;
pub const flag_headers_end_stream: Flags = 0x1;
pub const flag_headers_end_headers: Flags = 0x4;
pub const flag_headers_padded: Flags = 0x8;
pub const flag_headers_priority: Flags = 0x20;
pub const flag_settings_ack: Flags = 0x1;
pub const flag_ping_ack: Flags = 0x1;
pub const flag_continuation_end_headers: Flags = 0x4;

pub const ErrCode = enum(u32) {
    no = 0x0,
    protocol = 0x1,
    internal = 0x2,
    flow_control = 0x3,
    settings_timeout = 0x4,
    stream_closed = 0x5,
    frame_size = 0x6,
    refused_stream = 0x7,
    cancel = 0x8,
    compression = 0x9,
    connect = 0xa,
    enhance_your_calm = 0xb,
    inadequate_security = 0xc,
    http_1_1_required = 0xd,
    _,
};

pub const SettingID = enum(u16) {
    header_table_size = 0x1,
    enable_push = 0x2,
    max_concurrent_streams = 0x3,
    initial_window_size = 0x4,
    max_frame_size = 0x5,
    max_header_list_size = 0x6,
    _,
};

pub const Setting = struct {
    id: SettingID,
    val: u32,
};

pub const Error = error{
    Truncated,
    FrameTooLarge,
    Protocol,
    FrameSize,
    FlowControl,
    StreamClosed,
    NoSpaceLeft,
};

/// Connection vs stream error scope, mirroring Go's ConnectionError /
/// streamError / connError usage in frame.go parsers.
pub const Scope = enum { connection, stream };

pub const ParseError = struct {
    err: Error,
    scope: Scope,
    stream_id: u32,
};

pub const ParseResult = union(enum) {
    ok: Frame,
    err: ParseError,
};

pub const Header = struct {
    length: u32,
    type: FrameType,
    flags: Flags,
    stream_id: u32,

    pub fn parse(buf: *const [header_len]u8) Header {
        return .{
            .length = (@as(u32, buf[0]) << 16) | (@as(u32, buf[1]) << 8) | buf[2],
            .type = @enumFromInt(buf[3]),
            .flags = buf[4],
            .stream_id = std.mem.readInt(u32, buf[5..9], .big) & 0x7fffffff,
        };
    }

    pub fn hasFlags(h: *const Header, f: Flags) bool {
        return h.flags & f == f;
    }
};

pub const Data = struct {
    header: Header,
    data: []const u8,
};

pub const Headers = struct {
    header: Header,
    fragment: []const u8,
    priority_stream_dep: u32 = 0,
    priority_exclusive: bool = false,
    priority_weight: u8 = 0,

    pub fn headersEnded(h: *const Headers) bool {
        return h.header.hasFlags(flag_headers_end_headers);
    }
    pub fn streamEnded(h: *const Headers) bool {
        return h.header.hasFlags(flag_headers_end_stream);
    }
    pub fn hasPriority(h: *const Headers) bool {
        return h.header.hasFlags(flag_headers_priority);
    }
};

pub const Settings = struct {
    header: Header,
    payload: []const u8,

    pub fn isAck(s: *const Settings) bool {
        return s.header.hasFlags(flag_settings_ack);
    }
    pub fn numSettings(s: *const Settings) usize {
        return s.payload.len / 6;
    }
    pub fn setting(s: *const Settings, i: usize) Setting {
        return .{
            .id = @enumFromInt(std.mem.readInt(u16, s.payload[i * 6 ..][0..2], .big)),
            .val = std.mem.readInt(u32, s.payload[i * 6 + 2 ..][0..4], .big),
        };
    }
    pub fn value(s: *const Settings, id: SettingID) ?u32 {
        var i: usize = 0;
        while (i < s.numSettings()) : (i += 1) {
            const st = s.setting(i);
            if (st.id == id) return st.val;
        }
        return null;
    }
};

pub const Ping = struct {
    header: Header,
    data: [8]u8,
    pub fn isAck(p: *const Ping) bool {
        return p.header.hasFlags(flag_ping_ack);
    }
};

pub const GoAway = struct {
    header: Header,
    last_stream_id: u32,
    err_code: ErrCode,
    debug_data: []const u8,
};

pub const WindowUpdate = struct {
    header: Header,
    increment: u32,
};

pub const RstStream = struct {
    header: Header,
    err_code: ErrCode,
};

pub const Continuation = struct {
    header: Header,
    fragment: []const u8,
    pub fn headersEnded(c: *const Continuation) bool {
        return c.header.hasFlags(flag_continuation_end_headers);
    }
};

pub const Unknown = struct {
    header: Header,
    payload: []const u8,
};

pub const Frame = union(enum) {
    data: Data,
    headers: Headers,
    settings: Settings,
    ping: Ping,
    goaway: GoAway,
    window_update: WindowUpdate,
    rst_stream: RstStream,
    continuation: Continuation,
    unknown: Unknown,
};

fn connErr(err: Error, stream_id: u32) ParseResult {
    return .{ .err = .{ .err = err, .scope = .connection, .stream_id = stream_id } };
}

fn streamErr(err: Error, stream_id: u32) ParseResult {
    return .{ .err = .{ .err = err, .scope = .stream, .stream_id = stream_id } };
}

/// Parse one frame from header + payload (payload.len must equal
/// header.length). Validation mirrors Go's parse*Frame functions.
pub fn parse(header: Header, payload: []const u8) ParseResult {
    return switch (header.type) {
        .data => parseData(header, payload),
        .headers => parseHeaders(header, payload),
        .settings => parseSettings(header, payload),
        .ping => parsePing(header, payload),
        .goaway => parseGoAway(header, payload),
        .window_update => parseWindowUpdate(header, payload),
        .rst_stream => parseRstStream(header, payload),
        .continuation => parseContinuation(header, payload),
        else => .{ .ok = .{ .unknown = .{ .header = header, .payload = payload } } },
    };
}

fn parseData(header: Header, payload: []const u8) ParseResult {
    if (header.stream_id == 0) {
        return connErr(Error.Protocol, 0);
    }
    var body = payload;
    var pad: usize = 0;
    if (header.hasFlags(flag_data_padded)) {
        if (body.len == 0) return connErr(Error.Protocol, header.stream_id);
        pad = body[0];
        body = body[1..];
    }
    if (pad > body.len) {
        return connErr(Error.Protocol, header.stream_id);
    }
    return .{ .ok = .{ .data = .{ .header = header, .data = body[0 .. body.len - pad] } } };
}

fn parseHeaders(header: Header, payload: []const u8) ParseResult {
    if (header.stream_id == 0) {
        return connErr(Error.Protocol, 0);
    }
    var p = payload;
    var pad: usize = 0;
    if (header.hasFlags(flag_headers_padded)) {
        if (p.len == 0) return streamErr(Error.Protocol, header.stream_id);
        pad = p[0];
        p = p[1..];
    }
    var f = Headers{ .header = header, .fragment = &.{} };
    if (header.hasFlags(flag_headers_priority)) {
        if (p.len < 5) return streamErr(Error.Protocol, header.stream_id);
        const v = std.mem.readInt(u32, p[0..4], .big);
        f.priority_stream_dep = v & 0x7fffffff;
        f.priority_exclusive = v != f.priority_stream_dep;
        f.priority_weight = p[4];
        p = p[5..];
    }
    if (p.len < pad) {
        return streamErr(Error.Protocol, header.stream_id);
    }
    f.fragment = p[0 .. p.len - pad];
    return .{ .ok = .{ .headers = f } };
}

fn parseSettings(header: Header, payload: []const u8) ParseResult {
    if (header.hasFlags(flag_settings_ack) and header.length > 0) {
        return connErr(Error.FrameSize, 0);
    }
    if (header.stream_id != 0) {
        return connErr(Error.Protocol, 0);
    }
    if (payload.len % 6 != 0) {
        return connErr(Error.FrameSize, 0);
    }
    const f = Settings{ .header = header, .payload = payload };
    if (f.value(.initial_window_size)) |v| {
        if (v > (1 << 31) - 1) {
            return connErr(Error.FlowControl, 0);
        }
    }
    return .{ .ok = .{ .settings = f } };
}

fn parsePing(header: Header, payload: []const u8) ParseResult {
    if (payload.len != 8) {
        return connErr(Error.FrameSize, 0);
    }
    if (header.stream_id != 0) {
        return connErr(Error.Protocol, 0);
    }
    var data: [8]u8 = undefined;
    @memcpy(&data, payload);
    return .{ .ok = .{ .ping = .{ .header = header, .data = data } } };
}

fn parseGoAway(header: Header, payload: []const u8) ParseResult {
    if (header.stream_id != 0) {
        return connErr(Error.Protocol, 0);
    }
    if (payload.len < 8) {
        return connErr(Error.FrameSize, 0);
    }
    return .{ .ok = .{ .goaway = .{
        .header = header,
        .last_stream_id = std.mem.readInt(u32, payload[0..4], .big) & 0x7fffffff,
        .err_code = @enumFromInt(std.mem.readInt(u32, payload[4..8], .big)),
        .debug_data = payload[8..],
    } } };
}

fn parseWindowUpdate(header: Header, payload: []const u8) ParseResult {
    if (payload.len != 4) {
        return connErr(Error.FrameSize, header.stream_id);
    }
    const inc = std.mem.readInt(u32, payload[0..4], .big) & 0x7fffffff;
    if (inc == 0) {
        if (header.stream_id == 0) {
            return connErr(Error.Protocol, 0);
        }
        return streamErr(Error.Protocol, header.stream_id);
    }
    return .{ .ok = .{ .window_update = .{ .header = header, .increment = inc } } };
}

fn parseRstStream(header: Header, payload: []const u8) ParseResult {
    if (payload.len != 4) {
        return connErr(Error.FrameSize, header.stream_id);
    }
    if (header.stream_id == 0) {
        return connErr(Error.Protocol, 0);
    }
    return .{ .ok = .{ .rst_stream = .{
        .header = header,
        .err_code = @enumFromInt(std.mem.readInt(u32, payload[0..4], .big)),
    } } };
}

fn parseContinuation(header: Header, payload: []const u8) ParseResult {
    if (header.stream_id == 0) {
        return connErr(Error.Protocol, 0);
    }
    return .{ .ok = .{ .continuation = .{ .header = header, .fragment = payload } } };
}

/// Writer appends frames into a caller buffer (Framer without io).
pub const Writer = struct {
    buf: []u8,
    len: usize = 0,

    pub fn init(buf: []u8) Writer {
        return .{ .buf = buf };
    }

    pub fn bytes(w: *const Writer) []u8 {
        return w.buf[0..w.len];
    }

    fn start(w: *Writer, t: FrameType, flags: Flags, stream_id: u32) Error!usize {
        if (w.len + header_len > w.buf.len) return Error.NoSpaceLeft;
        const at = w.len;
        w.buf[at] = 0;
        w.buf[at + 1] = 0;
        w.buf[at + 2] = 0;
        w.buf[at + 3] = @intFromEnum(t);
        w.buf[at + 4] = flags;
        std.mem.writeInt(u32, w.buf[at + 5 ..][0..4], stream_id & 0x7fffffff, .big);
        w.len += header_len;
        return at;
    }

    fn end(w: *Writer, at: usize) Error!void {
        const length: u32 = @intCast(w.len - at - header_len);
        if (length >= 1 << 24) return Error.FrameTooLarge;
        w.buf[at] = @truncate(length >> 16);
        w.buf[at + 1] = @truncate(length >> 8);
        w.buf[at + 2] = @truncate(length);
    }

    fn raw(w: *Writer, data: []const u8) Error!void {
        if (w.len + data.len > w.buf.len) return Error.NoSpaceLeft;
        @memcpy(w.buf[w.len..][0..data.len], data);
        w.len += data.len;
    }

    fn u32be(w: *Writer, v: u32) Error!void {
        if (w.len + 4 > w.buf.len) return Error.NoSpaceLeft;
        std.mem.writeInt(u32, w.buf[w.len..][0..4], v, .big);
        w.len += 4;
    }

    fn validStreamID(id: u32) bool {
        return id != 0 and id & (1 << 31) == 0;
    }

    pub fn writeData(w: *Writer, stream_id: u32, end_stream: bool, data: []const u8) Error!void {
        if (!validStreamID(stream_id)) return Error.Protocol;
        const flags: Flags = if (end_stream) flag_data_end_stream else 0;
        const at = try w.start(.data, flags, stream_id);
        try w.raw(data);
        try w.end(at);
    }

    pub fn writeDataPadded(w: *Writer, stream_id: u32, end_stream: bool, data: []const u8, pad_len: u8) Error!void {
        if (!validStreamID(stream_id)) return Error.Protocol;
        var flags: Flags = flag_data_padded;
        if (end_stream) flags |= flag_data_end_stream;
        const at = try w.start(.data, flags, stream_id);
        try w.raw(&[_]u8{pad_len});
        try w.raw(data);
        var i: usize = 0;
        while (i < pad_len) : (i += 1) {
            try w.raw(&[_]u8{0});
        }
        try w.end(at);
    }

    pub fn writeHeaders(
        w: *Writer,
        stream_id: u32,
        fragment: []const u8,
        end_stream: bool,
        end_headers: bool,
        pad_len: u8,
    ) Error!void {
        if (!validStreamID(stream_id)) return Error.Protocol;
        var flags: Flags = 0;
        if (pad_len != 0) flags |= flag_headers_padded;
        if (end_stream) flags |= flag_headers_end_stream;
        if (end_headers) flags |= flag_headers_end_headers;
        const at = try w.start(.headers, flags, stream_id);
        if (pad_len != 0) {
            try w.raw(&[_]u8{pad_len});
        }
        try w.raw(fragment);
        var i: usize = 0;
        while (i < pad_len) : (i += 1) {
            try w.raw(&[_]u8{0});
        }
        try w.end(at);
    }

    pub fn writeContinuation(w: *Writer, stream_id: u32, end_headers: bool, fragment: []const u8) Error!void {
        if (!validStreamID(stream_id)) return Error.Protocol;
        const flags: Flags = if (end_headers) flag_continuation_end_headers else 0;
        const at = try w.start(.continuation, flags, stream_id);
        try w.raw(fragment);
        try w.end(at);
    }

    pub fn writeSettings(w: *Writer, settings: []const Setting) Error!void {
        const at = try w.start(.settings, 0, 0);
        for (settings) |s| {
            if (w.len + 6 > w.buf.len) return Error.NoSpaceLeft;
            std.mem.writeInt(u16, w.buf[w.len..][0..2], @intFromEnum(s.id), .big);
            std.mem.writeInt(u32, w.buf[w.len + 2 ..][0..4], s.val, .big);
            w.len += 6;
        }
        try w.end(at);
    }

    pub fn writeSettingsAck(w: *Writer) Error!void {
        const at = try w.start(.settings, flag_settings_ack, 0);
        try w.end(at);
    }

    pub fn writePing(w: *Writer, ack: bool, data: [8]u8) Error!void {
        const flags: Flags = if (ack) flag_ping_ack else 0;
        const at = try w.start(.ping, flags, 0);
        try w.raw(&data);
        try w.end(at);
    }

    pub fn writeGoAway(w: *Writer, last_stream_id: u32, code: ErrCode, debug_data: []const u8) Error!void {
        const at = try w.start(.goaway, 0, 0);
        try w.u32be(last_stream_id & 0x7fffffff);
        try w.u32be(@intFromEnum(code));
        try w.raw(debug_data);
        try w.end(at);
    }

    pub fn writeWindowUpdate(w: *Writer, stream_id: u32, incr: u32) Error!void {
        if (incr < 1 or incr > 2147483647) return Error.Protocol;
        const at = try w.start(.window_update, 0, stream_id);
        try w.u32be(incr);
        try w.end(at);
    }

    pub fn writeRstStream(w: *Writer, stream_id: u32, code: ErrCode) Error!void {
        if (!validStreamID(stream_id)) return Error.Protocol;
        const at = try w.start(.rst_stream, 0, stream_id);
        try w.u32be(@intFromEnum(code));
        try w.end(at);
    }
};
