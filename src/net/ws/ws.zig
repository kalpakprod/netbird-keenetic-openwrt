// RFC 6455 WebSocket client, plain TCP or TLS (std.crypto.tls, TLS 1.2/1.3).
// Scope: opening handshake with Sec-WebSocket-Accept verification, masked
// client frames, fragmented message reassembly with interleaved control
// frames, automatic pong on ping, close handling. One frame per write, like
// the upstream client (vendor/github.com/coder/websocket write.go). Message
// reads need no allocator: the caller supplies the buffer and oversize
// messages fail with MessageTooBig (the relay caps at 8820 bytes).
//
// Kernel 4.9 note: TLS certificate verification itself does no file I/O here;
// when CA bundles get loaded from disk for non-test connections, avoid
// File.stat (docs/kernel-4.9.md workaround).

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const websocket_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

pub const Opcode = enum(u4) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    close = 0x8,
    ping = 0x9,
    pong = 0xa,
    _,
};

pub const Message = struct {
    opcode: Opcode,
    data: []const u8,
};

pub const Error = error{
    /// EOF or unparseable HTTP response during the opening handshake
    HandshakeFailed,
    /// Sec-WebSocket-Accept mismatch
    BadAcceptKey,
    /// server frame violated RFC 6455 (mask, reserved bits, fragmented control,
    /// control payload > 125, continuation without start, data during fragments)
    ProtocolError,
    /// message does not fit the caller buffer
    MessageTooBig,
    /// peer sent a close frame (connection is done)
    CloseReceived,
    BufferTooSmall,
};

pub const TlsMode = union(enum) {
    /// plain TCP (ws://)
    none,
    /// verify the peer presents a valid self-signed certificate for `host`
    self_signed,
    /// verify against a caller-built CA bundle
    bundle: struct {
        gpa: Allocator,
        io: std.Io,
        lock: *std.Io.RwLock,
        bundle: *std.crypto.Certificate.Bundle,
    },
};

pub const ConnectOptions = struct {
    /// IP literal for the Host header, TLS SNI and certificate check.
    host: []const u8,
    port: u16,
    path: []const u8 = "/",
    tls: TlsMode = .none,
};

pub const CloseCode = enum(u16) {
    normal = 1000,
    going_away = 1001,
    protocol_error = 1002,
    unsupported_data = 1003,
    no_status_received = 1005,
    abnormal_closure = 1006,
    invalid_frame_payload = 1007,
    policy_violation = 1008,
    message_too_big = 1009,
    mandatory_extension = 1010,
    internal_error = 1011,
    _,
};

pub const Conn = struct {
    io: std.Io,
    gpa: Allocator,
    input: *std.Io.Reader,
    output: *std.Io.Writer,
    /// App-data writer: for TLS this is the plaintext writer inside the TLS
    /// client (std.http.Client.Connection.writer equivalent); for plain TCP it
    /// is the raw writer. Never write ciphertext through `output` directly.
    send: *std.Io.Writer,
    net: ?*NetState,
    scratch: []u8,
    close_sent: bool = false,

    /// Owns the socket and TLS state for connect()-built connections; tests
    /// inject reader/writer pairs instead and leave this null.
    pub const NetState = struct {
        stream: std.Io.net.Stream,
        raw_reader: std.Io.net.Stream.Reader,
        raw_writer: std.Io.net.Stream.Writer,
        tls_client: ?*std.crypto.tls.Client = null,
        heap: [4][]u8 = .{ &.{}, &.{}, &.{}, &.{} },
    };

    pub const ReadError = Error || std.Io.Reader.Error;

    pub fn readMessage(c: *Conn, out: []u8) ReadError!Message {
        var first_opcode: ?Opcode = null;
        var total: usize = 0;
        while (true) {
            const hdr = try c.readFrameHeader();
            switch (hdr.opcode) {
                .ping, .pong, .close => {
                    if (!hdr.fin or hdr.len > 125) return Error.ProtocolError;
                    var ctrl: [125]u8 = undefined;
                    try c.input.readSliceAll(ctrl[0..hdr.len]);
                    switch (hdr.opcode) {
                        .ping => c.writeFrame(.pong, ctrl[0..hdr.len]) catch {},
                        .pong => {},
                        else => {
                            // close: RFC 6455 §5.5.1 — echo the close, then stop.
                            if (!c.close_sent) {
                                c.close_sent = true;
                                c.writeFrame(.close, ctrl[0..hdr.len]) catch {};
                            }
                            return Error.CloseReceived;
                        },
                    }
                },
                .continuation, .text, .binary => {
                    if (hdr.opcode == .continuation) {
                        if (first_opcode == null) return Error.ProtocolError;
                    } else {
                        if (first_opcode != null) return Error.ProtocolError;
                        first_opcode = hdr.opcode;
                    }
                    if (total + hdr.len > out.len) return Error.MessageTooBig;
                    try c.input.readSliceAll(out[total..][0..hdr.len]);
                    total += hdr.len;
                    if (hdr.fin) return .{ .opcode = first_opcode.?, .data = out[0..total] };
                },
                else => return Error.ProtocolError,
            }
        }
    }

    /// One unfragmented data frame (the relay always sends whole messages).
    pub const WriteError = Error || std.Io.Writer.Error;

    pub fn writeMessage(c: *Conn, opcode: Opcode, payload: []const u8) WriteError!void {
        std.debug.assert(opcode == .text or opcode == .binary);
        try c.writeFrame(opcode, payload);
    }

    fn readFrameHeader(c: *Conn) !struct { fin: bool, opcode: Opcode, len: usize } {
        const base = try c.input.takeArray(2);
        const rsv = base[0] & 0x70;
        if (rsv != 0) return Error.ProtocolError; // no extensions negotiated
        if (base[1] & 0x80 != 0) return Error.ProtocolError; // server frames are never masked
        const fin = base[0] & 0x80 != 0;
        const opcode: Opcode = @fromBackingInt(@intCast(@as(u4, @truncate(base[0] & 0x0f))));
        const len7: u8 = base[1] & 0x7f;
        var len: usize = len7;
        switch (len7) {
            126 => {
                const ext = try c.input.takeArray(2);
                len = std.mem.readInt(u16, ext, .big);
            },
            127 => {
                const ext = try c.input.takeArray(8);
                const v = std.mem.readInt(u64, ext, .big);
                if (v & 0x8000_0000_0000_0000 != 0) return Error.ProtocolError;
                len = @intCast(v);
            },
            else => {},
        }
        return .{ .fin = fin, .opcode = opcode, .len = len };
    }

    fn writeFrame(c: *Conn, opcode: Opcode, payload: []const u8) !void {
        var hdr: [14]u8 = undefined;
        var mask: [4]u8 = undefined;
        c.io.random(&mask);
        hdr[0] = @as(u8, 0x80) | @as(u8, @backingInt(opcode));
        const plen = payload.len;
        var hdr_len: usize = switch (plen) {
            0...125 => blk: {
                hdr[1] = 0x80 | @as(u8, @intCast(plen));
                break :blk 2;
            },
            126...0xffff => blk: {
                hdr[1] = 0x80 | 126;
                std.mem.writeInt(u16, hdr[2..4], @intCast(plen), .big);
                break :blk 4;
            },
            else => blk: {
                hdr[1] = 0x80 | 127;
                std.mem.writeInt(u64, hdr[2..10], @intCast(plen), .big);
                break :blk 10;
            },
        };
        @memcpy(hdr[hdr_len..][0..4], &mask);
        hdr_len += 4;
        try c.send.writeAll(hdr[0..hdr_len]);
        var off: usize = 0;
        while (off < payload.len) {
            const n = @min(c.scratch.len, payload.len - off);
            const chunk = payload[off..][0..n];
            for (chunk, 0..) |b, i| c.scratch[i] = b ^ mask[(off + i) % 4];
            try c.send.writeAll(c.scratch[0..n]);
            off += n;
        }
        // one frame per flush: without it frames sit in the writer buffer
        try flushSend(c);
    }

    /// std.http.Client.Connection.flush equivalent: with TLS, flush the
    /// plaintext writer (encrypts into the raw writer), then push ciphertext
    /// to the socket.
    fn flushSend(c: *Conn) std.Io.Writer.Error!void {
        try c.send.flush();
        try c.output.flush();
    }

    /// Sends a close frame (best effort) and drops the socket.
    pub fn close(c: *Conn, code: CloseCode) void {
        if (!c.close_sent) {
            c.close_sent = true;
            var payload: [2]u8 = undefined;
            std.mem.writeInt(u16, &payload, @backingInt(code), .big);
            c.writeFrame(.close, &payload) catch {};
        }
        if (c.net) |n| n.stream.close(c.io);
    }

    pub fn destroy(c: *Conn) void {
        const gpa = c.gpa;
        if (c.net) |n| {
            if (n.tls_client) |t| gpa.destroy(t);
            for (n.heap) |buf| if (buf.len > 0) gpa.free(buf);
            gpa.destroy(n);
        }
        gpa.free(c.scratch);
        gpa.destroy(c);
    }
};

/// Opens a TCP (or TLS) connection, performs the RFC 6455 opening handshake
/// and returns the ready connection.
pub fn connect(gpa: Allocator, io: std.Io, opts: ConnectOptions) !*Conn {
    const addr = try std.Io.net.IpAddress.parse(opts.host, opts.port);
    const stream = try std.Io.net.IpAddress.connect(&addr, io, .{ .mode = .stream });
    errdefer stream.close(io);

    const conn = try gpa.create(Conn);
    errdefer gpa.destroy(conn);
    const scratch = try gpa.alloc(u8, 4096);
    errdefer gpa.free(scratch);

    const net = try gpa.create(Conn.NetState);
    errdefer gpa.destroy(net);
    net.* = .{ .stream = stream, .raw_reader = undefined, .raw_writer = undefined };

    const tls_mode = opts.tls;
    // Buffer sizes follow std.http.Client: raw readers/writers hold at least
    // one max-size TLS record.
    const raw_len: usize = switch (tls_mode) {
        .none => 4096,
        else => std.crypto.tls.Client.min_buffer_len,
    };
    const read_buf = try gpa.alloc(u8, raw_len);
    errdefer gpa.free(read_buf);
    const write_buf = try gpa.alloc(u8, raw_len);
    errdefer gpa.free(write_buf);
    net.heap[0] = read_buf;
    net.heap[1] = write_buf;

    net.raw_reader = stream.reader(io, read_buf);
    net.raw_writer = stream.writer(io, write_buf);

    var input: *std.Io.Reader = &net.raw_reader.interface;

    if (tls_mode != .none) {
        var entropy: [std.crypto.tls.Client.Options.entropy_len]u8 = undefined;
        io.random(&entropy);
        const tls_read_buf = try gpa.alloc(u8, std.crypto.tls.Client.min_buffer_len);
        errdefer gpa.free(tls_read_buf);
        const tls_write_buf = try gpa.alloc(u8, 1024);
        errdefer gpa.free(tls_write_buf);
        net.heap[2] = tls_read_buf;
        net.heap[3] = tls_write_buf;

        const client = try gpa.create(std.crypto.tls.Client);
        errdefer gpa.destroy(client);
        client.* = try std.crypto.tls.Client.init(
            &net.raw_reader.interface,
            &net.raw_writer.interface,
            .{
                .host = .{ .explicit = opts.host },
                .ca = switch (tls_mode) {
                    .none => unreachable,
                    .self_signed => .self_signed,
                    .bundle => |b| .{ .bundle = .{ .gpa = b.gpa, .io = b.io, .lock = b.lock, .bundle = b.bundle } },
                },
                .read_buffer = tls_read_buf,
                .write_buffer = tls_write_buf,
                .entropy = &entropy,
                .realtime_now = std.Io.Timestamp.now(io, .real),
            },
        );
        net.tls_client = client;
        input = &client.reader;
        try handshake(input, &client.writer, &net.raw_writer.interface, opts.host, opts.port, opts.path, io);
        conn.* = .{
            .io = io,
            .gpa = gpa,
            .input = input,
            .output = &net.raw_writer.interface,
            .send = &client.writer,
            .net = net,
            .scratch = scratch,
        };
        return conn;
    }

    try handshake(input, &net.raw_writer.interface, &net.raw_writer.interface, opts.host, opts.port, opts.path, io);

    conn.* = .{
        .io = io,
        .gpa = gpa,
        .input = input,
        .output = &net.raw_writer.interface,
        .send = &net.raw_writer.interface,
        .net = net,
        .scratch = scratch,
    };
    return conn;
}

fn handshake(
    input: *std.Io.Reader,
    send: *std.Io.Writer,
    raw_output: *std.Io.Writer,
    host: []const u8,
    port: u16,
    path: []const u8,
    io: std.Io,
) !void {
    var key_raw: [16]u8 = undefined;
    io.random(&key_raw);
    var key_b64: [24]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&key_b64, &key_raw);

    var host_buf: [256]u8 = undefined;
    const hostport = try formatHost(&host_buf, host, port);

    var req_buf: [1024]u8 = undefined;
    const req = try std.fmt.bufPrint(&req_buf, "GET {s} HTTP/1.1\r\n" ++
        "Host: {s}\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: {s}\r\n" ++
        "Sec-WebSocket-Version: 13\r\n" ++
        "\r\n", .{ path, hostport, &key_b64 });
    try send.writeAll(req);
    // TLS: first flush encrypts the request into the raw writer, second push
    // ciphertext to the socket (std.http.Client.Connection.flush recipe).
    try send.flush();
    try raw_output.flush();

    // Response head: status line + headers, then the message stream continues
    // on the same connection.
    var accept_expected: [28]u8 = undefined;
    {
        var sha = std.crypto.hash.Sha1.init(.{});
        sha.update(&key_b64);
        sha.update(websocket_guid);
        _ = std.base64.standard.Encoder.encode(&accept_expected, &sha.finalResult());
    }

    const status = (try takeLine(input)) orelse return Error.HandshakeFailed;
    if (!std.mem.startsWith(u8, status, "HTTP/1.1 101") and !std.mem.startsWith(u8, status, "HTTP/1.0 101")) {
        return Error.HandshakeFailed;
    }

    var saw_upgrade = false;
    var saw_connection = false;
    var saw_accept = false;
    var lines: usize = 0;
    while (true) {
        lines += 1;
        if (lines > 128) return Error.HandshakeFailed;
        const line = (try takeLine(input)) orelse return Error.HandshakeFailed;
        if (line.len == 0) break; // end of headers
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return Error.HandshakeFailed;
        const name = std.mem.trim(u8, line[0..colon], " \t");
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (std.ascii.eqlIgnoreCase(name, "upgrade")) {
            if (std.ascii.eqlIgnoreCase(value, "websocket")) saw_upgrade = true;
        } else if (std.ascii.eqlIgnoreCase(name, "connection")) {
            // token list; Upgrade may appear anywhere in it
            var it = std.mem.splitScalar(u8, value, ',');
            while (it.next()) |tok| {
                if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, tok, " \t"), "upgrade")) saw_connection = true;
            }
        } else if (std.ascii.eqlIgnoreCase(name, "sec-websocket-accept")) {
            if (std.ascii.eqlIgnoreCase(value, &accept_expected)) saw_accept = true;
        }
    }
    if (!saw_upgrade or !saw_connection or !saw_accept) return Error.BadAcceptKey;
}

pub fn formatHost(buf: []u8, host: []const u8, port: u16) ![]const u8 {
    const bracketed = std.mem.indexOfScalar(u8, host, ':') != null and !std.mem.startsWith(u8, host, "[");
    if (port == 80) return if (bracketed) try std.fmt.bufPrint(buf, "[{s}]", .{host}) else host;
    return if (bracketed) try std.fmt.bufPrint(buf, "[{s}]:{d}", .{host, port}) else try std.fmt.bufPrint(buf, "{s}:{d}", .{host, port});
}

fn takeLine(input: *std.Io.Reader) !?[]const u8 {
    // takeDelimiter consumes the '\n' too (the Exclusive variant leaves it in
    // the buffer, which would make every other call return an empty line)
    const line = try input.takeDelimiter('\n');
    if (line) |l| return std.mem.trim(u8, l, "\r");
    return null;
}

test {
    _ = @import("ws_test.zig");
}
