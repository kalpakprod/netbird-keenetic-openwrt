// Port of golang.org/x/net/http2 client connection (BSD-3-Clause) — tests.
// Server bytes: testdata/conn.txt from gen/h2servervecs (real Framer +
// hpack Encoder). Transport is an in-memory pipe pair.

const std = @import("std");
const frame = @import("frame.zig");
const hpack = @import("hpack.zig");
const conn = @import("conn.zig");

const vectors_raw = @embedFile("testdata/conn.txt");

fn hexOf(name: []const u8) []const u8 {
    var it = std.mem.splitScalar(u8, vectors_raw, '\n');
    while (it.next()) |line| {
        if (line.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, line, '=').?;
        if (std.mem.eql(u8, line[0..eq], name)) {
            return line[eq + 1 ..];
        }
    }
    unreachable;
}

fn bytesOf(allocator: std.mem.Allocator, name: []const u8) ![]u8 {
    const hx = hexOf(name);
    const out = try allocator.alloc(u8, hx.len / 2);
    _ = try std.fmt.hexToBytes(out, hx);
    return out;
}

/// In-memory full-duplex pipe: inbound feeds reads, outbound records writes.
const Pipe = struct {
    inbound: []const u8,
    in_pos: usize = 0,
    outbound: [65536]u8 = undefined,
    out_len: usize = 0,

    fn read(ctx: *anyopaque, buf: []u8) conn.Transport.ReadError!usize {
        const self: *Pipe = @ptrCast(@alignCast(ctx));
        if (self.in_pos >= self.inbound.len) return 0;
        const n = @min(buf.len, self.inbound.len - self.in_pos);
        @memcpy(buf[0..n], self.inbound[self.in_pos..][0..n]);
        self.in_pos += n;
        return n;
    }

    fn write(ctx: *anyopaque, buf: []const u8) conn.Transport.WriteError!void {
        const self: *Pipe = @ptrCast(@alignCast(ctx));
        @memcpy(self.outbound[self.out_len..][0..buf.len], buf);
        self.out_len += buf.len;
    }

    fn transport(p: *Pipe) conn.Transport {
        return .{ .ctx = p, .readFn = read, .writeFn = write };
    }
};

fn frameBytes(allocator: std.mem.Allocator, t: frame.FrameType, flags: frame.Flags, id: u32, payload: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, frame.header_len + payload.len);
    out[0] = @truncate(payload.len >> 16);
    out[1] = @truncate(payload.len >> 8);
    out[2] = @truncate(payload.len);
    out[3] = @intFromEnum(t);
    out[4] = flags;
    std.mem.writeInt(u32, out[5..9], id, .big);
    @memcpy(out[9..], payload);
    return out;
}

test "handshake writes preface and acks server settings" {
    const srv_settings = try bytesOf(std.testing.allocator, "SRV_SETTINGS");
    defer std.testing.allocator.free(srv_settings);
    var pipe = Pipe{ .inbound = srv_settings };
    var c = conn.Conn.init(pipe.transport());
    try c.handshake();
    // preface magic + our settings + settings ack
    const magic = frame.client_preface;
    try std.testing.expectEqualSlices(u8, magic, pipe.outbound[0..magic.len]);
    var off = magic.len;
    // our settings: enable_push=0, initial_window=65535, max_frame=16384
    const sh = frame.Header.parse(pipe.outbound[off..][0..frame.header_len]);
    try std.testing.expectEqual(frame.FrameType.settings, sh.type);
    try std.testing.expectEqual(@as(u32, 18), sh.length);
    off += frame.header_len + sh.length;
    // settings ack
    const ah = frame.Header.parse(pipe.outbound[off..][0..frame.header_len]);
    try std.testing.expectEqual(frame.FrameType.settings, ah.type);
    try std.testing.expect(ah.hasFlags(frame.flag_settings_ack));
    try std.testing.expectEqual(@as(u32, 0), ah.length);
    // peer settings applied
    try std.testing.expectEqual(@as(u32, 16384), c.peer_max_frame_size);
    try std.testing.expectEqual(@as(u32, 65535), c.peer_initial_window);
}

test "handshake rejects non-settings first frame" {
    var ping = [_]u8{ 0, 0, 8, 6, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8 };
    var pipe = Pipe{ .inbound = &ping };
    var c = conn.Conn.init(pipe.transport());
    try std.testing.expectError(conn.Error.Protocol, c.handshake());
}

test "request/response/data/trailers round trip" {
    const alloc = std.testing.allocator;
    const srv_settings = try bytesOf(alloc, "SRV_SETTINGS");
    defer alloc.free(srv_settings);
    const resp_headers = try bytesOf(alloc, "RESP_HEADERS");
    defer alloc.free(resp_headers);
    const trailers = try bytesOf(alloc, "TRAILERS");
    defer alloc.free(trailers);

    const f_resp = try frameBytes(alloc, .headers, frame.flag_headers_end_headers, 1, resp_headers);
    defer alloc.free(f_resp);
    const f_data = try frameBytes(alloc, .data, 0, 1, "grpc-payload-bytes");
    defer alloc.free(f_data);
    const f_trail = try frameBytes(alloc, .headers, frame.flag_headers_end_headers | frame.flag_headers_end_stream, 1, trailers);
    defer alloc.free(f_trail);

    var inbound: [4096]u8 = undefined;
    var ilen: usize = 0;
    for ([_][]const u8{ srv_settings, f_resp, f_data, f_trail }) |b| {
        @memcpy(inbound[ilen..][0..b.len], b);
        ilen += b.len;
    }
    var pipe = Pipe{ .inbound = inbound[0..ilen] };
    var c = conn.Conn.init(pipe.transport());
    try c.handshake();

    const sid = try c.writeHeaders(&[_]hpack.HeaderField{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/svc/Method" },
    }, false);
    try std.testing.expectEqual(@as(u32, 1), sid);

    // response headers
    const ev1 = (try c.readNext()).?;
    try std.testing.expectEqual(@as(u32, 1), ev1.response_headers.stream_id);
    try std.testing.expect(!ev1.response_headers.end_stream);
    try std.testing.expectEqual(@as(usize, 2), ev1.response_headers.fields.len);
    try std.testing.expectEqualStrings(":status", ev1.response_headers.fields[0].name);
    try std.testing.expectEqualStrings("200", ev1.response_headers.fields[0].value);
    try std.testing.expectEqualStrings("application/grpc", ev1.response_headers.fields[1].value);

    // data
    const ev2 = (try c.readNext()).?;
    try std.testing.expectEqualStrings("grpc-payload-bytes", ev2.data.bytes);
    try std.testing.expect(!ev2.data.end_stream);
    try std.testing.expectEqual(@as(i64, 65535 - 18), c.conn_recv_window);

    // trailers
    const ev3 = (try c.readNext()).?;
    try std.testing.expect(ev3.trailers.end_stream);
    try std.testing.expectEqual(@as(usize, 1), ev3.trailers.fields.len);
    try std.testing.expectEqualStrings("grpc-status", ev3.trailers.fields[0].name);
    try std.testing.expectEqualStrings("0", ev3.trailers.fields[0].value);
}

test "continuation reassembly and sequencing" {
    const alloc = std.testing.allocator;
    const srv_settings = try bytesOf(alloc, "SRV_SETTINGS");
    defer alloc.free(srv_settings);
    const big = try bytesOf(alloc, "BIG");
    defer alloc.free(big);

    // split the block across HEADERS + 2 CONTINUATIONs
    const f1 = try frameBytes(alloc, .headers, 0, 1, big[0..100]);
    defer alloc.free(f1);
    const f2 = try frameBytes(alloc, .continuation, 0, 1, big[100..200]);
    defer alloc.free(f2);
    const f3 = try frameBytes(alloc, .continuation, frame.flag_continuation_end_headers, 1, big[200..]);
    defer alloc.free(f3);

    var inbound: [4096]u8 = undefined;
    var ilen: usize = 0;
    for ([_][]const u8{ srv_settings, f1, f2, f3 }) |b| {
        @memcpy(inbound[ilen..][0..b.len], b);
        ilen += b.len;
    }
    var pipe = Pipe{ .inbound = inbound[0..ilen] };
    var c = conn.Conn.init(pipe.transport());
    try c.handshake();
    _ = try c.writeHeaders(&[_]hpack.HeaderField{.{ .name = ":method", .value = "POST" }}, false);

    try std.testing.expect((try c.readNext()) == null);
    try std.testing.expect((try c.readNext()) == null);
    const ev = (try c.readNext()).?;
    try std.testing.expectEqual(@as(usize, 1), ev.response_headers.fields.len);
    try std.testing.expectEqualStrings("x-big", ev.response_headers.fields[0].name);
    try std.testing.expectEqual(@as(usize, 300), ev.response_headers.fields[0].value.len);

    // interleaved frame during continuation is a protocol error
    const f_ping = try frameBytes(alloc, .ping, 0, 0, &[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 });
    defer alloc.free(f_ping);
    var inbound2: [4096]u8 = undefined;
    var ilen2: usize = 0;
    for ([_][]const u8{ srv_settings, f1, f_ping }) |b| {
        @memcpy(inbound2[ilen2..][0..b.len], b);
        ilen2 += b.len;
    }
    var pipe2 = Pipe{ .inbound = inbound2[0..ilen2] };
    var c2 = conn.Conn.init(pipe2.transport());
    try c2.handshake();
    _ = try c2.writeHeaders(&[_]hpack.HeaderField{.{ .name = ":method", .value = "POST" }}, false);
    try std.testing.expect((try c2.readNext()) == null);
    try std.testing.expectError(conn.Error.Protocol, c2.readNext());
}

test "flow control accounting" {
    const alloc = std.testing.allocator;
    const srv_settings = try bytesOf(alloc, "SRV_SETTINGS");
    defer alloc.free(srv_settings);
    const resp_headers = try bytesOf(alloc, "RESP_HEADERS");
    defer alloc.free(resp_headers);
    const f_resp = try frameBytes(alloc, .headers, frame.flag_headers_end_headers, 1, resp_headers);
    defer alloc.free(f_resp);

    var inbound: [2048]u8 = undefined;
    @memcpy(inbound[0..srv_settings.len], srv_settings);
    @memcpy(inbound[srv_settings.len..][0..f_resp.len], f_resp);
    var pipe = Pipe{ .inbound = inbound[0 .. srv_settings.len + f_resp.len] };
    var c = conn.Conn.init(pipe.transport());
    try c.handshake();
    _ = try c.writeHeaders(&[_]hpack.HeaderField{.{ .name = ":method", .value = "POST" }}, false);
    _ = try c.readNext();

    // send window starts at peer initial window
    var big: [70000]u8 = undefined;
    @memset(&big, 'x');
    try std.testing.expectError(conn.Error.FlowControl, c.writeData(1, &big, false));
    // small write fits and decrements
    try c.writeData(1, "12345", false);
    try std.testing.expectEqual(@as(i64, 65535 - 5), c.conn_send_window);
    // window update grows the connection window
    const f_wu = try frameBytes(alloc, .window_update, 0, 0, &[_]u8{ 0, 1, 0, 0 });
    defer alloc.free(f_wu);
    var pipe2 = Pipe{ .inbound = f_wu };
    c.transport = pipe2.transport();
    const ev = (try c.readNext()).?;
    try std.testing.expectEqual(@as(u32, 65536), ev.window_update.increment);
    try std.testing.expectEqual(@as(i64, 65535 - 5 + 65536), c.conn_send_window);
    // window update overflow is a flow-control error
    const f_big = try frameBytes(alloc, .window_update, 0, 0, &[_]u8{ 0x7f, 0xff, 0xff, 0xff });
    defer alloc.free(f_big);
    var pipe3 = Pipe{ .inbound = f_big };
    c.transport = pipe3.transport();
    try std.testing.expectError(conn.Error.FlowControl, c.readNext());
    // explicit receive-window top-up emits the frame and grows the window
    var pipe4 = Pipe{ .inbound = &.{} };
    c.transport = pipe4.transport();
    const before = c.conn_recv_window;
    try c.sendWindowUpdate(0, 1000);
    try std.testing.expectEqual(before + 1000, c.conn_recv_window);
    const wh = frame.Header.parse(pipe4.outbound[0..frame.header_len]);
    try std.testing.expectEqual(frame.FrameType.window_update, wh.type);
}

test "settings apply and rst/goaway handling" {
    const alloc = std.testing.allocator;
    const srv_settings = try bytesOf(alloc, "SRV_SETTINGS");
    defer alloc.free(srv_settings);
    var pipe = Pipe{ .inbound = srv_settings };
    var c = conn.Conn.init(pipe.transport());
    try c.handshake();
    _ = try c.writeHeaders(&[_]hpack.HeaderField{.{ .name = ":method", .value = "POST" }}, false);

    // peer grows max frame size -> applied and acked
    const f_set = try frameBytes(alloc, .settings, 0, 0, &[_]u8{ 0, 5, 0, 0, 0x80, 0 });
    defer alloc.free(f_set);
    var pipe2 = Pipe{ .inbound = f_set };
    c.transport = pipe2.transport();
    const ev = (try c.readNext()).?;
    try std.testing.expect(ev == .settings_applied);
    try std.testing.expectEqual(@as(u32, 32768), c.peer_max_frame_size);
    // ack was written
    const ah = frame.Header.parse(pipe2.outbound[0..frame.header_len]);
    try std.testing.expect(ah.hasFlags(frame.flag_settings_ack));

    // max frame size below 2^14 is a protocol error
    const f_bad = try frameBytes(alloc, .settings, 0, 0, &[_]u8{ 0, 5, 0, 0, 0, 64 });
    defer alloc.free(f_bad);
    var pipe2b = Pipe{ .inbound = f_bad };
    c.transport = pipe2b.transport();
    try std.testing.expectError(conn.Error.Protocol, c.readNext());

    // big headers fragment into HEADERS + CONTINUATION (white-box small
    // peer max frame; the wire minimum is 2^14)
    c.peer_max_frame_size = 64;
    var big_val: [300]u8 = undefined;
    @memset(&big_val, 'y');
    var pipe3 = Pipe{ .inbound = &.{} };
    c.transport = pipe3.transport();
    _ = try c.writeHeaders(&[_]hpack.HeaderField{.{ .name = "x-big", .value = &big_val }}, false);
    const h1 = frame.Header.parse(pipe3.outbound[0..frame.header_len]);
    try std.testing.expectEqual(frame.FrameType.headers, h1.type);
    try std.testing.expect(!h1.hasFlags(frame.flag_headers_end_headers));
    try std.testing.expectEqual(@as(u32, 64), h1.length);
    const h2 = frame.Header.parse(pipe3.outbound[frame.header_len + 64 ..][0..frame.header_len]);
    try std.testing.expectEqual(frame.FrameType.continuation, h2.type);

    // rst closes the stream; further data is refused
    const f_rst = try frameBytes(alloc, .rst_stream, 0, 1, &[_]u8{ 0, 0, 0, 8 });
    defer alloc.free(f_rst);
    var pipe4 = Pipe{ .inbound = f_rst };
    c.transport = pipe4.transport();
    const ev2 = (try c.readNext()).?;
    try std.testing.expectEqual(frame.ErrCode.cancel, ev2.rst.code);
    try std.testing.expectError(conn.Error.StreamClosed, c.writeData(1, "x", false));

    // goaway is recorded and blocks new streams
    const f_ga = try frameBytes(alloc, .goaway, 0, 0, &[_]u8{ 0, 0, 0, 1, 0, 0, 0, 0 });
    defer alloc.free(f_ga);
    var pipe5 = Pipe{ .inbound = f_ga };
    c.transport = pipe5.transport();
    const ev3 = (try c.readNext()).?;
    try std.testing.expectEqual(@as(u32, 1), ev3.goaway.last_stream_id);
    try std.testing.expectError(conn.Error.RefusedStream, c.writeHeaders(&[_]hpack.HeaderField{.{ .name = ":method", .value = "POST" }}, false));
}
