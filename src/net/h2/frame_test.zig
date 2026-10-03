// Port of golang.org/x/net/http2 frame codec (BSD-3-Clause) — tests.
// Vectors: src/ntestdata/frames.txt from gen/h2framevecs (real Framer).

const std = @import("std");
const frame = @import("frame.zig");

const vectors_raw = @embedFile("testdata/frames.txt");

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

fn splitHeader(buf: []const u8) struct { header: frame.Header, payload: []const u8 } {
    const h = frame.Header.parse(buf[0..frame.header_len]);
    return .{ .header = h, .payload = buf[frame.header_len .. frame.header_len + h.length] };
}

test "settings round trip" {
    const raw = try bytesOf(std.testing.allocator, "SETTINGS");
    defer std.testing.allocator.free(raw);
    const sp = splitHeader(raw);
    try std.testing.expectEqual(frame.FrameType.settings, sp.header.type);
    try std.testing.expectEqual(@as(u32, 0), sp.header.stream_id);
    const r = frame.parse(sp.header, sp.payload);
    const s = r.ok.settings;
    try std.testing.expect(!s.isAck());
    try std.testing.expectEqual(@as(usize, 3), s.numSettings());
    try std.testing.expectEqual(@as(u32, 4096), s.value(.header_table_size).?);
    try std.testing.expectEqual(@as(u32, 1048576), s.value(.initial_window_size).?);
    try std.testing.expectEqual(@as(u32, 16384), s.value(.max_frame_size).?);

    var buf: [64]u8 = undefined;
    var w = frame.Writer.init(&buf);
    try w.writeSettings(&[_]frame.Setting{
        .{ .id = .header_table_size, .val = 4096 },
        .{ .id = .initial_window_size, .val = 1048576 },
        .{ .id = .max_frame_size, .val = 16384 },
    });
    try std.testing.expectEqualSlices(u8, raw, w.bytes());

    const ack_raw = try bytesOf(std.testing.allocator, "SETTINGS_ACK");
    defer std.testing.allocator.free(ack_raw);
    const ap = splitHeader(ack_raw);
    const ar = frame.parse(ap.header, ap.payload);
    try std.testing.expect(ar.ok.settings.isAck());
    var buf2: [16]u8 = undefined;
    var w2 = frame.Writer.init(&buf2);
    try w2.writeSettingsAck();
    try std.testing.expectEqualSlices(u8, ack_raw, w2.bytes());
}

test "headers and continuation round trip" {
    const raw = try bytesOf(std.testing.allocator, "HEADERS");
    defer std.testing.allocator.free(raw);
    const sp = splitHeader(raw);
    const r = frame.parse(sp.header, sp.payload);
    const h = r.ok.headers;
    try std.testing.expectEqual(@as(u32, 1), sp.header.stream_id);
    try std.testing.expect(h.headersEnded());
    try std.testing.expect(!h.streamEnded());
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x82, 0x86, 0x84 }, h.fragment);

    var buf: [32]u8 = undefined;
    var w = frame.Writer.init(&buf);
    try w.writeHeaders(1, &[_]u8{ 0x82, 0x86, 0x84 }, false, true, 0);
    try std.testing.expectEqualSlices(u8, raw, w.bytes());

    const open_raw = try bytesOf(std.testing.allocator, "HEADERS_OPEN");
    defer std.testing.allocator.free(open_raw);
    const op = splitHeader(open_raw);
    const or_ = frame.parse(op.header, op.payload);
    try std.testing.expect(!or_.ok.headers.headersEnded());
    try std.testing.expect(or_.ok.headers.streamEnded());

    const cont_raw = try bytesOf(std.testing.allocator, "CONTINUATION");
    defer std.testing.allocator.free(cont_raw);
    const cp = splitHeader(cont_raw);
    const cr = frame.parse(cp.header, cp.payload);
    try std.testing.expect(cr.ok.continuation.headersEnded());
    try std.testing.expectEqualSlices(u8, &[_]u8{0xc1}, cr.ok.continuation.fragment);
    var buf3: [16]u8 = undefined;
    var w3 = frame.Writer.init(&buf3);
    try w3.writeContinuation(3, true, &[_]u8{0xc1});
    try std.testing.expectEqualSlices(u8, cont_raw, w3.bytes());
}

test "data round trip incl padding" {
    const raw = try bytesOf(std.testing.allocator, "DATA");
    defer std.testing.allocator.free(raw);
    const sp = splitHeader(raw);
    const r = frame.parse(sp.header, sp.payload);
    try std.testing.expectEqualStrings("hello-h2-data", r.ok.data.data);
    var buf: [64]u8 = undefined;
    var w = frame.Writer.init(&buf);
    try w.writeData(1, false, "hello-h2-data");
    try std.testing.expectEqualSlices(u8, raw, w.bytes());

    const empty_raw = try bytesOf(std.testing.allocator, "DATA_EMPTY_END");
    defer std.testing.allocator.free(empty_raw);
    const ep = splitHeader(empty_raw);
    try std.testing.expect(ep.header.hasFlags(frame.flag_data_end_stream));
    const er = frame.parse(ep.header, ep.payload);
    try std.testing.expectEqual(@as(usize, 0), er.ok.data.data.len);

    const pad_raw = try bytesOf(std.testing.allocator, "DATA_PADDED");
    defer std.testing.allocator.free(pad_raw);
    const pp = splitHeader(pad_raw);
    const pr = frame.parse(pp.header, pp.payload);
    try std.testing.expectEqualStrings("padme", pr.ok.data.data);
    var buf2: [32]u8 = undefined;
    var w2 = frame.Writer.init(&buf2);
    try w2.writeDataPadded(5, false, "padme", 3);
    try std.testing.expectEqualSlices(u8, pad_raw, w2.bytes());
}

test "ping goaway window rst round trip" {
    const alloc = std.testing.allocator;

    const ping_raw = try bytesOf(alloc, "PING");
    defer alloc.free(ping_raw);
    const pgp = splitHeader(ping_raw);
    const pgr = frame.parse(pgp.header, pgp.payload);
    try std.testing.expect(!pgr.ok.ping.isAck());
    try std.testing.expectEqual([8]u8{ 1, 2, 3, 4, 5, 6, 7, 8 }, pgr.ok.ping.data);
    var buf: [32]u8 = undefined;
    var w = frame.Writer.init(&buf);
    try w.writePing(false, .{ 1, 2, 3, 4, 5, 6, 7, 8 });
    try std.testing.expectEqualSlices(u8, ping_raw, w.bytes());

    const pa_raw = try bytesOf(alloc, "PING_ACK");
    defer alloc.free(pa_raw);
    const pap = splitHeader(pa_raw);
    const par = frame.parse(pap.header, pap.payload);
    try std.testing.expect(par.ok.ping.isAck());

    const ga_raw = try bytesOf(alloc, "GOAWAY");
    defer alloc.free(ga_raw);
    const gp = splitHeader(ga_raw);
    const gr = frame.parse(gp.header, gp.payload);
    try std.testing.expectEqual(@as(u32, 7), gr.ok.goaway.last_stream_id);
    try std.testing.expectEqual(frame.ErrCode.no, gr.ok.goaway.err_code);
    try std.testing.expectEqualStrings("bye", gr.ok.goaway.debug_data);
    var buf2: [32]u8 = undefined;
    var w2 = frame.Writer.init(&buf2);
    try w2.writeGoAway(7, .no, "bye");
    try std.testing.expectEqualSlices(u8, ga_raw, w2.bytes());

    const wc_raw = try bytesOf(alloc, "WINDOW_CONN");
    defer alloc.free(wc_raw);
    const wcp = splitHeader(wc_raw);
    const wcr = frame.parse(wcp.header, wcp.payload);
    try std.testing.expectEqual(@as(u32, 65535), wcr.ok.window_update.increment);
    var buf3: [16]u8 = undefined;
    var w3 = frame.Writer.init(&buf3);
    try w3.writeWindowUpdate(0, 65535);
    try std.testing.expectEqualSlices(u8, wc_raw, w3.bytes());

    const ws_raw = try bytesOf(alloc, "WINDOW_STREAM");
    defer alloc.free(ws_raw);
    const wsp = splitHeader(ws_raw);
    const wsr = frame.parse(wsp.header, wsp.payload);
    try std.testing.expectEqual(@as(u32, 1024), wsr.ok.window_update.increment);

    const rst_raw = try bytesOf(alloc, "RST");
    defer alloc.free(rst_raw);
    const rp = splitHeader(rst_raw);
    const rr = frame.parse(rp.header, rp.payload);
    try std.testing.expectEqual(frame.ErrCode.cancel, rr.ok.rst_stream.err_code);
    var buf4: [16]u8 = undefined;
    var w4 = frame.Writer.init(&buf4);
    try w4.writeRstStream(3, .cancel);
    try std.testing.expectEqualSlices(u8, rst_raw, w4.bytes());
}

test "headers padding and priority parse" {
    const raw = try bytesOf(std.testing.allocator, "HEADERS_PAD_PRIO");
    defer std.testing.allocator.free(raw);
    const sp = splitHeader(raw);
    const r = frame.parse(sp.header, sp.payload);
    const h = r.ok.headers;
    try std.testing.expect(h.hasPriority());
    try std.testing.expectEqual(@as(u32, 1), h.priority_stream_dep);
    try std.testing.expect(h.priority_exclusive);
    try std.testing.expectEqual(@as(u8, 200), h.priority_weight);
    try std.testing.expectEqualSlices(u8, &[_]u8{0x82}, h.fragment);
}

test "frame validation errors" {
    // settings ack with payload
    var h = frame.Header{ .length = 6, .type = .settings, .flags = frame.flag_settings_ack, .stream_id = 0 };
    var r = frame.parse(h, &[_]u8{ 0, 1, 0, 0, 0, 0 });
    try std.testing.expectEqual(frame.Error.FrameSize, r.err.err);
    try std.testing.expectEqual(frame.Scope.connection, r.err.scope);
    // settings on a stream
    h = frame.Header{ .length = 0, .type = .settings, .flags = 0, .stream_id = 1 };
    r = frame.parse(h, &[_]u8{});
    try std.testing.expectEqual(frame.Error.Protocol, r.err.err);
    // settings length not multiple of 6
    h = frame.Header{ .length = 5, .type = .settings, .flags = 0, .stream_id = 0 };
    r = frame.parse(h, &[_]u8{ 0, 1, 2, 3, 4 });
    try std.testing.expectEqual(frame.Error.FrameSize, r.err.err);
    // initial window size over 2^31-1
    h = frame.Header{ .length = 6, .type = .settings, .flags = 0, .stream_id = 0 };
    r = frame.parse(h, &[_]u8{ 0, 4, 0x80, 0, 0, 0 });
    try std.testing.expectEqual(frame.Error.FlowControl, r.err.err);
    // ping wrong length
    h = frame.Header{ .length = 4, .type = .ping, .flags = 0, .stream_id = 0 };
    r = frame.parse(h, &[_]u8{ 1, 2, 3, 4 });
    try std.testing.expectEqual(frame.Error.FrameSize, r.err.err);
    // ping on stream
    h = frame.Header{ .length = 8, .type = .ping, .flags = 0, .stream_id = 1 };
    r = frame.parse(h, &[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 });
    try std.testing.expectEqual(frame.Error.Protocol, r.err.err);
    // data on stream 0
    h = frame.Header{ .length = 1, .type = .data, .flags = 0, .stream_id = 0 };
    r = frame.parse(h, &[_]u8{0xaa});
    try std.testing.expectEqual(frame.Error.Protocol, r.err.err);
    try std.testing.expectEqual(frame.Scope.connection, r.err.scope);
    // data padding longer than payload
    h = frame.Header{ .length = 2, .type = .data, .flags = frame.flag_data_padded, .stream_id = 1 };
    r = frame.parse(h, &[_]u8{ 5, 0xaa });
    try std.testing.expectEqual(frame.Error.Protocol, r.err.err);
    // window update zero increment on connection vs stream scope
    h = frame.Header{ .length = 4, .type = .window_update, .flags = 0, .stream_id = 0 };
    r = frame.parse(h, &[_]u8{ 0, 0, 0, 0 });
    try std.testing.expectEqual(frame.Scope.connection, r.err.scope);
    h = frame.Header{ .length = 4, .type = .window_update, .flags = 0, .stream_id = 3 };
    r = frame.parse(h, &[_]u8{ 0, 0, 0, 0 });
    try std.testing.expectEqual(frame.Scope.stream, r.err.scope);
    // continuation on stream 0
    h = frame.Header{ .length = 1, .type = .continuation, .flags = 0, .stream_id = 0 };
    r = frame.parse(h, &[_]u8{0xc1});
    try std.testing.expectEqual(frame.Error.Protocol, r.err.err);
    // rst on stream 0
    h = frame.Header{ .length = 4, .type = .rst_stream, .flags = 0, .stream_id = 0 };
    r = frame.parse(h, &[_]u8{ 0, 0, 0, 8 });
    try std.testing.expectEqual(frame.Error.Protocol, r.err.err);
    // writer rejects bad stream ids and increments
    var buf: [32]u8 = undefined;
    var w = frame.Writer.init(&buf);
    try std.testing.expectError(frame.Error.Protocol, w.writeData(0, false, "x"));
    try std.testing.expectError(frame.Error.Protocol, w.writeWindowUpdate(0, 0));
    try std.testing.expectError(frame.Error.Protocol, w.writeWindowUpdate(0, 1 << 31));
}
