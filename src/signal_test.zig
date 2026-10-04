// Signal client tests: codec goldens (Go-marshaled bytes) + a live exchange
// between two Zig clients through the real upstream signal server built from
// upstream/netbird/signal. Sits at src/ because build.zig discovery gives
// each suite no named imports: only relative imports within the suite file's
// directory work. SIGNAL_HELPER env or
// $HOME/.cache/netbird-zig-context/gen/signal_server/signal-server; missing
// helper skips the live test. Goldens from gen/signal_golden (go run .).

const std = @import("std");
const builtin = @import("builtin");
const h2 = @import("net/h2/conn.zig");
const signal = @import("signal/client.zig");
const messages = @import("signal/messages.zig");
const wgbox = @import("mgmt/wgbox.zig");

const tio = std.testing.io;

// Go-marshaled Body{CANDIDATE, candidate payload, 51820, 0.79.0,
// Mode{true}, features[1,2,300], Rosenpass{[1,2,3,4],"10.0.0.9:9999"},
// relay "rel://relay.test:443", session deadbeef, ip 10.0.0.1}.
const body_golden_hex = "0802123763616e6469646174653a312031207564702032313133393337313531203139322e3136382e312e322035343332312074797020686f737418ec94032206302e37392e302a02080132040102ac023a150a0401020304120d31302e302e302e393a39393939421472656c3a2f2f72656c61792e746573743a3434335204deadbeef5a040a000001";

// Go-marshaled EncryptedMessage{key 0x00*32, remoteKey 0x01,0x02,0x03.., body 9,8,7,6,5}.
const env_golden_hex = "122c414141414141414141414141414141414141414141414141414141414141414141414141414141414141413d1a2c4151494441414141414141414141414141414141414141414141414141414141414141414141414141413d3d22050908070605";

test "signal body matches Go golden" {
    const alloc = std.testing.allocator;
    var golden: [256]u8 = undefined;
    const gb = try std.fmt.hexToBytes(&golden, body_golden_hex);
    const feats = [_]u32{ 1, 2, 300 };
    const rp = messages.RosenpassConfig{
        .rosenpass_pub_key = &.{ 1, 2, 3, 4 },
        .rosenpass_server_addr = "10.0.0.9:9999",
    };
    const b = messages.Body{
        .msg_type = .candidate,
        .payload = "candidate:1 1 udp 2113937151 192.168.1.2 54321 typ host",
        .wg_listen_port = 51820,
        .netbird_version = "0.79.0",
        .mode = .{ .direct = true },
        .features_supported = &feats,
        .rosenpass_config = rp,
        .relay_server_address = "rel://relay.test:443",
        .session_id = &.{ 0xde, 0xad, 0xbe, 0xef },
        .relay_server_ip = &.{ 10, 0, 0, 1 },
    };
    const enc = try b.encode(alloc);
    defer alloc.free(enc);
    try std.testing.expectEqualSlices(u8, gb, enc);
    var dec = try messages.Body.decode(alloc, gb);
    defer dec.deinit(alloc);
    try std.testing.expectEqual(messages.BodyType.candidate, dec.msg_type);
    try std.testing.expectEqualStrings(b.payload, dec.payload);
    try std.testing.expectEqual(@as(u32, 51820), dec.wg_listen_port);
    try std.testing.expectEqual(true, dec.mode.?.direct.?);
    try std.testing.expectEqualSlices(u32, &feats, dec.features_supported);
    try std.testing.expectEqualStrings("10.0.0.9:9999", dec.rosenpass_config.?.rosenpass_server_addr);
    try std.testing.expectEqualStrings("rel://relay.test:443", dec.relay_server_address.?);
    try std.testing.expectEqualSlices(u8, &.{ 0xde, 0xad, 0xbe, 0xef }, dec.session_id.?);
}

test "signal envelope matches Go golden" {
    const alloc = std.testing.allocator;
    var golden: [128]u8 = undefined;
    const gb = try std.fmt.hexToBytes(&golden, env_golden_hex);
    const e = messages.EncryptedMessage{
        .key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        .remote_key = "AQIDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
        .body = &.{ 9, 8, 7, 6, 5 },
    };
    const enc = try e.encode(alloc);
    defer alloc.free(enc);
    try std.testing.expectEqualSlices(u8, gb, enc);
    var dec = try messages.EncryptedMessage.decode(alloc, gb);
    defer dec.deinit(alloc);
    try std.testing.expectEqualStrings(e.key, dec.key);
    try std.testing.expectEqualStrings(e.remote_key, dec.remote_key);
    try std.testing.expectEqualSlices(u8, e.body, dec.body);
}

test "signal optional presence encodes zero values" {
    // proto3-optional: set-but-false and set-but-empty still hit the wire,
    // unset stays absent.
    const alloc = std.testing.allocator;
    const b = messages.Body{
        .mode = .{ .direct = false },
        .relay_server_address = "",
    };
    const enc = try b.encode(alloc);
    defer alloc.free(enc);
    // field 5 (mode, len 2: field 1 varint 0) + field 8 (empty string).
    try std.testing.expectEqualSlices(u8, &.{ 0x2a, 0x02, 0x08, 0x00, 0x42, 0x00 }, enc);
    var dec = try messages.Body.decode(alloc, enc);
    defer dec.deinit(alloc);
    try std.testing.expectEqual(false, dec.mode.?.direct.?);
    try std.testing.expectEqualStrings("", dec.relay_server_address.?);
    try std.testing.expect(dec.session_id == null);
}

fn getenv(allocator: std.mem.Allocator, key: []const u8) !?[]u8 {
    var file = std.Io.Dir.openFileAbsolute(tio, "/proc/self/environ", .{ .mode = .read_only }) catch return null;
    defer file.close(tio);
    var buf: [16384]u8 = undefined;
    const n = file.readPositionalAll(tio, &buf, 0) catch return null;
    var rest = buf[0..n];
    while (rest.len > 0) {
        const end = std.mem.indexOfScalar(u8, rest, 0) orelse break;
        const entry = rest[0..end];
        rest = rest[end + 1 ..];
        const eq = std.mem.indexOfScalar(u8, entry, '=') orelse continue;
        if (std.mem.eql(u8, entry[0..eq], key)) {
            return try allocator.dupe(u8, entry[eq + 1 ..]);
        }
    }
    return null;
}

fn helperPath(allocator: std.mem.Allocator) ![]u8 {
    if (try getenv(allocator, "SIGNAL_HELPER")) |p| return p;
    const home = (try getenv(allocator, "HOME")) orelse return error.SkipZigTest;
    defer allocator.free(home);
    const def = try std.fmt.allocPrint(allocator, "{s}/.cache/netbird-zig-context/gen/signal_server/signal-server", .{home});
    errdefer allocator.free(def);
    var f = std.Io.Dir.openFileAbsolute(tio, def, .{ .mode = .read_only }) catch return error.SkipZigTest;
    f.close(tio);
    return def;
}

const Live = struct {
    child: std.process.Child,
    stream: std.Io.net.Stream,
    rdr: std.Io.net.Stream.Reader,
    wtr: std.Io.net.Stream.Writer,
    rx_buf: [16384]u8,
    tx_buf: [16384]u8,
    conn: h2.Conn,
    tctx: Ctx,

    const Ctx = struct {
        reader: *std.Io.Reader,
        writer: *std.Io.Writer,
    };

    fn readFn(ctx: *anyopaque, buf: []u8) h2.Transport.ReadError!usize {
        const c: *Ctx = @ptrCast(@alignCast(ctx));
        c.reader.readSliceAll(buf) catch return error.Closed;
        return buf.len;
    }

    fn writeFn(ctx: *anyopaque, buf: []const u8) h2.Transport.WriteError!void {
        const c: *Ctx = @ptrCast(@alignCast(ctx));
        c.writer.writeAll(buf) catch return error.Closed;
        c.writer.flush() catch return error.Closed;
    }

    fn dial(allocator: std.mem.Allocator, port: u16) !*Live {
        const self = try allocator.create(Live);
        errdefer allocator.destroy(self);
        var addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(port) };
        var i: usize = 0;
        const stream = while (i < 200000) : (i += 1) {
            if (addr.connect(tio, .{ .mode = .stream })) |s| break s else |_| {}
        } else return error.ConnectTimeout;
        self.stream = stream;
        self.rdr = std.Io.net.Stream.Reader.init(stream, tio, &self.rx_buf);
        self.wtr = stream.writer(tio, &self.tx_buf);
        self.tctx = .{ .reader = &self.rdr.interface, .writer = &self.wtr.interface };
        self.conn = h2.Conn.init(.{ .ctx = &self.tctx, .readFn = readFn, .writeFn = writeFn });
        try self.conn.handshake();
        return self;
    }

    fn closeConn(self: *Live, allocator: std.mem.Allocator) void {
        self.stream.close(tio);
        allocator.destroy(self);
    }
};

test "signal two clients exchange through real server" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    const port: u16 = 18701;
    const helper = try helperPath(alloc);
    defer alloc.free(helper);
    const argv = [_][]const u8{
        helper,          "run",
        "--port",        "18701",
        "--metrics-port", "18702",
        "--log-level",   "error",
        "--log-file",    "console",
    };
    var child = try std.process.spawn(tio, .{
        .argv = &argv,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    defer child.kill(tio);

    const a_priv = wgbox.generatePrivateKey(tio);
    const b_priv = wgbox.generatePrivateKey(tio);
    const a_pub = try wgbox.allocString(alloc, wgbox.publicKey(a_priv));
    defer alloc.free(a_pub);
    const b_pub = try wgbox.allocString(alloc, wgbox.publicKey(b_priv));
    defer alloc.free(b_pub);
    const authority = "127.0.0.1:18701";

    const la = try Live.dial(alloc, port);
    defer la.closeConn(alloc);
    var ca = signal.Client{
        .conn = &la.conn,
        .alloc = alloc,
        .authority = authority,
        .io = tio,
        .key = a_priv,
    };
    defer ca.deinit();
    const lb = try Live.dial(alloc, port);
    defer lb.closeConn(alloc);
    var cb = signal.Client{
        .conn = &lb.conn,
        .alloc = alloc,
        .authority = authority,
        .io = tio,
        .key = b_priv,
    };
    defer cb.deinit();

    var sa = try ca.connectStream();
    defer sa.deinit();
    var sb = try cb.connectStream();
    defer sb.deinit();
    try std.testing.expect(sa.registered());
    try std.testing.expect(sb.registered());

    // A -> B via unary Send.
    const offer = messages.Message{
        .key = a_pub,
        .remote_key = b_pub,
        .body = .{
            .msg_type = .offer,
            .payload = "offer-sdp-a",
            .wg_listen_port = 51820,
            .netbird_version = "0.79.0-test",
        },
    };
    try ca.send(&offer);
    var got_b = (try sb.recv()) orelse return error.NoMessageB;
    defer got_b.deinit(alloc);
    try std.testing.expectEqualStrings(a_pub, got_b.key);
    try std.testing.expectEqual(messages.BodyType.offer, got_b.body.msg_type);
    try std.testing.expectEqualStrings("offer-sdp-a", got_b.body.payload);
    try std.testing.expectEqual(@as(u32, 51820), got_b.body.wg_listen_port);

    // B -> A via unary Send (the server never reads ConnectStream
    // messages, so stream sends are not routed; upstream SendToStream has
    // no callers either).
    const answer = messages.Message{
        .key = b_pub,
        .remote_key = a_pub,
        .body = .{
            .msg_type = .answer,
            .payload = "answer-sdp-b",
        },
    };
    try cb.send(&answer);
    var got_a = (try sa.recv()) orelse return error.NoMessageA;
    defer got_a.deinit(alloc);
    try std.testing.expectEqualStrings(b_pub, got_a.key);
    try std.testing.expectEqual(messages.BodyType.answer, got_a.body.msg_type);
    try std.testing.expectEqualStrings("answer-sdp-b", got_a.body.payload);

    // Stream send executes cleanly (server accepts and ignores it).
    try sb.send(&answer);
}
