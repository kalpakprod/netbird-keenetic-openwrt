// Live interop test: Zig device vs real wireguard-go over 127.0.0.1 UDP.
// Spawns the gen/wgdev helper (build it first: go build in
// ~/.cache/netbird-zig-context/gen/wgdev). Override path with WGDEV_HELPER.
// Skips when the helper is missing.

const std = @import("std");
const builtin = @import("builtin");
const noise = @import("noise.zig");
const device = @import("device.zig");

const tio = std.testing.io;

fn wallNs() i64 {
    const ts = std.Io.Timestamp.now(tio, .real);
    return @intCast(ts.nanoseconds);
}

fn timeoutMs(ms: i64) std.Io.Timeout {
    return .{ .duration = .{ .raw = .fromMilliseconds(ms), .clock = .awake } };
}

/// Minimal getenv via /proc/self/environ (no libc, Linux-only test).
fn getenv(allocator: std.mem.Allocator, key: []const u8) !?[]u8 {
    var file = std.Io.Dir.openFileAbsolute(tio, "/proc/self/environ", .{ .mode = .read_only }) catch return null;
    defer file.close(tio);
    var buf: [8192]u8 = undefined;
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
    if (try getenv(allocator, "WGDEV_HELPER")) |p| return p;
    const home = (try getenv(allocator, "HOME")) orelse return error.MissingHome;
    defer allocator.free(home);
    return std.fmt.allocPrint(allocator, "{s}/.cache/netbird-zig-context/gen/wgdev/wgdev", .{home});
}

const Helper = struct {
    child: std.process.Child,
    reader: std.Io.File.Reader,
    writer: std.Io.File.Writer,
    read_buf: [4096]u8 = undefined,
    write_buf: [4096]u8 = undefined,

    fn spawn(h: *Helper, path: []const u8) !void {
        const child = std.process.spawn(tio, .{
            .argv = &.{path},
            .stdin = .pipe,
            .stdout = .pipe,
            .stderr = .inherit,
        }) catch return error.SkipZigTest;
        h.* = Helper{
            .child = child,
            .reader = undefined,
            .writer = undefined,
        };
        h.reader = child.stdout.?.readerStreaming(tio, &h.read_buf);
        h.writer = child.stdin.?.writerStreaming(tio, &h.write_buf);
    }

    fn close(h: *Helper) void {
        h.command("QUIT") catch {};
        _ = h.child.wait(tio) catch {};
    }

    fn command(h: *Helper, line: []const u8) !void {
        var w = &h.writer.interface;
        try w.writeAll(line);
        try w.writeByte('\n');
        try w.flush();
    }

    fn answer(h: *Helper) ![]u8 {
        var r = &h.reader.interface;
        return (try r.takeDelimiter('\n')) orelse error.EndOfStream;
    }
};

const Ctx = struct {
    dev: *device.Device,
    socket: *const std.Io.net.Socket,
    go_addr: std.Io.net.IpAddress,
    sent_sizes: std.ArrayList(usize) = .empty,
    sent_types: std.ArrayList(u32) = .empty,

    fn udpSend(ctx: ?*anyopaque, datagram: []const u8, to: device.Endpoint) void {
        const c: *Ctx = @ptrCast(@alignCast(ctx));
        _ = to;
        c.sent_sizes.append(std.testing.allocator, datagram.len) catch {};
        if (datagram.len >= 4) {
            c.sent_types.append(std.testing.allocator, std.mem.readInt(u32, datagram[0..4], .little)) catch {};
        }
        c.socket.send(tio, &c.go_addr, datagram) catch {};
    }

    var sink_packets: std.ArrayList([]u8) = .empty;

    fn sink(ctx: ?*anyopaque, peer: *device.Peer, pkt: []const u8) void {
        _ = ctx;
        _ = peer;
        sink_packets.append(
            std.testing.allocator,
            std.testing.allocator.dupe(u8, pkt) catch return,
        ) catch {};
    }
};

fn toEndpoint(addr: std.Io.net.IpAddress) device.Endpoint {
    return switch (addr) {
        .ip4 => |a| device.Endpoint.v4(a.bytes[0], a.bytes[1], a.bytes[2], a.bytes[3], a.port),
        .ip6 => unreachable,
    };
}

fn ip4Packet(src: [4]u8, dst: [4]u8, payload: []const u8, out: []u8) []u8 {
    const total = 20 + payload.len;
    @memset(out[0..total], 0);
    out[0] = 0x45;
    std.mem.writeInt(u16, out[2..4], @intCast(total), .big);
    @memcpy(out[12..16], &src);
    @memcpy(out[16..20], &dst);
    @memcpy(out[20..total], payload);
    return out[0..total];
}

/// Drain the UDP socket until quiet, feeding the device. Returns true if any
/// datagram arrived.
fn drain(dev: *device.Device, socket: *const std.Io.net.Socket) bool {
    var buf: [2048]u8 = undefined;
    var any = false;
    while (true) {
        const msg = socket.receiveTimeout(tio, &buf, timeoutMs(50)) catch return any;
        any = true;
        dev.receiveDatagram(msg.data, toEndpoint(msg.from), wallNs());
        dev.pollAll(wallNs());
    }
}

test "interop with wireguard-go" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const path = try helperPath(allocator);
    defer allocator.free(path);
    var helper: Helper = undefined;
    Helper.spawn(&helper, path) catch return error.SkipZigTest;
    defer helper.close();

    // PUBKEY + READY
    const pub_line = try helper.answer();
    try std.testing.expect(std.mem.startsWith(u8, pub_line, "PUBKEY "));
    const ready_line = try helper.answer();
    try std.testing.expectEqualStrings("READY", ready_line);
    var go_pub: noise.PublicKey = undefined;
    try std.base64.standard.Decoder.decode(&go_pub, pub_line["PUBKEY ".len..]);

    const constants = device.Constants{
        .timers = .{
            .rekey_timeout_ns = 200 * std.time.ns_per_ms,
            .keepalive_timeout_ns = 300 * std.time.ns_per_ms,
            .reject_after_time_ns = 30 * std.time.ns_per_s,
        },
        .rekey_after_time_ns = 800 * std.time.ns_per_ms,
        .reject_after_time_ns = 30 * std.time.ns_per_s,
        .mtu = 0,
    };
    var sk: noise.PrivateKey = @splat(0xE4);
    noise.clamp(&sk);
    var dev = device.Device.init(allocator, tio, sk, constants);
    defer dev.deinit();
    const peer = try dev.addPeer(go_pub, @splat(0));
    try peer.allowed.append(allocator, device.Cidr.parseV4("10.0.0.2/32").?);

    var bind_addr = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var socket = try bind_addr.bind(tio, .{ .mode = .dgram });
    defer socket.close(tio);
    const zig_port = socket.address.getPort();
    try std.testing.expect(zig_port != 0);

    var zig_pub_b64: [44]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&zig_pub_b64, &dev.static_public);
    var cfg_cmd: [128]u8 = undefined;
    const cfg = try std.fmt.bufPrint(&cfg_cmd, "CONFIG {s} 127.0.0.1:{d} 10.0.0.1/32", .{ zig_pub_b64, zig_port });
    try helper.command(cfg);
    try std.testing.expectEqualStrings("OK", try helper.answer());
    try helper.command("PORT");
    const port_line = try helper.answer();
    try std.testing.expect(std.mem.startsWith(u8, port_line, "PORT "));
    const go_port = try std.fmt.parseInt(u16, port_line["PORT ".len..], 10);
    try std.testing.expect(go_port != 0);

    var ctx = Ctx{
        .dev = &dev,
        .socket = &socket,
        .go_addr = try .parse("127.0.0.1", go_port),
    };
    defer ctx.sent_sizes.deinit(allocator);
    defer ctx.sent_types.deinit(allocator);
    defer {
        for (Ctx.sink_packets.items) |p| allocator.free(p);
        Ctx.sink_packets.deinit(allocator);
        Ctx.sink_packets = .empty;
    }
    dev.udp_ctx = &ctx;
    dev.udp_send = Ctx.udpSend;
    dev.packet_sink = Ctx.sink;
    peer.endpoint = device.Endpoint.v4(127, 0, 0, 1, go_port);

    var buf: [128]u8 = undefined;

    // Pump helper POLLs and the UDP socket together: neither side makes
    // progress while the test blocks on only one of them.
    const Pump = struct {
        fn untilGoPacket(h: *Helper, d: *device.Device, sock: *const std.Io.net.Socket, secs: i64) ![]u8 {
            const t0 = wallNs();
            while (wallNs() - t0 < secs * std.time.ns_per_s) {
                _ = drain(d, sock);
                try h.command("POLL 200");
                const a = try h.answer();
                if (std.mem.startsWith(u8, a, "PKT ")) return a;
            }
            return error.Timeout;
        }
    };

    // 1. Zig -> Go: handshake + data.
    dev.sendPacket(ip4Packet(.{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 }, "hello-go", &buf), wallNs());
    const polled = try Pump.untilGoPacket(&helper, &dev, &socket, 15);
    _ = drain(&dev, &socket);
    const go_got = try allocator.alloc(u8, (polled.len - 4) / 2);
    defer allocator.free(go_got);
    _ = try std.fmt.hexToBytes(go_got, polled["PKT ".len..]);
    try std.testing.expectEqualSlices(u8, "hello-go", go_got[20..28]);
    try std.testing.expect(peer.current != null);

    // 2. Go -> Zig.
    var go_pkt_hex: [256]u8 = undefined;
    const go_pkt = ip4Packet(.{ 10, 0, 0, 2 }, .{ 10, 0, 0, 1 }, "hello-zig", &buf);
    const hex_digits = "0123456789abcdef";
    for (go_pkt, 0..) |b, i| {
        go_pkt_hex[2 * i] = hex_digits[b >> 4];
        go_pkt_hex[2 * i + 1] = hex_digits[b & 0xf];
    }
    const hex_len = go_pkt.len * 2;
    var send_cmd: [320]u8 = undefined;
    const send = try std.fmt.bufPrint(&send_cmd, "SEND {s}", .{go_pkt_hex[0..hex_len]});
    try helper.command(send);
    try std.testing.expectEqualStrings("OK", try helper.answer());
    const t_start = wallNs();
    while (Ctx.sink_packets.items.len == 0 and wallNs() - t_start < 5 * std.time.ns_per_s) {
        _ = drain(&dev, &socket);
        dev.pollAll(wallNs());
    }
    try std.testing.expectEqual(@as(usize, 1), Ctx.sink_packets.items.len);
    try std.testing.expectEqualSlices(u8, "hello-zig", Ctx.sink_packets.items[0][20..29]);

    // 3. Keepalive timer fired on the Zig side (a 32-byte transport packet).
    const ka_start = wallNs();
    var saw_keepalive = false;
    while (wallNs() - ka_start < 5 * std.time.ns_per_s) {
        _ = drain(&dev, &socket);
        dev.pollAll(wallNs());
        for (ctx.sent_sizes.items) |s| {
            if (s == noise.message_transport_header_size + noise.tag_size) saw_keepalive = true;
        }
        if (saw_keepalive) break;
    }
    try std.testing.expect(saw_keepalive);

    // 4. Rekey: after rekey_after_time the next send triggers a new handshake
    // and traffic still flows.
    const created_before = peer.current.?.created_ns;
    try std.Io.sleep(tio, .fromMilliseconds(900), .awake);
    dev.sendPacket(ip4Packet(.{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 }, "rekeyed!", &buf), wallNs());
    const polled2 = try Pump.untilGoPacket(&helper, &dev, &socket, 15);
    try std.testing.expect(std.mem.startsWith(u8, polled2, "PKT "));
    _ = drain(&dev, &socket);
    try std.testing.expect(peer.current.?.created_ns > created_before);
    var initiations: usize = 0;
    for (ctx.sent_types.items) |t| {
        if (t == noise.message_initiation_type) initiations += 1;
    }
    try std.testing.expect(initiations >= 2);
}
