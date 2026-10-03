// WireGuard over TUN between two unprivileged network namespaces.
//
// Run (outer userns; `timeout` is the watchdog):
//   zig test src/wireguard/wgtun_test.zig --test-cmd timeout --test-cmd 150 \
//     --test-cmd unshare --test-cmd -Urn --test-cmd-bin
// Skips on a plain host. Topology (veth, my choice per card):
//   X (this process, outer userns): creates a veth pair, spawns A and B as
//     `unshare -Urn /proc/self/exe`, moves one veth end into each.
//   A (Zig): vetha 10.200.0.1, wga0 10.99.0.1, Zig device in-process.
//   B (Go):  vethb 10.200.0.2, wgb0 10.99.0.2, gen/wgdev helper with real tun.
// Ping A->B and B->A over the tunnel must both succeed.

const std = @import("std");
const builtin = @import("builtin");
const noise = @import("noise.zig");
const device = @import("device.zig");

const linux = std.os.linux;
const tio = std.testing.io;

fn wallNs() i64 {
    return @intCast(std.Io.Timestamp.now(tio, .real).nanoseconds);
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

fn inUserNamespace() bool {
    var file = std.Io.Dir.openFileAbsolute(tio, "/proc/self/uid_map", .{ .mode = .read_only }) catch return false;
    defer file.close(tio);
    var buf: [128]u8 = undefined;
    const n = file.readPositionalAll(tio, &buf, 0) catch return false;
    const trimmed = std.mem.trim(u8, buf[0..n], " \t\n");
    return !std.mem.eql(u8, trimmed, "0          0 4294967295") and
        !std.mem.eql(u8, trimmed, "0 0 4294967295");
}

fn run(args: []const []const u8) !void {
    var child = try std.process.spawn(tio, .{
        .argv = args,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    const term = try child.wait(tio);
    if (!term.success()) return error.ChildFailed;
}

/// Bidirectional line channel to a child process.
const Pipe = struct {
    child: std.process.Child,
    reader: std.Io.File.Reader,
    writer: std.Io.File.Writer,
    read_buf: [4096]u8 = undefined,
    write_buf: [4096]u8 = undefined,

    fn writeLine(p: *Pipe, line: []const u8) !void {
        var w = &p.writer.interface;
        try w.writeAll(line);
        try w.writeByte('\n');
        try w.flush();
    }

    fn readLine(p: *Pipe) ![]u8 {
        var r = &p.reader.interface;
        return (try r.takeDelimiter('\n')) orelse error.EndOfStream;
    }
};

/// Own binary path: /proc/self/exe must be resolved HERE, since the literal
/// string would resolve to unshare itself in the child (bare unshare runs
/// $SHELL, which is exactly the confusing failure we debugged).
fn ownExePath(allocator: std.mem.Allocator) ![]u8 {
    var buf: [4096]u8 = undefined;
    const n = linux.readlink("/proc/self/exe", &buf, buf.len);
    if (n > 0xfffffffffffff000 or n == 0) return error.NoExePath;
    return allocator.dupe(u8, buf[0..n]);
}

/// Spawn `unshare -Urn <own binary>` with extra env, piped stdio.
/// In-place: Pipe holds buffers its reader/writer point to.
fn spawnSide(p: *Pipe, extra_env: []const [2][]const u8) !void {
    var map = std.process.Environ.Map.init(std.testing.allocator);
    defer map.deinit();
    // inherit current environment
    var file = try std.Io.Dir.openFileAbsolute(tio, "/proc/self/environ", .{ .mode = .read_only });
    defer file.close(tio);
    var buf: [16384]u8 = undefined;
    const n = try file.readPositionalAll(tio, &buf, 0);
    var rest = buf[0..n];
    while (rest.len > 0) {
        const end = std.mem.indexOfScalar(u8, rest, 0) orelse break;
        const entry = rest[0..end];
        rest = rest[end + 1 ..];
        const eq = std.mem.indexOfScalar(u8, entry, '=') orelse continue;
        try map.put(entry[0..eq], entry[eq + 1 ..]);
    }
    for (extra_env) |kv| try map.put(kv[0], kv[1]);
    const exe = try ownExePath(std.testing.allocator);
    defer std.testing.allocator.free(exe);
    const argv = [_][]const u8{ "unshare", "-Urn", exe };
    p.* = Pipe{
        .child = try std.process.spawn(tio, .{
            .argv = &argv,
            .stdin = .pipe,
            .stdout = .pipe,
            .stderr = .inherit,
            .environ_map = &map,
        }),
        .reader = undefined,
        .writer = undefined,
    };
    p.reader = p.child.stdout.?.readerStreaming(tio, &p.read_buf);
    p.writer = p.child.stdin.?.writerStreaming(tio, &p.write_buf);
}

fn childPid(p: *Pipe) i32 {
    return p.child.id.?;
}

// ---------------------------------------------------------------- role X --

fn helperPath(allocator: std.mem.Allocator) ![]u8 {
    if (try getenv(allocator, "WG_HELPER")) |p| return p;
    const home = (try getenv(allocator, "HOME")) orelse return error.SkipZigTest;
    defer allocator.free(home);
    const def = try std.fmt.allocPrint(allocator, "{s}/.cache/netbird-zig-context/gen/wgdev/wgdev", .{home});
    errdefer allocator.free(def);
    var f = std.Io.Dir.openFileAbsolute(tio, def, .{ .mode = .read_only }) catch return error.SkipZigTest;
    f.close(tio);
    return def;
}

fn roleX() !void {
    const helper = try helperPath(std.testing.allocator);
    defer std.testing.allocator.free(helper);
    var mk = [_][]const u8{ "ip", "link", "add", "vetha", "type", "veth", "peer", "name", "vethb" };
    try run(&mk);

    var b: Pipe = undefined;
    try spawnSide(&b, &.{ .{ "WG_SIDE", "B" }, .{ "WG_HELPER", helper } });
    var pid_buf: [16]u8 = undefined;
    const bpid = try std.fmt.bufPrint(&pid_buf, "{d}", .{childPid(&b)});
    var mvb = [_][]const u8{ "ip", "link", "set", "vethb", "netns", bpid };
    try run(&mvb);
    try b.writeLine("LINK");
    const b_pub_line = try b.readLine();
    if (!std.mem.startsWith(u8, b_pub_line, "PUBKEY ")) return error.BadProto;

    var a: Pipe = undefined;
    try spawnSide(&a, &.{
        .{ "WG_SIDE", "A" },
        .{ "WG_PEER_PUB", b_pub_line["PUBKEY ".len..] },
    });
    const apid = try std.fmt.bufPrint(&pid_buf, "{d}", .{childPid(&a)});
    var mva = [_][]const u8{ "ip", "link", "set", "vetha", "netns", apid };
    try run(&mva);
    try a.writeLine("LINK");
    const a_pub_line = try a.readLine();
    // "PUBKEY <b64> PORT <n>"
    var ait = std.mem.splitScalar(u8, a_pub_line, ' ');
    if (!std.mem.eql(u8, ait.next() orelse "", "PUBKEY")) return error.BadProto;
    const a_pub = ait.next() orelse return error.BadProto;
    if (!std.mem.eql(u8, ait.next() orelse "", "PORT")) return error.BadProto;
    const a_port = ait.next() orelse return error.BadProto;

    var cfg_buf: [160]u8 = undefined;
    const cfg = try std.fmt.bufPrint(&cfg_buf, "CONFIG {s} 10.200.0.1:{s} 10.99.0.1/32", .{ a_pub, a_port });
    try b.writeLine(cfg);
    const b_port_line = try b.readLine();
    if (!std.mem.startsWith(u8, b_port_line, "PORT ")) return error.BadProto;

    var go_buf: [32]u8 = undefined;
    const go = try std.fmt.bufPrint(&go_buf, "GO {s}", .{b_port_line["PORT ".len..]});
    try a.writeLine(go);
    const a_res = try a.readLine();
    if (!std.mem.startsWith(u8, a_res, "PRESULT ok")) return error.PingAFailed;

    try b.writeLine("PING");
    const b_res = try b.readLine();
    if (!std.mem.startsWith(u8, b_res, "PRESULT ok")) return error.PingBFailed;
    // proof the Go side moved tunnel bytes
    const rx_at = std.mem.indexOf(u8, b_res, "rx=") orelse return error.BadProto;
    const rx = try std.fmt.parseInt(u64, b_res[rx_at + 3 ..], 10);
    if (rx == 0) return error.NoTraffic;

    try b.writeLine("QUIT");
    try a.writeLine("QUIT");
    _ = a.child.wait(tio) catch {};
    _ = b.child.wait(tio) catch {};
    std.debug.print("C3: A->B ok, B->A ok, go rx={d}\n", .{rx});
}

// ---------------------------------------------------------------- role A --

const CtxA = struct {
    socket: *const std.Io.net.Socket,
    go_addr: std.Io.net.IpAddress,

    fn udpSend(ctx: ?*anyopaque, datagram: []const u8, to: device.Endpoint) void {
        const c: *CtxA = @ptrCast(@alignCast(ctx));
        _ = to;
        c.socket.send(tio, &c.go_addr, datagram) catch {};
    }
};

const Pump = struct {
    dev: *device.Device,
    tun_fd: linux.fd_t,
    socket: *const std.Io.net.Socket,
    stop: std.atomic.Value(bool) = .init(false),

    fn loop(p: *Pump) void {
        var buf: [2048]u8 = undefined;
        while (!p.stop.load(.acquire)) {
            var pfd = [_]linux.pollfd{.{ .fd = p.tun_fd, .events = linux.POLL.IN }};
            const n = linux.poll(&pfd, 1, 50);
            if (n != 0 and n <= 0xfffffffffffff000) {
                const rn = linux.read(p.tun_fd, &buf, buf.len);
                if (rn > 0 and rn <= 0xfffffffffffff000) {
                    p.dev.sendPacket(buf[0..rn], wallNs());
                }
            }
            const timeout: std.Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(50), .clock = .awake } };
            if (p.socket.receiveTimeout(tio, &buf, timeout)) |msg| {
                const from = switch (msg.from) {
                    .ip4 => |a| device.Endpoint.v4(a.bytes[0], a.bytes[1], a.bytes[2], a.bytes[3], a.port),
                    .ip6 => continue,
                };
                p.dev.receiveDatagram(msg.data, from, wallNs());
            } else |_| {}
            p.dev.pollAll(wallNs());
        }
    }
};

fn roleA() !void {
    const allocator = std.testing.allocator;
    // stdin/out are X's pipes
    var in_buf: [1024]u8 = undefined;
    var stdin = std.Io.File.stdin().readerStreaming(tio, &in_buf);
    var sin = &stdin.interface;
    const link = (try sin.takeDelimiter('\n')) orelse return error.BadProto;
    if (!std.mem.eql(u8, link, "LINK")) return error.BadProto;

    var ac = [_][]const u8{ "ip", "addr", "add", "10.200.0.1/24", "dev", "vetha" };
    try run(&ac);
    var au = [_][]const u8{ "ip", "link", "set", "vetha", "up" };
    try run(&au);

    var bind_addr = std.Io.net.IpAddress{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } };
    var socket = try bind_addr.bind(tio, .{ .mode = .dgram });
    defer socket.close(tio);
    const zig_port = socket.address.getPort();

    var sk: noise.PrivateKey = @splat(0xA5);
    noise.clamp(&sk);
    var dev = device.Device.init(allocator, tio, sk, .{});
    defer dev.deinit();
    const peer_pub_b64 = (try getenv(allocator, "WG_PEER_PUB")) orelse return error.BadEnv;
    defer allocator.free(peer_pub_b64);
    var go_pub: noise.PublicKey = undefined;
    try std.base64.standard.Decoder.decode(&go_pub, peer_pub_b64);
    const peer = try dev.addPeer(go_pub, @splat(0));
    try peer.allowed.append(allocator, device.Cidr.parseV4("10.99.0.2/32").?);

    var zig_b64: [44]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&zig_b64, &dev.static_public);
    var out_buf: [1024]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(tio, &out_buf);
    var sout = &stdout.interface;
    try sout.print("PUBKEY {s} PORT {d}\n", .{ zig_b64, zig_port });
    try sout.flush();

    const go_line = (try sin.takeDelimiter('\n')) orelse return error.BadProto;
    if (!std.mem.startsWith(u8, go_line, "GO ")) return error.BadProto;
    const go_port = try std.fmt.parseInt(u16, go_line["GO ".len..], 10);

    var tt = [_][]const u8{ "ip", "tuntap", "add", "dev", "wga0", "mode", "tun" };
    try run(&tt);
    const tun_fd = try attachTun("wga0");
    defer _ = linux.close(tun_fd);
    var ta = [_][]const u8{ "ip", "addr", "add", "10.99.0.1/24", "dev", "wga0" };
    try run(&ta);
    var tu = [_][]const u8{ "ip", "link", "set", "wga0", "up" };
    try run(&tu);

    var ctx = CtxA{ .socket = &socket, .go_addr = try .parse("10.200.0.2", go_port) };
    dev.udp_ctx = &ctx;
    dev.udp_send = CtxA.udpSend;
    dev.packet_sink = sinkToTun;
    dev.sink_ctx = @ptrFromInt(@as(usize, @intCast(tun_fd)));
    peer.endpoint = device.Endpoint.v4(10, 200, 0, 2, go_port);

    var pump = Pump{ .dev = &dev, .tun_fd = tun_fd, .socket = &socket };
    const thread = try std.Thread.spawn(.{}, Pump.loop, .{&pump});
    defer {
        pump.stop.store(true, .release);
        thread.join();
    }

    var ping = [_][]const u8{ "ping", "-c5", "-W2", "-w15", "10.99.0.2" };
    var child = try std.process.spawn(tio, .{
        .argv = &ping,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    const term = try child.wait(tio);
    if (!term.success()) {
        try sout.print("PRESULT fail ping\n", .{});
        try sout.flush();
        return error.PingFailed;
    }
    if (peer.current == null) {
        try sout.print("PRESULT fail no-session\n", .{});
        try sout.flush();
        return error.NoSession;
    }
    try sout.print("PRESULT ok tx={d}\n", .{peer.tx_bytes});
    try sout.flush();
    // linger: B still needs us for its ping
    const quit = (try sin.takeDelimiter('\n')) orelse return error.BadProto;
    if (!std.mem.eql(u8, quit, "QUIT")) return error.BadProto;
}

/// Attach to an existing persistent tun by name (open + TUNSETIFF).
fn attachTun(name: []const u8) !linux.fd_t {
    const fd_usize = linux.open("/dev/net/tun", .{ .ACCMODE = .RDWR, .CLOEXEC = true }, 0);
    if (fd_usize > 0xfffffffffffff000) return error.TunOpen;
    const fd: linux.fd_t = @intCast(fd_usize);
    errdefer _ = linux.close(fd);
    var ifr: [40]u8 = std.mem.zeroes([40]u8);
    @memcpy(ifr[0..name.len], name);
    std.mem.writeInt(u16, ifr[16..18], 0x0001 | 0x1000, .little); // IFF_TUN|IFF_NO_PI
    const rc = linux.ioctl(fd, 0x400454ca, @intFromPtr(&ifr)); // TUNSETIFF
    if (rc > 0xfffffffffffff000) return error.TunIoctl;
    return fd;
}

fn sinkToTun(ctx: ?*anyopaque, peer: *device.Peer, pkt: []const u8) void {
    _ = peer;
    const fd: linux.fd_t = @intCast(@intFromPtr(ctx));
    var off: usize = 0;
    while (off < pkt.len) {
        const n = linux.write(fd, pkt[off..].ptr, pkt.len - off);
        if (n == 0 or n > 0xfffffffffffff000) return;
        off += n;
    }
}

// ---------------------------------------------------------------- role B --

fn roleB() !void {
    const allocator = std.testing.allocator;
    var in_buf: [1024]u8 = undefined;
    var stdin = std.Io.File.stdin().readerStreaming(tio, &in_buf);
    var sin = &stdin.interface;
    var out_buf: [1024]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(tio, &out_buf);
    var sout = &stdout.interface;

    const link = (try sin.takeDelimiter('\n')) orelse return error.BadProto;
    if (!std.mem.eql(u8, link, "LINK")) return error.BadProto;

    var ac = [_][]const u8{ "ip", "addr", "add", "10.200.0.2/24", "dev", "vethb" };
    try run(&ac);
    var au = [_][]const u8{ "ip", "link", "set", "vethb", "up" };
    try run(&au);

    const helper_path = (try getenv(allocator, "WG_HELPER")) orelse return error.BadEnv;
    defer allocator.free(helper_path);
    const hargv = [_][]const u8{ helper_path, "-tun", "wgb0", "-port", "0" };
    var hchild = try std.process.spawn(tio, .{
        .argv = &hargv,
        .stdin = .pipe,
        .stdout = .pipe,
        .stderr = .inherit,
    });
    var hread_buf: [4096]u8 = undefined;
    var hwrite_buf: [4096]u8 = undefined;
    var hreader = hchild.stdout.?.readerStreaming(tio, &hread_buf);
    var hwriter = hchild.stdin.?.writerStreaming(tio, &hwrite_buf);
    const hr = &hreader.interface;
    const hw = &hwriter.interface;
    const hwriteLine = struct {
        fn f(w: *std.Io.Writer, line: []const u8) !void {
            try w.writeAll(line);
            try w.writeByte('\n');
            try w.flush();
        }
    }.f;
    const hreadLine = struct {
        fn f(r: *std.Io.Reader) ![]u8 {
            return (try r.takeDelimiter('\n')) orelse error.EndOfStream;
        }
    }.f;

    const pub_line = try hreadLine(hr);
    if (!std.mem.startsWith(u8, pub_line, "PUBKEY ")) return error.BadProto;
    const ready = try hreadLine(hr);
    if (!std.mem.eql(u8, ready, "READY")) return error.BadProto;
    try sout.print("{s}\n", .{pub_line});
    try sout.flush();

    // helper created wgb0 at startup; address it now
    var ta = [_][]const u8{ "ip", "addr", "add", "10.99.0.2/24", "dev", "wgb0" };
    try run(&ta);
    var tu = [_][]const u8{ "ip", "link", "set", "wgb0", "up" };
    try run(&tu);

    const cfg = (try sin.takeDelimiter('\n')) orelse return error.BadProto;
    try hwriteLine(hw, cfg);
    const ok = try hreadLine(hr);
    if (!std.mem.eql(u8, ok, "OK")) return error.HelperConfig;
    try hwriteLine(hw, "PORT");
    const port_line = try hreadLine(hr);
    if (!std.mem.startsWith(u8, port_line, "PORT ")) return error.BadProto;
    try sout.print("{s}\n", .{port_line});
    try sout.flush();

    const ping_cmd = (try sin.takeDelimiter('\n')) orelse return error.BadProto;
    if (!std.mem.eql(u8, ping_cmd, "PING")) return error.BadProto;
    var pargv = [_][]const u8{ "ping", "-c5", "-W2", "-w15", "10.99.0.1" };
    var pchild = try std.process.spawn(tio, .{
        .argv = &pargv,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    const term = try pchild.wait(tio);
    try hwriteLine(hw, "STATS");
    const stats = try hreadLine(hr);
    // "STATS rx=N tx=M"
    var rx: u64 = 0;
    if (std.mem.indexOf(u8, stats, "rx=")) |at| {
        const rest = stats[at + 3 ..];
        const end = std.mem.indexOfScalar(u8, rest, ' ') orelse rest.len;
        rx = std.fmt.parseInt(u64, rest[0..end], 10) catch 0;
    }
    if (!term.success()) {
        try sout.print("PRESULT fail ping\n", .{});
        try sout.flush();
        return error.PingFailed;
    }
    try sout.print("PRESULT ok rx={d}\n", .{rx});
    try sout.flush();

    const quit = (try sin.takeDelimiter('\n')) orelse return error.BadProto;
    if (!std.mem.eql(u8, quit, "QUIT")) return error.BadProto;
    try hwriteLine(hw, "QUIT");
    _ = hreadLine(hr) catch {};
    _ = hchild.wait(tio) catch {};
}

test "wg over tun between namespaces" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const side = try getenv(allocator, "WG_SIDE");
    defer if (side) |s| allocator.free(s);
    if (side) |s| {
        if (std.mem.eql(u8, s, "A")) return roleA();
        if (std.mem.eql(u8, s, "B")) return roleB();
    }
    if (!inUserNamespace()) return error.SkipZigTest;
    return roleX();
}
