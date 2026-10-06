// Tests for the WireGuard runtime adapter (runtime.zig) at its real I/O and
// lifecycle boundary: UDP socket, TUN fd, Device callbacks.
//
// The lifecycle and loopback-UDP tests run anywhere (ephemeral ports on
// localhost). The full TUN test needs root-capabilities inside an isolated
// user+net namespace; run the suite through the namespace wrapper (the
// watchdog `timeout` guards against hung children):
//   zig test src/wireguard/runtime_test.zig --test-cmd timeout --test-cmd 150 \
//     --test-cmd unshare --test-cmd -Urn --test-cmd-bin
// On a plain host the TUN test skips (SkipZigTest) and is reported as not run.
//
// Namespace topology (same harness as wgtun_test.zig, adapter instead of the
// hand pump in role A):
//   X (this process, root in the outer userns): veth pair, one end into each
//     role's namespace.
//   A (Zig): vetha 10.200.0.1, runtime adapter with tun wga0 10.99.0.1.
//   B (Go):  vethb 10.200.0.2, gen/wgdev helper with real tun wgb0 10.99.0.2.
// Ping A->B and B->A over the tunnel must both succeed.

const std = @import("std");
const builtin = @import("builtin");
const noise = @import("noise.zig");
const device = @import("device.zig");
const runtime = @import("runtime.zig");

const linux = std.os.linux;
const tio = std.testing.io;
const max_errno_usize: usize = 0xfffffffffffff000;

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

/// Namespace preflight: true when already inside a (nested) user namespace,
/// i.e. we are root there and every interface change is throwaway.
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

/// Minimal valid IPv4 packet (20-byte header, no checksum needed: the Device
/// routes by dst, checks src against allowedips and trims by total length).
fn ipv4Packet(src: [4]u8, dst: [4]u8) [20]u8 {
    var p: [20]u8 = std.mem.zeroes([20]u8);
    p[0] = 0x45; // version 4, IHL 5
    std.mem.writeInt(u16, p[2..4], 20, .big); // total length
    p[8] = 64; // TTL
    p[9] = 1; // protocol ICMP (never parsed by the Device)
    @memcpy(p[12..16], &src);
    @memcpy(p[16..20], &dst);
    return p;
}

// ------------------------------------------------------- lifecycle tests --

test "runtime: start/poll/stop lifecycle, idempotent stop" {
    const allocator = std.testing.allocator;
    var sk: noise.PrivateKey = @splat(0xA5);
    noise.clamp(&sk);
    var dev = device.Device.init(allocator, tio, sk, .{});
    defer dev.deinit();

    var r = runtime.Runtime.init(allocator, &dev, .{}); // UDP-only: no TUN
    try r.start();
    defer r.stop(); // double stop at scope exit must be a safe no-op

    try std.testing.expect(r.localPort() != 0); // kernel picked an ephemeral port
    try std.testing.expect(dev.udp_send != null); // callbacks installed
    try std.testing.expect(dev.udp_ctx != null);
    try std.testing.expect(dev.sink_ctx == null); // no TUN: sink untouched
    try r.poll(1); // idle tick: no peers, no traffic
    try r.poll(1);

    r.stop();
    try std.testing.expect(dev.udp_send == null); // callbacks detached
    try std.testing.expect(dev.udp_ctx == null);
    try std.testing.expectError(runtime.Error.NotRunning, r.poll(1));
    r.stop(); // idempotent: no double close, no double free
}

test "runtime: failed start cleans up and allows retry" {
    const allocator = std.testing.allocator;
    var sk: noise.PrivateKey = @splat(0xA5);
    noise.clamp(&sk);
    var dev = device.Device.init(allocator, tio, sk, .{});
    defer dev.deinit();

    // TUN name longer than IFNAMSIZ fails deterministically after the socket
    // is already open: exercises the partial-start cleanup path.
    var r = runtime.Runtime.init(allocator, &dev, .{ .tun_name = "name-way-too-long-for-tun" });
    try std.testing.expectError(error.NameTooLong, r.start());
    try std.testing.expect(dev.udp_send == null); // callbacks never installed
    try std.testing.expect(dev.udp_ctx == null);
    r.stop(); // safe after the failed start
    try std.testing.expect(r.sock_fd == -1); // socket of the failed attempt closed

    r.config = .{}; // retry with a valid UDP-only config
    try r.start();
    defer r.stop();
    try std.testing.expect(r.localPort() != 0);
}

// ------------------------------------------------ loopback UDP (no TUN) --

const SinkCtx = struct {
    allocator: std.mem.Allocator,
    got: ?[]u8 = null,

    fn capture(ctx: ?*anyopaque, peer: *device.Peer, packet: []const u8) void {
        _ = peer;
        const s: *SinkCtx = @ptrCast(@alignCast(ctx.?));
        if (s.got) |g| s.allocator.free(g);
        s.got = s.allocator.dupe(u8, packet) catch null;
    }
};

test "runtime: handshake and data plane over loopback UDP" {
    const allocator = std.testing.allocator;
    // Fresh network namespaces start with lo down; on a normal host lo is up
    // and this no-op fails harmlessly without privileges.
    run(&[_][]const u8{ "ip", "link", "set", "lo", "up" }) catch {};

    var sk_a: noise.PrivateKey = @splat(0xA5);
    noise.clamp(&sk_a);
    var sk_b: noise.PrivateKey = @splat(0x5A);
    noise.clamp(&sk_b);
    var dev_a = device.Device.init(allocator, tio, sk_a, .{});
    defer dev_a.deinit();
    var dev_b = device.Device.init(allocator, tio, sk_b, .{});
    defer dev_b.deinit();

    var ra = runtime.Runtime.init(allocator, &dev_a, .{});
    defer ra.stop();
    try ra.start();
    var rb = runtime.Runtime.init(allocator, &dev_b, .{});
    defer rb.stop();
    try rb.start();

    const pa = try dev_a.addPeer(dev_b.static_public, @splat(0));
    try pa.allowed.append(allocator, device.Cidr.parseV4("10.99.0.2/32").?);
    pa.endpoint = device.Endpoint.v4(127, 0, 0, 1, rb.localPort());
    const pb = try dev_b.addPeer(dev_a.static_public, @splat(0));
    try pb.allowed.append(allocator, device.Cidr.parseV4("10.99.0.1/32").?); // no endpoint: roaming

    // The adapter leaves packet_sink unset without a TUN; capture B's output.
    var sink = SinkCtx{ .allocator = allocator };
    dev_b.packet_sink = SinkCtx.capture;
    dev_b.sink_ctx = &sink;
    defer {
        if (sink.got) |g| allocator.free(g);
        dev_b.packet_sink = null;
        dev_b.sink_ctx = null;
    }

    // sendPacket triggers the handshake initiation through the real socket.
    const pkt = ipv4Packet(.{ 10, 99, 0, 1 }, .{ 10, 99, 0, 2 });
    dev_a.sendPacket(&pkt, wallNs());

    var i: usize = 0;
    while (i < 1500) : (i += 1) {
        try ra.poll(2);
        try rb.poll(2);
        if (pa.current != null and pb.current != null and sink.got != null) break;
    }
    try std.testing.expect(pa.current != null); // initiator derived keys
    try std.testing.expect(pb.current != null); // responder derived keys
    try std.testing.expect(pb.endpoint != null); // roaming learned A's real address
    try std.testing.expectEqual(ra.localPort(), pb.endpoint.?.port);
    try std.testing.expect(sink.got != null);
    try std.testing.expectEqualSlices(u8, &pkt, sink.got.?); // round trip through real UDP
}

// --------------------------------------------- namespace E2E vs Go (TUN) --

/// Own binary path: /proc/self/exe must be resolved HERE, since the literal
/// string would resolve to unshare itself in the child.
fn ownExePath(allocator: std.mem.Allocator) ![]u8 {
    var buf: [4096]u8 = undefined;
    const n = linux.readlink("/proc/self/exe", &buf, buf.len);
    if (n > max_errno_usize or n == 0) return error.NoExePath;
    return allocator.dupe(u8, buf[0..n]);
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

/// Spawn `unshare -Urn <own binary>` with extra env, piped stdio.
fn spawnSide(p: *Pipe, extra_env: []const [2][]const u8) !void {
    var map = std.process.Environ.Map.init(std.testing.allocator);
    defer map.deinit();
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

// -------- role A: two peers, this side driven by the runtime adapter -----

fn roleA() !void {
    const allocator = std.testing.allocator;
    var in_buf: [1024]u8 = undefined;
    var stdin = std.Io.File.stdin().readerStreaming(tio, &in_buf);
    var sin = &stdin.interface;
    const link = (try sin.takeDelimiter('\n')) orelse return error.BadProto;
    if (!std.mem.eql(u8, link, "LINK")) return error.BadProto;

    var sk: noise.PrivateKey = @splat(0xA5);
    noise.clamp(&sk);
    var dev = device.Device.init(allocator, tio, sk, .{});
    defer dev.deinit();

    // veth addressing first: the adapter's UDP traffic rides the veth.
    var ac = [_][]const u8{ "ip", "addr", "add", "10.200.0.1/24", "dev", "vetha" };
    try run(&ac);
    var vup = [_][]const u8{ "ip", "link", "set", "vetha", "up" };
    try run(&vup);

    // The adapter creates and owns the TUN and the UDP socket.
    var rt = runtime.Runtime.init(allocator, &dev, .{ .tun_name = "wga0" });
    try rt.start();
    defer rt.stop();
    const tun_name = rt.tunIfName().?;

    var aa = [_][]const u8{ "ip", "addr", "add", "10.99.0.1/24", "dev", tun_name };
    try run(&aa);
    var au = [_][]const u8{ "ip", "link", "set", tun_name, "up" };
    try run(&au);

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
    try sout.print("PUBKEY {s} PORT {d}\n", .{ zig_b64, rt.localPort() });
    try sout.flush();

    const go_line = (try sin.takeDelimiter('\n')) orelse return error.BadProto;
    if (!std.mem.startsWith(u8, go_line, "GO ")) return error.BadProto;
    const go_port = try std.fmt.parseInt(u16, go_line["GO ".len..], 10);
    peer.endpoint = device.Endpoint.v4(10, 200, 0, 2, go_port);

    // Ping through the tunnel while the adapter polls both fds itself.
    var ping = [_][]const u8{ "ping", "-c5", "-W2", "-w15", "10.99.0.2" };
    var child = try std.process.spawn(tio, .{
        .argv = &ping,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    var st: i32 = 0;
    var exited = false;
    var success = false;
    var i: usize = 0;
    while (i < 6000) : (i += 1) {
        try rt.poll(2);
        const w = linux.waitpid(child.id.?, &st, linux.W.NOHANG);
        if (w > max_errno_usize) continue; // EINTR
        if (w == child.id.?) {
            exited = true; // reaped here; child.wait() below would fail with ECHILD
            const su: u32 = @bitCast(st);
            success = linux.W.IFEXITED(su) and linux.W.EXITSTATUS(su) == 0;
            break;
        }
    }
    if (!exited) {
        const term = child.wait(tio) catch return error.PingWaitFailed;
        success = term.success();
    }
    if (!success or peer.current == null) {
        try sout.print("PRESULT fail\n", .{});
        try sout.flush();
        return error.PingFailed;
    }
    try sout.print("PRESULT ok tx={d}\n", .{peer.tx_bytes});
    try sout.flush();

    // Stay up (and keep polling) while B pings us back; X sends only "QUIT",
    // nothing is buffered ahead in `sin` at this point.
    var quit_seen = false;
    i = 0;
    while (i < 9000 and !quit_seen) : (i += 1) {
        try rt.poll(2);
        var pf = [_]linux.pollfd{.{ .fd = 0, .events = linux.POLL.IN }};
        const pn = linux.poll(&pf, 1, 0);
        if (pn > 0 and pn <= max_errno_usize) {
            const line = sin.takeDelimiter('\n') catch |e| {
                std.debug.print("roleA: quit-read err {}\n", .{e});
                return error.QuitReadFailed;
            } orelse {
                std.debug.print("roleA: quit-read EOF\n", .{});
                return error.QuitEOF;
            };
            if (!std.mem.eql(u8, line, "QUIT")) {
                std.debug.print("roleA: unexpected line {s}\n", .{line});
                return error.BadProto;
            }
            quit_seen = true;
        }
    }
    if (!quit_seen) return error.QuitTimeout;
}

// -------- role B: Go WireGuard helper (verbatim harness protocol) --------

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

// -------- role X: orchestrates A (adapter) and B (Go) namespaces ---------

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
    std.debug.print("runtime E2E: A->B ok, B->A ok, go rx={d}\n", .{rx});
}

test "runtime adapter vs Go WireGuard over tun namespaces" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const side = try getenv(allocator, "WG_SIDE");
    defer if (side) |s| allocator.free(s);
    if (side) |s| {
        if (std.mem.eql(u8, s, "A")) return roleA();
        if (std.mem.eql(u8, s, "B")) return roleB();
    }
    // Preflight before any TUN is created: only run inside the wrapper's
    // isolated user namespace, where we are root and nothing is shared.
    if (!inUserNamespace()) return error.SkipZigTest;
    return roleX();
}

test "runtime: TUN hangup propagates through poll and run" {
    var sk: noise.PrivateKey = @splat(0xA5);
    noise.clamp(&sk);
    var dev = device.Device.init(std.testing.allocator, tio, sk, .{});
    defer dev.deinit();
    var r = runtime.Runtime.init(std.testing.allocator, &dev, .{});
    try r.start();
    defer r.stop();
    var pipes: [2]linux.fd_t = undefined;
    try std.testing.expect(linux.pipe2(&pipes, .{}) <= max_errno_usize);
    r.tun = .{ .fd = pipes[0], .name = undefined, .name_len = 0 };
    _ = linux.close(pipes[1]);
    var readiness = [1]linux.pollfd{.{ .fd = pipes[0], .events = linux.POLL.IN }};
    try std.testing.expectEqual(@as(usize, 1), linux.poll(&readiness, 1, 0));
    try std.testing.expect(readiness[0].revents & linux.POLL.HUP != 0);
    try std.testing.expect(readiness[0].revents & linux.POLL.IN == 0);
    try std.testing.expectError(error.TunClosed, r.poll(0));
    var stop_flag = std.atomic.Value(bool).init(false);
    try std.testing.expectError(error.TunClosed, r.run(&stop_flag));
}

test "runtime: callback send failures are observable and success stays clean" {
    var sk: noise.PrivateKey = @splat(0xA5);
    noise.clamp(&sk);
    var dev = device.Device.init(std.testing.allocator, tio, sk, .{});
    defer dev.deinit();
    var r = runtime.Runtime.init(std.testing.allocator, &dev, .{});
    try r.start();
    defer r.stop();
    const target = device.Endpoint.v4(127, 0, 0, 1, r.localPort());
    dev.udp_send.?(dev.udp_ctx, "packet", target);
    try std.testing.expectEqual(@as(usize, 0), r.udp_send_failures);
    try std.testing.expect(r.last_udp_errno == null);
    try std.testing.expect(r.last_tun_error == null);
    const saved = r.sock_fd;
    r.sock_fd = -1;
    dev.udp_send.?(dev.udp_ctx, "packet", target);
    r.sock_fd = saved;
    try std.testing.expectEqual(@as(usize, 1), r.udp_send_failures);
    try std.testing.expectEqual(@as(?usize, @backingInt(linux.E.BADF)), r.last_udp_errno);
}

test "runtime: TUN callback write failure is visible" {
    if (!inUserNamespace()) return error.SkipZigTest;
    var sk: noise.PrivateKey = @splat(0xA5);
    noise.clamp(&sk);
    var dev = device.Device.init(std.testing.allocator, tio, sk, .{});
    defer dev.deinit();
    var r = runtime.Runtime.init(std.testing.allocator, &dev, .{ .tun_name = "wgerr%d" });
    try r.start();
    defer r.stop();
    try run(&.{ "ip", "link", "set", r.tunIfName().?, "up" });
    var remote: noise.PrivateKey = @splat(0xB6);
    noise.clamp(&remote);
    const peer = try dev.addPeer(noise.publicKeyFromPrivate(remote), @splat(0));
    const packet = ipv4Packet(.{10, 1, 0, 1}, .{10, 1, 0, 2});
    dev.packet_sink.?(dev.sink_ctx, peer, &packet);
    try std.testing.expectEqual(@as(usize, 0), r.tun_write_failures);
    try std.testing.expect(r.last_tun_error == null);
    const saved = r.tun.?.fd;
    r.tun.?.fd = -1;
    dev.packet_sink.?(dev.sink_ctx, peer, &packet);
    r.tun.?.fd = saved;
    try std.testing.expectEqual(@as(usize, 1), r.tun_write_failures);
    try std.testing.expectEqual(@as(?runtime.Error, error.WriteFailed), r.last_tun_error);
}
