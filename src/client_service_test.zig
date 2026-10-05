// Port of netbird client/internal/connect.go and engine.go (v0.80.0), BSD-3-Clause
// Adapter tests: management authentication against the fake Go
// ManagementService (gen/mgmt_fake: real grpc-go, upstream proto, NaCl
// box), signal + management connection lifecycle against the real
// upstream signal server (gen/signal_server), and resource
// lifecycle/failure paths with a stub WG binding (the stub proves only
// the binding call contract, not WG behavior). Sits at src/ because
// build.zig discovery gives each suite no named imports: only relative
// imports within the suite file's directory work. MGMT_HELPER /
// SIGNAL_HELPER env or the gen/ defaults; missing helpers skip the
// corresponding live tests. Ports 188xx avoid the mgmt/signal suites.

const std = @import("std");
const builtin = @import("builtin");
const engine = @import("engine.zig");
const profile = @import("state/profile.zig");
const client_service = @import("client_service.zig");
const wgbox = @import("mgmt/wgbox.zig");

const tio = std.testing.io;

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

fn helperPath(allocator: std.mem.Allocator, env_key: []const u8, comptime def_suffix: []const u8) ![]u8 {
    if (try getenv(allocator, env_key)) |p| return p;
    const home = (try getenv(allocator, "HOME")) orelse return error.SkipZigTest;
    defer allocator.free(home);
    const def = try std.fmt.allocPrint(allocator, "{s}/.cache/netbird-zig-context/gen/" ++ def_suffix, .{home});
    errdefer allocator.free(def);
    var f = std.Io.Dir.openFileAbsolute(tio, def, .{ .mode = .read_only }) catch return error.SkipZigTest;
    f.close(tio);
    return def;
}

fn mgmtHelperPath(allocator: std.mem.Allocator) ![]u8 {
    return helperPath(allocator, "MGMT_HELPER", "mgmt_fake/mgmt_fake");
}

fn signalHelperPath(allocator: std.mem.Allocator) ![]u8 {
    return helperPath(allocator, "SIGNAL_HELPER", "signal_server/signal-server");
}

/// Spawn the fake management service and wait until it listens. Caller
/// kills the child.
fn spawnMgmt(allocator: std.mem.Allocator, port: u16) !std.process.Child {
    const helper = try mgmtHelperPath(allocator);
    defer allocator.free(helper);
    const addr = try std.fmt.allocPrint(allocator, "127.0.0.1:{d}", .{port});
    defer allocator.free(addr);
    const argv = [_][]const u8{ "/bin/sh", "-c", "exec 9>&-; exec \"$@\"", "service-helper", helper, addr };
    const child = try std.process.spawn(tio, .{
        .argv = &argv,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    waitListen(port);
    return child;
}

/// Spawn the real upstream signal server and wait until it listens.
fn spawnSignal(allocator: std.mem.Allocator, port: u16) !std.process.Child {
    const helper = try signalHelperPath(allocator);
    defer allocator.free(helper);
    const port_arg = try std.fmt.allocPrint(allocator, "{d}", .{port});
    defer allocator.free(port_arg);
    const metrics_arg = try std.fmt.allocPrint(allocator, "{d}", .{port + 1});
    defer allocator.free(metrics_arg);
    const argv = [_][]const u8{
        "/bin/sh", "-c", "exec 9>&-; exec \"$@\"", "service-helper",
        helper,          "run",
        "--port",        port_arg,
        "--metrics-port", metrics_arg,
        "--log-level",   "error",
        "--log-file",    "console",
    };
    const child = try std.process.spawn(tio, .{
        .argv = &argv,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    waitListen(port);
    return child;
}

fn waitListen(port: u16) void {
    var addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(port) };
    var i: usize = 0;
    while (i < 200000) : (i += 1) {
        if (addr.connect(tio, .{ .mode = .stream })) |s| {
            s.close(tio);
            return;
        } else |_| {}
    }
}

fn testConfig(signal_uri: ?[]const u8) client_service.Adapter.Config {
    return .{
        .wg_priv = wgbox.generatePrivateKey(tio),
        .meta = .{
            .hostname = "zig-adapter-test",
            .go_os = "linux",
            .netbird_version = "0.80.0-test",
        },
        .ssh_pub_key = "ssh-test-key",
        .signal_uri = signal_uri,
    };
}

fn backendFor(sc: *client_service.ServiceContext, mgmt_url: []const u8) engine.Service {
    return client_service.ServiceContext.serviceFn(sc, &profile.Config{}, mgmt_url, null);
}

/// Stub WG runtime: records the binding calls the adapter makes. Proves
/// the WgBinding call contract only, never WG behavior.
const WgStub = struct {
    starts: usize = 0,
    stops: usize = 0,
    fail: bool = false,
    saw_peer_address: bool = false,

    fn startFn(ctx: *anyopaque, view: client_service.WgBinding.View) client_service.WgBinding.WgError!void {
        const s: *WgStub = @ptrCast(@alignCast(ctx));
        s.starts += 1;
        s.saw_peer_address = view.peer_address.len > 0;
        if (s.fail) return error.WgFailed;
    }

    fn stopFn(ctx: *anyopaque) void {
        const s: *WgStub = @ptrCast(@alignCast(ctx));
        s.stops += 1;
    }

    fn binding(s: *WgStub) client_service.WgBinding {
        return .{ .ctx = s, .startFn = startFn, .stopFn = stopFn };
    }
};

test "adapter login stores state only after management response" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    var child = try spawnMgmt(alloc, 18801);
    defer child.kill(tio);
    const sc = try client_service.ServiceContext.create(alloc, tio, testConfig(null), client_service.plain_dial);
    defer sc.destroy();
    const svc = backendFor(sc, "127.0.0.1:18801");
    try svc.loginFn(svc.ctx, "test-setup-key");
    const a = &sc.adapter;
    const auth = a.auth orelse return error.NoAuthState;
    // Both values come from the actual LoginResponse of the Go fake.
    try std.testing.expectEqualStrings("signal.netbird.io:443", auth.signal_uri);
    try std.testing.expectEqualStrings("100.120.0.1/16", auth.peer_address);
    // Login holds no connection resources after it returns.
    try std.testing.expect(a.mgmt_transport == null and a.mgmt_conn == null);
    try std.testing.expect(a.sig_transport == null and a.sync == null);
}

test "adapter login bad setup key denied, no state" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    var child = try spawnMgmt(alloc, 18802);
    defer child.kill(tio);
    const sc = try client_service.ServiceContext.create(alloc, tio, testConfig(null), client_service.plain_dial);
    defer sc.destroy();
    const svc = backendFor(sc, "127.0.0.1:18802");
    try std.testing.expectError(error.AuthFailed, svc.loginFn(svc.ctx, "wrong-key"));
    try std.testing.expect(sc.adapter.auth == null);
}

test "adapter login unreachable management is Network, no state" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    const sc = try client_service.ServiceContext.create(alloc, tio, testConfig(null), client_service.plain_dial);
    defer sc.destroy();
    const svc = backendFor(sc, "127.0.0.1:18803");
    try std.testing.expectError(error.Network, svc.loginFn(svc.ctx, "test-setup-key"));
    try std.testing.expect(sc.adapter.auth == null);
}

test "adapter start without login fails and acquires nothing" {
    const alloc = std.testing.allocator;
    const sc = try client_service.ServiceContext.create(alloc, tio, testConfig(null), client_service.plain_dial);
    defer sc.destroy();
    var stub = WgStub{};
    sc.adapter.wg = stub.binding();
    const svc = backendFor(sc, "127.0.0.1:18803");
    try std.testing.expectError(error.StartFailed, svc.startFn(svc.ctx));
    try std.testing.expectEqual(@as(usize, 0), stub.starts);
    try std.testing.expect(sc.adapter.sig_transport == null and sc.adapter.sync == null);
}

test "adapter start stop lifecycle releases once" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    var mgmt_child = try spawnMgmt(alloc, 18804);
    defer mgmt_child.kill(tio);
    var sig_child = try spawnSignal(alloc, 18810);
    defer sig_child.kill(tio);
    const sc = try client_service.ServiceContext.create(alloc, tio, testConfig("127.0.0.1:18810"), client_service.plain_dial);
    defer sc.destroy();
    var stub = WgStub{};
    sc.adapter.wg = stub.binding();
    const svc = backendFor(sc, "127.0.0.1:18804");
    try svc.loginFn(svc.ctx, "test-setup-key");
    try svc.startFn(svc.ctx);
    const a = &sc.adapter;
    try std.testing.expectEqual(@as(usize, 1), stub.starts);
    try std.testing.expect(stub.saw_peer_address);
    const sig_stream = a.sig_stream orelse return error.NoSignalStream;
    try std.testing.expect(sig_stream.registered());
    try std.testing.expect(a.sync != null);
    svc.stopFn(svc.ctx);
    try std.testing.expectEqual(@as(usize, 1), stub.stops);
    try std.testing.expect(a.sig_transport == null and a.sig_stream == null);
    try std.testing.expect(a.mgmt_transport == null and a.sync == null);
    try std.testing.expect(!a.wg_started);
    // A second stop (Engine down after a stop) is a quiet no-op.
    svc.stopFn(svc.ctx);
    try std.testing.expectEqual(@as(usize, 1), stub.stops);
    // Authentication survives stop: a later up reconnects without login.
    try std.testing.expect(a.auth != null);
}

test "adapter start failing wg binding releases acquired resources" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    var mgmt_child = try spawnMgmt(alloc, 18805);
    defer mgmt_child.kill(tio);
    var sig_child = try spawnSignal(alloc, 18812);
    defer sig_child.kill(tio);
    const sc = try client_service.ServiceContext.create(alloc, tio, testConfig("127.0.0.1:18812"), client_service.plain_dial);
    defer sc.destroy();
    var stub = WgStub{ .fail = true };
    sc.adapter.wg = stub.binding();
    const svc = backendFor(sc, "127.0.0.1:18805");
    try svc.loginFn(svc.ctx, "test-setup-key");
    try std.testing.expectError(error.StartFailed, svc.startFn(svc.ctx));
    try std.testing.expectEqual(@as(usize, 1), stub.starts);
    try std.testing.expectEqual(@as(usize, 0), stub.stops);
    // Partial startup failure: signal resources released, stop is safe.
    try std.testing.expect(sc.adapter.sig_transport == null and sc.adapter.sig_stream == null);
    try std.testing.expect(sc.adapter.mgmt_transport == null and sc.adapter.sync == null);
    svc.stopFn(svc.ctx);
    try std.testing.expectEqual(@as(usize, 0), stub.stops);
}

test "adapter start unbound wg releases signal and management" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    var mgmt_child = try spawnMgmt(alloc, 18806);
    defer mgmt_child.kill(tio);
    var sig_child = try spawnSignal(alloc, 18814);
    defer sig_child.kill(tio);
    const sc = try client_service.ServiceContext.create(alloc, tio, testConfig("127.0.0.1:18814"), client_service.plain_dial);
    defer sc.destroy();
    const svc = backendFor(sc, "127.0.0.1:18806");
    try svc.loginFn(svc.ctx, "test-setup-key");
    // No WgBinding: the required data-plane resources do not exist, so
    // the start fails instead of claiming success.
    try std.testing.expectError(error.StartFailed, svc.startFn(svc.ctx));
    try std.testing.expect(sc.adapter.sig_transport == null and sc.adapter.sig_stream == null);
    try std.testing.expect(sc.adapter.mgmt_transport == null and sc.adapter.sync == null);
}

test "engine login down up reconnect through real adapter" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    var mgmt_child = try spawnMgmt(alloc, 18807);
    defer mgmt_child.kill(tio);
    var sig_child = try spawnSignal(alloc, 18816);
    defer sig_child.kill(tio);
    const sc = try client_service.ServiceContext.create(alloc, tio, testConfig("127.0.0.1:18816"), client_service.plain_dial);
    defer sc.destroy();
    var stub = WgStub{};
    sc.adapter.wg = stub.binding();
    var eng = try engine.Engine.init(alloc, backendFor(sc, "127.0.0.1:18807"));
    defer eng.deinit();
    try eng.login("test-setup-key");
    try std.testing.expectEqual(engine.State.connected, eng.status().state);
    eng.down() catch {};
    try std.testing.expectEqual(engine.State.stopped, eng.status().state);
    try std.testing.expectEqual(@as(usize, 1), stub.stops);
    // Reconnect from stored authentication: no second login call.
    try eng.up();
    try std.testing.expectEqual(engine.State.connected, eng.status().state);
    try std.testing.expectEqual(@as(usize, 2), stub.starts);
    eng.down() catch {};
    try std.testing.expectEqual(@as(usize, 2), stub.stops);
}

test "engine up without login is NotAuthenticated" {
    const alloc = std.testing.allocator;
    const sc = try client_service.ServiceContext.create(alloc, tio, testConfig(null), client_service.plain_dial);
    defer sc.destroy();
    var eng = try engine.Engine.init(alloc, backendFor(sc, "127.0.0.1:18803"));
    defer eng.deinit();
    try std.testing.expectError(error.NotAuthenticated, eng.up());
    try std.testing.expectEqual(engine.State.needs_login, eng.status().state);
    try std.testing.expect(sc.adapter.auth == null);
}

/// Finite scripted transport: advertises non-default SETTINGS, records
/// the first RPC HEADERS, then closes rather than waiting for a server.
const HandshakeProbe = struct {
    sc: *client_service.ServiceContext = undefined,
    input: [64]u8 = undefined,
    len: usize = 0,
    off: usize = 0,
    closes: usize = 0,
    first_rpc: ?u32 = null,
    preserved: bool = false,

    fn dial(ctx: *anyopaque, _: []const u8, _: std.mem.Allocator, _: std.Io) client_service.DialError!client_service.DialResult {
        const p: *HandshakeProbe = @ptrCast(@alignCast(ctx));
        const frame = @import("net/h2/frame.zig");
        var w = frame.Writer.init(&p.input);
        w.writeSettings(&.{
            .{ .id = .initial_window_size, .val = 12345 },
            .{ .id = .max_concurrent_streams, .val = 3 },
            .{ .id = .max_frame_size, .val = 32768 },
        }) catch unreachable;
        p.len = w.bytes().len;
        p.off = 0;
        return .{ .ctx = p, .transport = .{ .ctx = p, .readFn = read, .writeFn = write }, .closeFn = close };
    }
    fn read(ctx: *anyopaque, buf: []u8) @import("net/h2/conn.zig").Transport.ReadError!usize {
        const p: *HandshakeProbe = @ptrCast(@alignCast(ctx));
        if (p.off == p.len) return error.Closed;
        const n = @min(buf.len, p.len - p.off);
        @memcpy(buf[0..n], p.input[p.off..][0..n]);
        p.off += n;
        return n;
    }
    fn write(ctx: *anyopaque, bytes: []const u8) @import("net/h2/conn.zig").Transport.WriteError!void {
        const p: *HandshakeProbe = @ptrCast(@alignCast(ctx));
        const frame = @import("net/h2/frame.zig");
        if (std.mem.eql(u8, bytes, frame.client_preface)) return;
        if (bytes.len < 9) return;
        const header = frame.Header.parse(bytes[0..9]);
        if (header.type == .headers and p.first_rpc == null) {
            p.first_rpc = header.stream_id;
            const c = &p.sc.adapter.sig_conn.?;
            p.preserved = c.peer_initial_window == 12345 and
                c.peer_max_concurrent == 3 and c.peer_max_frame_size == 32768 and
                c.next_stream_id == 3 and c.streams[0].send_window == 12345;
        }
    }
    fn close(ctx: *anyopaque) void {
        const p: *HandshakeProbe = @ptrCast(@alignCast(ctx));
        p.closes += 1;
    }
};

test "handshaken signal Conn preserves SETTINGS for first RPC and rollback stop is idempotent" {
    const alloc = std.testing.allocator;
    var probe = HandshakeProbe{};
    const sc = try client_service.ServiceContext.create(alloc, tio, testConfig(null), .{ .ctx = &probe, .dialFn = HandshakeProbe.dial });
    defer sc.destroy();
    probe.sc = sc;
    sc.adapter.auth = .{
        .signal_uri = try alloc.dupe(u8, "local-signal"),
        .peer_address = try alloc.dupe(u8, "100.120.0.1/16"),
    };
    const svc = backendFor(sc, "local-management");
    try std.testing.expectError(error.StartFailed, svc.startFn(svc.ctx));
    try std.testing.expectEqual(@as(?u32, 1), probe.first_rpc);
    try std.testing.expect(probe.preserved);
    try std.testing.expectEqual(@as(usize, 1), probe.closes);
    svc.stopFn(svc.ctx);
    svc.stopFn(svc.ctx);
    try std.testing.expectEqual(@as(usize, 1), probe.closes);
    try std.testing.expect(sc.adapter.sig_conn == null and sc.adapter.sig_client == null);
}

test "service selection borrows endpoint and never retains setup key or profile" {
    const alloc = std.testing.allocator;
    const sc = try client_service.ServiceContext.create(alloc, tio, testConfig(null), client_service.plain_dial);
    defer sc.destroy();
    var endpoint = "127.0.0.1:18803".*;
    var key = "transient-selection-key".*;
    var cfg = profile.Config{ .Name = "invocation-profile" };
    const svc = client_service.ServiceContext.serviceFn(sc, &cfg, &endpoint, &key);
    @memset(&key, 'x');
    cfg.Name = "changed";
    try std.testing.expectEqual(endpoint[0..].ptr, sc.adapter.mgmt_url.ptr);
    // The only key consumed is the subsequent login argument. A failed
    // dial cannot leave any authentication or key-containing resources.
    try std.testing.expectError(error.Network, svc.loginFn(svc.ctx, "login-only-key"));
    try std.testing.expect(sc.adapter.auth == null);
    try std.testing.expect(sc.adapter.mgmt_client == null and sc.adapter.sig_client == null);
}
