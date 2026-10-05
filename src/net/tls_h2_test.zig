// Live TLS-to-H2/gRPC tests against gen/tls-grpc (TLS grpc-go service).
// Sits at src/net/ (not src/net/grpc/) because each test suite gets no
// named imports: only relative imports work, and only within the suite
// file's own directory. TLS_GRPC_HELPER env or
// <release>/gen/tls-grpc-l1/tls-grpc; missing helper skips. No skips are
// accepted in CI-gated runs: the helper is a card-owned prerequisite.
// Localhost only, synthetic echo payloads. Covers: unary + server-stream
// + bidi over TLS, wrong-CA / wrong-hostname / no-ALPN rejection, close
// idempotence, and client cancel (RST CANCEL observed server-side).
// A TLS alert or record failure never maps to a fake successful EOF: the
// transport callbacks surface Reset, and every live case asserts either a
// real gRPC status or a visible error.

const std = @import("std");
const builtin = @import("builtin");
const tls_h2 = @import("tls_h2.zig");
const grpc = @import("grpc/client.zig");

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

fn helperPath(allocator: std.mem.Allocator) ![]u8 {
    if (try getenv(allocator, "TLS_GRPC_HELPER")) |p| {
        errdefer allocator.free(p);
        var f = std.Io.Dir.openFileAbsolute(tio, p, .{ .mode = .read_only }) catch return error.SkipZigTest;
        f.close(tio);
        return p;
    }
    const home = (try getenv(allocator, "HOME")) orelse return error.SkipZigTest;
    defer allocator.free(home);
    // Release-local helper first (card-owned prerequisite).
    const rel = try std.fmt.allocPrint(allocator, "{s}/.cache/netbird-zig-context/release-v080-20261005/gen/tls-grpc-l1/tls-grpc", .{home});
    errdefer allocator.free(rel);
    var rf = std.Io.Dir.openFileAbsolute(tio, rel, .{ .mode = .read_only }) catch {
        allocator.free(rel);
        const def = try std.fmt.allocPrint(allocator, "{s}/.cache/netbird-zig-context/gen/tls-grpc-l1/tls-grpc", .{home});
        errdefer allocator.free(def);
        var f = std.Io.Dir.openFileAbsolute(tio, def, .{ .mode = .read_only }) catch return error.SkipZigTest;
        f.close(tio);
        return def;
    };
    rf.close(tio);
    return rel;
}

const Live = struct {
    child: std.process.Child,
    conn: ?*tls_h2.Conn,
    alloc: std.mem.Allocator,
    tmp: std.Io.Dir,
    tmp_path: []u8,
    ca_path: []u8,
    status_path: []u8,
    ca_pem: []u8,

    fn spawn(
        allocator: std.mem.Allocator,
        mode: []const u8,
        port: u16,
    ) !*Live {
        const self = try allocator.create(Live);
        errdefer allocator.destroy(self);
        const helper = try helperPath(allocator);
        defer allocator.free(helper);

        var tmp_buf: [std.fs.max_path_bytes]u8 = undefined;
        const base = try std.fmt.bufPrint(&tmp_buf, "/tmp/tls-h2-{d}-{s}", .{ port, mode });
        std.Io.Dir.createDirAbsolute(tio, base, .default_dir) catch {};
        self.tmp_path = try allocator.dupe(u8, base);
        errdefer allocator.free(self.tmp_path);
        self.tmp = std.Io.Dir.openDirAbsolute(tio, base, .{}) catch return error.SkipZigTest;
        errdefer self.tmp.close(tio);
        self.ca_path = try std.fmt.allocPrint(allocator, "{s}/ca.pem", .{base});
        errdefer allocator.free(self.ca_path);
        self.status_path = try std.fmt.allocPrint(allocator, "{s}/status", .{base});
        errdefer allocator.free(self.status_path);
        // Pre-create the cancel-status file so a missing write is visible.
        {
            var sf = std.Io.Dir.createFileAbsolute(tio, self.status_path, .{}) catch return error.SkipZigTest;
            sf.close(tio);
        }

        std.Io.Dir.deleteFileAbsolute(tio, self.ca_path) catch |err| {
            if (err != error.FileNotFound) return err;
        };
        const addr_str = try std.fmt.allocPrint(allocator, "127.0.0.1:{d}", .{port});
        defer allocator.free(addr_str);
        const argv = [_][]const u8{ helper, mode, addr_str, self.ca_path, self.status_path };
        self.child = try std.process.spawn(tio, .{
            .argv = &argv,
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .ignore,
        });
        errdefer self.child.kill(tio);
        self.alloc = allocator;
        self.conn = null;
        self.ca_pem = &.{};

        // Wait for the helper to write the CA file (server is up then).
        var i: usize = 0;
        while (i < 5000) : (i += 1) {
            var caf = std.Io.Dir.openFileAbsolute(tio, self.ca_path, .{ .mode = .read_only }) catch {
                std.Io.sleep(tio, .fromMilliseconds(1), .awake) catch {};
                continue;
            };
            defer caf.close(tio);
            const size_raw = std.os.linux.lseek(caf.handle, 0, std.os.linux.SEEK.END);
            if (std.os.linux.errno(size_raw) != .SUCCESS) {
                std.Io.sleep(tio, .fromMilliseconds(1), .awake) catch {};
                continue;
            }
            if (size_raw == 0) {
                std.Io.sleep(tio, .fromMilliseconds(1), .awake) catch {};
                continue;
            }
            break;
        } else return error.ConnectTimeout;
        // Load the CA PEM into memory (no statx in tests either).
        {
            var caf = try std.Io.Dir.openFileAbsolute(tio, self.ca_path, .{ .mode = .read_only });
            defer caf.close(tio);
            const size: usize = @intCast(std.os.linux.lseek(caf.handle, 0, std.os.linux.SEEK.END));
            _ = std.os.linux.lseek(caf.handle, 0, std.os.linux.SEEK.SET);
            self.ca_pem = try allocator.alloc(u8, size);
            errdefer allocator.free(self.ca_pem);
            var off: usize = 0;
            var rbuf: [4096]u8 = undefined;
            var rdr = caf.reader(tio, &rbuf);
            while (off < size) {
                const n = try rdr.interface.readSliceShort(self.ca_pem[off..]);
                if (n == 0) break;
                off += n;
            }
            if (off != size) return error.ConnectTimeout;
        }
        return self;
    }

    fn dial(self: *Live, host: []const u8, ca: tls_h2.Ca, port: u16) !void {
        var addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(port) };
        self.conn = try tls_h2.Conn.connect(self.alloc, &addr, .{
            .host = host,
            .ca = ca,
            .io = tio,
            .alloc = self.alloc,
        });
    }

    fn dialTestCa(self: *Live, port: u16) !void {
        return self.dial("127.0.0.1", .{ .test_pem = self.ca_pem }, port);
    }

    fn readStatus(self: *Live) ![]u8 {
        var f = try std.Io.Dir.openFileAbsolute(tio, self.status_path, .{ .mode = .read_only });
        defer f.close(tio);
        const size: usize = @intCast(std.os.linux.lseek(f.handle, 0, std.os.linux.SEEK.END));
        _ = std.os.linux.lseek(f.handle, 0, std.os.linux.SEEK.SET);
        const out = try self.alloc.alloc(u8, size);
        errdefer self.alloc.free(out);
        var off: usize = 0;
        var rbuf: [1024]u8 = undefined;
        var rdr = f.reader(tio, &rbuf);
        while (off < size) {
            const n = try rdr.interface.readSliceShort(out[off..]);
            if (n == 0) break;
            off += n;
        }
        return out[0..off];
    }

    fn close(self: *Live) void {
        if (self.conn) |c| {
            c.deinit(self.alloc);
            self.conn = null;
        }
        self.child.kill(tio);
        self.tmp.close(tio);
        self.alloc.free(self.ca_pem);
        self.alloc.free(self.ca_path);
        self.alloc.free(self.status_path);
        self.alloc.free(self.tmp_path);
        self.alloc.destroy(self);
    }
};

/// Hand-encode echo.Payload{body}: field 1, wire type 2.
fn encodePayload(allocator: std.mem.Allocator, body: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, 2 + body.len);
    out[0] = 0x0a;
    out[1] = @intCast(body.len);
    @memcpy(out[2..], body);
    return out;
}

/// Hand-decode echo.Payload.body.
fn decodeBody(msg: []const u8) ![]const u8 {
    if (msg.len < 2 or msg[0] != 0x0a) return error.BadPayload;
    const len = msg[1];
    if (msg.len != 2 + len) return error.BadPayload;
    return msg[2..];
}

test "tls_h2 unary echo over TLS" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    const live = try Live.spawn(alloc, "h2", 18671);
    defer live.close();
    try live.dialTestCa(18671);
    const req = try encodePayload(alloc, "hello");
    defer alloc.free(req);
    var res = try grpc.unary(live.conn.?.h2Conn(), alloc, "/echo.Echo/Unary", "127.0.0.1:18671", null, req, tio);
    defer res.deinit(alloc);
    try std.testing.expectEqual(@as(u32, 0), res.status);
    try std.testing.expectEqualStrings("echo:hello", try decodeBody(res.body.?));
}

test "tls_h2 server stream collects three over TLS" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    const live = try Live.spawn(alloc, "h2", 18672);
    defer live.close();
    try live.dialTestCa(18672);
    var c = try grpc.startCall(live.conn.?.h2Conn(), alloc, "/echo.Echo/ServerStream", "127.0.0.1:18672", null, tio);
    defer c.deinit();
    const req = try encodePayload(alloc, "s");
    defer alloc.free(req);
    try grpc.sendMessage(&c, req, true);
    var bodies: [3][]u8 = undefined;
    var n: usize = 0;
    defer for (bodies[0..n]) |b| alloc.free(b);
    while (n < 3) {
        const m = (try grpc.recvMessage(&c)) orelse return error.MissingMessage;
        bodies[n] = try alloc.dupe(u8, try decodeBody(m));
        n += 1;
    }
    try live.conn.?.cancelStream(c.stream_id);
    try std.testing.expectEqual(@as(usize, 3), n);
    try std.testing.expectEqualStrings("s0", bodies[0]);
    try std.testing.expectEqualStrings("s1", bodies[1]);
    try std.testing.expectEqualStrings("s2", bodies[2]);
}

test "tls_h2 bidi echo interleaved over TLS" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    const live = try Live.spawn(alloc, "h2", 18673);
    defer live.close();
    try live.dialTestCa(18673);
    var c = try grpc.startCall(live.conn.?.h2Conn(), alloc, "/echo.Echo/Bidi", "127.0.0.1:18673", null, tio);
    defer c.deinit();
    const ra = try encodePayload(alloc, "a");
    defer alloc.free(ra);
    try grpc.sendMessage(&c, ra, false);
    const ma = try grpc.recvMessage(&c);
    try std.testing.expectEqualStrings("b:a", try decodeBody(ma.?));
    const rb = try encodePayload(alloc, "b");
    defer alloc.free(rb);
    try grpc.sendMessage(&c, rb, false);
    const mb = try grpc.recvMessage(&c);
    try std.testing.expectEqualStrings("b:b", try decodeBody(mb.?));
    try grpc.closeSend(&c);
    try std.testing.expect(try grpc.recvMessage(&c) == null);
    try std.testing.expectEqual(@as(u32, 0), c.status().?);
}

test "tls_h2 error maps status and message" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    const live = try Live.spawn(alloc, "h2", 18674);
    defer live.close();
    try live.dialTestCa(18674);
    const req = try encodePayload(alloc, "x");
    defer alloc.free(req);
    var res = try grpc.unary(live.conn.?.h2Conn(), alloc, "/echo.Echo/Fail", "127.0.0.1:18674", null, req, tio);
    defer res.deinit(alloc);
    try std.testing.expectEqual(@as(u32, 5), res.status); // NotFound
    try std.testing.expectEqualStrings("no such thing", res.message);
    try std.testing.expect(res.body == null);
}

test "tls_h2 wrong CA is rejected" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    const live = try Live.spawn(alloc, "h2", 18675);
    defer live.close();
    const wrong_path = try std.fmt.allocPrint(alloc, "{s}.wrong", .{live.ca_path});
    defer alloc.free(wrong_path);
    var wrong_file = try std.Io.Dir.openFileAbsolute(tio, wrong_path, .{ .mode = .read_only });
    defer wrong_file.close(tio);
    var wrong_buf: [4096]u8 = undefined;
    const wrong_n = try wrong_file.readPositionalAll(tio, &wrong_buf, 0);
    const wrong_ca = wrong_buf[0..wrong_n];
    var addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(18675) };
    const err = tls_h2.Conn.connect(alloc, &addr, .{
        .host = "127.0.0.1",
        .ca = .{ .test_pem = wrong_ca },
        .io = tio,
        .alloc = alloc,
    }) catch |e| e;
    try std.testing.expect(err == error.TlsFailed);
}

test "tls_h2 wrong hostname is rejected" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    const live = try Live.spawn(alloc, "h2", 18676);
    defer live.close();
    var addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(18676) };
    // The helper leaf is issued for 127.0.0.1/localhost only; asking for a
    // foreign name must fail hostname verification (TlsFailed).
    const err = tls_h2.Conn.connect(alloc, &addr, .{
        .host = "not-localhost.invalid",
        .ca = .{ .test_pem = live.ca_pem },
        .io = tio,
        .alloc = alloc,
    }) catch |e| e;
    try std.testing.expect(err == error.TlsFailed);
}

test "tls_h2 missing server ALPN is rejected" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    const live = try Live.spawn(alloc, "noalpn", 18677);
    defer live.close();
    // The helper offers no ALPN in this mode; the adapter requires h2, so
    // connect() must return AlpnRejected (not a silent h2c fallback).
    var addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(18677) };
    const err = tls_h2.Conn.connect(alloc, &addr, .{
        .host = "127.0.0.1",
        .ca = .{ .test_pem = live.ca_pem },
        .io = tio,
        .alloc = alloc,
    }) catch |e| e;
    try std.testing.expect(err == error.AlpnRejected);
}

test "tls_h2 close is idempotent and kills the transport" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    const live = try Live.spawn(alloc, "h2", 18678);
    defer live.close();
    try live.dialTestCa(18678);
    // One real call first so the session is proven alive.
    const req = try encodePayload(alloc, "hello");
    defer alloc.free(req);
    var res = try grpc.unary(live.conn.?.h2Conn(), alloc, "/echo.Echo/Unary", "127.0.0.1:18678", null, req, tio);
    res.deinit(alloc);
    try std.testing.expectEqual(@as(u32, 0), res.status);
    live.conn.?.close();
    // Second close is a no-op (exactly-once teardown, no double-close).
    live.conn.?.close();
    var observed = false;
    for (0..500) |_| {
        const st = try live.readStatus();
        defer alloc.free(st);
        if (std.mem.indexOf(u8, st, "connection_closed=true") != null or
            std.mem.indexOf(u8, st, "connection_eof=true") != null) {
            observed = true;
            break;
        }
        try std.Io.sleep(tio, .fromMilliseconds(10), .awake);
    }
    try std.testing.expect(observed);
    // Further transport use is a visible Closed, never a fake success.
    const err = live.conn.?.cancelStream(1) catch |e| e;
    try std.testing.expect(err == error.Closed);
}

test "tls_h2 client cancel aborts the server stream" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    const live = try Live.spawn(alloc, "h2", 18679);
    defer live.close();
    try live.dialTestCa(18679);
    var c = try grpc.startCall(live.conn.?.h2Conn(), alloc, "/echo.Echo/ServerStream", "127.0.0.1:18679", null, tio);
    defer c.deinit();
    const req = try encodePayload(alloc, "q");
    defer alloc.free(req);
    try grpc.sendMessage(&c, req, true);
    // Read one message, then cancel: the server blocks until the client
    // goes away (or is canceled), and records canceled=true on abort.
    const first = try grpc.recvMessage(&c);
    try std.testing.expect(first != null);
    try live.conn.?.cancelStream(c.stream_id);
    // The stream is over from our side; the server must observe the abort.
    var i: usize = 0;
    const seen = while (i < 500) : (i += 1) {
        const st = try live.readStatus();
        defer alloc.free(st);
        if (std.mem.indexOf(u8, st, "canceled=true") != null) break true;
        std.Io.sleep(tio, .fromMilliseconds(10), .awake) catch {};
    } else false;
    try std.testing.expect(seen);
}

test "tls_h2 partial CA allocation failures clean up" {
    const alloc = std.testing.allocator;
    const live = try Live.spawn(alloc, "h2", 18680);
    defer live.close();
    var reached_success = false;
    for (0..20) |fail_index| {
        var failing = std.testing.FailingAllocator.init(alloc, .{ .fail_index = fail_index });
        const fa = failing.allocator();
        var addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(18680) };
        const c = tls_h2.Conn.connect(fa, &addr, .{
            .host = "127.0.0.1", .ca = .{ .test_pem = live.ca_pem }, .io = tio, .alloc = fa,
        }) catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            continue;
        };
        c.deinit(fa);
        reached_success = true;
        break;
    }
    try std.testing.expect(reached_success);
}

test "tls_h2 H2 handshake failure frees owned CA" {
    const alloc = std.testing.allocator;
    const live = try Live.spawn(alloc, "badh2", 18681);
    defer live.close();
    try std.testing.expectError(error.HandshakeFailed, live.dialTestCa(18681));
}
