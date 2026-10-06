// Ownership regression for signal decryptMessage through the public
// connectStream/recv path (review of #81, part of #6). An in-memory H2 peer
// serves response headers plus one length-prefixed boxed EncryptedMessage;
// every recv-phase allocation failure must yield OutOfMemory with zero live
// bytes and no invalid frees. The transport never fails (H2 is alloc-free;
// connect runs on the ordinary allocator), so the checker covers recv only.
// Pipe/framing pattern reused from the transport lane's
// grpc_headers_ownership_test (public APIs only).
// Run: zig test src/signal_ownership_test.zig

const std = @import("std");
const signal = @import("signal/client.zig");
const messages = @import("signal/messages.zig");
const wgbox = @import("mgmt/wgbox.zig");
const grpc = @import("net/grpc/client.zig");
const h2 = @import("net/h2/conn.zig");
const hpack = @import("net/h2/hpack.zig");
const frame = @import("net/h2/frame.zig");

const tio = std.testing.io;

/// Fail-once + liveness checker over a backing allocator. Fails exactly the
/// `fail_at`-th alloc/resize/remap call (usize.max disables), tracks live
/// non-empty allocations, and counts invalid frees without forwarding them
/// (keeps the backing allocator consistent so the failure point is reported
/// before the debug allocator aborts on the use-after-free write).
const Checker = struct {
    backing: std.mem.Allocator,
    fail_at: usize,
    calls: usize = 0,
    live: [32][2]usize = undefined,
    live_count: usize = 0,
    violations: usize = 0,

    fn allocator(c: *Checker) std.mem.Allocator {
        return .{
            .ptr = c,
            .vtable = &.{
                .alloc = allocFn,
                .resize = resizeFn,
                .remap = remapFn,
                .free = freeFn,
            },
        };
    }

    fn shouldFail(c: *Checker) bool {
        const i = c.calls;
        c.calls += 1;
        return i == c.fail_at;
    }

    fn track(c: *Checker, addr: usize, len: usize) void {
        if (len == 0) return;
        if (c.live_count == c.live.len) {
            c.violations += 1;
            return;
        }
        c.live[c.live_count] = .{ addr, len };
        c.live_count += 1;
    }

    fn untrack(c: *Checker, addr: usize, len: usize) bool {
        if (len == 0) return true;
        for (c.live[0..c.live_count], 0..) |e, i| {
            if (e[0] == addr) {
                c.live[i] = c.live[c.live_count - 1];
                c.live_count -= 1;
                return true;
            }
        }
        return false;
    }

    fn allocFn(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const c: *Checker = @ptrCast(@alignCast(ctx));
        if (c.shouldFail()) return null;
        const ptr = c.backing.rawAlloc(len, alignment, ret_addr) orelse return null;
        c.track(@intFromPtr(ptr), len);
        return ptr;
    }

    fn resizeFn(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const c: *Checker = @ptrCast(@alignCast(ctx));
        if (c.shouldFail()) return false;
        if (!c.backing.rawResize(memory, alignment, new_len, ret_addr)) return false;
        if (c.untrack(@intFromPtr(memory.ptr), memory.len)) c.track(@intFromPtr(memory.ptr), new_len) else c.violations += 1;
        return true;
    }

    fn remapFn(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const c: *Checker = @ptrCast(@alignCast(ctx));
        if (c.shouldFail()) return null;
        const ptr = c.backing.rawRemap(memory, alignment, new_len, ret_addr) orelse return null;
        if (!c.untrack(@intFromPtr(memory.ptr), memory.len)) c.violations += 1;
        c.track(@intFromPtr(ptr), new_len);
        return ptr;
    }

    fn freeFn(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const c: *Checker = @ptrCast(@alignCast(ctx));
        if (c.untrack(@intFromPtr(memory.ptr), memory.len)) {
            c.backing.rawFree(memory, alignment, ret_addr);
        } else {
            c.violations += 1;
        }
    }
};

/// In-memory full-duplex pipe: inbound feeds reads, outbound records writes.
const Pipe = struct {
    inbound: []const u8,
    in_pos: usize = 0,
    outbound: [65536]u8 = undefined,
    out_len: usize = 0,

    fn read(ctx: *anyopaque, buf: []u8) h2.Transport.ReadError!usize {
        const self: *Pipe = @ptrCast(@alignCast(ctx));
        if (self.in_pos >= self.inbound.len) return 0;
        const n = @min(buf.len, self.inbound.len - self.in_pos);
        @memcpy(buf[0..n], self.inbound[self.in_pos..][0..n]);
        self.in_pos += n;
        return n;
    }

    fn write(ctx: *anyopaque, buf: []const u8) h2.Transport.WriteError!void {
        const self: *Pipe = @ptrCast(@alignCast(ctx));
        @memcpy(self.outbound[self.out_len..][0..buf.len], buf);
        self.out_len += buf.len;
    }

    fn transport(p: *Pipe) h2.Transport {
        return .{ .ctx = p, .readFn = read, .writeFn = write };
    }
};

fn encodeFrame(out: []u8, t: frame.FrameType, flags: frame.Flags, id: u32, payload: []const u8) []u8 {
    out[0] = @truncate(payload.len >> 16);
    out[1] = @truncate(payload.len >> 8);
    out[2] = @truncate(payload.len);
    out[3] = @intFromEnum(t);
    out[4] = flags;
    std.mem.writeInt(u32, out[5..9], id, .big);
    @memcpy(out[9..][0..payload.len], payload);
    return out[0 .. 9 + payload.len];
}

/// One scripted session. Self-referential (pipe/conn/client/stream borrow
/// each other); always used in place, never moved after setup.
const Session = struct {
    pipe: Pipe = undefined,
    conn: h2.Conn = undefined,
    client: signal.Client = undefined,
    stream: signal.Stream = undefined,
};

/// Connect over scripted server bytes with the ordinary allocator, then
/// switch signal-side allocators to the checker for recv. Transport
/// allocations (startCall fields, captured headers) never fail, so the
/// sweep covers the recv/decrypt phase only.
fn sessionSetup(s: *Session, ordinary: std.mem.Allocator, chk: *Checker, server: []const u8, priv: wgbox.Key) !void {
    s.pipe = Pipe{ .inbound = server };
    s.conn = h2.Conn.init(s.pipe.transport());
    try s.conn.handshake();
    s.client = signal.Client{
        .conn = &s.conn,
        .alloc = ordinary,
        .authority = "127.0.0.1:1",
        .io = tio,
        .key = priv,
    };
    errdefer s.client.deinit();
    s.stream = try s.client.connectStream();
    errdefer s.stream.deinit();
    s.client.alloc = chk.allocator();
    s.stream.call.alloc = chk.allocator();
}

/// Phased teardown: checker-owned recv memory (rx buffer) first, then
/// ordinary-owned connect memory (captured headers, status).
fn sessionTeardown(s: *Session, ordinary: std.mem.Allocator, chk: *Checker) void {
    s.stream.call.rx.deinit(chk.allocator());
    s.stream.call.rx = .empty;
    s.stream.call.alloc = ordinary;
    s.stream.deinit();
    s.client.alloc = ordinary;
    s.client.deinit();
}

test "signal decrypt owns keys through recv under allocation failure" {
    const alloc = std.testing.allocator;

    // Fixed clamped private keys: deterministic, no randomness in this test.
    var a_priv: wgbox.Key = @splat(0x42);
    a_priv[0] &= 248;
    a_priv[31] &= 127;
    a_priv[31] |= 64;
    var b_priv: wgbox.Key = @splat(0x24);
    b_priv[0] &= 248;
    b_priv[31] &= 127;
    b_priv[31] |= 64;
    const a_pub = try wgbox.allocString(alloc, wgbox.publicKey(a_priv));
    defer alloc.free(a_pub);
    const b_pub = try wgbox.allocString(alloc, wgbox.publicKey(b_priv));
    defer alloc.free(b_pub);

    // B encrypts a Body for A; the scripted peer routes it back to A.
    const body = messages.Body{
        .msg_type = .offer,
        .payload = "offer-sdp-regression",
        .wg_listen_port = 51820,
        .netbird_version = "0.79.0",
    };
    const plain = try body.encode(alloc);
    defer alloc.free(plain);
    const nonce: [wgbox.nonce_size]u8 = @splat(7);
    const enc_body = try wgbox.encryptWithNonce(alloc, plain, wgbox.publicKey(a_priv), b_priv, nonce);
    defer alloc.free(enc_body);
    const env = messages.EncryptedMessage{ .key = b_pub, .remote_key = a_pub, .body = enc_body };
    const env_bytes = try env.encode(alloc);
    defer alloc.free(env_bytes);

    // Scripted server bytes: SETTINGS, registered response HEADERS, one
    // length-prefixed DATA message carrying the boxed envelope.
    var enc = hpack.Encoder.init();
    var block: [512]u8 = undefined;
    var blen: usize = 0;
    for ([_]hpack.HeaderField{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "application/grpc" },
        .{ .name = "x-wiretrustee-peer-registered", .value = "true" },
    }) |f| {
        blen += try enc.writeField(block[blen..], f);
    }
    var gframe: [2048]u8 = undefined;
    gframe[0] = 0;
    std.mem.writeInt(u32, gframe[1..5], @intCast(env_bytes.len), .big);
    @memcpy(gframe[5..][0..env_bytes.len], env_bytes);
    var inbound: [2048]u8 = undefined;
    var ilen: usize = 0;
    ilen += encodeFrame(inbound[ilen..], .settings, 0, 0, &.{}).len;
    ilen += encodeFrame(inbound[ilen..], .headers, frame.flag_headers_end_headers, 1, block[0..blen]).len;
    ilen += encodeFrame(inbound[ilen..], .data, 0, 1, gframe[0 .. 5 + env_bytes.len]).len;
    const server = inbound[0..ilen];

    // Success path through the checker: full decrypted assertions + count.
    var probe = Checker{ .backing = alloc, .fail_at = std.math.maxInt(usize) };
    var ps: Session = undefined;
    try sessionSetup(&ps, alloc, &probe, server, a_priv);
    var good = (try ps.stream.recv()) orelse return error.ExpectedMessage;
    errdefer good.deinit(probe.allocator());
    try std.testing.expect(ps.stream.registered());
    try std.testing.expectEqualStrings(b_pub, good.key);
    try std.testing.expectEqualStrings(a_pub, good.remote_key);
    try std.testing.expectEqual(messages.BodyType.offer, good.body.msg_type);
    try std.testing.expectEqualStrings("offer-sdp-regression", good.body.payload);
    try std.testing.expectEqual(@as(u32, 51820), good.body.wg_listen_port);
    try std.testing.expectEqualStrings("0.79.0", good.body.netbird_version);
    good.deinit(probe.allocator());
    sessionTeardown(&ps, alloc, &probe);
    try std.testing.expectEqual(@as(usize, 0), probe.live_count);
    try std.testing.expectEqual(@as(usize, 0), probe.violations);
    const total = probe.calls;
    try std.testing.expect(total > 0);

    // Every recv-phase failure point: OutOfMemory, nothing live, no bad free.
    var i: usize = 0;
    while (i < total) : (i += 1) {
        var chk = Checker{ .backing = alloc, .fail_at = i };
        var s: Session = undefined;
        try sessionSetup(&s, alloc, &chk, server, a_priv);
        if (s.stream.recv()) |maybe| {
            var m = maybe orelse return error.ExpectedMessage;
            m.deinit(chk.allocator());
        } else |err| {
            try std.testing.expectEqual(signal.Error.OutOfMemory, err);
        }
        sessionTeardown(&s, alloc, &chk);
        if (chk.live_count != 0 or chk.violations != 0) {
            std.debug.print("recv failed check at call {d}/{d}: live={d} violations={d}\n", .{ i, total, chk.live_count, chk.violations });
        }
        try std.testing.expectEqual(@as(usize, 0), chk.live_count);
        try std.testing.expectEqual(@as(usize, 0), chk.violations);
    }
}
