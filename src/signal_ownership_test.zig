// Ownership regression for signal decryptMessage (review of #81, part of #6).
// Sweeps every single-allocation failure point through decryptMessage over a
// valid EncryptedMessage and requires OutOfMemory-or-success with zero live
// bytes and no invalid frees. Run: zig test src/signal_ownership_test.zig

const std = @import("std");
const messages = @import("signal/messages.zig");
const signal = @import("signal/client.zig");
const wgbox = @import("mgmt/wgbox.zig");

const tio = std.testing.io;

/// Fail-once + liveness checker over a backing allocator. Fails exactly the
/// `fail_at`-th alloc/resize/remap call (usize.max disables), tracks live
/// non-empty allocations, and counts invalid frees without forwarding them
/// (keeps the backing allocator consistent so the test fails gracefully).
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

test "decryptMessage owns both keys under any single allocation failure" {
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

    // B encrypts a Body for A; decryptMessage runs as A with env.key = B.
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

    var c = signal.Client{
        .conn = undefined,
        .alloc = alloc,
        .authority = "127.0.0.1:1",
        .io = tio,
        .key = a_priv,
    };

    // Success path through the checker: full output assertions + call count.
    var probe = Checker{ .backing = alloc, .fail_at = std.math.maxInt(usize) };
    c.alloc = probe.allocator();
    var good = try c.decryptMessage(env_bytes);
    errdefer good.deinit(probe.allocator());
    try std.testing.expectEqualStrings(b_pub, good.key);
    try std.testing.expectEqualStrings(a_pub, good.remote_key);
    try std.testing.expectEqual(messages.BodyType.offer, good.body.msg_type);
    try std.testing.expectEqualStrings("offer-sdp-regression", good.body.payload);
    try std.testing.expectEqual(@as(u32, 51820), good.body.wg_listen_port);
    try std.testing.expectEqualStrings("0.79.0", good.body.netbird_version);
    good.deinit(probe.allocator());
    try std.testing.expectEqual(@as(usize, 0), probe.live_count);
    try std.testing.expectEqual(@as(usize, 0), probe.violations);
    const total = probe.calls;
    try std.testing.expect(total > 0);

    // Every single failure point: OutOfMemory, nothing live, no invalid free.
    var i: usize = 0;
    while (i < total) : (i += 1) {
        var chk = Checker{ .backing = alloc, .fail_at = i };
        c.alloc = chk.allocator();
        if (c.decryptMessage(env_bytes)) |msg| {
            var mp = msg;
            mp.deinit(chk.allocator());
        } else |err| {
            try std.testing.expectEqual(signal.Error.OutOfMemory, err);
        }
        if (chk.live_count != 0 or chk.violations != 0) {
            std.debug.print("decryptMessage failed check at call {d}/{d}: live={d} violations={d}\n", .{ i, total, chk.live_count, chk.violations });
        }
        try std.testing.expectEqual(@as(usize, 0), chk.live_count);
        try std.testing.expectEqual(@as(usize, 0), chk.violations);
    }
}
