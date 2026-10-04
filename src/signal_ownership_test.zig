// Ownership regression for signal decoders (review of #81, part of #6).
// Each decoder gets a buffer with every owned field repeated (two concatenated
// valid encodings, last wins) and every single-allocation failure point is
// swept, requiring OutOfMemory-or-success with zero live bytes and no invalid
// frees. Run: zig test src/signal_ownership_test.zig

const std = @import("std");
const messages = @import("signal/messages.zig");

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

fn sweep(
    comptime T: type,
    backing: std.mem.Allocator,
    bytes: []const u8,
    decode: *const fn (std.mem.Allocator, []const u8) messages.Error!T,
    deinitFn: *const fn (*T, std.mem.Allocator) void,
    check: *const fn (*const T) anyerror!void,
) anyerror!void {
    var probe = Checker{ .backing = backing, .fail_at = std.math.maxInt(usize) };
    var good = try decode(probe.allocator(), bytes);
    errdefer deinitFn(&good, probe.allocator());
    try check(&good);
    deinitFn(&good, probe.allocator());
    try std.testing.expectEqual(@as(usize, 0), probe.live_count);
    try std.testing.expectEqual(@as(usize, 0), probe.violations);
    const total = probe.calls;
    try std.testing.expect(total > 0);

    var i: usize = 0;
    while (i < total) : (i += 1) {
        var chk = Checker{ .backing = backing, .fail_at = i };
        if (decode(chk.allocator(), bytes)) |v| {
            var owned = v;
            deinitFn(&owned, chk.allocator());
        } else |err| {
            try std.testing.expectEqual(messages.Error.OutOfMemory, err);
        }
        if (chk.live_count != 0 or chk.violations != 0) {
            std.debug.print("{s} failed check at call {d}/{d}: live={d} violations={d}\n", .{ @typeName(T), i, total, chk.live_count, chk.violations });
        }
        try std.testing.expectEqual(@as(usize, 0), chk.live_count);
        try std.testing.expectEqual(@as(usize, 0), chk.violations);
    }
}

fn checkEnvB(m: *const messages.EncryptedMessage) anyerror!void {
    try std.testing.expectEqualStrings("env-B-key", m.key);
    try std.testing.expectEqualStrings("env-B-remote", m.remote_key);
    try std.testing.expectEqualStrings("env-B-body", m.body);
}

test "EncryptedMessage decode replaces repeated fields cleanly" {
    const alloc = std.testing.allocator;
    const ea = messages.EncryptedMessage{ .key = "env-A-key", .remote_key = "env-A-remote", .body = "env-A-body" };
    const eb = messages.EncryptedMessage{ .key = "env-B-key", .remote_key = "env-B-remote", .body = "env-B-body" };
    const ba = try ea.encode(alloc);
    defer alloc.free(ba);
    const bb = try eb.encode(alloc);
    defer alloc.free(bb);
    const both = try std.mem.concat(alloc, u8, &.{ ba, bb });
    defer alloc.free(both);
    try sweep(messages.EncryptedMessage, alloc, both, &messages.EncryptedMessage.decode, &messages.EncryptedMessage.deinit, &checkEnvB);
}

// Repeated packed field 6 merges across occurrences (proto semantics);
// singular fields below take the last occurrence.
const body_merged_feats = [_]u32{ 1, 2, 7, 8, 300 };

fn checkBodyB(m: *const messages.Body) anyerror!void {
    try std.testing.expectEqual(messages.BodyType.answer, m.msg_type);
    try std.testing.expectEqualStrings("payload-B", m.payload);
    try std.testing.expectEqual(@as(u32, 2222), m.wg_listen_port);
    try std.testing.expectEqualStrings("ver-B", m.netbird_version);
    try std.testing.expectEqual(true, m.mode.?.direct.?);
    try std.testing.expectEqualSlices(u32, &body_merged_feats, m.features_supported);
    try std.testing.expectEqualStrings("rp-B-pub", m.rosenpass_config.?.rosenpass_pub_key);
    try std.testing.expectEqualStrings("rp-B-addr", m.rosenpass_config.?.rosenpass_server_addr);
    try std.testing.expectEqualStrings("relay-B", m.relay_server_address.?);
    try std.testing.expectEqualStrings("sess-B", m.session_id.?);
    try std.testing.expectEqualStrings("ip-B", m.relay_server_ip.?);
}

test "Body decode replaces repeated fields cleanly" {
    const alloc = std.testing.allocator;
    const a_feats = [_]u32{ 1, 2 };
    const b_feats = [_]u32{ 7, 8, 300 };
    const ba_in = messages.Body{
        .msg_type = .offer,
        .payload = "payload-A",
        .wg_listen_port = 1111,
        .netbird_version = "ver-A",
        .mode = .{ .direct = false },
        .features_supported = &a_feats,
        .rosenpass_config = .{ .rosenpass_pub_key = "rp-A-pub", .rosenpass_server_addr = "rp-A-addr" },
        .relay_server_address = "relay-A",
        .session_id = "sess-A",
        .relay_server_ip = "ip-A",
    };
    const bb_in = messages.Body{
        .msg_type = .answer,
        .payload = "payload-B",
        .wg_listen_port = 2222,
        .netbird_version = "ver-B",
        .mode = .{ .direct = true },
        .features_supported = &b_feats,
        .rosenpass_config = .{ .rosenpass_pub_key = "rp-B-pub", .rosenpass_server_addr = "rp-B-addr" },
        .relay_server_address = "relay-B",
        .session_id = "sess-B",
        .relay_server_ip = "ip-B",
    };
    const ba = try ba_in.encode(alloc);
    defer alloc.free(ba);
    const bb = try bb_in.encode(alloc);
    defer alloc.free(bb);
    const both = try std.mem.concat(alloc, u8, &.{ ba, bb });
    defer alloc.free(both);
    try sweep(messages.Body, alloc, both, &messages.Body.decode, &messages.Body.deinit, &checkBodyB);
}

fn checkRpB(m: *const messages.RosenpassConfig) anyerror!void {
    try std.testing.expectEqualStrings("direct-B-pub", m.rosenpass_pub_key);
    try std.testing.expectEqualStrings("direct-B-addr", m.rosenpass_server_addr);
}

test "RosenpassConfig decode replaces repeated fields cleanly" {
    const alloc = std.testing.allocator;
    const ra = messages.RosenpassConfig{ .rosenpass_pub_key = "direct-A-pub", .rosenpass_server_addr = "direct-A-addr" };
    const rb = messages.RosenpassConfig{ .rosenpass_pub_key = "direct-B-pub", .rosenpass_server_addr = "direct-B-addr" };
    const ba = try ra.encode(alloc);
    defer alloc.free(ba);
    const bb = try rb.encode(alloc);
    defer alloc.free(bb);
    const both = try std.mem.concat(alloc, u8, &.{ ba, bb });
    defer alloc.free(both);
    try sweep(messages.RosenpassConfig, alloc, both, &messages.RosenpassConfig.decode, &messages.RosenpassConfig.deinit, &checkRpB);
}
