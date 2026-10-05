// Tests for the timers.go port. Fake clock, fixed jitter.

const std = @import("std");
const timers = @import("timers.zig");

const C = timers.Constants{
    .rekey_timeout_ns = 5_000,
    .max_timer_handshakes = 3,
    .jitter_max_ms = 0,
    .keepalive_timeout_ns = 10_000,
    .reject_after_time_ns = 180_000,
};

test "handshake retry then give up" {
    var t: timers.Timers = .{};
    t.start();
    t.handshakeInitiated(0, C, 0, true);
    var now: i64 = 5_000;
    // attempts 1..4 fire retransmit (attempts > max only after 4th)
    var i: u32 = 0;
    while (i < 4) : (i += 1) {
        const a = t.poll(now, C, 0, true);
        try std.testing.expect(a.retransmit_handshake);
        try std.testing.expect(!a.give_up);
        // device retries: re-arm like SendHandshakeInitiation does
        t.handshakeInitiated(now, C, 0, true);
        now += 5_000;
    }
    try std.testing.expectEqual(@as(u32, 4), t.handshake_attempts);
    // 5th expiry: 4 > 3 -> give up, zero armed at reject*3
    const a = t.poll(now, C, 0, true);
    try std.testing.expect(a.give_up);
    try std.testing.expect(!a.retransmit_handshake);
    try std.testing.expectEqual(now + 180_000 * 3, t.zero_key_material.?);
    // zero fires later
    const z = t.poll(now + 180_000 * 3, C, 0, true);
    try std.testing.expect(z.zero_key_material);
}

test "give up cancels pending keepalive" {
    var t: timers.Timers = .{};
    t.start();
    // keepalive armed for later, attempts exhausted, retransmit due now
    t.send_keepalive = 100_000;
    t.handshake_attempts = 4; // > max(3)
    t.retransmit_handshake = 5_000;
    const a = t.poll(5_000, C, 0, true);
    try std.testing.expect(a.give_up);
    try std.testing.expect(t.send_keepalive == null);
    // later poll stays quiet: the cancelled keepalive never fires
    const late = t.poll(100_000, C, 0, true);
    try std.testing.expect(!late.send_keepalive);
    // same when both expire at once: give-up wins, no keepalive action
    t.send_keepalive = 200_000;
    t.handshake_attempts = 9;
    t.retransmit_handshake = 200_000;
    const b = t.poll(200_000, C, 0, true);
    try std.testing.expect(b.give_up);
    try std.testing.expect(!b.send_keepalive);
    try std.testing.expect(t.send_keepalive == null);
}

test "handshake complete resets attempts" {
    var t: timers.Timers = .{};
    t.handshakeInitiated(0, C, 0, true);
    _ = t.poll(5_000, C, 0, true);
    try std.testing.expectEqual(@as(u32, 1), t.handshake_attempts);
    t.handshakeComplete(6_000);
    try std.testing.expectEqual(@as(u32, 0), t.handshake_attempts);
    try std.testing.expect(t.retransmit_handshake == null);
    try std.testing.expectEqual(@as(i64, 6_000), t.last_handshake_ns);
}

test "data sent arms new handshake, auth received clears it" {
    var t: timers.Timers = .{};
    t.dataSent(100, C, 7, true);
    try std.testing.expectEqual(@as(i64, 100 + 10_000 + 5_000 + 7 * std.time.ns_per_ms), t.new_handshake.?);
    // second send while pending does not move it
    t.dataSent(200, C, 9, true);
    try std.testing.expectEqual(@as(i64, 100 + 10_000 + 5_000 + 7 * std.time.ns_per_ms), t.new_handshake.?);
    t.anyAuthReceived(true);
    try std.testing.expect(t.new_handshake == null);
}

test "new handshake fires after silence" {
    var t: timers.Timers = .{};
    t.dataSent(0, C, 0, true);
    const a = t.poll(15_000, C, 0, true);
    try std.testing.expect(a.new_handshake);
    try std.testing.expect(t.new_handshake == null);
}

test "data received arms keepalive, second receive extends" {
    var t: timers.Timers = .{};
    t.dataReceived(0, C, true);
    try std.testing.expectEqual(@as(i64, 10_000), t.send_keepalive.?);
    t.dataReceived(1_000, C, true); // already pending -> need another
    try std.testing.expect(t.need_another_keepalive);
    const a = t.poll(10_000, C, 0, true);
    try std.testing.expect(a.send_keepalive);
    try std.testing.expect(!t.need_another_keepalive);
    try std.testing.expectEqual(@as(i64, 20_000), t.send_keepalive.?);
    // auth sent clears keepalive
    t.anyAuthSent(true);
    try std.testing.expect(t.send_keepalive == null);
}

test "session derived arms zero key material" {
    var t: timers.Timers = .{};
    t.sessionDerived(50, C, true);
    try std.testing.expectEqual(@as(i64, 50 + 180_000 * 3), t.zero_key_material.?);
}

test "persistent keepalive re-arms on traversal" {
    var t: timers.Timers = .{};
    t.anyAuthTraversal(0, 25, true);
    try std.testing.expectEqual(@as(i64, 25 * std.time.ns_per_s), t.persistent_keepalive.?);
    const a = t.poll(25 * std.time.ns_per_s, C, 0, true);
    try std.testing.expect(a.persistent_keepalive);
    // disabled interval never arms
    t.anyAuthTraversal(0, 0, true);
    try std.testing.expect(t.persistent_keepalive == null);
}

test "inactive peer arms nothing" {
    var t: timers.Timers = .{};
    t.dataSent(0, C, 0, false);
    t.dataReceived(0, C, false);
    t.handshakeInitiated(0, C, 0, false);
    t.sessionDerived(0, C, false);
    t.anyAuthTraversal(0, 25, false);
    try std.testing.expect(t.new_handshake == null);
    try std.testing.expect(t.send_keepalive == null);
    try std.testing.expect(t.retransmit_handshake == null);
    try std.testing.expect(t.zero_key_material == null);
    try std.testing.expect(t.persistent_keepalive == null);
    try std.testing.expect(!t.poll(1_000_000, C, 0, false).any());
}

test "nothing pending polls quiet" {
    var t: timers.Timers = .{};
    try std.testing.expect(!t.poll(999_999_999, C, 0, true).any());
}
