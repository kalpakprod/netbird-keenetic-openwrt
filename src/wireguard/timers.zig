// Port of wireguard-go device/timers.go (v0.79.0 vendored copy, MIT).
// Reference: upstream/netbird/vendor/golang.zx2c4.com/wireguard/device/timers.go.
// Single-threaded port: deadlines as int64 nanoseconds against a caller
// clock (no goroutines, no time.Timer). The device polls and acts on the
// returned Actions; short constants make timer behavior testable.

const std = @import("std");

pub const Constants = struct {
    rekey_timeout_ns: i64 = 5 * std.time.ns_per_s,
    max_timer_handshakes: u32 = 90 / 5,
    jitter_max_ms: u16 = 334,
    keepalive_timeout_ns: i64 = 10 * std.time.ns_per_s,
    reject_after_time_ns: i64 = 180 * std.time.ns_per_s,
};

pub const default_constants: Constants = .{};

/// Timer expirations the device must act on. Mirrors the expired* callbacks:
/// retransmit_handshake -> SendHandshakeInitiation(retry) + handshakeInitiated,
/// send_keepalive/new_handshake/persistent_keepalive -> send packet,
/// zero_key_material -> ZeroAndFlushAll, give_up -> FlushStagedPackets.
pub const Actions = struct {
    retransmit_handshake: bool = false,
    send_keepalive: bool = false,
    new_handshake: bool = false,
    zero_key_material: bool = false,
    persistent_keepalive: bool = false,
    give_up: bool = false,

    pub fn any(a: Actions) bool {
        return a.retransmit_handshake or a.send_keepalive or a.new_handshake or
            a.zero_key_material or a.persistent_keepalive or a.give_up;
    }
};

pub const Timers = struct {
    retransmit_handshake: ?i64 = null,
    send_keepalive: ?i64 = null,
    new_handshake: ?i64 = null,
    zero_key_material: ?i64 = null,
    persistent_keepalive: ?i64 = null,
    handshake_attempts: u32 = 0,
    need_another_keepalive: bool = false,
    sent_last_minute_handshake: bool = false,
    last_handshake_ns: i64 = 0,

    /// timersStart: reset attempt bookkeeping.
    pub fn start(t: *Timers) void {
        t.handshake_attempts = 0;
        t.sent_last_minute_handshake = false;
        t.need_another_keepalive = false;
    }

    /// Fire due timers. jitter_ms plays fastrandn(RekeyTimeoutJitterMaxMs);
    /// the device supplies randomness, tests supply fixed values.
    pub fn poll(t: *Timers, now_ns: i64, c: Constants, jitter_ms: u16, active: bool) Actions {
        var a: Actions = .{};
        if (due(t.retransmit_handshake, now_ns)) {
            t.retransmit_handshake = null;
            if (t.handshake_attempts > c.max_timer_handshakes) {
                a.give_up = true;
                // Upstream timers.go:82-84: Del() the keepalive while
                // active, before any other expiration is handled.
                if (active) t.send_keepalive = null;
                if (active and t.zero_key_material == null) {
                    t.zero_key_material = now_ns + c.reject_after_time_ns * 3;
                }
            } else {
                t.handshake_attempts += 1;
                a.retransmit_handshake = true;
            }
        }
        if (due(t.send_keepalive, now_ns)) {
            t.send_keepalive = null;
            a.send_keepalive = true;
            if (t.need_another_keepalive) {
                t.need_another_keepalive = false;
                if (active) t.send_keepalive = now_ns + c.keepalive_timeout_ns;
            }
        }
        if (due(t.new_handshake, now_ns)) {
            t.new_handshake = null;
            a.new_handshake = true;
        }
        if (due(t.zero_key_material, now_ns)) {
            t.zero_key_material = null;
            a.zero_key_material = true;
        }
        if (due(t.persistent_keepalive, now_ns)) {
            t.persistent_keepalive = null;
            a.persistent_keepalive = true;
        }
        _ = jitter_ms;
        return a;
    }

    fn due(deadline: ?i64, now_ns: i64) bool {
        return deadline != null and deadline.? <= now_ns;
    }

    /// timersDataSent.
    pub fn dataSent(t: *Timers, now_ns: i64, c: Constants, jitter_ms: u16, active: bool) void {
        if (active and t.new_handshake == null) {
            t.new_handshake = now_ns + c.keepalive_timeout_ns + c.rekey_timeout_ns +
                @as(i64, jitter_ms) * std.time.ns_per_ms;
        }
    }

    /// timersDataReceived.
    pub fn dataReceived(t: *Timers, now_ns: i64, c: Constants, active: bool) void {
        if (!active) return;
        if (t.send_keepalive == null) {
            t.send_keepalive = now_ns + c.keepalive_timeout_ns;
        } else {
            t.need_another_keepalive = true;
        }
    }

    /// timersAnyAuthenticatedPacketSent.
    pub fn anyAuthSent(t: *Timers, active: bool) void {
        if (active) t.send_keepalive = null;
    }

    /// timersAnyAuthenticatedPacketReceived.
    pub fn anyAuthReceived(t: *Timers, active: bool) void {
        if (active) t.new_handshake = null;
    }

    /// timersHandshakeInitiated.
    pub fn handshakeInitiated(t: *Timers, now_ns: i64, c: Constants, jitter_ms: u16, active: bool) void {
        if (active) {
            t.retransmit_handshake = now_ns + c.rekey_timeout_ns +
                @as(i64, jitter_ms) * std.time.ns_per_ms;
        }
    }

    /// timersHandshakeComplete.
    pub fn handshakeComplete(t: *Timers, now_ns: i64) void {
        t.retransmit_handshake = null;
        t.handshake_attempts = 0;
        t.sent_last_minute_handshake = false;
        t.last_handshake_ns = now_ns;
    }

    /// timersSessionDerived.
    pub fn sessionDerived(t: *Timers, now_ns: i64, c: Constants, active: bool) void {
        if (active) t.zero_key_material = now_ns + c.reject_after_time_ns * 3;
    }

    /// timersAnyAuthenticatedPacketTraversal.
    pub fn anyAuthTraversal(t: *Timers, now_ns: i64, persistent_keepalive_s: u32, active: bool) void {
        if (persistent_keepalive_s > 0 and active) {
            t.persistent_keepalive = now_ns + @as(i64, persistent_keepalive_s) * std.time.ns_per_s;
        }
    }
};
