// Port of netbird client/internal/portforward/manager.go (v0.79.0), BSD-3-Clause.
//
// Adaptation: Go's Manager runs Start in a goroutine with tickers and
// channels; here it is a tick-driven struct the embedder drives (start once,
// tick on a timer, stop at shutdown). Discovery order, lease/renew timing
// (2h lease, renew at half, 60s health checks) and cleanup-on-stop match.
const std = @import("std");
const linux = std.os.linux;
const discover = @import("discover.zig");
const env = @import("env.zig");

pub const mapping_ttl_s: u32 = 7200;
pub const health_interval_ms: i64 = 60000;
pub const mapping_timeout_ms: i64 = 30000;
pub const health_timeout_ms: i64 = 10000;
pub const cleanup_timeout_ms: i64 = 10000;
pub const description = "NetBird";

pub const Error = discover.Error || error{
    Disabled,
    InvalidPort,
};

fn nowMs() i64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return ts.sec * 1000 + @divTrunc(ts.nsec, 1_000_000);
}

/// Port of manager.go Mapping (in-memory; only State has a JSON form).
pub const Mapping = struct {
    protocol_buf: [8]u8 = undefined,
    protocol_len: usize = 0,
    internal_port: u16 = 0,
    external_port: u16 = 0,
    external_ip: [16]u8 = std.mem.zeroes([16]u8),
    external_is_v6: bool = false,
    has_external: bool = false,
    nat_type_buf: [48]u8 = undefined,
    nat_type_len: usize = 0,
    ttl_s: u32 = 0,
    permanent: bool = false,
    pinhole_failed: bool = false,

    pub fn protocol(m: *const Mapping) []const u8 {
        return m.protocol_buf[0..m.protocol_len];
    }

    pub fn natType(m: *const Mapping) []const u8 {
        return m.nat_type_buf[0..m.nat_type_len];
    }
};

pub const Manager = struct {
    gateway: ?discover.Gateway = null,
    mapping: ?Mapping = null,
    wg_port: u16 = 0,
    renew_at_ms: i64 = 0,
    health_at_ms: i64 = 0,
    active: bool = false,

    /// Full start: default-route discovery, then createMapping.
    pub fn start(m: *Manager, wg_port: u16, now_ms: i64) Error!void {
        if (m.active) return;
        if (env.isDisabledByEnv()) return Error.Disabled;
        if (wg_port == 0) return Error.InvalidPort;
        const gw = try discover.discover(now_ms + discover.discovery_timeout_ms);
        // startWithGateway owns (and on error closes) the gateway.
        try m.startWithGateway(wg_port, now_ms, gw);
    }

    /// Start on an already-discovered gateway (test seam); takes ownership.
    pub fn startWithGateway(m: *Manager, wg_port: u16, now_ms: i64, gw_in: discover.Gateway) Error!void {
        if (m.active) return;
        var gw = gw_in;
        errdefer gw.close();
        m.wg_port = wg_port;
        var ttl = mapping_ttl_s;
        var permanent = false;
        const ext: u16 = blk: {
            break :blk gw.addPortMapping("udp", wg_port, description, ttl, mapping_timeout_ms) catch |e| {
                if (e != error.PermanentLeaseOnly) return e;
                ttl = 0;
                permanent = true;
                break :blk try gw.addPortMapping("udp", wg_port, description, 0, mapping_timeout_ms);
            };
        };
        var mapping = Mapping{};
        const proto = "udp";
        @memcpy(mapping.protocol_buf[0..proto.len], proto);
        mapping.protocol_len = proto.len;
        mapping.internal_port = wg_port;
        mapping.external_port = ext;
        mapping.ttl_s = ttl;
        mapping.permanent = permanent;
        if (gw.externalAddress(mapping_timeout_ms)) |addr| {
            mapping.external_ip = addr.ip16;
            mapping.external_is_v6 = addr.is_v6;
            mapping.has_external = true;
        } else |_| {}
        const t = gw.typeString(&mapping.nat_type_buf) catch mapping.nat_type_buf[0..0];
        if (t.ptr != mapping.nat_type_buf[0..].ptr) {
            @memcpy(mapping.nat_type_buf[0..t.len], t);
        }
        mapping.nat_type_len = t.len;
        mapping.pinhole_failed = switch (gw) {
            .dual => |*d| d.pinhole_failed,
            else => false,
        };
        m.gateway = gw;
        m.mapping = mapping;
        m.renew_at_ms = now_ms + @divTrunc(@as(i64, ttl) * 1000, 2);
        m.health_at_ms = now_ms + health_interval_ms;
        m.active = true;
    }

    /// One renew/health step (port of renewLoop/permanentLeaseLoop bodies).
    pub fn tick(m: *Manager, now_ms: i64) void {
        if (!m.active) return;
        const mp = &(m.mapping orelse return);
        const gw = &(m.gateway orelse return);
        if (!mp.permanent and now_ms >= m.renew_at_ms) {
            m.renew_at_ms = now_ms + @divTrunc(@as(i64, mp.ttl_s) * 1000, 2);
            renewMapping(gw, mp) catch {};
        }
        if (gw.supportsHealth() and !env.isHealthCheckDisabled() and now_ms >= m.health_at_ms) {
            m.health_at_ms = now_ms + health_interval_ms;
            const hc = gw.healthCheck(health_timeout_ms) catch return;
            if (!hc.restarted) return;
            renewMapping(gw, mp) catch return;
            if (!mp.permanent) {
                m.renew_at_ms = now_ms + @divTrunc(@as(i64, mp.ttl_s) * 1000, 2);
            }
        }
    }

    /// Port of cleanup: delete the mapping best effort, drop the gateway.
    /// Unlike Go (whose channels forbid it) a stopped manager may start again.
    pub fn stop(m: *Manager) void {
        if (!m.active) return;
        if (m.mapping) |mp| {
            if (m.gateway) |*gw| {
                gw.deletePortMapping(mp.protocol(), mp.internal_port, cleanup_timeout_ms) catch {};
                gw.close();
            }
        }
        m.mapping = null;
        m.gateway = null;
        m.active = false;
    }

    pub fn getMapping(m: *const Manager) ?Mapping {
        return m.mapping;
    }
};

/// Port of renewMapping: re-add, adopt a changed external port.
fn renewMapping(gw: *discover.Gateway, mp: *Mapping) Error!void {
    const ext = try gw.addPortMapping(mp.protocol(), mp.internal_port, description, mp.ttl_s, mapping_timeout_ms);
    if (ext != mp.external_port) {
        // Go warns the candidate may be stale; the update is the fix.
        mp.external_port = ext;
    }
}
