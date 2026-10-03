// Tests for the manager.go port: map once, renew at half lease, health
// recreates after a PCP restart, stop deletes. Live tests run only in a
// namespace (PF_TEST_NS=<mode>) with fake logs at /tmp/fakegw.ns.log and
// /tmp/fakeigd.ns.log; modes: full, restart, upnp, natpmp, perm, disabled.
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const discover = @import("discover.zig");
const manager = @import("manager.zig");
const env = @import("env.zig");

fn testMode(out: []u8) ?[]u8 {
    const path = "/proc/self/environ";
    const rc = linux.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (rc > 0xfffffffffffff000 or rc == 0) return null;
    const fd: linux.fd_t = @intCast(rc);
    defer _ = linux.close(fd);
    var ebuf: [65536]u8 = undefined;
    const n = linux.read(fd, &ebuf, ebuf.len);
    if (n > 0xfffffffffffff000 or n == 0) return null;
    var entries = std.mem.splitScalar(u8, ebuf[0..n], 0);
    const name = "PF_TEST_NS";
    while (entries.next()) |e| {
        if (e.len > name.len and std.mem.eql(u8, e[0..name.len], name) and e[name.len] == '=') {
            const v = e[name.len + 1 ..];
            if (v.len == 0 or v.len > out.len) return null;
            @memcpy(out[0..v.len], v);
            return out[0..v.len];
        }
    }
    return null;
}

fn wantMode(mode: []const u8) bool {
    var buf: [16]u8 = undefined;
    const m = testMode(&buf) orelse return false;
    return std.mem.eql(u8, m, mode);
}

fn nowMs() i64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return ts.sec * 1000 + @divTrunc(ts.nsec, 1_000_000);
}

/// Count log lines starting with "<label> " (deltas prove renew/delete).
fn countLabel(path: [*:0]const u8, label: []const u8) usize {
    const rc = linux.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (rc > 0xfffffffffffff000 or rc == 0) return 0;
    const fd: linux.fd_t = @intCast(rc);
    defer _ = linux.close(fd);
    var buf: [131072]u8 = undefined;
    var total: usize = 0;
    var count: usize = 0;
    var line_start: usize = 0;
    while (true) {
        const n = linux.read(fd, @ptrCast(&buf[total]), buf.len - total);
        if (n > 0xfffffffffffff000 or n == 0) break;
        total += n;
        if (total >= buf.len) break;
    }
    var i: usize = 0;
    while (i < total) : (i += 1) {
        if (buf[i] == '\n') {
            const line = buf[line_start..i];
            if (line.len > label.len and std.mem.eql(u8, line[0..label.len], label) and line[label.len] == ' ') {
                count += 1;
            }
            line_start = i + 1;
        }
    }
    return count;
}

/// Lifetime field (bytes 4:8) of the last pcp_map_req in the gateway log.
fn lastPcpMapLifetime(path: [*:0]const u8) ?u32 {
    const rc = linux.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (rc > 0xfffffffffffff000 or rc == 0) return null;
    const fd: linux.fd_t = @intCast(rc);
    defer _ = linux.close(fd);
    var buf: [131072]u8 = undefined;
    var total: usize = 0;
    while (true) {
        const n = linux.read(fd, @ptrCast(&buf[total]), buf.len - total);
        if (n > 0xfffffffffffff000 or n == 0) break;
        total += n;
        if (total >= buf.len) break;
    }
    const label = "pcp_map_req ";
    var last: ?u32 = null;
    var line_start: usize = 0;
    var i: usize = 0;
    while (i < total) : (i += 1) {
        if (buf[i] == '\n') {
            const line = buf[line_start..i];
            if (line.len > label.len + 16 and std.mem.eql(u8, line[0..label.len], label)) {
                // Lifetime is request bytes 4:8 = hex chars 8:16.
                const hex = line[label.len + 8 .. label.len + 16];
                var v: u32 = 0;
                for (hex) |ch| {
                    const d: u32 = if (ch >= '0' and ch <= '9')
                        ch - '0'
                    else if (ch >= 'a' and ch <= 'f')
                        ch - 'a' + 10
                    else
                        return last;
                    v = v * 16 + d;
                }
                last = v;
            }
            line_start = i + 1;
        }
    }
    return last;
}

const gw_log = "/tmp/fakegw.ns.log";
const igd_log = "/tmp/fakeigd.ns.log";
const gw4: [4]u8 = .{ 127, 0, 0, 1 };

test "start with port 0 is invalid" {
    if (env.isDisabledByEnv()) return error.SkipZigTest;
    var m = manager.Manager{};
    try std.testing.expectError(manager.Error.InvalidPort, m.start(0, nowMs()));
}

test "live PCP map, renew at half lease, delete on stop" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!wantMode("full")) return error.SkipZigTest;
    if (env.isDisabledByEnv()) return error.SkipZigTest;
    const t0 = nowMs();
    const maps0 = countLabel(gw_log, "pcp_map_req");
    var m = manager.Manager{};
    const gw = try discover.discoverWithGateways(gw4, gw4, null, t0 + 10000);
    try m.startWithGateway(51820, t0, gw);
    try std.testing.expect(m.active);
    const mp = m.getMapping() orelse return error.NoMapping;
    try std.testing.expectEqual(@as(u16, 51820), mp.external_port);
    try std.testing.expect(mp.has_external);
    try std.testing.expectEqualStrings("PCP", mp.natType());
    try std.testing.expectEqual(@as(u32, 7200), mp.ttl_s);
    try std.testing.expect(!mp.permanent);
    try std.testing.expectEqual(@as(usize, maps0 + 1), countLabel(gw_log, "pcp_map_req"));
    m.tick(t0 + 1000);
    try std.testing.expectEqual(@as(usize, maps0 + 1), countLabel(gw_log, "pcp_map_req"));
    m.tick(t0 + 3600 * 1000);
    try std.testing.expectEqual(@as(usize, maps0 + 2), countLabel(gw_log, "pcp_map_req"));
    m.stop();
    try std.testing.expect(!m.active);
    try std.testing.expectEqual(@as(usize, maps0 + 3), countLabel(gw_log, "pcp_map_req"));
    try std.testing.expectEqual(@as(?u32, 0), lastPcpMapLifetime(gw_log));
}

test "live PCP restart recreates the mapping and resets renew" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!wantMode("restart")) return error.SkipZigTest;
    if (env.isDisabledByEnv()) return error.SkipZigTest;
    const t0 = nowMs();
    const maps0 = countLabel(gw_log, "pcp_map_req");
    var m = manager.Manager{};
    const gw = try discover.discoverWithGateways(gw4, gw4, null, t0 + 10000);
    try m.startWithGateway(51820, t0, gw);
    // First health tick sees the dropped epoch and recreates.
    m.tick(t0 + 60000);
    try std.testing.expectEqual(@as(usize, maps0 + 2), countLabel(gw_log, "pcp_map_req"));
    // Renew was reset to recreate+3600s, so nothing at start+3600s ...
    m.tick(t0 + 3600 * 1000);
    try std.testing.expectEqual(@as(usize, maps0 + 2), countLabel(gw_log, "pcp_map_req"));
    // ... and the renew lands at recreate+3600s.
    m.tick(t0 + 3660 * 1000);
    try std.testing.expectEqual(@as(usize, maps0 + 3), countLabel(gw_log, "pcp_map_req"));
    m.stop();
}

test "live UPnP map, renew, delete on stop" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!wantMode("upnp")) return error.SkipZigTest;
    if (env.isDisabledByEnv()) return error.SkipZigTest;
    const t0 = nowMs();
    const adds0 = countLabel(igd_log, "soap_AddPortMapping_req");
    const dels0 = countLabel(igd_log, "soap_DeletePortMapping_req");
    var m = manager.Manager{};
    const gw = try discover.discoverWithGateways(gw4, gw4, null, t0 + 15000);
    try m.startWithGateway(51820, t0, gw);
    const mp = m.getMapping() orelse return error.NoMapping;
    try std.testing.expectEqualStrings("UPnP unicast (IP2)", mp.natType());
    try std.testing.expect(mp.external_port >= 10000);
    try std.testing.expectEqual(@as(usize, adds0 + 1), countLabel(igd_log, "soap_AddPortMapping_req"));
    m.tick(t0 + 3600 * 1000);
    try std.testing.expectEqual(@as(usize, adds0 + 2), countLabel(igd_log, "soap_AddPortMapping_req"));
    const mp2 = m.getMapping() orelse return error.NoMapping;
    try std.testing.expectEqual(mp.external_port, mp2.external_port);
    m.stop();
    try std.testing.expectEqual(@as(usize, dels0 + 1), countLabel(igd_log, "soap_DeletePortMapping_req"));
}

test "live NAT-PMP renew reuses the port, stop sends nothing" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!wantMode("natpmp")) return error.SkipZigTest;
    if (env.isDisabledByEnv()) return error.SkipZigTest;
    const t0 = nowMs();
    const maps0 = countLabel(gw_log, "natpmp_map_req");
    var m = manager.Manager{};
    const gw = try discover.discoverWithGateways(gw4, gw4, null, t0 + 10000);
    try m.startWithGateway(51820, t0, gw);
    const mp = m.getMapping() orelse return error.NoMapping;
    try std.testing.expectEqualStrings("NAT-PMP", mp.natType());
    m.tick(t0 + 3600 * 1000);
    try std.testing.expectEqual(@as(usize, maps0 + 2), countLabel(gw_log, "natpmp_map_req"));
    const mp2 = m.getMapping() orelse return error.NoMapping;
    try std.testing.expectEqual(mp.external_port, mp2.external_port);
    // Go's natpmpNAT.DeletePortMapping only drops the cache: no packet.
    m.stop();
    try std.testing.expectEqual(@as(usize, maps0 + 2), countLabel(gw_log, "natpmp_map_req"));
}

test "live permanent-only gateway maps with lease 0 and never renews" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!wantMode("perm")) return error.SkipZigTest;
    if (env.isDisabledByEnv()) return error.SkipZigTest;
    const t0 = nowMs();
    const adds0 = countLabel(igd_log, "soap_AddPortMapping_req");
    var m = manager.Manager{};
    const gw = try discover.discoverWithGateways(gw4, gw4, null, t0 + 15000);
    try m.startWithGateway(51820, t0, gw);
    const mp = m.getMapping() orelse return error.NoMapping;
    try std.testing.expect(mp.permanent);
    try std.testing.expectEqual(@as(u32, 0), mp.ttl_s);
    // Three finite tries (725 each) plus the permanent one.
    try std.testing.expectEqual(@as(usize, adds0 + 4), countLabel(igd_log, "soap_AddPortMapping_req"));
    m.tick(t0 + 7200 * 1000);
    try std.testing.expectEqual(@as(usize, adds0 + 4), countLabel(igd_log, "soap_AddPortMapping_req"));
    m.stop();
}

test "live disabled manager and health flag" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!wantMode("disabled")) return error.SkipZigTest;
    try std.testing.expect(env.isDisabledByEnv());
    try std.testing.expect(env.isHealthCheckDisabled());
    var m = manager.Manager{};
    try std.testing.expectError(manager.Error.Disabled, m.start(51820, nowMs()));
}
