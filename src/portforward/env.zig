// Port of netbird client/internal/portforward/env.go (v0.79.0), BSD-3-Clause.
const std = @import("std");
const linux = std.os.linux;

pub const env_disable_mapper = "NB_DISABLE_NAT_MAPPER";
pub const env_disable_health = "NB_DISABLE_PCP_HEALTH_CHECK";

/// Port of strconv.ParseBool: only these spellings count, anything else is false.
pub fn parseBoolGo(s: []const u8) bool {
    for ([_][]const u8{ "1", "t", "T", "TRUE", "true", "True" }) |t| {
        if (std.mem.eql(u8, s, t)) return true;
    }
    return false;
}

fn readEnv(name: []const u8, val_out: []u8) ?[]u8 {
    const path = "/proc/self/environ";
    const rc = linux.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (rc > 0xfffffffffffff000 or rc == 0) return null;
    const fd: linux.fd_t = @intCast(rc);
    defer _ = linux.close(fd);
    var ebuf: [65536]u8 = undefined;
    const n = linux.read(fd, &ebuf, ebuf.len);
    if (n > 0xfffffffffffff000 or n == 0) return null;
    var entries = std.mem.splitScalar(u8, ebuf[0..n], 0);
    while (entries.next()) |e| {
        if (e.len > name.len and std.mem.eql(u8, e[0..name.len], name) and e[name.len] == '=') {
            const v = e[name.len + 1 ..];
            if (v.len == 0 or v.len > val_out.len) return null;
            @memcpy(val_out[0..v.len], v);
            return val_out[0..v.len];
        }
    }
    return null;
}

pub fn isDisabledByEnv() bool {
    var buf: [16]u8 = undefined;
    const v = readEnv(env_disable_mapper, &buf) orelse return false;
    return parseBoolGo(v);
}

pub fn isHealthCheckDisabled() bool {
    var buf: [16]u8 = undefined;
    const v = readEnv(env_disable_health, &buf) orelse return false;
    return parseBoolGo(v);
}
