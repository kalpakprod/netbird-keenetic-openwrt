// Tests for the default-route lookup. Deterministic only in a namespace with
// `ip route add default via 192.0.2.1 dev lo onlink src 127.0.0.1` (GW_TEST_NS=1).
const std = @import("std");
const builtin = @import("builtin");
const gateway = @import("gateway.zig");

fn hasEnv(name: []const u8) bool {
    const path = "/proc/self/environ";
    const rc = std.os.linux.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (rc > 0xfffffffffffff000 or rc == 0) return false;
    const fd: std.os.linux.fd_t = @intCast(rc);
    defer _ = std.os.linux.close(fd);
    var ebuf: [65536]u8 = undefined;
    const n = std.os.linux.read(fd, &ebuf, ebuf.len);
    if (n > 0xfffffffffffff000 or n == 0) return false;
    var entries = std.mem.splitScalar(u8, ebuf[0..n], 0);
    while (entries.next()) |e| {
        if (e.len > name.len and std.mem.eql(u8, e[0..name.len], name) and e[name.len] == '=') {
            return e[name.len + 1 ..].len > 0;
        }
    }
    return false;
}

test "live default route via loopback in namespace" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!hasEnv("GW_TEST_NS")) return error.SkipZigTest;
    const r = try gateway.defaultRouteV4();
    try std.testing.expectEqualSlices(u8, &[_]u8{ 192, 0, 2, 1 }, &r.gateway);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 127, 0, 0, 1 }, &r.local);
}
