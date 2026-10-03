// Tests for the state.go port: JSON byte-identical to Go for the same input.
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const state = @import("state.zig");

test "state name matches upstream" {
    try std.testing.expectEqualStrings("port_forward_state", state.name);
}

test "state JSON is byte-identical to Go" {
    const vectors = @embedFile("testdata/state_vectors.txt");
    var lines = std.mem.splitScalar(u8, vectors, '\n');
    var count: usize = 0;
    while (lines.next()) |line| {
        if (line.len == 0 or line[0] == '#') continue;
        var parts = std.mem.splitScalar(u8, line, ' ');
        const tag = parts.next() orelse return error.BadVector;
        const port_s = parts.next() orelse return error.BadVector;
        const proto_s = parts.next() orelse return error.BadVector;
        const want = parts.next() orelse return error.BadVector;
        var st = state.State{};
        st.internal_port = try std.fmt.parseInt(u16, port_s, 10);
        if (!std.mem.eql(u8, proto_s, "-")) try st.setProtocol(proto_s);
        var buf: [64]u8 = undefined;
        const got = try st.encodeJson(&buf);
        std.testing.expectEqualSlices(u8, want, got) catch |e| {
            std.debug.print("vector {s}: got {s} want {s}\n", .{ tag, got, want });
            return e;
        };
        count += 1;
    }
    try std.testing.expectEqual(@as(usize, 4), count);
}

test "cleanup with port 0 is a no-op" {
    try state.cleanup(0, "udp", 0);
}

test "cleanup without a gateway is not an error" {
    // Namespace without a default route: discovery fails fast, cleanup is nil.
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const path = "/proc/self/environ";
    const rc = linux.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (rc > 0xfffffffffffff000 or rc == 0) return error.SkipZigTest;
    const fd: linux.fd_t = @intCast(rc);
    defer _ = linux.close(fd);
    var ebuf: [65536]u8 = undefined;
    const n = linux.read(fd, &ebuf, ebuf.len);
    if (n > 0xfffffffffffff000 or n == 0) return error.SkipZigTest;
    var found = false;
    var entries = std.mem.splitScalar(u8, ebuf[0..n], 0);
    const name = "PF_TEST_NS";
    while (entries.next()) |e| {
        if (e.len > name.len + 1 and std.mem.eql(u8, e[0..name.len], name) and e[name.len] == '=' and
            std.mem.eql(u8, e[name.len + 1 ..], "full"))
        {
            found = true;
        }
    }
    if (!found) return error.SkipZigTest;
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    const now = ts.sec * 1000 + @divTrunc(ts.nsec, 1_000_000);
    try state.cleanup(51820, "udp", now + 10000);
}
