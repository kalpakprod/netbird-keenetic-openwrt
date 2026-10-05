// TUN test: runs inside `unshare -Urn`, skips on a plain host.
// Creates a tun, addresses it with `ip`, writes an ICMP echo request for the
// tun address, reads the kernel's echo reply back.

const std = @import("std");
const builtin = @import("builtin");
const tun = @import("tun.zig");

const tio = std.testing.io;

fn checksum(data: []const u8) u16 {
    var sum: u32 = 0;
    var i: usize = 0;
    while (i + 1 < data.len) : (i += 2) {
        sum += std.mem.readInt(u16, data[i..][0..2], .big);
    }
    if (i < data.len) sum += @as(u32, data[i]) << 8;
    while (sum >> 16 != 0) sum = (sum & 0xffff) + (sum >> 16);
    return @truncate(~sum);
}

/// True when running inside a user namespace (uid_map is not the identity).
fn inUserNamespace() bool {
    var file = std.Io.Dir.openFileAbsolute(tio, "/proc/self/uid_map", .{ .mode = .read_only }) catch return false;
    defer file.close(tio);
    var buf: [128]u8 = undefined;
    const n = file.readPositionalAll(tio, &buf, 0) catch return false;
    const trimmed = std.mem.trim(u8, buf[0..n], " \t\n");
    // host identity mapping is exactly "0 0 4294967295"
    return !std.mem.eql(u8, trimmed, "0          0 4294967295") and
        !std.mem.eql(u8, trimmed, "0 0 4294967295");
}

fn runIp(args: []const []const u8) !void {
    var child = try std.process.spawn(tio, .{
        .argv = args,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    const term = try child.wait(tio);
    if (!term.success()) return error.IpFailed;
}

test "tun icmp echo in namespace" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var t = tun.Tun.create("nbt%d", 1420) catch |err| {
        // plain host without userns caps: skip, don't fail
        if (!inUserNamespace()) return error.SkipZigTest;
        return err;
    };
    defer t.close();

    try std.testing.expectEqual(@as(u16, 1420), try t.getMtu());
    try std.testing.expect((try t.ifIndex()) > 0);

    const name = t.ifName();
    var addr_cmd = [_][]const u8{ "ip", "addr", "add", "10.99.0.1/24", "dev", name };
    try runIp(&addr_cmd);
    var up_cmd = [_][]const u8{ "ip", "link", "set", name, "up" };
    try runIp(&up_cmd);

    // ICMP echo request: 10.99.0.2 -> 10.99.0.1 (tun address)
    var req: [20 + 8 + 8]u8 = undefined;
    @memset(&req, 0);
    req[0] = 0x45;
    std.mem.writeInt(u16, req[2..4], req.len, .big);
    req[8] = 64; // ttl
    req[9] = 1; // icmp
    @memcpy(req[12..16], &[_]u8{ 10, 99, 0, 2 });
    @memcpy(req[16..20], &[_]u8{ 10, 99, 0, 1 });
    std.mem.writeInt(u16, req[10..12], checksum(req[0..20]), .big);
    req[20] = 8; // echo request
    std.mem.writeInt(u16, req[24..26], 0x1234, .big); // ident
    std.mem.writeInt(u16, req[26..28], 0x0007, .big); // seq
    @memcpy(req[28..36], "tunping!");
    std.mem.writeInt(u16, req[22..24], checksum(req[20..36]), .big);

    try t.write(&req);
    // the kernel may emit other packets first (IPv6 RS on link up):
    // read until our echo reply arrives
    var reply: [1500]u8 = undefined;
    var pkt: []u8 = &.{};
    var tries: usize = 0;
    while (tries < 20) : (tries += 1) {
        try t.waitReadable(5000);
        const n = try t.read(&reply);
        if (n >= 28 and reply[0] == 0x45 and reply[9] == 1 and reply[20] == 0 and
            std.mem.readInt(u16, reply[24..26], .big) == 0x1234)
        {
            pkt = reply[0..n];
            break;
        }
    }
    try std.testing.expect(pkt.len >= 28);
    // kernel's echo reply: 10.99.0.1 -> 10.99.0.2, icmp type 0
    try std.testing.expectEqual(@as(u8, 0x45), pkt[0]);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 10, 99, 0, 1 }, pkt[12..16]);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 10, 99, 0, 2 }, pkt[16..20]);
    try std.testing.expectEqual(@as(u8, 0), pkt[20]);
    try std.testing.expectEqual(@as(u16, 0x1234), std.mem.readInt(u16, pkt[24..26], .big));
    try std.testing.expectEqual(@as(u16, 0x0007), std.mem.readInt(u16, pkt[26..28], .big));
    try std.testing.expectEqualSlices(u8, "tunping!", pkt[28..36]);
}
