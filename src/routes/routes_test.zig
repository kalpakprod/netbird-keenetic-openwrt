// rtnetlink test: runs inside `unshare -Urn`, skips on a plain host.
// Creates a tun via `ip tuntap`, drives link/addr/route through routes.zig,
// reads the state back with `ip -j addr` and `ip -j route`.

const std = @import("std");
const builtin = @import("builtin");
const routes = @import("routes.zig");

const tio = std.testing.io;

fn inUserNamespace() bool {
    var file = std.Io.Dir.openFileAbsolute(tio, "/proc/self/uid_map", .{ .mode = .read_only }) catch return false;
    defer file.close(tio);
    var buf: [128]u8 = undefined;
    const n = file.readPositionalAll(tio, &buf, 0) catch return false;
    const trimmed = std.mem.trim(u8, buf[0..n], " \t\n");
    return !std.mem.eql(u8, trimmed, "0          0 4294967295") and
        !std.mem.eql(u8, trimmed, "0 0 4294967295");
}

fn run(args: []const []const u8) !void {
    var child = try std.process.spawn(tio, .{
        .argv = args,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    const term = try child.wait(tio);
    if (!term.success()) return error.IpFailed;
}

fn runCapture(args: []const []const u8, out: []u8) ![]u8 {
    var child = try std.process.spawn(tio, .{
        .argv = args,
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .ignore,
    });
    var read_buf: [65536]u8 = undefined;
    var reader = child.stdout.?.readerStreaming(tio, &read_buf);
    var r = &reader.interface;
    var len: usize = 0;
    while (len < out.len) {
        const n = r.readSliceShort(out[len..]) catch break;
        if (n == 0) break;
        len += n;
    }
    const term = try child.wait(tio);
    if (!term.success()) return error.IpFailed;
    return out[0..len];
}

test "rtnetlink link addr route in namespace" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!inUserNamespace()) return error.SkipZigTest;

    var tuntap = [_][]const u8{ "ip", "tuntap", "add", "dev", "rt0", "mode", "tun" };
    try run(&tuntap);
    const ifindex = try routes.RouteSock.linkIndex("rt0");
    try std.testing.expect(ifindex > 0);

    var rs = try routes.RouteSock.open();
    defer rs.close();

    try rs.linkSetUp(ifindex, true);
    try rs.addrAdd(ifindex, .{ 10, 98, 0, 1 }, 24);
    try rs.routeAdd(.{ 10, 97, 0, 0 }, 24, ifindex, null);

    var cap_buf: [65536]u8 = undefined;
    var addr_cmd = [_][]const u8{ "ip", "-j", "addr", "show", "rt0" };
    const addr_json = try runCapture(&addr_cmd, &cap_buf);
    try std.testing.expect(std.mem.indexOf(u8, addr_json, "10.98.0.1") != null);
    // persistent tun with no open fd reports operstate DOWN; the UP *flag* is
    // what linkSetUp sets
    try std.testing.expect(std.mem.indexOf(u8, addr_json, "\"UP\"") != null);
    var route_cmd = [_][]const u8{ "ip", "-j", "route" };
    const route_json = try runCapture(&route_cmd, &cap_buf);
    try std.testing.expect(std.mem.indexOf(u8, route_json, "10.97.0.0/24") != null);

    // delete everything again
    try rs.routeDel(.{ 10, 97, 0, 0 }, 24, ifindex, null);
    try rs.addrDel(ifindex, .{ 10, 98, 0, 1 }, 24);
    try rs.linkSetUp(ifindex, false);
    const route_json2 = try runCapture(&route_cmd, &cap_buf);
    try std.testing.expect(std.mem.indexOf(u8, route_json2, "10.97.0.0/24") == null);
    const addr_json2 = try runCapture(&addr_cmd, &cap_buf);
    try std.testing.expect(std.mem.indexOf(u8, addr_json2, "10.98.0.1") == null);
}
