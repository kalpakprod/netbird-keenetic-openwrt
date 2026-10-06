// Regression for ownership in the port of management.proto (v0.79.0), BSD-3-Clause.
const std = @import("std");
const messages = @import("mgmt/messages.zig");

fn decodePeers(alloc: std.mem.Allocator) !void {
    // NetworkMap{remotePeers:[{wgPubKey:"key",allowedIps:["ip1","ip2"]},{wgPubKey:"next"}]}.
    const input = "\x1a\x0f\x0a\x03key\x12\x03ip1\x12\x03ip2\x1a\x06\x0a\x04next";
    var m = try messages.NetworkMap.decode(alloc, input);
    defer m.deinit(alloc);
    try std.testing.expectEqual(@as(usize, 2), m.remote_peers.items.len);
    try std.testing.expectEqualStrings("key", m.remote_peers.items[0].wg_pub_key);
    try std.testing.expectEqual(@as(usize, 2), m.remote_peers.items[0].allowed_ips.items.len);
    try std.testing.expectEqualStrings("ip1", m.remote_peers.items[0].allowed_ips.items[0]);
    try std.testing.expectEqualStrings("ip2", m.remote_peers.items[0].allowed_ips.items[1]);
    try std.testing.expectEqualStrings("next", m.remote_peers.items[1].wg_pub_key);
    try std.testing.expectEqual(@as(usize, 0), m.remote_peers.items[1].allowed_ips.items.len);
}

fn decodeRelayUrls(alloc: std.mem.Allocator) !void {
    const input = "\x0a\x09rel://one\x0a\x09rel://two";
    var m = try messages.RelayConfig.decode(alloc, input);
    defer m.deinit(alloc);
    try std.testing.expectEqual(@as(usize, 2), m.urls.items.len);
    try std.testing.expectEqualStrings("rel://one", m.urls.items[0]);
    try std.testing.expectEqualStrings("rel://two", m.urls.items[1]);
}

test "Management repeated messages retain ownership on append OOM" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, decodePeers, .{});
}

test "Management repeated strings retain ownership on append OOM" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, decodeRelayUrls, .{});
}
