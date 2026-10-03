// Go-vector tests for the generated protobuf codecs.
// Vectors: src/proto/testdata/*.bin marshaled by the vendored
// google.golang.org/protobuf (proto.MarshalOptions{Deterministic: true}) from
// gen/proto-vectors.go against the real upstream messages. Every vector must
// decode into the generated structs, reproduce the asserted field values, and
// re-encode byte-identically.

const std = @import("std");
const mgmt = @import("gen/management.zig");
const signal = @import("gen/signal.zig");

const login_raw = @embedFile("testdata/login_request.bin");
const sync_raw = @embedFile("testdata/sync_response.bin");
const enc_raw = @embedFile("testdata/encrypted_message.bin");
const body_raw = @embedFile("testdata/signal_body.bin");
const ssh_raw = @embedFile("testdata/ssh_auth_map.bin");

fn roundTrip(m: anytype, raw: []const u8) ![]u8 {
    const out = try std.testing.allocator.alloc(u8, m.size());
    defer std.testing.allocator.free(out);
    try m.encode(out);
    try std.testing.expectEqualSlices(u8, raw, out);
    return out;
}

test "login_request decodes and re-encodes byte-identically" {
    const a = std.testing.allocator;
    var m = try mgmt.LoginRequest.decode(a, login_raw);
    defer m.deinit(a);
    try std.testing.expectEqualStrings("A3CE2A4E-C7A9-4B1F-9E2D-5B6F8A0C1D2E", m.setupKey);
    try std.testing.expectEqualStrings("jwt-token-abc123", m.jwtToken);
    try std.testing.expectEqualStrings("ktrouter", m.meta.?.hostname);
    try std.testing.expectEqualStrings("linux", m.meta.?.goOS);
    try std.testing.expectEqualStrings("linux", m.meta.?.OS);
    try std.testing.expectEqualStrings("0.79.0", m.meta.?.netbirdVersion);
    try std.testing.expectEqualStrings("4.9.0", m.meta.?.kernelVersion);
    try std.testing.expectEqual(@as(usize, 2), m.meta.?.capabilities.len);
    try std.testing.expectEqual(@as(i32, 1), @intFromEnum(m.meta.?.capabilities[0]));
    try std.testing.expectEqual(@as(i32, 3), @intFromEnum(m.meta.?.capabilities[1]));
    try std.testing.expectEqual(@as(i32, 2), m.meta.?.syncMessageVersion);
    try std.testing.expectEqual(@as(usize, 32), m.peerKeys.?.sshPubKey.len);
    try std.testing.expectEqual(@as(u8, 0xAB), m.peerKeys.?.sshPubKey[0]);
    try std.testing.expectEqual(@as(u8, 0xCD), m.peerKeys.?.wgPubKey[31]);
    try std.testing.expectEqual(@as(usize, 2), m.dnsLabels.len);
    try std.testing.expectEqualStrings("lab", m.dnsLabels[0]);
    try std.testing.expectEqualStrings("home", m.dnsLabels[1]);
    _ = try roundTrip(m, login_raw);
}

test "sync_response decodes and re-encodes byte-identically" {
    const a = std.testing.allocator;
    var m = try mgmt.SyncResponse.decode(a, sync_raw);
    defer m.deinit(a);
    try std.testing.expectEqualStrings("100.64.0.7/16", m.peerConfig.?.address);
    try std.testing.expectEqualStrings("100.64.0.1", m.peerConfig.?.dns);
    try std.testing.expectEqualStrings("ktrouter.lab.local", m.peerConfig.?.fqdn);
    try std.testing.expect(m.peerConfig.?.RoutingPeerDnsResolutionEnabled);
    try std.testing.expectEqual(@as(i32, 1280), m.peerConfig.?.mtu);

    try std.testing.expectEqual(@as(usize, 2), m.remotePeers.len);
    try std.testing.expectEqualStrings("remote-pub-key-1", m.remotePeers[0].wgPubKey);
    try std.testing.expectEqual(@as(usize, 2), m.remotePeers[0].allowedIps.len);
    try std.testing.expectEqualStrings("10.30.30.11/32", m.remotePeers[0].allowedIps[1]);
    try std.testing.expectEqualStrings("0.79.0", m.remotePeers[0].agentVersion);
    try std.testing.expectEqual(@as(i32, 1), @intFromEnum(m.remotePeers[0].lazyState));
    try std.testing.expectEqual(@as(i32, 2), @intFromEnum(m.remotePeers[1].lazyState));
    try std.testing.expect(m.remotePeersIsEmpty);

    const nm = m.NetworkMap.?;
    try std.testing.expectEqual(@as(u64, 7), nm.Serial);
    try std.testing.expectEqualStrings("100.64.0.7/16", nm.peerConfig.?.address);
    try std.testing.expectEqual(@as(i32, 1420), nm.peerConfig.?.mtu);
    try std.testing.expect(nm.remotePeersIsEmpty);
    try std.testing.expectEqual(@as(usize, 2), nm.Routes.len);
    try std.testing.expectEqualStrings("route-1", nm.Routes[0].ID);
    try std.testing.expectEqualStrings("10.10.0.0/24", nm.Routes[0].Network);
    try std.testing.expectEqual(@as(i64, 1), nm.Routes[0].NetworkType);
    try std.testing.expectEqualStrings("peer-a", nm.Routes[0].Peer);
    try std.testing.expectEqual(@as(i64, 9999), nm.Routes[0].Metric);
    try std.testing.expect(nm.Routes[0].Masquerade);
    try std.testing.expectEqualStrings("net-1", nm.Routes[0].NetID);
    try std.testing.expectEqual(@as(usize, 1), nm.Routes[0].Domains.len);
    try std.testing.expectEqualStrings("corp.example", nm.Routes[0].Domains[0]);
    try std.testing.expect(nm.Routes[0].keepRoute);
    try std.testing.expectEqual(@as(i64, 5), nm.Routes[1].Metric);

    const dns = nm.DNSConfig.?;
    try std.testing.expect(dns.ServiceEnable);
    try std.testing.expectEqual(@as(i64, 53), dns.ForwarderPort);
    try std.testing.expectEqual(@as(usize, 1), dns.NameServerGroups.len);
    try std.testing.expect(dns.NameServerGroups[0].Primary);
    try std.testing.expectEqualStrings("lab.local", dns.NameServerGroups[0].Domains[0]);
    try std.testing.expect(dns.NameServerGroups[0].SearchDomainsEnabled);

    try std.testing.expectEqual(@as(usize, 1), nm.offlinePeers.len);
    try std.testing.expectEqualStrings("offline-peer-1", nm.offlinePeers[0].wgPubKey);

    try std.testing.expectEqual(@as(usize, 1), nm.FirewallRules.len);
    const rule = nm.FirewallRules[0];
    try std.testing.expectEqual(@as(i32, 1), @intFromEnum(rule.Direction));
    try std.testing.expectEqual(@as(i32, 1), @intFromEnum(rule.Action));
    try std.testing.expectEqual(@as(i32, 2), @intFromEnum(rule.Protocol));
    try std.testing.expectEqualStrings("22", rule.Port);
    try std.testing.expectEqual(@as(usize, 5), rule.PolicyID.len);
    try std.testing.expectEqual(@as(usize, 2), rule.sourcePrefixes.len);
    try std.testing.expectEqualSlices(u8, &.{ 10, 0, 0, 1, 32 }, rule.sourcePrefixes[0]);

    try std.testing.expectEqual(@as(i64, 1759600000), m.sessionExpiresAt.?.seconds);
    try std.testing.expectEqual(@as(i32, 123456789), m.sessionExpiresAt.?.nanos);
    try std.testing.expectEqual(@as(i32, 3), m.Version);
    _ = try roundTrip(m, sync_raw);
}

test "encrypted_message decodes and re-encodes byte-identically" {
    const a = std.testing.allocator;
    var m = try signal.EncryptedMessage.decode(a, enc_raw);
    defer m.deinit(a);
    try std.testing.expectEqualStrings("server-wg-pub-key", m.key);
    try std.testing.expectEqualStrings("client-wg-pub-key", m.remoteKey);
    try std.testing.expectEqual(@as(usize, 16), m.body.len);
    try std.testing.expectEqual(@as(u8, 0x42), m.body[15]);
    _ = try roundTrip(m, enc_raw);
}

test "signal body decodes and re-encodes byte-identically" {
    const a = std.testing.allocator;
    var m = try signal.Body.decode(a, body_raw);
    defer m.deinit(a);
    try std.testing.expectEqual(@as(i32, 2), @intFromEnum(m.@"type"));
    try std.testing.expectEqualStrings("candidate:udp 10.30.30.11", m.payload);
    try std.testing.expectEqual(@as(u32, 51820), m.wgListenPort);
    try std.testing.expectEqualStrings("0.79.0", m.netBirdVersion);
    try std.testing.expect(m.mode.?.direct.?);
    try std.testing.expectEqualSlices(u32, &.{ 1, 2, 3 }, m.featuresSupported);
    try std.testing.expectEqual(@as(usize, 32), m.rosenpassConfig.?.rosenpassPubKey.len);
    try std.testing.expectEqual(@as(u8, 0x7E), m.rosenpassConfig.?.rosenpassPubKey[0]);
    try std.testing.expectEqualStrings("10.0.0.1:9999", m.rosenpassConfig.?.rosenpassServerAddr);
    try std.testing.expectEqualStrings("relay.example:443", m.relayServerAddress.?);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, m.sessionId.?);
    try std.testing.expectEqualSlices(u8, &.{ 10, 0, 0, 1 }, m.relayServerIP.?);
    _ = try roundTrip(m, body_raw);
}

test "ssh_auth_map decodes map entries and re-encodes byte-identically" {
    const a = std.testing.allocator;
    var m = try mgmt.SSHAuth.decode(a, ssh_raw);
    defer m.deinit(a);
    try std.testing.expectEqualStrings("sub", m.UserIDClaim);
    try std.testing.expectEqual(@as(usize, 2), m.AuthorizedUsers.len);
    try std.testing.expectEqualStrings("user-hash-1", m.AuthorizedUsers[0]);
    try std.testing.expectEqual(@as(usize, 2), m.machine_users.len);
    try std.testing.expectEqualStrings("admin", m.machine_users[0].key);
    try std.testing.expectEqualSlices(u32, &.{ 0, 1 }, m.machine_users[0].value.indexes);
    try std.testing.expectEqualStrings("audit", m.machine_users[1].key);
    try std.testing.expectEqualSlices(u32, &.{1}, m.machine_users[1].value.indexes);
    _ = try roundTrip(m, ssh_raw);
}
