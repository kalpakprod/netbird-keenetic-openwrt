// Tests for the device core port: two Devices wired loopback in memory,
// fake clock, fixed keys. No sockets, no threads.

const std = @import("std");
const noise = @import("noise.zig");
const device = @import("device.zig");

const T0: i64 = 1_000_000_000_000;

fn clampedKey(byte: u8) noise.PrivateKey {
    var k: noise.PrivateKey = @splat(byte);
    noise.clamp(&k);
    return k;
}

const psk_zero: noise.PresharedKey = @splat(0);

/// Minimal IPv4 packet with src/dst/total-length set.
fn ip4Packet(src: [4]u8, dst: [4]u8, payload: []const u8, out: []u8) []u8 {
    const total = 20 + payload.len;
    std.debug.assert(out.len >= total);
    @memset(out[0..total], 0);
    out[0] = 0x45;
    std.mem.writeInt(u16, out[2..4], @intCast(total), .big);
    @memcpy(out[12..16], &src);
    @memcpy(out[16..20], &dst);
    @memcpy(out[20..total], payload);
    return out[0..total];
}

const Harness = struct {
    a: device.Device,
    b: device.Device,
    pa: *device.Peer, // a's view of b
    pb: *device.Peer, // b's view of a
    now: i64 = T0,
    a_ep: device.Endpoint = device.Endpoint.v4(127, 0, 0, 1, 1001),
    b_ep: device.Endpoint = device.Endpoint.v4(127, 0, 0, 1, 1002),
    a_sink: std.ArrayList([]u8) = .empty,
    b_sink: std.ArrayList([]u8) = .empty,
    sent_count: usize = 0,

    fn udpSend(ctx: ?*anyopaque, datagram: []const u8, to: device.Endpoint) void {
        const h: *Harness = @ptrCast(@alignCast(ctx));
        h.sent_count += 1;
        if (to.eql(h.b_ep)) {
            h.b.receiveDatagram(datagram, h.a_ep, h.now);
        } else if (to.eql(h.a_ep)) {
            h.a.receiveDatagram(datagram, h.b_ep, h.now);
        }
    }

    fn sinkA(ctx: ?*anyopaque, peer: *device.Peer, pkt: []const u8) void {
        const h: *Harness = @ptrCast(@alignCast(ctx));
        _ = peer;
        h.a_sink.append(std.testing.allocator, std.testing.allocator.dupe(u8, pkt) catch return) catch return;
    }

    fn sinkB(ctx: ?*anyopaque, peer: *device.Peer, pkt: []const u8) void {
        const h: *Harness = @ptrCast(@alignCast(ctx));
        _ = peer;
        h.b_sink.append(std.testing.allocator, std.testing.allocator.dupe(u8, pkt) catch return) catch return;
    }
};

fn setup(h: *Harness, constants: device.Constants) !void {
    h.* = Harness{
        .a = device.Device.init(std.testing.allocator, std.testing.io, clampedKey(0xA1), constants),
        .b = device.Device.init(std.testing.allocator, std.testing.io, clampedKey(0xB2), constants),
        .pa = undefined,
        .pb = undefined,
    };
    h.a.udp_ctx = h;
    h.a.udp_send = Harness.udpSend;
    h.a.sink_ctx = h;
    h.a.packet_sink = Harness.sinkA;
    h.b.udp_ctx = h;
    h.b.udp_send = Harness.udpSend;
    h.b.sink_ctx = h;
    h.b.packet_sink = Harness.sinkB;
    h.pa = try h.a.addPeer(h.b.static_public, psk_zero);
    h.pb = try h.b.addPeer(h.a.static_public, psk_zero);
    h.pa.endpoint = h.b_ep;
    h.pb.endpoint = h.a_ep;
    h.pa.allowed.append(std.testing.allocator, device.Cidr.parseV4("10.0.0.2/32").?) catch unreachable;
    h.pb.allowed.append(std.testing.allocator, device.Cidr.parseV4("10.0.0.1/32").?) catch unreachable;
}

fn teardown(h: *Harness) void {
    for (h.a_sink.items) |p| std.testing.allocator.free(p);
    for (h.b_sink.items) |p| std.testing.allocator.free(p);
    h.a_sink.deinit(std.testing.allocator);
    h.b_sink.deinit(std.testing.allocator);
    h.a.deinit();
    h.b.deinit();
}

test "handshake then data both ways" {
    var h: Harness = undefined;
    try setup(&h, .{});
    defer teardown(&h);
    var buf: [64]u8 = undefined;
    const pkt = ip4Packet(.{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 }, "hello", &buf);
    h.a.sendPacket(pkt, h.now);
    // session up on both sides, packet arrived trimmed
    try std.testing.expect(h.pa.current != null);
    try std.testing.expect(h.pb.current != null);
    try std.testing.expectEqual(@as(usize, 1), h.b_sink.items.len);
    try std.testing.expectEqualSlices(u8, pkt, h.b_sink.items[0]);
    try std.testing.expect(h.pa.current.?.is_initiator);
    try std.testing.expect(!h.pb.current.?.is_initiator);
    // and back
    const back = ip4Packet(.{ 10, 0, 0, 2 }, .{ 10, 0, 0, 1 }, "world!", &buf);
    h.b.sendPacket(back, h.now);
    try std.testing.expectEqual(@as(usize, 1), h.a_sink.items.len);
    try std.testing.expectEqualSlices(u8, back, h.a_sink.items[0]);
}

test "duplicate counter is dropped" {
    var h: Harness = undefined;
    try setup(&h, .{});
    defer teardown(&h);
    // capture one transport datagram by wrapping b's receive path
    var buf: [64]u8 = undefined;
    const pkt = ip4Packet(.{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 }, "once", &buf);
    h.a.sendPacket(pkt, h.now);
    try std.testing.expectEqual(@as(usize, 1), h.b_sink.items.len);
    // re-drive the last handshake... instead: send same packet again is a new
    // counter; true replay needs the same counter. Forge by re-sending the
    // recorded datagram: use a fresh packet, capture, replay.
    const Interceptor = struct {
        var last: ?[]u8 = null;
        fn send(ctx: ?*anyopaque, datagram: []const u8, to: device.Endpoint) void {
            if (datagram.len >= 16 and std.mem.readInt(u32, datagram[0..4], .little) == noise.message_transport_type) {
                if (last) |l| std.testing.allocator.free(l);
                last = std.testing.allocator.dupe(u8, datagram) catch null;
            }
            Harness.udpSend(ctx, datagram, to);
        }
    };
    h.a.udp_send = Interceptor.send;
    const pkt2 = ip4Packet(.{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 }, "twice", &buf);
    h.a.sendPacket(pkt2, h.now);
    try std.testing.expectEqual(@as(usize, 2), h.b_sink.items.len);
    // replay the captured datagram: decrypts fine, replay filter drops it
    h.b.receiveDatagram(Interceptor.last.?, h.a_ep, h.now);
    try std.testing.expectEqual(@as(usize, 2), h.b_sink.items.len);
    std.testing.allocator.free(Interceptor.last.?);
    Interceptor.last = null;
}

test "keepalive timer fires after data" {
    var h: Harness = undefined;
    try setup(&h, .{});
    defer teardown(&h);
    var buf: [64]u8 = undefined;
    h.a.sendPacket(ip4Packet(.{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 }, "ping", &buf), h.now);
    try std.testing.expectEqual(@as(usize, 1), h.b_sink.items.len);
    // b armed send_keepalive; a armed new_handshake. Advance past keepalive.
    const before = h.sent_count;
    h.now += 11 * std.time.ns_per_s;
    h.b.pollAll(h.now);
    try std.testing.expect(h.sent_count > before); // keepalive emitted
    try std.testing.expectEqual(@as(usize, 1), h.b_sink.items.len); // nothing new delivered
    try std.testing.expectEqual(@as(usize, 0), h.a_sink.items.len); // keepalive has no content
    // a got an authenticated packet: its new_handshake cleared
    try std.testing.expect(h.pa.timers.new_handshake == null);
}

test "rekey after time" {
    const c = device.Constants{
        .timers = .{ .rekey_timeout_ns = 100, .keepalive_timeout_ns = 500, .reject_after_time_ns = 100_000 },
        .rekey_after_time_ns = 1_000,
        .reject_after_time_ns = 100_000,
        .mtu = 0,
    };
    var h: Harness = undefined;
    try setup(&h, c);
    defer teardown(&h);
    var buf: [64]u8 = undefined;
    h.a.sendPacket(ip4Packet(.{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 }, "one", &buf), h.now);
    const first_created = h.pa.current.?.created_ns;
    h.now += 25_000_000; // past rekey_after_time and the flood window
    h.a.sendPacket(ip4Packet(.{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 }, "two", &buf), h.now);
    // data still flowed and a fresh session was negotiated
    try std.testing.expectEqual(@as(usize, 2), h.b_sink.items.len);
    try std.testing.expect(h.pa.current.?.created_ns > first_created);
    try std.testing.expect(h.pb.current != null);
}

test "unknown peer initiation is dropped" {
    var h: Harness = undefined;
    try setup(&h, .{});
    defer teardown(&h);
    var stranger = device.Device.init(std.testing.allocator, std.testing.io, clampedKey(0xC3), .{});
    defer stranger.deinit();
    const sp = try stranger.addPeer(h.b.static_public, psk_zero);
    sp.endpoint = h.b_ep;
    var got_response = false;
    const Tap = struct {
        var flag: *bool = undefined;
        fn send(ctx: ?*anyopaque, datagram: []const u8, to: device.Endpoint) void {
            _ = datagram;
            _ = to;
            _ = ctx;
            flag.* = true;
        }
    };
    Tap.flag = &got_response;
    h.b.udp_send = Tap.send;
    // stranger initiates directly at b (bypass harness routing)
    const Direct = struct {
        fn send(ctx: ?*anyopaque, datagram: []const u8, to: device.Endpoint) void {
            const hh: *Harness = @ptrCast(@alignCast(ctx));
            _ = to;
            hh.b.receiveDatagram(datagram, hh.a_ep, hh.now);
        }
    };
    stranger.udp_send = Direct.send;
    stranger.udp_ctx = &h;
    try stranger.sendHandshakeInitiation(sp, false, h.now);
    try std.testing.expect(!got_response);
    try std.testing.expect(h.pb.current == null);
}

test "tampered mac1 is dropped" {
    var h: Harness = undefined;
    try setup(&h, .{});
    defer teardown(&h);
    var init: [noise.message_initiation_size]u8 = undefined;
    @memset(&init, 0x11);
    std.mem.writeInt(u32, init[0..4], noise.message_initiation_type, .little);
    const before = h.sent_count;
    h.b.receiveDatagram(&init, h.a_ep, h.now);
    try std.testing.expectEqual(before, h.sent_count);
    try std.testing.expect(h.pb.current == null);
}

test "padding sizes match Go" {
    // mtu 0: pad to multiple of 16
    try std.testing.expectEqual(@as(usize, 0), device.calculatePaddingSize(0, 0));
    try std.testing.expectEqual(@as(usize, 15), device.calculatePaddingSize(1, 0));
    try std.testing.expectEqual(@as(usize, 0), device.calculatePaddingSize(16, 0));
    try std.testing.expectEqual(@as(usize, 7), device.calculatePaddingSize(25, 0));
    // mtu 1420: 1410 -> 1420, 1415 -> 1420 (capped, not 1424)
    try std.testing.expectEqual(@as(usize, 10), device.calculatePaddingSize(1410, 1420));
    try std.testing.expectEqual(@as(usize, 5), device.calculatePaddingSize(1415, 1420));
    // over mtu: modulo
    try std.testing.expectEqual(device.calculatePaddingSize(1420 + 10, 1420), device.calculatePaddingSize(10, 1420));
}

test "staged packets are bounded and flush in order" {
    var c = device.Constants{};
    c.max_staged_packets = 4;
    var h: Harness = undefined;
    try setup(&h, c);
    defer teardown(&h);
    // no endpoint: handshake packets go nowhere, staged piles up
    h.pa.endpoint = null;
    var buf: [64]u8 = undefined;
    var i: u8 = 0;
    while (i < 6) : (i += 1) {
        const payload = [_]u8{ 0x30 + i };
        h.a.sendPacket(ip4Packet(.{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 }, &payload, &buf), h.now);
    }
    try std.testing.expectEqual(@as(usize, 4), h.pa.staged.items.len);
    // oldest two dropped: staged holds payloads '2'..'5'
    try std.testing.expectEqual(@as(u8, 0x32), h.pa.staged.items[0][20]);
    // endpoint appears, retry timer fires -> handshake, staged flush in order
    h.pa.endpoint = h.b_ep;
    h.now += 6 * std.time.ns_per_s;
    h.a.pollAll(h.now);
    try std.testing.expectEqual(@as(usize, 4), h.b_sink.items.len);
    try std.testing.expectEqual(@as(u8, 0x32), h.b_sink.items[0][20]);
    try std.testing.expectEqual(@as(u8, 0x35), h.b_sink.items[3][20]);
}

test "endpoint roams to latest sender" {
    var h: Harness = undefined;
    try setup(&h, .{});
    defer teardown(&h);
    var buf: [64]u8 = undefined;
    h.a.sendPacket(ip4Packet(.{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 }, "x", &buf), h.now);
    try std.testing.expect(h.pb.endpoint.?.eql(h.a_ep));
    // same device, new port: transport packet roams the endpoint
    const roamed = device.Endpoint.v4(127, 0, 0, 1, 9999);
    const Tap = struct {
        var datagram: ?[]u8 = null;
        fn send(ctx: ?*anyopaque, dgram: []const u8, to: device.Endpoint) void {
            _ = ctx;
            _ = to;
            if (dgram.len >= 16 and std.mem.readInt(u32, dgram[0..4], .little) == noise.message_transport_type) {
                if (datagram) |l| std.testing.allocator.free(l);
                datagram = std.testing.allocator.dupe(u8, dgram) catch null;
            }
        }
    };
    h.a.udp_send = Tap.send;
    h.a.sendPacket(ip4Packet(.{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 }, "y", &buf), h.now);
    h.b.receiveDatagram(Tap.datagram.?, roamed, h.now);
    try std.testing.expect(h.pb.endpoint.?.eql(roamed));
    std.testing.allocator.free(Tap.datagram.?);
    Tap.datagram = null;
}

test "expired keypair rejects transport" {
    var h: Harness = undefined;
    try setup(&h, .{});
    defer teardown(&h);
    var buf: [64]u8 = undefined;
    h.a.sendPacket(ip4Packet(.{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 }, "fresh", &buf), h.now);
    try std.testing.expectEqual(@as(usize, 1), h.b_sink.items.len);
    const Tap = struct {
        var datagram: ?[]u8 = null;
        fn send(ctx: ?*anyopaque, dgram: []const u8, to: device.Endpoint) void {
            _ = ctx;
            _ = to;
            if (dgram.len >= 16 and std.mem.readInt(u32, dgram[0..4], .little) == noise.message_transport_type) {
                if (datagram) |l| std.testing.allocator.free(l);
                datagram = std.testing.allocator.dupe(u8, dgram) catch null;
            }
        }
    };
    h.a.udp_send = Tap.send;
    h.a.sendPacket(ip4Packet(.{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 }, "late", &buf), h.now);
    // deliver past reject_after_time: dropped
    h.now += 181 * std.time.ns_per_s;
    h.b.receiveDatagram(Tap.datagram.?, h.a_ep, h.now);
    try std.testing.expectEqual(@as(usize, 1), h.b_sink.items.len);
    std.testing.allocator.free(Tap.datagram.?);
    Tap.datagram = null;
}

test "unrouted packet is dropped" {
    var h: Harness = undefined;
    try setup(&h, .{});
    defer teardown(&h);
    var buf: [64]u8 = undefined;
    const before = h.sent_count;
    h.a.sendPacket(ip4Packet(.{ 10, 0, 0, 1 }, .{ 192, 168, 9, 9 }, "nope", &buf), h.now);
    try std.testing.expectEqual(before, h.sent_count);
    try std.testing.expect(h.pa.current == null);
}

test "disallowed source is dropped" {
    var h: Harness = undefined;
    try setup(&h, .{});
    defer teardown(&h);
    var buf: [64]u8 = undefined;
    // b's peer allows only 10.0.0.1; spoof .9 inside an encrypted packet
    h.a.sendPacket(ip4Packet(.{ 10, 0, 0, 9 }, .{ 10, 0, 0, 2 }, "spoof", &buf), h.now);
    try std.testing.expect(h.pb.current != null); // handshake still completed
    try std.testing.expectEqual(@as(usize, 0), h.b_sink.items.len);
}


test "initiation propagates index allocation failure" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var d = device.Device.init(failing.allocator(), std.testing.io, clampedKey(0xA1), .{});
    defer d.deinit();
    const remote = noise.publicKeyFromPrivate(clampedKey(0xB2));
    const peer = try d.addPeer(remote, psk_zero);
    failing.fail_index = failing.alloc_index;
    try std.testing.expectError(error.OutOfMemory, d.sendHandshakeInitiation(peer, false, T0));
    try std.testing.expect(failing.has_induced_failure);
    try std.testing.expectEqual(@as(u32, 0), d.index_table.count());
}
