// Port of wireguard-go device core without TUN/threads (MIT).
// Reference: upstream/netbird/vendor/golang.zx2c4.com/wireguard/device/
// send.go, receive.go, peer.go, device.go, noise-protocol.go (BeginSymmetric
// Session / ReceivedWithKeypair rotation), indextable.go, allowedips.go,
// cookie.go under-load path and the transport/padding paths.
// Single peer table, deadline timers (timers.zig), Noise_IKpsk2 (noise.zig),
// MAC1/MAC2 (cookie.zig). No threads, no TUN: outbound datagrams go to a
// caller UdpSend callback, inbound IP packets to a PacketSink callback, the
// clock is caller-supplied nanoseconds.
// Out of scope: ratelimiter, GSO, mobile ClearSrc, multi-worker queues,
// uapi/ipc, tun device glue.

const std = @import("std");
const noise = @import("noise.zig");
const timers = @import("timers.zig");
const cookie = @import("cookie.zig");

const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

pub const Constants = struct {
    timers: timers.Constants = .{},
    rekey_after_time_ns: i64 = 120 * std.time.ns_per_s,
    reject_after_time_ns: i64 = 180 * std.time.ns_per_s,
    handshake_initiation_rate_ns: i64 = std.time.ns_per_s / 50,
    max_staged_packets: u32 = 128,
    mtu: u16 = 0, // 0: pad to 16 like a missing MTU (send.go)
};

pub const default_constants: Constants = .{};

/// Wire endpoint: 16-byte IP (v4 stored mapped ::ffff:a.b.c.d) + port.
pub const Endpoint = struct {
    ip: [16]u8,
    port: u16,

    pub fn v4(a: u8, b: u8, c: u8, d: u8, port: u16) Endpoint {
        return .{ .ip = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, a, b, c, d }, .port = port };
    }

    pub fn eql(a: Endpoint, b: Endpoint) bool {
        return a.port == b.port and std.mem.eql(u8, &a.ip, &b.ip);
    }

    /// Cookie MAC2 source bytes: ip || port big-endian.
    pub fn srcBytes(e: Endpoint, out: *[18]u8) []u8 {
        @memcpy(out[0..16], &e.ip);
        std.mem.writeInt(u16, out[16..18], e.port, .big);
        return out;
    }
};

/// Longest-prefix-match CIDR list, minimal allowedips.go.
pub const Cidr = struct {
    net: [16]u8,
    bits: u8,

    /// Parse "a.b.c.d/n" (IPv4 only; v6 via fromBytes).
    pub fn parseV4(text: []const u8) ?Cidr {
        const slash = std.mem.indexOfScalar(u8, text, '/') orelse return null;
        var parts: [4]u8 = undefined;
        var it = std.mem.splitScalar(u8, text[0..slash], '.');
        var i: usize = 0;
        while (it.next()) |p| {
            if (i >= 4) return null;
            parts[i] = std.fmt.parseInt(u8, p, 10) catch return null;
            i += 1;
        }
        if (i != 4) return null;
        const bits = std.fmt.parseInt(u8, text[slash + 1 ..], 10) catch return null;
        if (bits > 32) return null;
        var net: [16]u8 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0 };
        @memcpy(net[12..16], &parts);
        // mask host bits
        if (bits < 32) {
            const mask: u32 = if (bits == 0) 0 else (@as(u32, 0xffffffff) << @intCast(32 - bits));
            const addr = std.mem.readInt(u32, net[12..16], .big) & mask;
            std.mem.writeInt(u32, net[12..16], addr, .big);
        }
        return .{ .net = net, .bits = 96 + bits };
    }

    pub fn fromBytes(net: [16]u8, bits: u8) ?Cidr {
        if (bits > 128) return null;
        return .{ .net = net, .bits = bits };
    }

    pub fn matches(c: Cidr, ip: [16]u8) bool {
        var b: u16 = c.bits;
        var i: usize = 0;
        while (b >= 8) : (i += 1) {
            if (c.net[i] != ip[i]) return false;
            b -= 8;
        }
        if (b > 0) {
            const mask: u8 = @as(u8, 0xff) << @intCast(8 - b);
            if ((c.net[i] ^ ip[i]) & mask != 0) return false;
        }
        return true;
    }
};

pub const Keypair = struct {
    transport: noise.Transport, // owns send_nonce + replay filter
    is_initiator: bool,
    created_ns: i64,
    local_index: u32,
    remote_index: u32,
};

const IndexEntry = struct {
    peer: *Peer,
    keypair: ?*Keypair, // null: entry points at the peer handshake
};

pub const UdpSendFn = *const fn (ctx: ?*anyopaque, datagram: []const u8, to: Endpoint) void;
pub const PacketSinkFn = *const fn (ctx: ?*anyopaque, peer: *Peer, ip_packet: []const u8) void;

pub const Peer = struct {
    device: *Device,
    handshake: noise.Handshake,
    cookie_gen: cookie.CookieGenerator,
    current: ?*Keypair = null,
    previous: ?*Keypair = null,
    next: ?*Keypair = null,
    endpoint: ?Endpoint = null,
    disable_roaming: bool = false,
    timers: timers.Timers = .{},
    staged: std.ArrayList([]u8) = .empty,
    last_sent_handshake_ns: i64 = 0, // 0 = never
    last_initiation_consumption_ns: i64 = 0, // 0 = never
    persistent_keepalive_s: u32 = 0,
    allowed: std.ArrayList(Cidr) = .empty,
    tx_bytes: u64 = 0,
    rx_bytes: u64 = 0,

    pub fn remoteStatic(p: *const Peer) noise.PublicKey {
        return p.handshake.remote_static;
    }

    fn deinit(p: *Peer, allocator: std.mem.Allocator) void {
        p.flushStaged(allocator);
        p.staged.deinit(allocator);
        p.allowed.deinit(allocator);
        if (p.current) |k| allocator.destroy(k);
        if (p.previous) |k| allocator.destroy(k);
        if (p.next) |k| allocator.destroy(k);
    }

    /// FlushStagedPackets.
    fn flushStaged(p: *Peer, allocator: std.mem.Allocator) void {
        for (p.staged.items) |pkt| allocator.free(pkt);
        p.staged.clearRetainingCapacity();
    }
};

pub const Device = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    static_private: noise.PrivateKey,
    static_public: noise.PublicKey,
    checker: cookie.CookieChecker,
    peers: std.ArrayList(*Peer) = .empty,
    index_table: std.AutoHashMap(u32, IndexEntry) = undefined,
    constants: Constants = .{},
    udp_ctx: ?*anyopaque = null,
    udp_send: ?UdpSendFn = null,
    sink_ctx: ?*anyopaque = null,
    packet_sink: ?PacketSinkFn = null,
    under_load: bool = false,
    up: bool = true,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        static_private: noise.PrivateKey,
        constants: Constants,
    ) Device {
        const static_public = noise.publicKeyFromPrivate(static_private);
        var d = Device{
            .allocator = allocator,
            .io = io,
            .static_private = static_private,
            .static_public = static_public,
            .checker = cookie.CookieChecker.init(&static_public),
            .constants = constants,
        };
        d.index_table = .init(allocator);
        return d;
    }

    pub fn deinit(d: *Device) void {
        for (d.peers.items) |p| {
            p.deinit(d.allocator);
            d.allocator.destroy(p);
        }
        d.peers.deinit(d.allocator);
        d.index_table.deinit();
    }

    /// NewPeer (no endpoint yet, like the Go version).
    pub fn addPeer(d: *Device, remote_static: noise.PublicKey, psk: noise.PresharedKey) !*Peer {
        for (d.peers.items) |p| {
            if (std.mem.eql(u8, &p.handshake.remote_static, &remote_static)) return error.PeerExists;
        }
        const p = try d.allocator.create(Peer);
        errdefer d.allocator.destroy(p);
        p.* = .{
            .device = d,
            .handshake = try noise.Handshake.init(d.static_private, remote_static, psk),
            .cookie_gen = cookie.CookieGenerator.init(&remote_static),
        };
        p.timers.start();
        errdefer p.deinit(d.allocator);
        try d.peers.append(d.allocator, p);
        return p;
    }

    pub fn lookupPeer(d: *Device, remote_static: *const noise.PublicKey) ?*Peer {
        for (d.peers.items) |p| {
            if (std.mem.eql(u8, &p.handshake.remote_static, remote_static)) return p;
        }
        return null;
    }

    fn jitterMs(d: *Device) u16 {
        const max = d.constants.timers.jitter_max_ms;
        if (max == 0) return 0;
        var b: [2]u8 = undefined;
        d.io.random(&b);
        return @as(u16, std.mem.readInt(u16, &b, .little)) % max;
    }

    // -- index table (indextable.go) --

    fn newIndexForHandshake(d: *Device, peer: *Peer) u32 {
        while (true) {
            var b: [4]u8 = undefined;
            d.io.random(&b);
            const index = std.mem.readInt(u32, &b, .little);
            if (d.index_table.contains(index)) continue;
            d.index_table.put(index, .{ .peer = peer, .keypair = null }) catch continue;
            return index;
        }
    }

    fn deleteIndex(d: *Device, index: u32) void {
        _ = d.index_table.remove(index);
    }

    fn swapIndexForKeypair(d: *Device, index: u32, keypair: *Keypair) void {
        if (d.index_table.getPtr(index)) |e| {
            e.keypair = keypair;
        }
    }

    fn deleteKeypair(d: *Device, keypair: ?*Keypair) void {
        if (keypair) |k| d.deleteIndex(k.local_index);
    }

    // -- timers --

    fn active(d: *const Device) bool {
        return d.up;
    }

    /// Poll one peer's timers and act. Mirrors the expired* callbacks.
    pub fn pollPeer(d: *Device, peer: *Peer, now_ns: i64) void {
        const tc = d.constants.timers;
        const a = peer.timers.poll(now_ns, tc, d.jitterMs(), d.active());
        if (a.retransmit_handshake) d.sendHandshakeInitiation(peer, true, now_ns);
        if (a.give_up) peer.flushStaged(d.allocator);
        if (a.send_keepalive) d.sendKeepalive(peer, now_ns);
        if (a.new_handshake) d.sendHandshakeInitiation(peer, false, now_ns);
        if (a.zero_key_material) d.zeroAndFlushAll(peer);
        if (a.persistent_keepalive and peer.persistent_keepalive_s > 0) {
            d.sendKeepalive(peer, now_ns);
        }
    }

    pub fn pollAll(d: *Device, now_ns: i64) void {
        for (d.peers.items) |p| d.pollPeer(p, now_ns);
    }

    /// ZeroAndFlushAll.
    fn zeroAndFlushAll(d: *Device, peer: *Peer) void {
        d.deleteKeypair(peer.previous);
        d.deleteKeypair(peer.current);
        d.deleteKeypair(peer.next);
        if (peer.previous) |k| d.allocator.destroy(k);
        if (peer.current) |k| d.allocator.destroy(k);
        if (peer.next) |k| d.allocator.destroy(k);
        peer.previous = null;
        peer.current = null;
        peer.next = null;
        d.deleteIndex(peer.handshake.local_index);
        peer.handshake.clear();
        peer.flushStaged(d.allocator);
    }

    // -- send path (send.go) --

    /// StagePackets: bound the staged queue, drop oldest first.
    fn stagePacket(d: *Device, peer: *Peer, packet: []const u8) void {
        while (peer.staged.items.len >= d.constants.max_staged_packets) {
            const oldest = peer.staged.orderedRemove(0);
            d.allocator.free(oldest);
        }
        const copy = d.allocator.dupe(u8, packet) catch return;
        peer.staged.append(d.allocator, copy) catch {
            d.allocator.free(copy);
        };
    }

    /// TUN-reader equivalent: route an IP packet to a peer and flush.
    pub fn sendPacket(d: *Device, ip_packet: []const u8, now_ns: i64) void {
        const peer = d.routeToPeer(ip_packet) orelse return;
        d.stagePacket(peer, ip_packet);
        d.flushPeer(peer, now_ns);
    }

    /// Route by destination like RoutineReadFromTUN.
    fn routeToPeer(d: *Device, ip_packet: []const u8) ?*Peer {
        if (ip_packet.len < 1) return null;
        const dst = dstAddr(ip_packet) orelse return null;
        return d.lookupAllowedIP(dst);
    }

    /// Device-wide longest-prefix ownership, shared by send and receive.
    fn lookupAllowedIP(d: *Device, address: [16]u8) ?*Peer {
        var best: ?*Peer = null;
        var best_bits: u8 = 0;
        var first = true;
        for (d.peers.items) |p| {
            for (p.allowed.items) |c| {
                if (c.matches(address) and (first or c.bits >= best_bits)) {
                    best = p;
                    best_bits = c.bits;
                    first = false;
                }
            }
        }
        return best;
    }

    /// needsHandshake.
    fn needsHandshake(d: *Device, peer: *Peer, now_ns: i64) bool {
        const kp = peer.current orelse return true;
        return kp.transport.send_nonce >= noise.reject_after_messages or
            now_ns - kp.created_ns >= d.constants.reject_after_time_ns;
    }

    /// sendStagedPackets (single-threaded: all-or-nothing per call).
    fn flushPeer(d: *Device, peer: *Peer, now_ns: i64) void {
        if (peer.staged.items.len == 0 or !d.up) return;
        if (d.needsHandshake(peer, now_ns)) {
            d.sendHandshakeInitiation(peer, false, now_ns);
            return;
        }
        const kp = peer.current.?;
        var data_sent = false;
        var i: usize = 0;
        while (i < peer.staged.items.len) {
            const packet = peer.staged.items[i];
            if (kp.transport.send_nonce >= noise.reject_after_messages) {
                kp.transport.send_nonce = noise.reject_after_messages;
                d.sendHandshakeInitiation(peer, false, now_ns);
                break;
            }
            d.sealAndEmit(peer, packet, kp);
            if (packet.len != 0) data_sent = true;
            d.allocator.free(packet);
            i += 1;
        }
        // drop the emitted prefix
        std.mem.copyForwards([]u8, peer.staged.items[0..], peer.staged.items[i..]);
        peer.staged.shrinkRetainingCapacity(peer.staged.items.len - i);
        if (i == 0) return;
        peer.timers.anyAuthTraversal(now_ns, peer.persistent_keepalive_s, d.active());
        peer.timers.anyAuthSent(d.active());
        if (data_sent) peer.timers.dataSent(now_ns, d.constants.timers, d.jitterMs(), d.active());
        d.keepKeyFreshSending(peer, now_ns);
    }

    /// RoutineEncryption for one packet + sequential send.
    fn sealAndEmit(d: *Device, peer: *Peer, packet: []const u8, kp: *Keypair) void {
        const padding = calculatePaddingSize(packet.len, d.constants.mtu);
        const content_len = packet.len + padding;
        const plain = d.allocator.alloc(u8, content_len) catch return;
        defer d.allocator.free(plain);
        @memcpy(plain[0..packet.len], packet);
        @memset(plain[packet.len..], 0);
        const total = noise.message_transport_header_size + content_len + noise.tag_size;
        const buf = d.allocator.alloc(u8, total) catch return;
        defer d.allocator.free(buf);
        _ = kp.transport.seal(buf.ptr[0..16], buf[16..], plain) catch return;
        d.emit(peer, buf);
    }

    fn emit(d: *Device, peer: *Peer, datagram: []const u8) void {
        const ep = peer.endpoint orelse return;
        peer.tx_bytes += datagram.len;
        if (d.udp_send) |f| f(d.udp_ctx, datagram, ep);
    }

    /// SendKeepalive: stage one empty packet when idle, then flush.
    pub fn sendKeepalive(d: *Device, peer: *Peer, now_ns: i64) void {
        if (peer.staged.items.len == 0 and d.up) d.stagePacket(peer, &.{});
        d.flushPeer(peer, now_ns);
    }

    /// keepKeyFreshSending.
    fn keepKeyFreshSending(d: *Device, peer: *Peer, now_ns: i64) void {
        const kp = peer.current orelse return;
        if (kp.transport.send_nonce > noise.rekey_after_messages or
            (kp.is_initiator and now_ns - kp.created_ns > d.constants.rekey_after_time_ns))
        {
            d.sendHandshakeInitiation(peer, false, now_ns);
        }
    }

    /// SendHandshakeInitiation with the RekeyTimeout throttle.
    pub fn sendHandshakeInitiation(d: *Device, peer: *Peer, is_retry: bool, now_ns: i64) void {
        if (!is_retry) peer.timers.handshake_attempts = 0;
        if (peer.last_sent_handshake_ns != 0 and
            now_ns - peer.last_sent_handshake_ns < d.constants.timers.rekey_timeout_ns) return;
        peer.last_sent_handshake_ns = now_ns;
        d.sendHandshakeInitiationInner(peer, now_ns);
    }

    fn sendHandshakeInitiationInner(d: *Device, peer: *Peer, now_ns: i64) void {
        d.deleteIndex(peer.handshake.local_index);
        const index = d.newIndexForHandshake(peer);
        const ephemeral = noise.generatePrivateKey(d.io);
        const stamp = stampFor(now_ns);
        const msg = peer.handshake.createInitiation(ephemeral, index, stamp) catch return;
        var packet: [noise.message_initiation_size]u8 = undefined;
        msg.marshal(&packet);
        peer.cookie_gen.addMacs(&packet, now_ns);
        peer.timers.anyAuthTraversal(now_ns, peer.persistent_keepalive_s, d.active());
        peer.timers.anyAuthSent(d.active());
        d.emit(peer, &packet);
        peer.timers.handshakeInitiated(now_ns, d.constants.timers, d.jitterMs(), d.active());
    }

    /// SendHandshakeResponse + BeginSymmetricSession (responder side).
    fn sendHandshakeResponse(d: *Device, peer: *Peer, now_ns: i64) void {
        peer.last_sent_handshake_ns = now_ns;
        d.deleteIndex(peer.handshake.local_index);
        const index = d.newIndexForHandshake(peer);
        const ephemeral = noise.generatePrivateKey(d.io);
        const msg = peer.handshake.createResponse(ephemeral, index) catch return;
        var packet: [noise.message_response_size]u8 = undefined;
        msg.marshal(&packet);
        peer.cookie_gen.addMacs(&packet, now_ns);
        d.beginSymmetricSession(peer, now_ns);
        peer.timers.sessionDerived(now_ns, d.constants.timers, d.active());
        peer.timers.anyAuthTraversal(now_ns, peer.persistent_keepalive_s, d.active());
        peer.timers.anyAuthSent(d.active());
        d.emit(peer, &packet);
    }

    /// BeginSymmetricSession keypair rotation (noise-protocol.go).
    fn beginSymmetricSession(d: *Device, peer: *Peer, now_ns: i64) void {
        const keys = peer.handshake.beginSymmetricSession() catch return;
        const kp = d.allocator.create(Keypair) catch return;
        kp.* = .{
            .transport = noise.Transport.init(keys),
            .is_initiator = keys.is_initiator,
            .created_ns = now_ns,
            .local_index = keys.local_index,
            .remote_index = keys.remote_index,
        };
        d.swapIndexForKeypair(keys.local_index, kp);
        if (keys.is_initiator) {
            const old_previous = peer.previous;
            if (peer.next) |n| {
                peer.next = null;
                peer.previous = n;
                d.deleteKeypair(peer.current);
                if (peer.current) |c| d.allocator.destroy(c);
            } else {
                peer.previous = peer.current;
            }
            if (old_previous) |o| {
                d.deleteKeypair(o);
                d.allocator.destroy(o);
            }
            peer.current = kp;
        } else {
            const old_next = peer.next;
            peer.next = kp;
            if (old_next) |o| {
                d.deleteKeypair(o);
                d.allocator.destroy(o);
            }
            const old_previous = peer.previous;
            peer.previous = null;
            if (old_previous) |o| {
                d.deleteKeypair(o);
                d.allocator.destroy(o);
            }
        }
    }

    /// ReceivedWithKeypair: promote next -> current on first authenticated use.
    fn receivedWithKeypair(d: *Device, peer: *Peer, kp: *Keypair) bool {
        if (peer.next != kp) return false;
        const old = peer.previous;
        peer.previous = peer.current;
        d.deleteKeypair(old);
        if (old) |o| d.allocator.destroy(o);
        peer.current = peer.next;
        peer.next = null;
        return true;
    }

    /// keepKeyFreshReceiving.
    fn keepKeyFreshReceiving(d: *Device, peer: *Peer, now_ns: i64) void {
        if (peer.timers.sent_last_minute_handshake) return;
        const kp = peer.current orelse return;
        const c = d.constants;
        if (kp.is_initiator and
            now_ns - kp.created_ns > c.reject_after_time_ns - c.timers.keepalive_timeout_ns - c.timers.rekey_timeout_ns)
        {
            peer.timers.sent_last_minute_handshake = true;
            d.sendHandshakeInitiation(peer, false, now_ns);
        }
    }

    // -- receive path (receive.go) --

    /// RoutineReceiveIncoming + RoutineHandshake + sequential receiver,
    /// collapsed: one datagram in, timer/queue effects applied inline.
    pub fn receiveDatagram(d: *Device, datagram: []const u8, from: Endpoint, now_ns: i64) void {
        if (datagram.len < noise.message_transport_header_size + noise.tag_size) return;
        const msg_type = std.mem.readInt(u32, datagram[0..4], .little);
        switch (msg_type) {
            noise.message_transport_type => d.receiveTransport(datagram, from, now_ns),
            noise.message_initiation_type => {
                if (datagram.len != noise.message_initiation_size) return;
                d.receiveInitiation(datagram[0..noise.message_initiation_size], from, now_ns);
            },
            noise.message_response_type => {
                if (datagram.len != noise.message_response_size) return;
                d.receiveResponse(datagram[0..noise.message_response_size], from, now_ns);
            },
            cookie.message_cookie_reply_type => {
                if (datagram.len != cookie.message_cookie_reply_size) return;
                d.receiveCookieReply(datagram[0..cookie.message_cookie_reply_size], now_ns);
            },
            else => {},
        }
    }

    fn underLoadMacOk(d: *Device, packet: []const u8, from: Endpoint, now_ns: i64) bool {
        if (!d.checker.checkMac1(packet)) return false;
        if (!d.under_load) return true;
        var src: [18]u8 = undefined;
        if (d.checker.checkMac2(packet, from.srcBytes(&src), now_ns)) return true;
        // SendHandshakeCookie (no ratelimiter in this port).
        const sender = std.mem.readInt(u32, packet[4..8], .little);
        const reply = d.checker.createReply(d.io, packet, sender, from.srcBytes(&src), now_ns);
        var wire: [cookie.message_cookie_reply_size]u8 = undefined;
        reply.marshal(&wire);
        if (d.udp_send) |f| f(d.udp_ctx, &wire, from);
        return false;
    }

    fn receiveCookieReply(d: *Device, packet: *const [cookie.message_cookie_reply_size]u8, now_ns: i64) void {
        const reply = cookie.CookieReply.unmarshal(packet) orelse return;
        const entry = d.index_table.get(reply.receiver) orelse return;
        _ = entry.peer.cookie_gen.consumeReply(&reply, now_ns);
    }

    fn receiveInitiation(
        d: *Device,
        packet: *const [noise.message_initiation_size]u8,
        from: Endpoint,
        now_ns: i64,
    ) void {
        if (!d.underLoadMacOk(packet, from, now_ns)) return;
        const msg = noise.Initiation.unmarshal(packet) catch return;
        // ConsumeMessageInitiation: find the peer whose static key decrypts.
        // Handshake.consumeInitiation mutates nothing until all checks pass,
        // so probing peers in turn is side-effect free.
        for (d.peers.items) |peer| {
            if (peer.last_initiation_consumption_ns != 0 and
                now_ns - peer.last_initiation_consumption_ns <= d.constants.handshake_initiation_rate_ns)
                continue; // flood guard
            peer.handshake.consumeInitiation(&msg, null) catch continue;
            if (now_ns > peer.last_initiation_consumption_ns) {
                peer.last_initiation_consumption_ns = now_ns;
            }
            peer.timers.anyAuthTraversal(now_ns, peer.persistent_keepalive_s, d.active());
            peer.timers.anyAuthReceived(d.active());
            d.setEndpointFromPacket(peer, from);
            peer.rx_bytes += packet.len;
            d.sendHandshakeResponse(peer, now_ns);
            return;
        }
    }

    fn receiveResponse(
        d: *Device,
        packet: *const [noise.message_response_size]u8,
        from: Endpoint,
        now_ns: i64,
    ) void {
        if (!d.underLoadMacOk(packet, from, now_ns)) return;
        const msg = noise.Response.unmarshal(packet) catch return;
        const entry = d.index_table.get(msg.receiver) orelse return;
        if (entry.keypair != null) return; // must reference a handshake
        const peer = entry.peer;
        peer.handshake.consumeResponse(&msg) catch return;
        d.setEndpointFromPacket(peer, from);
        peer.rx_bytes += packet.len;
        peer.timers.anyAuthTraversal(now_ns, peer.persistent_keepalive_s, d.active());
        peer.timers.anyAuthReceived(d.active());
        d.beginSymmetricSession(peer, now_ns);
        peer.timers.sessionDerived(now_ns, d.constants.timers, d.active());
        peer.timers.handshakeComplete(now_ns);
        d.sendKeepalive(peer, now_ns);
    }

    fn receiveTransport(d: *Device, datagram: []const u8, from: Endpoint, now_ns: i64) void {
        if (datagram.len < noise.message_transport_header_size + noise.tag_size) return;
        const receiver = std.mem.readInt(u32, datagram[4..8], .little);
        const entry = d.index_table.get(receiver) orelse return;
        const kp = entry.keypair orelse return;
        if (now_ns - kp.created_ns >= d.constants.reject_after_time_ns) return; // expired
        const counter = std.mem.readInt(u64, datagram[8..16], .little);
        const content = datagram[noise.message_transport_offset_content..];
        if (content.len < noise.tag_size) return;
        // RoutineDecryption first, replay check after (like Go): a forged
        // packet must not burn a window bit.
        const body_len = content.len - noise.tag_size;
        const buf = d.allocator.alloc(u8, body_len) catch return;
        defer d.allocator.free(buf);
        var nonce: [12]u8 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        std.mem.writeInt(u64, nonce[4..12], counter, .little);
        const tag: [noise.tag_size]u8 = content[body_len..][0..noise.tag_size].*;
        ChaCha20Poly1305.decrypt(buf, content[0..body_len], tag, &.{}, nonce, kp.transport.receive_key) catch return;
        if (!kp.transport.replay.validateCounter(counter, noise.reject_after_messages)) return;
        const packet = buf[0..body_len];
        const peer = entry.peer;
        if (d.receivedWithKeypair(peer, kp)) {
            d.setEndpointFromPacket(peer, from);
            peer.timers.handshakeComplete(now_ns);
            d.flushPeer(peer, now_ns);
        }
        peer.rx_bytes += packet.len + noise.message_transport_header_size + noise.tag_size;
        d.setEndpointFromPacket(peer, from);
        d.keepKeyFreshReceiving(peer, now_ns);
        peer.timers.anyAuthTraversal(now_ns, peer.persistent_keepalive_s, d.active());
        peer.timers.anyAuthReceived(d.active());
        if (packet.len == 0) return; // keepalive
        peer.timers.dataReceived(now_ns, d.constants.timers, d.active());
        const trimmed = trimPacket(packet) orelse return;
        const src = srcAddr(trimmed) orelse return;
        if (d.lookupAllowedIP(src) != peer) return;
        if (d.packet_sink) |f| f(d.sink_ctx, peer, trimmed);
    }

    /// SetEndpointFromPacket (roaming unless disabled).
    fn setEndpointFromPacket(d: *Device, peer: *Peer, from: Endpoint) void {
        _ = d;
        if (peer.disable_roaming) return;
        peer.endpoint = from;
    }
};

/// tai64n stamp from caller nanoseconds.
fn stampFor(now_ns: i64) noise.Timestamp {
    const secs: i64 = @divFloor(now_ns, std.time.ns_per_s);
    const nanos: u32 = @intCast(@mod(now_ns, std.time.ns_per_s));
    return noise.tai64nStamp(secs, nanos);
}

/// calculatePaddingSize (send.go).
pub fn calculatePaddingSize(packet_size: usize, mtu: u16) usize {
    const padding_multiple: usize = 16;
    var last_unit = packet_size;
    if (mtu == 0) {
        return ((last_unit + padding_multiple - 1) & ~(padding_multiple - 1)) - last_unit;
    }
    if (last_unit > mtu) last_unit %= mtu;
    var padded_size = ((last_unit + padding_multiple - 1) & ~(padding_multiple - 1));
    if (padded_size > mtu) padded_size = mtu;
    return padded_size - last_unit;
}

/// Destination address of an IP packet as a 16-byte mapped address.
fn dstAddr(ip_packet: []const u8) ?[16]u8 {
    if (ip_packet.len < 1) return null;
    switch (ip_packet[0] >> 4) {
        4 => {
            if (ip_packet.len < 20) return null;
            var out: [16]u8 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0 };
            @memcpy(out[12..16], ip_packet[16..20]);
            return out;
        },
        6 => {
            if (ip_packet.len < 40) return null;
            return ip_packet[24..40].*;
        },
        else => return null,
    }
}

/// Source address of an IP packet.
fn srcAddr(ip_packet: []const u8) ?[16]u8 {
    if (ip_packet.len < 1) return null;
    switch (ip_packet[0] >> 4) {
        4 => {
            if (ip_packet.len < 20) return null;
            var out: [16]u8 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0 };
            @memcpy(out[12..16], ip_packet[12..16]);
            return out;
        },
        6 => {
            if (ip_packet.len < 40) return null;
            return ip_packet[8..24].*;
        },
        else => return null,
    }
}

/// Trim padding using the IP length fields (sequential receiver).
fn trimPacket(packet: []const u8) ?[]const u8 {
    switch (packet[0] >> 4) {
        4 => {
            if (packet.len < 20) return null;
            const length = std.mem.readInt(u16, packet[2..4], .big);
            if (length > packet.len or length < 20) return null;
            return packet[0..length];
        },
        6 => {
            if (packet.len < 40) return null;
            const length: usize = std.mem.readInt(u16, packet[4..6], .big) + 40;
            if (length > packet.len) return null;
            return packet[0..length];
        },
        else => return null,
    }
}

