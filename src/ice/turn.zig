// Port of NetBird TURN usage (v0.79.0), BSD-3-Clause for NetBird files, MIT for pion.
// Reference: upstream/netbird/vendor/github.com/pion/turn/v3/client.go
// (Allocate with the 401 long-term-auth dance, CreatePermission),
// internal/client/udp_conn.go (ChannelBind, Send indication vs ChannelData,
// auto-permission on write), internal/proto/* (attr codecs, ChannelData
// framing: RFC 5766 §11.4, §14).
// Scope: UDP allocation + permissions + channel bind + relayed send/recv over
// one socket. No TCP allocations, no Refresh/Delete (engine work), no
// EVEN-PORT/RESERVATION (relayed TCP only).

const std = @import("std");
const linux = std.os.linux;
const stun = @import("stun.zig");
const ice = @import("ice.zig");

pub const IpAddress = stun.IpAddress;

pub const Error = error{
    Timeout,
    Unauthorized,
    StaleNonce,
    NoAllocation,
    NoPermission,
    BadChannel,
    NotChannelData,
    TurnError,
} || stun.Error || ice.Error;

pub const proto_udp: u8 = 17;
pub const min_channel: u16 = 0x4000;
pub const max_channel: u16 = 0x7FFF;
pub const channel_header_len = 4;
pub const max_channels = 16;
pub const max_permissions = 32;

/// Port of proto.IsChannelData: 4+ bytes, length sane, number in range.
pub fn isChannelData(buf: []const u8) bool {
    if (buf.len < channel_header_len) return false;
    const len = std.mem.readInt(u16, buf[2..4], .big);
    if (len > buf.len - channel_header_len) return false;
    const num = std.mem.readInt(u16, buf[0..2], .big);
    return num >= min_channel and num <= max_channel;
}

/// Port of (ChannelData).Encode into buf; returns the framed length.
pub fn encodeChannelData(buf: []u8, number: u16, data: []const u8) Error!usize {
    if (number < min_channel or number > max_channel) return Error.BadChannel;
    if (data.len > 0xffff) return Error.BadAttrLen;
    const total = channel_header_len + stun.paddedLen(data.len);
    if (total > buf.len) return Error.NoSpace;
    std.mem.writeInt(u16, buf[0..2], number, .big);
    std.mem.writeInt(u16, buf[2..4], @intCast(data.len), .big);
    @memcpy(buf[4..][0..data.len], data);
    @memset(buf[4 + data.len .. total], 0);
    return total;
}

/// Port of (ChannelData).Decode: views into buf.
pub fn decodeChannelData(buf: []const u8) Error!struct { number: u16, data: []const u8 } {
    if (!isChannelData(buf)) return Error.NotChannelData;
    const num = std.mem.readInt(u16, buf[0..2], .big);
    const len: usize = std.mem.readInt(u16, buf[2..4], .big);
    return .{ .number = num, .data = buf[4 .. 4 + len] };
}

/// REQUESTED-TRANSPORT value. Port of proto.RequestedTransport.
pub fn encodeRequestedTransport(e: *stun.Encoder, protocol: u8) Error!void {
    const v = [_]u8{ protocol, 0, 0, 0 };
    try e.add(stun.Attr.requested_transport, &v);
}

pub fn decodeRequestedTransport(d: *const stun.Decoded) Error!u8 {
    const v = try d.get(stun.Attr.requested_transport);
    if (v.len != 4) return Error.BadAttrLen;
    return v[0];
}

/// LIFETIME value. Port of proto.Lifetime.
pub fn encodeLifetime(e: *stun.Encoder, seconds: u32) Error!void {
    var v: [4]u8 = undefined;
    std.mem.writeInt(u32, &v, seconds, .big);
    try e.add(stun.Attr.lifetime, &v);
}

pub fn decodeLifetime(d: *const stun.Decoded) Error!u32 {
    const v = try d.get(stun.Attr.lifetime);
    if (v.len != 4) return Error.BadAttrLen;
    return std.mem.readInt(u32, v[0..4], .big);
}

/// CHANNEL-NUMBER value. Port of proto.ChannelNumber.
pub fn encodeChannelNumber(e: *stun.Encoder, number: u16) Error!void {
    if (number < min_channel or number > max_channel) return Error.BadChannel;
    var v: [4]u8 = .{ 0, 0, 0, 0 };
    std.mem.writeInt(u16, v[0..2], number, .big);
    try e.add(stun.Attr.channel_number, &v);
}

pub fn decodeChannelNumber(d: *const stun.Decoded) Error!u16 {
    const v = try d.get(stun.Attr.channel_number);
    if (v.len != 4) return Error.BadAttrLen;
    const n = std.mem.readInt(u16, v[0..2], .big);
    if (n < min_channel or n > max_channel) return Error.BadChannel;
    return n;
}

fn failed(rc: usize) bool {
    return rc > 0xfffffffffffff000;
}

fn sameAddr(a: IpAddress, b: IpAddress) bool {
    return switch (a) {
        .ip4 => |x| switch (b) {
            .ip4 => |y| x.port == y.port and std.mem.eql(u8, &x.bytes, &y.bytes),
            else => false,
        },
        .ip6 => |x| switch (b) {
            .ip6 => |y| x.port == y.port and std.mem.eql(u8, &x.bytes, &y.bytes),
            else => false,
        },
    };
}

/// UDP TURN client: one socket, one allocation. Owns fd; call close().
pub const Client = struct {
    fd: linux.fd_t,
    server: IpAddress,
    username_buf: [64]u8 = undefined,
    username_len: usize = 0,
    password_buf: [128]u8 = undefined,
    password_len: usize = 0,
    realm_buf: [128]u8 = undefined,
    realm_len: usize = 0,
    nonce_buf: [128]u8 = undefined,
    nonce_len: usize = 0,
    key: [16]u8 = undefined,
    has_key: bool = false,
    relayed: IpAddress = stun.ip4(.{ 0, 0, 0, 0 }, 0),
    lifetime_s: u32 = 0,
    permissions: [max_permissions]IpAddress = undefined,
    n_permissions: usize = 0,
    channels: [max_channels]struct { number: u16, peer: IpAddress } = undefined,
    n_channels: usize = 0,
    next_channel: u16 = min_channel,
    rto_ms: i32 = 200,
    attempts: u8 = 5,

    pub fn username(c: *const Client) []const u8 {
        return c.username_buf[0..c.username_len];
    }

    pub fn password(c: *const Client) []const u8 {
        return c.password_buf[0..c.password_len];
    }

    pub fn realm(c: *const Client) []const u8 {
        return c.realm_buf[0..c.realm_len];
    }

    pub fn nonce(c: *const Client) []const u8 {
        return c.nonce_buf[0..c.nonce_len];
    }

    pub fn close(c: *Client) void {
        _ = linux.close(c.fd);
        c.fd = -1;
    }

    /// Local socket address (what the server sees as our peer address).
    pub fn localAddr(c: *const Client) Error!IpAddress {
        var sab = ice.SockAddrBuf{};
        var len: linux.socklen_t = @sizeOf(linux.sockaddr.in6);
        if (failed(linux.getsockname(c.fd, @ptrCast(@alignCast(&sab.buf)), &len)))
            return Error.SocketFailed;
        return sab.toIp(len);
    }

    fn refreshKey(c: *Client) void {
        stun.longTermKey(c.username(), c.realm(), c.password(), &c.key);
        c.has_key = true;
    }

    /// Build an authenticated request: method + method attrs + USERNAME,
    /// REALM, NONCE, MESSAGE-INTEGRITY, FINGERPRINT. Port of the pion
    /// allocate/permission/bind request shape.
    fn buildAuthed(
        c: *Client,
        buf: []u8,
        method: stun.Method,
        trid: stun.Trid,
        extra: ?*const fn (*stun.Encoder) Error!void,
    ) Error![]u8 {
        var enc = try stun.Encoder.init(buf, .{ .method = method, .class = .request }, trid);
        if (extra) |f| try f(&enc);
        try enc.add(stun.Attr.username, c.username());
        try enc.add(stun.Attr.realm, c.realm());
        try enc.add(stun.Attr.nonce, c.nonce());
        try enc.addIntegrity(&c.key);
        try enc.addFingerprint();
        return enc.bytes();
    }

    /// Request/response transaction with exponential-backoff retransmits
    /// (200ms doubling to 1600ms cap like pion's Transaction timer).
    /// Returns the response length in resp_buf.
    fn transact(
        c: *Client,
        req: []const u8,
        trid: stun.Trid,
        resp_buf: []u8,
    ) Error!usize {
        var sab = ice.SockAddrBuf{};
        const d = sab.fromIp(c.server);
        var wait_ms = c.rto_ms;
        var attempt: u8 = 0;
        while (attempt < c.attempts) : (attempt += 1) {
            const sent = linux.sendto(c.fd, req.ptr, req.len, 0, d.ptr, d.len);
            if (failed(sent) or sent != req.len) return Error.SendFailed;
            var pfd = [_]linux.pollfd{.{ .fd = c.fd, .events = linux.POLL.IN }};
            // Drain everything readable within this attempt's window; the
            // matching response may sit behind Data indications.
            const window_end = nowMs() + wait_ms;
            while (true) {
                const left = window_end - nowMs();
                if (left <= 0) break;
                const prc = linux.poll(&pfd, 1, @intCast(left));
                if (failed(prc)) return Error.RecvFailed;
                if (prc == 0) break;
                var rbuf: [2048]u8 = undefined;
                const n = linux.recvfrom(c.fd, &rbuf, rbuf.len, 0, null, null);
                if (failed(n) or n == 0) return Error.RecvFailed;
                const pkt = rbuf[0..n];
                if (isChannelData(pkt)) continue; // relayed data, not ours here.
                if (!stun.isMessage(pkt)) continue;
                const dd = stun.decode(pkt) catch continue;
                if (!std.mem.eql(u8, &dd.trid, &trid)) continue;
                if (n > resp_buf.len) return Error.NoSpace;
                @memcpy(resp_buf[0..n], pkt);
                return n;
            }
            wait_ms = @min(wait_ms * 2, 1600);
        }
        return Error.Timeout;
    }

    /// Store REALM+NONCE from a 401/438 and rebuild the long-term key.
    /// Returns true when the caller should retry the request once.
    fn authFromError(c: *Client, d: *const stun.Decoded) Error!bool {
        if (d.msg_type.class != .err) return false;
        const ec = try stun.ErrorCode.decode(d);
        if (ec.code != stun.ErrorCode.unauthorized and ec.code != 438) return false;
        const r = try d.get(stun.Attr.realm);
        const nn = try d.get(stun.Attr.nonce);
        if (r.len > c.realm_buf.len or nn.len > c.nonce_buf.len) return Error.BadAttrLen;
        @memcpy(c.realm_buf[0..r.len], r);
        c.realm_len = r.len;
        @memcpy(c.nonce_buf[0..nn.len], nn);
        c.nonce_len = nn.len;
        c.refreshKey();
        return true;
    }

    fn hasPermission(c: *const Client, peer: IpAddress) bool {
        for (c.permissions[0..c.n_permissions]) |p| {
            // Permissions cover whole IPs (RFC 5766 §9); compare addr only.
            switch (p) {
                .ip4 => |x| switch (peer) {
                    .ip4 => |y| if (std.mem.eql(u8, &x.bytes, &y.bytes)) return true,
                    else => {},
                },
                .ip6 => |x| switch (peer) {
                    .ip6 => |y| if (std.mem.eql(u8, &x.bytes, &y.bytes)) return true,
                    else => {},
                },
            }
        }
        return false;
    }

    fn channelFor(c: *const Client, peer: IpAddress) ?u16 {
        for (c.channels[0..c.n_channels]) |ch| {
            if (sameAddr(ch.peer, peer)) return ch.number;
        }
        return null;
    }

    fn peerForChannel(c: *const Client, number: u16) ?IpAddress {
        for (c.channels[0..c.n_channels]) |ch| {
            if (ch.number == number) return ch.peer;
        }
        return null;
    }
};

fn nowMs() i64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return ts.sec * 1000 + @divTrunc(ts.nsec, 1_000_000);
}

pub const AllocateOptions = struct {
    rto_ms: i32 = 200,
    attempts: u8 = 5,
};

/// Allocate a relayed UDP address. Port of Client.Allocate/sendAllocateRequest
/// (ProtoUDP): anonymous Allocate → 401 → authed Allocate → relayed address.
pub fn allocate(
    server: IpAddress,
    username: []const u8,
    password: []const u8,
    opts: AllocateOptions,
) Error!Client {
    const domain: u32 = switch (server) {
        .ip4 => linux.AF.INET,
        .ip6 => linux.AF.INET6,
    };
    const s = linux.socket(domain, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    if (failed(s)) return Error.SocketFailed;
    var c = Client{
        .fd = @intCast(s),
        .server = server,
        .rto_ms = opts.rto_ms,
        .attempts = opts.attempts,
    };
    errdefer c.close();
    if (username.len > c.username_buf.len or password.len > c.password_buf.len)
        return Error.BadAttrLen;
    @memcpy(c.username_buf[0..username.len], username);
    c.username_len = username.len;
    @memcpy(c.password_buf[0..password.len], password);
    c.password_len = password.len;

    // Anonymous allocate to learn REALM+NONCE.
    var req_buf: [512]u8 = undefined;
    var enc = try stun.Encoder.init(&req_buf, .{ .method = .allocate, .class = .request }, stun.randomTrid());
    try encodeRequestedTransport(&enc, proto_udp);
    try enc.addFingerprint();
    try ice.sendTo(c.fd, server, enc.bytes());

    var resp_buf: [2048]u8 = undefined;
    // First response (401 expected); reuse transact matching by rebuilding:
    // simpler to run our own first wait here since the request is already out.
    const first_trid = enc.bytes()[8..20].*;
    const n1 = try c.transact(enc.bytes(), first_trid, &resp_buf);
    // transact re-sent the request; that is fine (idempotent pre-auth).
    const d1 = try stun.decode(resp_buf[0..n1]);
    if (!(try c.authFromError(&d1))) {
        if (d1.msg_type.class == .err) return Error.Unauthorized;
        return Error.TurnError;
    }

    // Authenticated allocate.
    var req2_buf: [1024]u8 = undefined;
    const trid2 = stun.randomTrid();
    var enc2 = try stun.Encoder.init(&req2_buf, .{ .method = .allocate, .class = .request }, trid2);
    try encodeRequestedTransport(&enc2, proto_udp);
    try enc2.add(stun.Attr.username, c.username());
    try enc2.add(stun.Attr.realm, c.realm());
    try enc2.add(stun.Attr.nonce, c.nonce());
    try enc2.addIntegrity(&c.key);
    try enc2.addFingerprint();
    const n2 = try c.transact(enc2.bytes(), trid2, &resp_buf);
    const d2 = try stun.decode(resp_buf[0..n2]);
    if (d2.msg_type.class == .err) {
        // Stale nonce: one retry with fresh REALM+NONCE.
        if (try c.authFromError(&d2)) {
            var req3_buf: [1024]u8 = undefined;
            const trid3 = stun.randomTrid();
            const req3 = try c.buildAuthed(&req3_buf, .allocate, trid3, &struct {
                fn f(e: *stun.Encoder) Error!void {
                    try encodeRequestedTransport(e, proto_udp);
                }
            }.f);
            const n3 = try c.transact(req3, trid3, &resp_buf);
            const d3 = try stun.decode(resp_buf[0..n3]);
            if (d3.msg_type.class == .err) return Error.TurnError;
            const x = try stun.XorAddr.decode(&d3, stun.Attr.xor_relayed_address, d3.trid);
            c.relayed = switch (x.ip) {
                .ip4 => |v| stun.ip4(v.bytes, x.port),
                .ip6 => |v| stun.ip6(v.bytes, x.port),
            };
            c.lifetime_s = try decodeLifetime(&d3);
            return c;
        }
        return Error.TurnError;
    }
    const x = try stun.XorAddr.decode(&d2, stun.Attr.xor_relayed_address, d2.trid);
    c.relayed = switch (x.ip) {
        .ip4 => |v| stun.ip4(v.bytes, x.port),
        .ip6 => |v| stun.ip6(v.bytes, x.port),
    };
    c.lifetime_s = try decodeLifetime(&d2);
    return c;
}

/// Install a permission for a peer address. Port of allocation.CreatePermissions.
/// Idempotent: installing twice is a no-op (server treats it as refresh).
pub fn createPermission(c: *Client, peer: IpAddress) Error!void {
    var req_buf: [1024]u8 = undefined;
    const trid = stun.randomTrid();
    var enc = try stun.Encoder.init(&req_buf, .{ .method = .create_permission, .class = .request }, trid);
    const port: u16 = switch (peer) {
        .ip4 => |a| a.port,
        .ip6 => |a| a.port,
    };
    try stun.XorAddr.encode(&enc, stun.Attr.xor_peer_address, trid, peer, port);
    try enc.add(stun.Attr.username, c.username());
    try enc.add(stun.Attr.realm, c.realm());
    try enc.add(stun.Attr.nonce, c.nonce());
    try enc.addIntegrity(&c.key);
    try enc.addFingerprint();
    var resp_buf: [1024]u8 = undefined;
    var attempt: u8 = 0;
    var cur_trid = trid;
    var cur_req: []u8 = enc.bytes();
    var cur_buf: [1024]u8 = req_buf;
    while (true) {
        const n = try c.transact(cur_req, cur_trid, &resp_buf);
        const d = try stun.decode(resp_buf[0..n]);
        if (d.msg_type.class != .err) break;
        if (attempt < 1 and try c.authFromError(&d)) {
            // Stale nonce: rebuild with fresh credentials.
            attempt += 1;
            cur_trid = stun.randomTrid();
            var e2 = try stun.Encoder.init(&cur_buf, .{ .method = .create_permission, .class = .request }, cur_trid);
            try stun.XorAddr.encode(&e2, stun.Attr.xor_peer_address, cur_trid, peer, port);
            try e2.add(stun.Attr.username, c.username());
            try e2.add(stun.Attr.realm, c.realm());
            try e2.add(stun.Attr.nonce, c.nonce());
            try e2.addIntegrity(&c.key);
            try e2.addFingerprint();
            cur_req = e2.bytes();
            continue;
        }
        return Error.TurnError;
    }
    if (!c.hasPermission(peer) and c.n_permissions < max_permissions) {
        c.permissions[c.n_permissions] = peer;
        c.n_permissions += 1;
    }
}

/// Bind a channel to a peer (installs the permission first, like pion's
/// UDPConn.WriteTo path). Returns the channel number.
pub fn channelBind(c: *Client, peer: IpAddress) Error!u16 {
    if (c.channelFor(peer)) |existing| return existing;
    try createPermission(c, peer);
    if (c.next_channel > max_channel) return Error.BadChannel;
    const number = c.next_channel;
    c.next_channel += 1;

    var req_buf: [1024]u8 = undefined;
    const trid = stun.randomTrid();
    var enc = try stun.Encoder.init(&req_buf, .{ .method = .channel_bind, .class = .request }, trid);
    try encodeChannelNumber(&enc, number);
    const port: u16 = switch (peer) {
        .ip4 => |a| a.port,
        .ip6 => |a| a.port,
    };
    try stun.XorAddr.encode(&enc, stun.Attr.xor_peer_address, trid, peer, port);
    try enc.add(stun.Attr.username, c.username());
    try enc.add(stun.Attr.realm, c.realm());
    try enc.add(stun.Attr.nonce, c.nonce());
    try enc.addIntegrity(&c.key);
    try enc.addFingerprint();
    var resp_buf: [1024]u8 = undefined;
    const n = try c.transact(enc.bytes(), trid, &resp_buf);
    const d = try stun.decode(resp_buf[0..n]);
    if (d.msg_type.class == .err) {
        if (try c.authFromError(&d)) {
            // One retry with fresh credentials.
            var req2_buf: [1024]u8 = undefined;
            const trid2 = stun.randomTrid();
            var e2 = try stun.Encoder.init(&req2_buf, .{ .method = .channel_bind, .class = .request }, trid2);
            try encodeChannelNumber(&e2, number);
            try stun.XorAddr.encode(&e2, stun.Attr.xor_peer_address, trid2, peer, port);
            try e2.add(stun.Attr.username, c.username());
            try e2.add(stun.Attr.realm, c.realm());
            try e2.add(stun.Attr.nonce, c.nonce());
            try e2.addIntegrity(&c.key);
            try e2.addFingerprint();
            const n2 = try c.transact(e2.bytes(), trid2, &resp_buf);
            const d2 = try stun.decode(resp_buf[0..n2]);
            if (d2.msg_type.class == .err) return Error.TurnError;
        } else {
            return Error.TurnError;
        }
    }
    c.channels[c.n_channels] = .{ .number = number, .peer = peer };
    c.n_channels += 1;
    return number;
}

/// Send through the relay: ChannelData when bound, Send indication otherwise
/// (installing the permission on demand like pion's UDPConn.WriteTo).
pub fn sendTo(c: *Client, peer: IpAddress, data: []const u8) Error!void {
    if (!c.hasPermission(peer)) try createPermission(c, peer);
    if (c.channelFor(peer)) |number| {
        var buf: [2048]u8 = undefined;
        const n = try encodeChannelData(&buf, number, data);
        try ice.sendTo(c.fd, c.server, buf[0..n]);
        return;
    }
    // Send indication (no integrity; trid only feeds the XOR address).
    var buf: [2048]u8 = undefined;
    const trid = stun.randomTrid();
    var enc = try stun.Encoder.init(
        &buf,
        .{ .method = .send, .class = .indication },
        trid,
    );
    const port: u16 = switch (peer) {
        .ip4 => |a| a.port,
        .ip6 => |a| a.port,
    };
    try stun.XorAddr.encode(&enc, stun.Attr.xor_peer_address, trid, peer, port);
    try enc.add(stun.Attr.data, data);
    try ice.sendTo(c.fd, c.server, enc.bytes());
}

/// Receive one relayed datagram (Data indication or ChannelData), skipping
/// stray STUN responses. Blocks up to timeout_ms.
pub fn recvFrom(c: *Client, buf: []u8, timeout_ms: i32) Error!struct { len: usize, from: IpAddress } {
    const deadline = nowMs() + timeout_ms;
    var rbuf: [2048]u8 = undefined;
    while (true) {
        const left = deadline - nowMs();
        if (left <= 0) return Error.Timeout;
        var pfd = [_]linux.pollfd{.{ .fd = c.fd, .events = linux.POLL.IN }};
        const prc = linux.poll(&pfd, 1, @intCast(left));
        if (failed(prc)) return Error.RecvFailed;
        if (prc == 0) return Error.Timeout;
        const n = linux.recvfrom(c.fd, &rbuf, rbuf.len, 0, null, null);
        if (failed(n) or n == 0) return Error.RecvFailed;
        const pkt = rbuf[0..n];
        if (isChannelData(pkt)) {
            const cd = try decodeChannelData(pkt);
            const from = c.peerForChannel(cd.number) orelse continue;
            if (cd.data.len > buf.len) return Error.NoSpace;
            @memcpy(buf[0..cd.data.len], cd.data);
            return .{ .len = cd.data.len, .from = from };
        }
        if (!stun.isMessage(pkt)) continue;
        const d = stun.decode(pkt) catch continue;
        // Data indication: XOR-PEER-ADDRESS + DATA.
        if (d.msg_type.method == .data and d.msg_type.class == .indication) {
            const x = stun.XorAddr.decode(&d, stun.Attr.xor_peer_address, d.trid) catch continue;
            const data = d.get(stun.Attr.data) catch continue;
            if (data.len > buf.len) return Error.NoSpace;
            @memcpy(buf[0..data.len], data);
            const from: IpAddress = switch (x.ip) {
                .ip4 => |v| stun.ip4(v.bytes, x.port),
                .ip6 => |v| stun.ip6(v.bytes, x.port),
            };
            return .{ .len = data.len, .from = from };
        }
        // Stray transaction response: ignore.
    }
}
