// Port of netbird vendor/github.com/pion/stun/v3 (v0.79.0 vendored v3.1.0), MIT.
// Reference: upstream/netbird/vendor/github.com/pion/stun/v3/message.go,
// xoraddr.go, integrity.go, fingerprint.go, errorcode.go, textattrs.go,
// client.go (RTO schedule only).
// Scope: message codec over caller buffers, the attr codecs NetBird/ICE/TURN
// use (USERNAME, MESSAGE-INTEGRITY short/long-term, FINGERPRINT,
// XOR-MAPPED-ADDRESS v4/v6, ERROR-CODE, REALM, NONCE, SOFTWARE, PRIORITY,
// USE-CANDIDATE, ICE-CONTROLLING/CONTROLLED), and a UDP binding client with
// pion's retransmit schedule (300ms linear, 7 attempts). No TCP/TLS/DTLS.

const std = @import("std");
const linux = std.os.linux;

pub const magic_cookie: u32 = 0x2112A442;
pub const header_len = 20;
pub const trid_len = 12;
pub const attr_header_len = 4;
pub const integrity_len = 20;
pub const fingerprint_len = 4;
pub const max_attrs = 32;
pub const max_msg_len = 2048;

pub const default_rto_ms: i32 = 300;
pub const default_attempts: u8 = 7;

pub const Error = error{
    Truncated,
    BadCookie,
    BadLength,
    TooManyAttrs,
    NoSpace,
    AttrNotFound,
    BadAttrLen,
    BadFamily,
    BadIpLen,
    IntegrityMismatch,
    FingerprintMismatch,
    FingerprintNotLast,
    Timeout,
    SocketFailed,
    SendFailed,
    RecvFailed,
    StaleResponse,
    ErrorResponse,
};

pub const Trid = [trid_len]u8;

/// STUN method (12-bit). RFC 5389 §6 + TURN methods RFC 5766 §15.
pub const Method = enum(u16) {
    binding = 0x001,
    allocate = 0x003,
    refresh = 0x004,
    send = 0x006,
    data = 0x007,
    create_permission = 0x008,
    channel_bind = 0x009,
    connect = 0x00a,
    connection_bind = 0x00b,
    connection_attempt = 0x00c,
    _,

    pub fn fromInt(v: u16) Method {
        return @enumFromInt(v);
    }
};

/// STUN class (2-bit).
pub const Class = enum(u2) {
    request = 0x00,
    indication = 0x01,
    success = 0x02,
    err = 0x03,
};

pub const MessageType = struct {
    method: Method,
    class: Class,

    pub const binding_request: MessageType = .{ .method = .binding, .class = .request };
    pub const binding_success: MessageType = .{ .method = .binding, .class = .success };
    pub const binding_error: MessageType = .{ .method = .binding, .class = .err };

    const method_a_bits: u16 = 0xf;
    const method_b_bits: u16 = 0x70;
    const method_d_bits: u16 = 0xf80;
    const method_b_shift = 1;
    const method_d_shift = 2;
    const c0_bit: u16 = 0x1;
    const c1_bit: u16 = 0x2;
    const class_c0_shift = 4;
    const class_c1_shift = 7;

    /// Port of (MessageType).Value: interleave method bits with class bits.
    pub fn encode(t: MessageType) u16 {
        const msg: u16 = @intFromEnum(t.method);
        const a = msg & method_a_bits;
        const b = msg & method_b_bits;
        const d = msg & method_d_bits;
        var v = a + (b << method_b_shift) + (d << method_d_shift);
        const c: u16 = @intFromEnum(t.class);
        const c0 = (c & c0_bit) << class_c0_shift;
        const c1 = (c & c1_bit) << class_c1_shift;
        v += c0 + c1;
        return v;
    }

    /// Port of (*MessageType).ReadValue.
    pub fn decode(v: u16) MessageType {
        const c0 = (v >> class_c0_shift) & c0_bit;
        const c1 = (v >> class_c1_shift) & c1_bit;
        const a = v & method_a_bits;
        const b = (v >> method_b_shift) & method_b_bits;
        const d = (v >> method_d_shift) & method_d_bits;
        return .{
            .method = @enumFromInt(a + b + d),
            .class = @enumFromInt(@as(u2, @truncate(c0 + c1))),
        };
    }
};

/// Attribute types used by NetBird's STUN/ICE/TURN subset.
pub const Attr = struct {
    pub const mapped_address: u16 = 0x0001;
    pub const username: u16 = 0x0006;
    pub const message_integrity: u16 = 0x0008;
    pub const error_code: u16 = 0x0009;
    pub const unknown_attributes: u16 = 0x000a;
    pub const channel_number: u16 = 0x000c;
    pub const lifetime: u16 = 0x000d;
    pub const xor_peer_address: u16 = 0x0012;
    pub const data: u16 = 0x0013;
    pub const realm: u16 = 0x0014;
    pub const nonce: u16 = 0x0015;
    pub const xor_relayed_address: u16 = 0x0016;
    pub const even_port: u16 = 0x0018;
    pub const requested_transport: u16 = 0x0019;
    pub const dont_fragment: u16 = 0x001a;
    pub const xor_mapped_address: u16 = 0x0020;
    pub const reservation_token: u16 = 0x0022;
    pub const priority: u16 = 0x0024;
    pub const use_candidate: u16 = 0x0025;
    pub const software: u16 = 0x8022;
    pub const alternate_server: u16 = 0x8023;
    pub const fingerprint: u16 = 0x8028;
    pub const ice_controlled: u16 = 0x8029;
    pub const ice_controlling: u16 = 0x802a;
    /// draft-ietf-behave-rfc3489bis-02 MS-TURN value, mapped to
    /// xor_mapped_address on decode like pion's compatAttrType.
    pub const xor_mapped_compat: u16 = 0x8020;
};

pub fn paddedLen(l: usize) usize {
    return (l + 3) & ~@as(usize, 3);
}

/// Port of stun.IsMessage: cheap multiplexing check, not a validity proof.
pub fn isMessage(b: []const u8) bool {
    if (b.len < header_len) return false;
    // ChannelData (TURN) starts with 0x40..0x7f; STUN types start with 0x00/0x01.
    if (b[0] >= 0x40) return false;
    return std.mem.readInt(u32, b[4..8], .big) == magic_cookie;
}

/// Port of stun.IsChannelData shape check is in turn.zig; this is the STUN half.

/// Encoder builds a message into a caller-owned buffer. Port of Message with
/// WriteHeader/Add semantics (attributes appended with zero padding).
pub const Encoder = struct {
    buf: []u8,
    len: usize = 0,

    pub fn init(buf: []u8, msg_type: MessageType, trid: Trid) Error!Encoder {
        if (buf.len < header_len) return Error.NoSpace;
        var e = Encoder{ .buf = buf };
        std.mem.writeInt(u16, e.buf[0..2], msg_type.encode(), .big);
        std.mem.writeInt(u16, e.buf[2..4], 0, .big);
        std.mem.writeInt(u32, e.buf[4..8], magic_cookie, .big);
        @memcpy(e.buf[8..20], &trid);
        e.len = header_len;
        return e;
    }

    pub fn bytes(e: *const Encoder) []u8 {
        return e.buf[0..e.len];
    }

    fn bodyLen(e: *const Encoder) u16 {
        return @intCast(e.len - header_len);
    }

    fn writeLen(e: *Encoder, body: u16) void {
        std.mem.writeInt(u16, e.buf[2..4], body, .big);
    }

    /// Port of (*Message).Add: append TLV with zero padding.
    pub fn add(e: *Encoder, attr: u16, val: []const u8) Error!void {
        if (val.len > 0xffff) return Error.BadAttrLen;
        const need = attr_header_len + paddedLen(val.len);
        if (e.len + need > e.buf.len) return Error.NoSpace;
        std.mem.writeInt(u16, e.buf[e.len..][0..2], attr, .big);
        std.mem.writeInt(u16, e.buf[e.len..][2..4], @intCast(val.len), .big);
        @memcpy(e.buf[e.len + attr_header_len ..][0..val.len], val);
        const pad = paddedLen(val.len) - val.len;
        @memset(e.buf[e.len + attr_header_len + val.len ..][0..pad], 0);
        e.len += need;
        e.writeLen(e.bodyLen());
    }

    /// Port of MessageIntegrity.AddTo: HMAC-SHA1 over the message with the
    /// length header adjusted to include this attribute.
    pub fn addIntegrity(e: *Encoder, key: []const u8) Error!void {
        const with_attr: u16 = e.bodyLen() + attr_header_len + integrity_len;
        e.writeLen(with_attr);
        var mac: [integrity_len]u8 = undefined;
        std.crypto.auth.hmac.HmacSha1.create(&mac, e.bytes(), key);
        e.writeLen(e.bodyLen());
        try e.add(Attr.message_integrity, &mac);
    }

    /// Port of FingerprintAttr.AddTo: CRC-32 IEEE XOR 0x5354554e.
    pub fn addFingerprint(e: *Encoder) Error!void {
        const with_attr: u16 = e.bodyLen() + attr_header_len + fingerprint_len;
        e.writeLen(with_attr);
        const Crc = std.hash.crc.@"CRC-32/ISO-HDLC";
        const val = Crc.hash(e.bytes()) ^ 0x5354554e;
        e.writeLen(e.bodyLen());
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, val, .big);
        try e.add(Attr.fingerprint, &b);
    }
};

pub const RawAttr = struct {
    typ: u16,
    val: []const u8,
};

/// Decoded message: views into the input buffer, valid while it is alive.
/// Port of (*Message).Decode.
pub const Decoded = struct {
    msg_type: MessageType,
    trid: Trid,
    attrs: [max_attrs]RawAttr = undefined,
    count: usize = 0,

    pub fn get(d: *const Decoded, attr: u16) Error![]const u8 {
        for (d.attrs[0..d.count]) |a| {
            if (a.typ == attr) return a.val;
        }
        return Error.AttrNotFound;
    }

    pub fn contains(d: *const Decoded, attr: u16) bool {
        for (d.attrs[0..d.count]) |a| {
            if (a.typ == attr) return true;
        }
        return false;
    }
};

pub fn decode(raw: []const u8) Error!Decoded {
    if (raw.len < header_len) return Error.Truncated;
    const cookie = std.mem.readInt(u32, raw[4..8], .big);
    if (cookie != magic_cookie) return Error.BadCookie;
    const size: usize = std.mem.readInt(u16, raw[2..4], .big);
    if (raw.len < header_len + size) return Error.Truncated;
    var d = Decoded{
        .msg_type = MessageType.decode(std.mem.readInt(u16, raw[0..2], .big)),
        .trid = raw[8..20].*,
    };
    var off: usize = 0;
    var b = raw[header_len .. header_len + size];
    while (off < size) {
        if (b.len < attr_header_len) return Error.Truncated;
        var typ = std.mem.readInt(u16, b[0..2], .big);
        if (typ == Attr.xor_mapped_compat) typ = Attr.xor_mapped_address;
        const alen: usize = std.mem.readInt(u16, b[2..4], .big);
        const padded = paddedLen(alen);
        b = b[attr_header_len..];
        off += attr_header_len;
        if (b.len < padded) return Error.Truncated;
        if (d.count >= max_attrs) return Error.TooManyAttrs;
        d.attrs[d.count] = .{ .typ = typ, .val = b[0..alen] };
        d.count += 1;
        off += padded;
        b = b[padded..];
    }
    return d;
}

pub const IpAddress = std.Io.net.IpAddress;

pub fn ip4(bytes: [4]u8, port: u16) IpAddress {
    return .{ .ip4 = .{ .bytes = bytes, .port = port } };
}

pub fn ip6(bytes: [16]u8, port: u16) IpAddress {
    return .{ .ip6 = .{ .port = port, .bytes = bytes } };
}

/// XOR-MAPPED-ADDRESS value. Port of stun.XORMappedAddress (AddToAs/GetFromAs).
pub const XorAddr = struct {
    ip: IpAddress,
    port: u16,

    pub fn encode(e: *Encoder, attr: u16, trid: Trid, addr: IpAddress, port: u16) Error!void {
        var val: [20]u8 = undefined;
        const xor_port: u16 = port ^ @as(u16, @truncate(magic_cookie >> 16));
        const cookie_bytes = std.mem.toBytes(std.mem.nativeToBig(u32, magic_cookie));
        switch (addr) {
            .ip4 => |a| {
                std.mem.writeInt(u16, val[0..2], 0x0001, .big);
                std.mem.writeInt(u16, val[2..4], xor_port, .big);
                for (0..4) |i| val[4 + i] = a.bytes[i] ^ cookie_bytes[i];
                try e.add(attr, val[0..8]);
            },
            .ip6 => |a| {
                std.mem.writeInt(u16, val[0..2], 0x0002, .big);
                std.mem.writeInt(u16, val[2..4], xor_port, .big);
                for (0..4) |i| val[4 + i] = a.bytes[i] ^ cookie_bytes[i];
                for (0..12) |i| val[8 + i] = a.bytes[4 + i] ^ trid[i];
                try e.add(attr, val[0..20]);
            },
        }
    }

    pub fn decode(d: *const Decoded, attr: u16, trid: Trid) Error!XorAddr {
        const val = try d.get(attr);
        if (val.len < 4) return Error.Truncated;
        const family = std.mem.readInt(u16, val[0..2], .big);
        const port: u16 = std.mem.readInt(u16, val[2..4], .big) ^ @as(u16, @truncate(magic_cookie >> 16));
        const cookie_bytes = std.mem.toBytes(std.mem.nativeToBig(u32, magic_cookie));
        switch (family) {
            0x01 => {
                if (val.len < 8) return Error.Truncated;
                var addr_bytes: [4]u8 = undefined;
                for (0..4) |i| addr_bytes[i] = val[4 + i] ^ cookie_bytes[i];
                return .{
                    .ip = ip4(addr_bytes, 0),
                    .port = port,
                };
            },
            0x02 => {
                if (val.len < 20) return Error.Truncated;
                var addr_bytes: [16]u8 = undefined;
                for (0..4) |i| addr_bytes[i] = val[4 + i] ^ cookie_bytes[i];
                for (0..12) |i| addr_bytes[4 + i] = val[8 + i] ^ trid[i];
                return .{
                    .ip = ip6(addr_bytes, 0),
                    .port = port,
                };
            },
            else => return Error.BadFamily,
        }
    }
};

/// ERROR-CODE value. Port of stun.ErrorCodeAttribute.
pub const ErrorCode = struct {
    code: u16,
    reason: []const u8,

    pub const try_alternate: u16 = 300;
    pub const bad_request: u16 = 400;
    pub const unauthorized: u16 = 401;
    pub const forbidden: u16 = 403;
    pub const unknown_attribute: u16 = 420;
    /// Port of stun.CodeUnauthorised alias.
    pub const unauthorised: u16 = 401;
    pub const stale_nonce: u16 = 438;
    pub const role_conflict: u16 = 487;
    pub const server_error: u16 = 500;

    pub fn encode(e: *Encoder, code: u16, reason: []const u8) Error!void {
        var val: [4 + 763]u8 = undefined;
        if (reason.len > 763) return Error.BadAttrLen;
        val[0] = 0;
        val[1] = 0;
        val[2] = @intCast(code / 100);
        val[3] = @intCast(code % 100);
        @memcpy(val[4..][0..reason.len], reason);
        try e.add(Attr.error_code, val[0 .. 4 + reason.len]);
    }

    pub fn decode(d: *const Decoded) Error!ErrorCode {
        const val = try d.get(Attr.error_code);
        if (val.len < 4) return Error.Truncated;
        const code: u16 =
            @as(u16, val[2]) * 100 + @as(u16, val[3]);
        return .{ .code = code, .reason = val[4..] };
    }
};

/// Port of stun.NewLongTermIntegrity: MD5("username:realm:password").
pub fn longTermKey(username: []const u8, realm: []const u8, password: []const u8, out: *[16]u8) void {
    var md5 = std.crypto.hash.Md5.init(.{});
    md5.update(username);
    md5.update(":");
    md5.update(realm);
    md5.update(":");
    md5.update(password);
    md5.final(out);
}

/// Port of MessageIntegrity.Check over the raw bytes plus decoded attrs.
pub fn checkIntegrity(raw: []const u8, d: *const Decoded, key: []const u8) Error!void {
    const want = try d.get(Attr.message_integrity);
    // Prefix ends at the integrity attribute: 20 + padded sizes before it.
    var prefix: usize = header_len;
    var found = false;
    for (d.attrs[0..d.count]) |a| {
        if (a.typ == Attr.message_integrity) {
            found = true;
            break;
        }
        prefix += attr_header_len + paddedLen(a.val.len);
    }
    if (!found) return Error.AttrNotFound;
    // HMAC input is the prefix with the length header adjusted to include
    // the integrity attribute, like pion's Check.
    var tmp: [max_msg_len]u8 = undefined;
    if (prefix > tmp.len) return Error.BadLength;
    @memcpy(tmp[0..prefix], raw[0..prefix]);
    std.mem.writeInt(u16, tmp[2..4], @intCast(prefix - header_len + attr_header_len + integrity_len), .big);
    var mac: [integrity_len]u8 = undefined;
    std.crypto.auth.hmac.HmacSha1.create(&mac, tmp[0..prefix], key);
    if (want.len != integrity_len) return Error.BadAttrLen;
    if (!std.crypto.timing_safe.eql([integrity_len]u8, mac, want[0..integrity_len].*))
        return Error.IntegrityMismatch;
}

/// Port of FingerprintAttr.Check: FINGERPRINT must be the last attribute.
pub fn checkFingerprint(raw: []const u8, d: *const Decoded) Error!void {
    const want = try d.get(Attr.fingerprint);
    if (want.len != fingerprint_len) return Error.BadAttrLen;
    if (d.count == 0 or d.attrs[d.count - 1].typ != Attr.fingerprint)
        return Error.FingerprintNotLast;
    const body: usize = std.mem.readInt(u16, raw[2..4], .big);
    const total = header_len + body;
    if (raw.len < total) return Error.Truncated;
    const attr_start = total - (attr_header_len + fingerprint_len);
    const Crc = std.hash.crc.@"CRC-32/ISO-HDLC";
    const expected = Crc.hash(raw[0..attr_start]) ^ 0x5354554e;
    if (std.mem.readInt(u32, want[0..4], .big) != expected)
        return Error.FingerprintMismatch;
}

pub fn randomTrid() Trid {
    var t: Trid = undefined;
    // getrandom(2) exists since Linux 3.17, safe on the 4.9 target.
    var off: usize = 0;
    while (off < t.len) {
        const n = linux.getrandom(t[off..].ptr, t.len - off, 0);
        if (n > 0xfffffffffffff000 or n == 0) {
            // Fall back to a pid/counter mix; transaction IDs only need uniqueness.
            const S = struct {
                var counter: u64 = 0;
            };
            S.counter +%= 1;
            var x: u64 = @as(u64, @intCast(linux.getpid())) << 32 | S.counter;
            x ^= @as(u64, @intCast(@intFromPtr(&t)));
            x ^= x >> 29;
            x *%= 0xbf58476d1ce4e5b9;
            for (t[off..], 0..) |*b, i| b.* = @truncate((x >> @intCast((i % 8) * 8)) ^ i ^ off);
            return t;
        }
        off += n;
    }
    return t;
}

fn failed(rc: usize) bool {
    return rc > 0xfffffffffffff000;
}

pub const RequestOptions = struct {
    rto_ms: i32 = default_rto_ms,
    attempts: u8 = default_attempts,
    software: ?[]const u8 = null,
};

/// Binding transaction over UDP. Port of the pion client schedule:
/// resend after (attempt+1)*rto, match transaction ID, accept the first
/// success or error response with our ID. Returns the response length in
/// resp_raw; decode it with decode().
pub fn bindingRequest(
    server: IpAddress,
    trid: Trid,
    opts: RequestOptions,
    resp_raw: []u8,
) Error!usize {
    const domain: u32 = switch (server) {
        .ip4 => linux.AF.INET,
        .ip6 => linux.AF.INET6,
    };
    const sock_usize = linux.socket(domain, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    if (failed(sock_usize)) return Error.SocketFailed;
    const sock: linux.fd_t = @intCast(sock_usize);
    defer _ = linux.close(sock);

    var req_buf: [256]u8 = undefined;
    var enc = try Encoder.init(&req_buf, MessageType.binding_request, trid);
    if (opts.software) |sw| try enc.add(Attr.software, sw);
    const req = enc.bytes();

    var sa_buf: [@sizeOf(linux.sockaddr.in6)]u8 align(@alignOf(linux.sockaddr.in6)) = undefined;
    const sa_len: linux.socklen_t = switch (server) {
        .ip4 => |a| blk: {
            const sa: *linux.sockaddr.in = @ptrCast(@alignCast(&sa_buf));
            sa.family = linux.AF.INET;
            sa.port = std.mem.nativeToBig(u16, a.port);
            // sa.addr is network order in memory; bytes already are.
            sa.addr = @bitCast(a.bytes);
            break :blk @sizeOf(linux.sockaddr.in);
        },
        .ip6 => |a| blk: {
            const sa: *linux.sockaddr.in6 = @ptrCast(@alignCast(&sa_buf));
            sa.family = linux.AF.INET6;
            sa.port = std.mem.nativeToBig(u16, a.port);
            sa.flowinfo = 0;
            sa.addr = a.bytes;
            sa.scope_id = 0;
            break :blk @sizeOf(linux.sockaddr.in6);
        },
    };
    const dest: *const linux.sockaddr = @ptrCast(@alignCast(&sa_buf));

    var attempt: u8 = 0;
    while (attempt < opts.attempts) : (attempt += 1) {
        const sent = linux.sendto(sock, req.ptr, req.len, 0, dest, sa_len);
        if (failed(sent) or sent != req.len) return Error.SendFailed;
        // Port of clientTransaction.nextTimeout: (attempt+1)*rto, linear.
        const wait_ms: i32 = @as(i32, attempt + 1) * opts.rto_ms;
        var pfd = [_]linux.pollfd{.{ .fd = sock, .events = linux.POLL.IN }};
        const prc = linux.poll(&pfd, 1, wait_ms);
        if (failed(prc)) return Error.RecvFailed;
        if (prc == 0) continue; // RTO, resend.
        const n = linux.recvfrom(sock, resp_raw.ptr, resp_raw.len, 0, null, null);
        if (failed(n) or n == 0) return Error.RecvFailed;
        const got = resp_raw[0..n];
        if (!isMessage(got)) continue;
        const d = decode(got) catch continue;
        if (!std.mem.eql(u8, &d.trid, &trid)) continue; // not ours.
        if (d.msg_type.method != .binding) continue;
        return n;
    }
    return Error.Timeout;
}
