// Port of NetBird PCP usage (v0.79.0), BSD-3-Clause for NetBird files.
// Reference: upstream/netbird/vendor/github.com/netbirdio/go-nat/pcp/
// protocol.go (wire layout), client.go (nonce cache, retries, epoch tracking,
// external-address dance). Single-threaded: no locks, one mapping at a time.
// NOTE: go-nat's MAP *response* mirrors the *request* layout (nonce at
// [24:36], proto [36], ports [40:44], IP [44:60]); this port reproduces that
// dialect byte-for-byte rather than RFC 6887 §11.2.

const std = @import("std");
const linux = std.os.linux;

pub const port: u16 = 5351;
pub const version: u8 = 2;
pub const op_announce: u8 = 0;
pub const op_map: u8 = 1;
pub const op_reply: u8 = 0x80;
pub const proto_tcp: u8 = 6;
pub const proto_udp: u8 = 17;
pub const proto_any: u8 = 0;
pub const default_lifetime_s: u32 = 7200;
pub const default_timeout_ms: i32 = 3000;
pub const default_retries: u8 = 4;
pub const initial_retry_ms: i32 = 3000;
pub const max_retry_ms: i32 = 1024 * 1000;

pub const Error = error{
    SocketFailed,
    SendFailed,
    RecvFailed,
    Timeout,
    BadResponse,
    BadVersion,
    MissingReply,
    NonceMismatch,
    ProtocolMismatch,
    PortMismatch,
    PcpError,
    NoGateway,
    NoLocalIP,
    NoSpace,
    TooManyNonces,
};

pub const Nonce = [12]u8;

/// Port of buildAnnounceRequest. client_ip16 is the 16-byte mapped address.
pub fn encodeAnnounceRequest(buf: *[24]u8, client_ip16: [16]u8) []u8 {
    @memset(buf, 0);
    buf[0] = version;
    buf[1] = op_announce;
    @memcpy(buf[8..24], &client_ip16);
    return buf;
}

/// Port of buildMapRequest (no options, like go-nat).
pub fn encodeMapRequest(
    buf: *[60]u8,
    client_ip16: [16]u8,
    nonce: Nonce,
    proto: u8,
    internal: u16,
    external_want: u16,
    external_ip16: [16]u8,
    lifetime_s: u32,
) []u8 {
    @memset(buf, 0);
    buf[0] = version;
    buf[1] = op_map;
    std.mem.writeInt(u32, buf[4..8], lifetime_s, .big);
    @memcpy(buf[8..24], &client_ip16);
    @memcpy(buf[24..36], &nonce);
    buf[36] = proto;
    std.mem.writeInt(u16, buf[40..42], internal, .big);
    std.mem.writeInt(u16, buf[42..44], external_want, .big);
    @memcpy(buf[44..60], &external_ip16);
    return buf;
}

pub fn mapV4(ip4: [4]u8) [16]u8 {
    var out: [16]u8 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0 };
    @memcpy(out[12..16], &ip4);
    return out;
}

pub fn isMappedV4(ip16: [16]u8) bool {
    return std.mem.eql(u8, ip16[0..12], &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff });
}

pub const MapResponse = struct {
    result: u8,
    lifetime_s: u32,
    epoch: u32,
    nonce: Nonce,
    proto: u8,
    internal_port: u16,
    external_port: u16,
    external_ip16: [16]u8,
};

/// Port of parseResponse (header part).
pub fn decodeHeader(data: []const u8) Error!struct { result: u8, lifetime_s: u32, epoch: u32 } {
    if (data.len < 24) return Error.BadResponse;
    if (data[0] != version) return Error.BadVersion;
    if (data[1] & op_reply == 0) return Error.MissingReply;
    return .{
        .result = data[3],
        .lifetime_s = std.mem.readInt(u32, data[4..8], .big),
        .epoch = std.mem.readInt(u32, data[8..12], .big),
    };
}

/// Port of parseMapResponse in go-nat's response dialect.
pub fn decodeMapResponse(data: []const u8) Error!MapResponse {
    if (data.len < 60) return Error.BadResponse;
    const h = try decodeHeader(data);
    return .{
        .result = h.result,
        .lifetime_s = h.lifetime_s,
        .epoch = h.epoch,
        .nonce = data[24..36].*,
        .proto = data[36],
        .internal_port = std.mem.readInt(u16, data[40..42], .big),
        .external_port = std.mem.readInt(u16, data[42..44], .big),
        .external_ip16 = data[44..60].*,
    };
}

pub fn resultString(code: u8) []const u8 {
    return switch (code) {
        0 => "SUCCESS",
        1 => "UNSUPP_VERSION",
        2 => "NOT_AUTHORIZED",
        3 => "MALFORMED_REQUEST",
        4 => "UNSUPP_OPCODE",
        5 => "UNSUPP_OPTION",
        6 => "MALFORMED_OPTION",
        7 => "NETWORK_FAILURE",
        8 => "NO_RESOURCES",
        9 => "UNSUPP_PROTOCOL",
        10 => "USER_EX_QUOTA",
        11 => "CANNOT_PROVIDE_EXTERNAL",
        12 => "ADDRESS_MISMATCH",
        13 => "EXCESSIVE_REMOTE_PEERS",
        else => "UNKNOWN",
    };
}

fn failed(rc: usize) bool {
    return rc > 0xfffffffffffff000;
}

fn nowMs() i64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return ts.sec * 1000 + @divTrunc(ts.nsec, 1_000_000);
}

fn randomBytes(buf: []u8) void {
    var off: usize = 0;
    while (off < buf.len) {
        const n = linux.getrandom(buf[off..].ptr, buf.len - off, 0);
        if (n > 0xfffffffffffff000 or n == 0) break;
        off += n;
    }
    const S = struct {
        var counter: u64 = 0x9e3779b97f4a7c15;
    };
    for (buf[off..]) |*b| {
        S.counter +%= 0x9e3779b97f4a7c15;
        var x = S.counter;
        x ^= x >> 29;
        x *%= 0xbf58476d1ce4e5b9;
        b.* = @truncate(x);
    }
}

pub const max_nonces = 16;

/// Port of pcp.Client (single-threaded subset).
pub const Client = struct {
    gateway_is_v6: bool = false,
    gateway_scope_id: u32 = 0,
    gateway4: [4]u8 = .{ 0, 0, 0, 0 },
    gateway6: [16]u8 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    has_gateway: bool = false,
    local_ip16: [16]u8 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    has_local: bool = false,
    timeout_ms: i32 = default_timeout_ms,
    retries: u8 = default_retries,
    last_epoch: u32 = 0,
    epoch_time_ms: i64 = 0,
    has_epoch: bool = false,
    epoch_state_lost: bool = false,
    external_ip16: [16]u8 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    has_external: bool = false,
    nonce_keys: [max_nonces]struct { proto: u8, port: u16 } = undefined,
    nonce_vals: [max_nonces]Nonce = undefined,
    n_nonces: usize = 0,

    pub fn setGateway4(c: *Client, ip: [4]u8) void {
        c.gateway_is_v6 = false;
        c.gateway_scope_id = 0;
        c.gateway4 = ip;
        c.has_gateway = true;
    }

    pub fn setGateway6(c: *Client, ip: [16]u8) void {
        c.setGateway6Scoped(ip, 0);
    }

    /// Preserve the interface index for link-local IPv6 gateways.
    pub fn setGateway6Scoped(c: *Client, ip: [16]u8, scope_id: u32) void {
        c.gateway_is_v6 = true;
        c.gateway6 = ip;
        c.gateway_scope_id = scope_id;
        c.has_gateway = true;
    }

    pub fn gatewaySockaddr6(c: *const Client) linux.sockaddr.in6 {
        return .{
            .family = linux.AF.INET6,
            .port = std.mem.nativeToBig(u16, port),
            .flowinfo = 0,
            .addr = c.gateway6,
            .scope_id = c.gateway_scope_id,
        };
    }

    pub fn gatewaySource6Matches(c: *const Client, sa: *const linux.sockaddr.in6) bool {
        return sa.family == linux.AF.INET6 and
            sa.scope_id == c.gateway_scope_id and
            std.mem.eql(u8, &sa.addr, &c.gateway6);
    }

    pub fn setLocal4(c: *Client, ip: [4]u8) void {
        c.local_ip16 = mapV4(ip);
        c.has_local = true;
    }

    pub fn setLocal6(c: *Client, ip: [16]u8) void {
        c.local_ip16 = ip;
        c.has_local = true;
    }

    fn findNonce(c: *Client, proto: u8, port_no: u16) ?*Nonce {
        for (c.nonce_keys[0..c.n_nonces], 0..) |k, i| {
            if (k.proto == proto and k.port == port_no) return &c.nonce_vals[i];
        }
        return null;
    }

    fn storeNonce(c: *Client, proto: u8, port_no: u16, nonce: Nonce) Error!void {
        if (c.findNonce(proto, port_no)) |slot| {
            slot.* = nonce;
            return;
        }
        if (c.n_nonces >= max_nonces) return Error.TooManyNonces;
        c.nonce_keys[c.n_nonces] = .{ .proto = proto, .port = port_no };
        c.nonce_vals[c.n_nonces] = nonce;
        c.n_nonces += 1;
    }

    fn dropNonce(c: *Client, proto: u8, port_no: u16) void {
        for (c.nonce_keys[0..c.n_nonces], 0..) |k, i| {
            if (k.proto == proto and k.port == port_no) {
                c.nonce_keys[i] = c.nonce_keys[c.n_nonces - 1];
                c.nonce_vals[i] = c.nonce_vals[c.n_nonces - 1];
                c.n_nonces -= 1;
                return;
            }
        }
    }

    /// Port of updateEpochLocked (RFC 6887 §8.5 state-loss detection).
    fn updateEpoch(c: *Client, new_epoch: u32) void {
        const now = nowMs();
        if (c.has_epoch and c.last_epoch > 0) {
            const client_delta: u32 = @intCast(@max(now - c.epoch_time_ms, 0) / 1000);
            const server_delta: u32 = new_epoch -% c.last_epoch;
            if (client_delta + 2 < server_delta - server_delta / 16 or
                server_delta + 2 < client_delta - client_delta / 16)
            {
                c.epoch_state_lost = true;
            }
        }
        c.last_epoch = new_epoch;
        c.epoch_time_ms = now;
        c.has_epoch = true;
    }

    /// Port of EpochStateLost: report and clear.
    pub fn epochStateLost(c: *Client) bool {
        const lost = c.epoch_state_lost;
        c.epoch_state_lost = false;
        return lost;
    }

    fn sendOnce(c: *Client, req: []const u8, resp_buf: []u8) Error!usize {
        if (!c.has_gateway) return Error.NoGateway;
        const domain: u32 = if (c.gateway_is_v6) linux.AF.INET6 else linux.AF.INET;
        // Fresh socket per attempt, like the Go sendOnce.
        const s = linux.socket(domain, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
        if (failed(s)) return Error.SocketFailed;
        const fd: linux.fd_t = @intCast(s);
        defer _ = linux.close(fd);
        var sab_buf: [@sizeOf(linux.sockaddr.in6)]u8 align(@alignOf(linux.sockaddr.in6)) = undefined;
        var sa_len: linux.socklen_t = undefined;
        if (c.gateway_is_v6) {
            const sa: *linux.sockaddr.in6 = @ptrCast(@alignCast(&sab_buf));
            sa.* = c.gatewaySockaddr6();
            sa_len = @sizeOf(linux.sockaddr.in6);
        } else {
            const sa: *linux.sockaddr.in = @ptrCast(@alignCast(&sab_buf));
            sa.family = linux.AF.INET;
            sa.port = std.mem.nativeToBig(u16, port);
            sa.addr = @bitCast(c.gateway4);
            sa_len = @sizeOf(linux.sockaddr.in);
        }
        const dest: *const linux.sockaddr = @ptrCast(@alignCast(&sab_buf));
        const sent = linux.sendto(fd, req.ptr, req.len, 0, dest, sa_len);
        if (failed(sent) or sent != req.len) return Error.SendFailed;
        var pfd = [_]linux.pollfd{.{ .fd = fd, .events = linux.POLL.IN }};
        const prc = linux.poll(&pfd, 1, c.timeout_ms);
        if (failed(prc)) return Error.RecvFailed;
        if (prc == 0) return Error.Timeout;
        var from_buf: [@sizeOf(linux.sockaddr.in6)]u8 align(@alignOf(linux.sockaddr.in6)) = undefined;
        var from_len: linux.socklen_t = @sizeOf(linux.sockaddr.in6);
        const n = linux.recvfrom(fd, resp_buf.ptr, resp_buf.len, 0, @ptrCast(@alignCast(&from_buf)), &from_len);
        if (failed(n) or n == 0) return Error.RecvFailed;
        // RFC 6887 §8.3: the response must come from the gateway.
        const fam: u16 = @bitCast(from_buf[0..2].*);
        if (!c.gateway_is_v6) {
            if (fam != linux.AF.INET or from_len < @sizeOf(linux.sockaddr.in)) return Error.RecvFailed;
            const sa: *const linux.sockaddr.in = @ptrCast(@alignCast(&from_buf));
            const from_ip: [4]u8 = @bitCast(sa.addr);
            if (!std.mem.eql(u8, &from_ip, &c.gateway4)) return Error.RecvFailed;
        } else {
            if (fam != linux.AF.INET6 or from_len < @sizeOf(linux.sockaddr.in6)) return Error.RecvFailed;
            const sa: *const linux.sockaddr.in6 = @ptrCast(@alignCast(&from_buf));
            if (!c.gatewaySource6Matches(sa)) return Error.RecvFailed;
        }
        return n;
    }

    /// Port of sendRequest: RFC 6887 §8.1.1 retries with ±10% jitter.
    fn sendRequest(c: *Client, req: []const u8, resp_buf: []u8) Error!usize {
        var delay_ms: i64 = initial_retry_ms;
        var attempt: u8 = 0;
        var last_err: Error = Error.Timeout;
        while (attempt < c.retries) : (attempt += 1) {
            if (c.sendOnce(req, resp_buf)) |n| {
                return n;
            } else |err| {
                last_err = err;
                if (attempt + 1 >= c.retries) break;
                // Jitter: delay * (1 + RAND), RAND in [-0.1, +0.1].
                var jb: [1]u8 = undefined;
                randomBytes(&jb);
                const num: i64 = 900 + @divTrunc(@as(i64, jb[0]) * 200, 255);
                const slept = @divTrunc(delay_ms * num, 1000);
                var ts = linux.timespec{
                    .sec = @divTrunc(slept, 1000),
                    .nsec = @mod(slept, 1000) * 1_000_000,
                };
                _ = linux.nanosleep(&ts, null);
                delay_ms = @min(delay_ms * 2, max_retry_ms);
                continue;
            }
        }
        return last_err;
    }

    /// Port of Client.Announce.
    pub fn announce(c: *Client) Error!u32 {
        if (!c.has_local) return Error.NoLocalIP;
        var req: [24]u8 = undefined;
        var resp: [128]u8 = undefined;
        const n = try c.sendRequest(encodeAnnounceRequest(&req, c.local_ip16), &resp);
        const h = try decodeHeader(resp[0..n]);
        if (h.result != 0) return Error.PcpError;
        c.updateEpoch(h.epoch);
        return h.epoch;
    }

    /// Port of addPortMappingWithHint. lifetime_s 0 deletes (reusing the
    /// stored nonce, like the Go client).
    pub fn mapPort(
        c: *Client,
        proto: u8,
        internal: u16,
        external_want: u16,
        external_ip16: ?[16]u8,
        lifetime_s: u32,
    ) Error!MapResponse {
        if (internal == 0) return Error.BadResponse;
        if (!c.has_local) return Error.NoLocalIP;
        var fresh: Nonce = undefined;
        randomBytes(&fresh);
        var nonce = fresh;
        if (c.findNonce(proto, internal)) |slot| nonce = slot.*;
        if (lifetime_s > 0) try c.storeNonce(proto, internal, nonce);

        const want_ip = external_ip16 orelse blk: {
            // RFC 6887 §11.1: no preference is ::ffff:0.0.0.0 for IPv4.
            if (isMappedV4(c.local_ip16)) break :blk mapV4(.{ 0, 0, 0, 0 });
            break :blk [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        };
        var req: [60]u8 = undefined;
        var resp: [128]u8 = undefined;
        const n = try c.sendRequest(
            encodeMapRequest(&req, c.local_ip16, nonce, proto, internal, external_want, want_ip, lifetime_s),
            &resp,
        );
        const m = try decodeMapResponse(resp[0..n]);
        if (!std.mem.eql(u8, &m.nonce, &nonce)) return Error.NonceMismatch;
        if (m.proto != proto) return Error.ProtocolMismatch;
        if (m.internal_port != internal) return Error.PortMismatch;
        if (m.result != 0) return Error.PcpError;
        c.updateEpoch(m.epoch);
        c.cacheExternalIP(m.external_ip16);
        if (lifetime_s == 0) c.dropNonce(proto, internal);
        return m;
    }

    /// Port of v0.80 client.go cacheExternalIPLocked. Every 16-byte wire
    /// address is valid, but unspecified IPv6 and unmapped IPv4 are not cached.
    fn cacheExternalIP(c: *Client, ip: [16]u8) void {
        const address = if (isMappedV4(ip)) ip[12..16] else ip[0..16];
        for (address) |byte| {
            if (byte != 0) {
                c.external_ip16 = ip;
                c.has_external = true;
                return;
            }
        }
    }

    /// Port of AddPortMapping (suggested external port = internal).
    /// The Go positive-duration-rounds-to-zero-then-default rule cannot
    /// trigger here: the input is already whole seconds.
    pub fn addPortMapping(c: *Client, proto: u8, internal: u16, lifetime_s: u32) Error!MapResponse {
        return c.mapPort(proto, internal, internal, null, lifetime_s);
    }

    /// Port of DeletePortMapping.
    pub fn deletePortMapping(c: *Client, proto: u8, internal: u16) Error!void {
        _ = try c.mapPort(proto, internal, 0, null, 0);
    }

    /// Port of GetExternalAddress: cached value or a 1-second temp mapping.
    pub fn externalAddress(c: *Client) Error![16]u8 {
        if (c.has_external) return c.external_ip16;
        var pb: [2]u8 = undefined;
        randomBytes(&pb);
        const eport: u16 = 49152 + @as(u16, std.mem.readInt(u16, &pb, .big)) % (65535 - 49152);
        const m = try c.addPortMapping(proto_udp, eport, 1);
        c.deletePortMapping(proto_udp, eport) catch {};
        // Upstream client.go:297 returns the raw temporary MAP address even
        // when unspecified, without turning it into a learned cache entry.
        return m.external_ip16;
    }
};
