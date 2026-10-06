// Port of NetBird ICE usage (v0.79.0), BSD-3-Clause for NetBird files, MIT for pion.
// Reference: upstream/netbird/client/internal/peer/ice/agent.go (AgentConfig:
// UDP4+UDP6, host+srflx+relay, creds, timeouts), worker_ice.go (roles:
// isController = LocalKey > Key, nomination flow), and the vendored pion/ice/v4
// fork (candidate priority/foundation, gather.go host/srflx, selection.go
// checks and nomination, agent.go inbound validation incl. 487 role conflict).
// Scope: UDP host + server-reflexive gathering and RFC 8445-lite connectivity
// checks with aggressive nomination. No TCP, no mDNS, no UDPMux, no relay/turn
// allocation (turn.zig), no keepalives after selection.

const std = @import("std");
const linux = std.os.linux;
const stun = @import("stun.zig");

pub const IpAddress = stun.IpAddress;
pub const ip4 = stun.ip4;
pub const ip6 = stun.ip6;

pub const Error = error{
    SocketFailed,
    BindFailed,
    SendFailed,
    RecvFailed,
    NetlinkFailed,
    TooManyAddrs,
    TooManyPairs,
    NoCandidates,
    Timeout,
    NoStunServer,
} || stun.Error;

pub const max_sockets = 16;
pub const max_pairs = 64;

/// Port of ice.CandidateType.
pub const CandidateType = enum {
    host,
    srflx,
    prflx,
    relay,

    pub fn parse(s: []const u8) ?CandidateType {
        if (std.mem.eql(u8, s, "host")) return .host;
        if (std.mem.eql(u8, s, "srflx")) return .srflx;
        if (std.mem.eql(u8, s, "prflx")) return .prflx;
        if (std.mem.eql(u8, s, "relay")) return .relay;
        return null;
    }

    pub fn str(t: CandidateType) []const u8 {
        return switch (t) {
            .host => "host",
            .srflx => "srflx",
            .prflx => "prflx",
            .relay => "relay",
        };
    }

    /// Port of (CandidateType).Preference: RFC 8445 §5.1.2.2 RECOMMENDED values.
    pub fn typePreference(t: CandidateType) u16 {
        return switch (t) {
            .host => 126,
            .prflx => 110,
            .srflx => 100,
            .relay => 0,
        };
    }
};

/// Port of candidateBase.Priority: (2^24)*type + (2^8)*local + (256-component).
/// Component is always 1 (RTP+RTCP muxed, like pion's default single component).
pub fn candidatePriority(ctype: CandidateType, local_pref: u16) u32 {
    return (@as(u32, 1) << 24) * @as(u32, ctype.typePreference()) +
        (@as(u32, 1) << 8) * @as(u32, local_pref) +
        @as(u32, 256 - 1);
}

/// Port of candidateBase.Foundation: CRC-32 over type + address + network.
pub fn foundation(ctype: CandidateType, addr: IpAddress) u32 {
    const Crc = std.hash.crc.@"CRC-32/ISO-HDLC";
    var c = Crc.init();
    c.update(ctype.str());
    switch (addr) {
        .ip4 => |a| {
            c.update(&a.bytes);
            c.update("udp4");
        },
        .ip6 => |a| {
            c.update(&a.bytes);
            c.update("udp6");
        },
    }
    return c.final();
}

/// Port of (CandidatePair).priority: RFC 5245 §5.7.2 with G = controlling side.
pub fn pairPriority(controlling_local: bool, local_prio: u32, remote_prio: u32) u64 {
    const g: u64, const d: u64 = if (controlling_local)
        .{ local_prio, remote_prio }
    else
        .{ remote_prio, local_prio };
    const min = @min(g, d);
    const max = @max(g, d);
    const cmp: u64 = if (g > d) 1 else 0;
    return ((@as(u64, 1) << 32) - 1) * min + 2 * max + cmp;
}

pub const Candidate = struct {
    ctype: CandidateType,
    addr: IpAddress,
    /// Socket address this candidate is served from (host candidate address
    /// for srflx, own address otherwise).
    base: IpAddress,
    priority: u32,
};

pub const RemoteCandidate = struct {
    ctype: CandidateType,
    addr: IpAddress,
    priority: u32,
};

/// One-line signaling format for tests and drivers:
/// `candidate:<foundation> <type> <ip> <port> <priority>`
/// Not the NetBird signal encoding (that is signal-proto work); just enough
/// to move candidates between two agents in a test.
pub fn formatCandidate(buf: []u8, c: Candidate) ![]u8 {
    var ip_buf: [64]u8 = undefined;
    const ip_s = try formatIp(&ip_buf, c.addr);
    const port: u16 = switch (c.addr) {
        .ip4 => |a| a.port,
        .ip6 => |a| a.port,
    };
    return try std.fmt.bufPrint(buf, "candidate:{d} {s} {s} {d} {d}", .{
        foundation(c.ctype, c.addr),
        c.ctype.str(),
        ip_s,
        port,
        c.priority,
    });
}

pub fn parseCandidateLine(line: []const u8) !RemoteCandidate {
    var parts = std.mem.splitScalar(u8, line, ' ');
    const head = parts.next() orelse return error.Invalid;
    if (!std.mem.startsWith(u8, head, "candidate:")) return error.Invalid;
    const typ_s = parts.next() orelse return error.Invalid;
    const ctype = CandidateType.parse(typ_s) orelse return error.Invalid;
    const ip_s = parts.next() orelse return error.Invalid;
    const port_s = parts.next() orelse return error.Invalid;
    const prio_s = parts.next() orelse return error.Invalid;
    const port = try std.fmt.parseInt(u16, port_s, 10);
    const priority = try std.fmt.parseInt(u32, prio_s, 10);
    const addr = try parseIp(ip_s, port);
    return .{ .ctype = ctype, .addr = addr, .priority = priority };
}

pub fn formatIp(buf: []u8, addr: IpAddress) ![]u8 {
    return switch (addr) {
        .ip4 => |a| try std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{
            a.bytes[0], a.bytes[1], a.bytes[2], a.bytes[3],
        }),
        .ip6 => |a| blk: {
            // Full uncompressed form; parseIp accepts it back.
            const digits = "0123456789abcdef";
            var len: usize = 0;
            for (a.bytes, 0..) |b, i| {
                if (i % 2 == 0 and i != 0) {
                    if (len >= buf.len) return error.NoSpaceLeft;
                    buf[len] = ':';
                    len += 1;
                }
                if (len + 2 > buf.len) return error.NoSpaceLeft;
                buf[len] = digits[b >> 4];
                buf[len + 1] = digits[b & 0xf];
                len += 2;
            }
            break :blk buf[0..len];
        },
    };
}

pub fn parseIp(s: []const u8, port: u16) !IpAddress {
    if (std.mem.indexOfScalar(u8, s, ':') != null) {
        // Full form plus one "::" compression.
        var words: [8]u16 = .{ 0, 0, 0, 0, 0, 0, 0, 0 };
        var head: []const u8 = s;
        var tail: []const u8 = "";
        if (std.mem.indexOf(u8, s, "::")) |at| {
            head = s[0..at];
            tail = s[at + 2 ..];
        } else if (std.mem.count(u8, s, ":") != 7) {
            return error.Invalid;
        }
        var n: usize = 0;
        if (head.len > 0) {
            var it = std.mem.splitScalar(u8, head, ':');
            while (it.next()) |w| {
                if (n >= 8) return error.Invalid;
                words[n] = try std.fmt.parseInt(u16, w, 16);
                n += 1;
            }
        }
        if (tail.len > 0) {
            var tmp: [8]u16 = undefined;
            var tn: usize = 0;
            var it = std.mem.splitScalar(u8, tail, ':');
            while (it.next()) |w| {
                if (tn >= 8) return error.Invalid;
                tmp[tn] = try std.fmt.parseInt(u16, w, 16);
                tn += 1;
            }
            if (n + tn > 8) return error.Invalid;
            @memcpy(words[8 - tn ..], tmp[0..tn]);
            n += tn;
        }
        if (tail.len == 0 and head.len == s.len and n != 8) return error.Invalid;
        var bytes: [16]u8 = undefined;
        for (words, 0..) |w, i| std.mem.writeInt(u16, bytes[i * 2 ..][0..2], w, .big);
        return ip6(bytes, port);
    }
    var bytes: [4]u8 = undefined;
    var it = std.mem.splitScalar(u8, s, '.');
    for (0..4) |i| {
        const part = it.next() orelse return error.Invalid;
        bytes[i] = try std.fmt.parseInt(u8, part, 10);
    }
    if (it.next() != null) return error.Invalid;
    return ip4(bytes, port);
}

/// Port of icemaker.GenerateICECredentials: 16/32 chars from runesAlpha.
pub fn generateCredentials(ufrag_out: *[16]u8, pwd_out: *[32]u8) void {
    const alpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    var rnd: [48]u8 = undefined;
    var off: usize = 0;
    while (off < rnd.len) {
        const n = linux.getrandom(rnd[off..].ptr, rnd.len - off, 0);
        if (n > 0xfffffffffffff000 or n == 0) break;
        off += n;
    }
    // getrandom failing entirely still yields unique-ish output via counter.
    const S = struct {
        var counter: u64 = 0x9e3779b97f4a7c15;
    };
    for (rnd[off..]) |*b| {
        S.counter +%= 0x9e3779b97f4a7c15;
        var x = S.counter;
        x ^= x >> 29;
        x *%= 0xbf58476d1ce4e5b9;
        b.* = @truncate(x);
    }
    for (ufrag_out, rnd[0..16]) |*o, r| o.* = alpha[r % alpha.len];
    for (pwd_out, rnd[16..48]) |*o, r| o.* = alpha[r % alpha.len];
}

pub fn randomTiebreaker() u64 {
    var b: [8]u8 = undefined;
    var off: usize = 0;
    while (off < b.len) {
        const n = linux.getrandom(b[off..].ptr, b.len - off, 0);
        if (n > 0xfffffffffffff000 or n == 0) break;
        off += n;
    }
    if (off < b.len) {
        var ts: linux.timespec = undefined;
        _ = linux.clock_gettime(.MONOTONIC, &ts);
        const x: u64 = @bitCast(ts.sec ^ ts.nsec ^ @as(i64, linux.getpid()));
        @memcpy(b[off..], std.mem.asBytes(&x)[0 .. b.len - off]);
    }
    return std.mem.readInt(u64, &b, .little);
}

fn failed(rc: usize) bool {
    return rc > 0xfffffffffffff000;
}

/// sockaddr storage big enough for v6, aligned for direct casts.
pub const SockAddrBuf = struct {
    buf: [@sizeOf(linux.sockaddr.in6)]u8 align(@alignOf(linux.sockaddr.in6)) = undefined,

    pub fn fromIp(s: *SockAddrBuf, addr: IpAddress) struct { ptr: *const linux.sockaddr, len: linux.socklen_t } {
        switch (addr) {
            .ip4 => |a| {
                const sa: *linux.sockaddr.in = @ptrCast(@alignCast(&s.buf));
                sa.family = linux.AF.INET;
                sa.port = std.mem.nativeToBig(u16, a.port);
                sa.addr = @bitCast(a.bytes);
                return .{ .ptr = @ptrCast(sa), .len = @sizeOf(linux.sockaddr.in) };
            },
            .ip6 => |a| {
                const sa: *linux.sockaddr.in6 = @ptrCast(@alignCast(&s.buf));
                sa.family = linux.AF.INET6;
                sa.port = std.mem.nativeToBig(u16, a.port);
                sa.flowinfo = 0;
                sa.addr = a.bytes;
                sa.scope_id = 0;
                return .{ .ptr = @ptrCast(sa), .len = @sizeOf(linux.sockaddr.in6) };
            },
        }
    }

    pub fn toIp(s: *const SockAddrBuf, len: linux.socklen_t) Error!IpAddress {
        const family: u16 = @bitCast(s.buf[0..2].*);
        if (family == linux.AF.INET) {
            if (len < @sizeOf(linux.sockaddr.in)) return Error.RecvFailed;
            const sa: *const linux.sockaddr.in = @ptrCast(@alignCast(&s.buf));
            const bytes: [4]u8 = @bitCast(sa.addr);
            return ip4(bytes, std.mem.bigToNative(u16, sa.port));
        }
        if (family == linux.AF.INET6) {
            if (len < @sizeOf(linux.sockaddr.in6)) return Error.RecvFailed;
            const sa: *const linux.sockaddr.in6 = @ptrCast(@alignCast(&s.buf));
            return ip6(sa.addr, std.mem.bigToNative(u16, sa.port));
        }
        return Error.RecvFailed;
    }
};

/// Bind a UDP socket to addr with an ephemeral port; returns fd and port.
pub fn bindUdp(addr: IpAddress) Error!struct { fd: linux.fd_t, port: u16 } {
    const domain: u32 = switch (addr) {
        .ip4 => linux.AF.INET,
        .ip6 => linux.AF.INET6,
    };
    const s = linux.socket(domain, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    if (failed(s)) return Error.SocketFailed;
    const fd: linux.fd_t = @intCast(s);
    errdefer _ = linux.close(fd);
    var sab = SockAddrBuf{};
    const d = sab.fromIp(addr);
    if (failed(linux.bind(fd, d.ptr, d.len))) return Error.BindFailed;
    var got = SockAddrBuf{};
    var got_len: linux.socklen_t = @sizeOf(linux.sockaddr.in6);
    if (failed(linux.getsockname(fd, @ptrCast(@alignCast(&got.buf)), &got_len))) return Error.BindFailed;
    const bound = try got.toIp(got_len);
    const port: u16 = switch (bound) {
        .ip4 => |a| a.port,
        .ip6 => |a| a.port,
    };
    return .{ .fd = fd, .port = port };
}

pub fn sendTo(fd: linux.fd_t, addr: IpAddress, data: []const u8) Error!void {
    var sab = SockAddrBuf{};
    const d = sab.fromIp(addr);
    const n = linux.sendto(fd, data.ptr, data.len, 0, d.ptr, d.len);
    if (failed(n) or n != data.len) return Error.SendFailed;
}

// --- Gathering: interface addresses via RTM_GETADDR/RTM_GETLINK ---

const nlmsg_done: u16 = 3;
const nlmsg_error: u16 = 2;
const rtm_getlink: u16 = 18;
const rtm_newlink: u16 = 16;
const rtm_getaddr: u16 = 22;
const rtm_newaddr: u16 = 20;
const ifla_ifname: u16 = 3;
const ifa_address: u16 = 1;
const ifa_local: u16 = 2;
const nlmsghdr_len = 16;

const sockaddr_nl = extern struct {
    family: u16 = linux.AF.NETLINK,
    pad: u16 = 0,
    pid: u32 = 0,
    groups: u32 = 0,
};

const IfAddr = struct {
    index: u32,
    family: u8,
    bytes: [16]u8,
    len: u8, // 4 or 16
};

const IfaceName = struct {
    index: u32,
    name: [16]u8,
    name_len: usize,
};

/// Dump addresses (RTM_GETADDR) and link names (RTM_GETLINK) for blacklist
/// filtering. Port of the NetBird InterfaceFilter(blacklist) input side:
/// stdnet.InterfaceFilter drops whole interfaces by name.
const DumpCounts = struct { n_ifaces: usize, n_addrs: usize };

fn dumpAddrs(
    ifaces_out: []IfaceName,
    addrs_out: []IfAddr,
) Error!DumpCounts {
    const s = linux.socket(linux.AF.NETLINK, linux.SOCK.RAW | linux.SOCK.CLOEXEC, linux.NETLINK.ROUTE);
    if (failed(s)) return Error.NetlinkFailed;
    const fd: linux.fd_t = @intCast(s);
    defer _ = linux.close(fd);
    const pid: u32 = @intCast(linux.getpid());
    var addr = sockaddr_nl{ .pid = pid };
    if (failed(linux.bind(fd, @ptrCast(&addr), @sizeOf(sockaddr_nl)))) return Error.NetlinkFailed;

    var n_ifaces: usize = 0;
    var n_addrs: usize = 0;
    // Two dumps: links for index->name, addrs for index->addresses.
    for ([_]u16{ rtm_getlink, rtm_getaddr }) |req_type| {
        var req: [32]u8 = std.mem.zeroes([32]u8);
        const body_len: usize = if (req_type == rtm_getlink) 16 else 8;
        std.mem.writeInt(u32, req[0..4], @intCast(nlmsghdr_len + body_len), .native);
        std.mem.writeInt(u16, req[4..6], req_type, .native);
        std.mem.writeInt(u16, req[6..8], linux.NLM_F_REQUEST | linux.NLM_F_DUMP, .native);
        std.mem.writeInt(u32, req[8..12], 1, .native);
        std.mem.writeInt(u32, req[12..16], pid, .native);
        var kaddr = sockaddr_nl{};
        const total = nlmsghdr_len + body_len;
        const sent = linux.sendto(fd, &req, total, 0, @ptrCast(&kaddr), @sizeOf(sockaddr_nl));
        if (failed(sent) or sent != total) return Error.NetlinkFailed;

        var reply: [16384]u8 = undefined;
        var done = false;
        while (!done) {
            const n = linux.recvfrom(fd, &reply, reply.len, 0, null, null);
            if (failed(n) or n < nlmsghdr_len) return Error.NetlinkFailed;
            var off: usize = 0;
            while (off + nlmsghdr_len <= n) {
                const mlen: usize = std.mem.readInt(u32, reply[off..][0..4], .native);
                const mtype = std.mem.readInt(u16, reply[off..][4..6], .native);
                if (mlen < nlmsghdr_len or off + mlen > n) break;
                if (mtype == nlmsg_done) {
                    done = true;
                    break;
                }
                if (mtype == nlmsg_error) return Error.NetlinkFailed;
                if (mtype == rtm_newlink and req_type == rtm_getlink) {
                    // ifinfomsg: family(1) pad(1) type(2) index(4) flags(4) change(4)
                    const index = std.mem.readInt(u32, reply[off + 20 ..][0..4], .native);
                    var aoff: usize = off + nlmsghdr_len + 16;
                    const aend = off + mlen;
                    while (aoff + 4 <= aend) {
                        const alen: usize = std.mem.readInt(u16, reply[aoff..][0..2], .native);
                        const atype = std.mem.readInt(u16, reply[aoff..][2..4], .native);
                        if (alen < 4 or aoff + alen > aend) break;
                        if (atype == ifla_ifname and n_ifaces < ifaces_out.len) {
                            const raw = reply[aoff + 4 .. aoff + alen];
                            const z = std.mem.indexOfScalar(u8, raw, 0) orelse raw.len;
                            const ife = &ifaces_out[n_ifaces];
                            ife.index = index;
                            ife.name_len = @min(z, ife.name.len);
                            @memcpy(ife.name[0..ife.name_len], raw[0..ife.name_len]);
                            n_ifaces += 1;
                        }
                        aoff += (alen + 3) & ~@as(usize, 3);
                    }
                }
                if (mtype == rtm_newaddr and req_type == rtm_getaddr) {
                    // ifaddrmsg: family(1) prefixlen(1) flags(1) scope(1) index(4)
                    const family = reply[off + nlmsghdr_len];
                    const index = std.mem.readInt(u32, reply[off + nlmsghdr_len + 4 ..][0..4], .native);
                    var aoff: usize = off + nlmsghdr_len + 8;
                    const aend = off + mlen;
                    while (aoff + 4 <= aend) {
                        const alen: usize = std.mem.readInt(u16, reply[aoff..][0..2], .native);
                        const atype = std.mem.readInt(u16, reply[aoff..][2..4], .native);
                        if (alen < 4 or aoff + alen > aend) break;
                        if ((atype == ifa_local or atype == ifa_address) and n_addrs < addrs_out.len) {
                            const raw = reply[aoff + 4 .. aoff + alen];
                            if ((family == linux.AF.INET and raw.len == 4) or
                                (family == linux.AF.INET6 and raw.len == 16))
                            {
                                // Prefer IFA_LOCAL (set on P2P); skip dup IFA_ADDRESS.
                                var dup = false;
                                for (addrs_out[0..n_addrs]) |prev| {
                                    if (prev.index == index and prev.family == family) dup = true;
                                }
                                if (!dup) {
                                    const a = &addrs_out[n_addrs];
                                    a.index = index;
                                    a.family = family;
                                    a.len = @intCast(raw.len);
                                    @memcpy(a.bytes[0..raw.len], raw);
                                    n_addrs += 1;
                                }
                            }
                        }
                        aoff += (alen + 3) & ~@as(usize, 3);
                    }
                }
                off += (mlen + 3) & ~@as(usize, 3);
            }
        }
    }
    return .{ .n_ifaces = n_ifaces, .n_addrs = n_addrs };
}

fn ifName(ifaces: []const IfaceName, index: u32) []const u8 {
    // NOTE: capture by pointer — returning a slice of a by-value loop copy
    // would point at dead stack memory.
    for (ifaces) |*i| {
        if (i.index == index) return i.name[0..i.name_len];
    }
    return "";
}

/// Gathered sockets and candidates. Caller must close().
pub const Gathered = struct {
    fds: [max_sockets]linux.fd_t = undefined,
    socks: [max_sockets]Candidate = undefined,
    n_socks: usize = 0,
    cands: [max_sockets * 2]Candidate = undefined,
    n_cands: usize = 0,

    pub fn close(g: *Gathered) void {
        for (g.fds[0..g.n_socks]) |fd| _ = linux.close(fd);
        g.n_socks = 0;
        g.n_cands = 0;
    }

    pub fn sockets(g: *Gathered) []linux.fd_t {
        return g.fds[0..g.n_socks];
    }

    pub fn candidates(g: *Gathered) []Candidate {
        return g.cands[0..g.n_cands];
    }
};

pub const GatherOptions = struct {
    stun_server: ?IpAddress = null,
    /// Interface names to skip (NetBird Config.InterfaceBlackList).
    blacklist: []const []const u8 = &.{},
    want_v6: bool = false,
    /// Local preference of the first socket; -1 per socket after that.
    base_local_pref: u16 = 65535,
};

/// Gather host candidates (one UDP socket per address) plus one srflx
/// candidate per socket when stun_server is set. Port of the pion gather
/// path NetBird uses (UDP only, no mDNS, no relay here).
pub fn gather(opts: GatherOptions) Error!Gathered {
    var g = Gathered{};
    errdefer g.close();
    var ifaces: [32]IfaceName = undefined;
    var addrs: [64]IfAddr = undefined;
    const dumped = try dumpAddrs(&ifaces, &addrs);
    const iflist = ifaces[0..dumped.n_ifaces];
    const adlist = addrs[0..dumped.n_addrs];

    for (adlist) |a| {
        if (g.n_socks >= max_sockets) break;
        if (a.family == linux.AF.INET6 and !opts.want_v6) continue;
        const name = ifName(iflist, a.index);
        var skip = false;
        for (opts.blacklist) |b| {
            if (std.mem.eql(u8, name, b)) skip = true;
        }
        if (skip) continue;
        const bind_addr: IpAddress = if (a.family == linux.AF.INET)
            ip4(a.bytes[0..4].*, 0)
        else
            ip6(a.bytes, 0);
        const b = bindUdp(bind_addr) catch continue;
        const local_pref: u16 = opts.base_local_pref -| @as(u16, @intCast(g.n_socks));
        const sock_addr: IpAddress = if (a.family == linux.AF.INET)
            ip4(a.bytes[0..4].*, b.port)
        else
            ip6(a.bytes, b.port);
        g.fds[g.n_socks] = b.fd;
        g.socks[g.n_socks] = .{
            .ctype = .host,
            .addr = sock_addr,
            .base = sock_addr,
            .priority = candidatePriority(.host, local_pref),
        };
        g.n_socks += 1;
    }
    if (g.n_socks == 0) return Error.NoCandidates;

    // Host candidates first, then srflx (pion gather order per socket).
    for (g.socks[0..g.n_socks], 0..) |s, i| {
        g.cands[g.n_cands] = s;
        g.n_cands += 1;
        if (opts.stun_server) |srv| {
            var resp: [1500]u8 = undefined;
            const n = stun.bindingRequestOn(
                g.fds[i],
                srv,
                stun.randomTrid(),
                null,
                &resp,
                .{ .rto_ms = 300, .attempts = 3 },
            ) catch continue;
            const d = stun.decode(resp[0..n]) catch continue;
            if (d.msg_type.class != .success) continue;
            const x = stun.XorAddr.decode(&d, stun.Attr.xor_mapped_address, d.trid) catch continue;
            const srflx_addr: IpAddress = switch (x.ip) {
                .ip4 => |v| ip4(v.bytes, x.port),
                .ip6 => |v| ip6(v.bytes, x.port),
            };
            const local_pref: u16 = opts.base_local_pref -| @as(u16, @intCast(i));
            g.cands[g.n_cands] = .{
                .ctype = .srflx,
                .addr = srflx_addr,
                .base = s.addr,
                .priority = candidatePriority(.srflx, local_pref),
            };
            g.n_cands += 1;
        }
    }
    return g;
}

// --- Connectivity checks ---

pub const Role = enum {
    controlling,
    controlled,
};

pub const Credentials = struct {
    ufrag: []const u8,
    pwd: []const u8,
};

pub const Selected = struct {
    sock_index: usize,
    local: Candidate,
    remote: RemoteCandidate,
};

pub const ConnectOptions = struct {
    check_rto_ms: i32 = 200,
    overall_timeout_ms: i32 = 15000,
};

fn nowMs() i64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return ts.sec * 1000 + @divTrunc(ts.nsec, 1_000_000);
}

fn sameFamily(a: IpAddress, b: IpAddress) bool {
    return std.meta.activeTag(a) == std.meta.activeTag(b);
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

const Pair = struct {
    sock_index: usize,
    local: Candidate,
    remote: RemoteCandidate,
    priority: u64,
    last_check_ms: i64 = 0,
    check_trid: stun.Trid = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    has_pending: bool = false,
    valid: bool = false,
    dead: bool = false,
};

/// Build a connectivity-check Binding request. Port of the pion controlling
/// (selection.go nominatePair/ping) and controlled check shape: USERNAME
/// remote:local, PRIORITY, ICE-CONTROLLING/CONTROLLED, short-term integrity
/// with the REMOTE password, FINGERPRINT; USE-CANDIDATE when nominating.
fn buildCheck(
    buf: []u8,
    trid: stun.Trid,
    local: Candidate,
    local_creds: Credentials,
    remote_creds: Credentials,
    role: Role,
    tiebreaker: u64,
    nominate: bool,
) Error![]u8 {
    var enc = try stun.Encoder.init(buf, stun.MessageType.binding_request, trid);
    var user: [128]u8 = undefined;
    if (remote_creds.ufrag.len + 1 + local_creds.ufrag.len > user.len) return Error.NoSpace;
    @memcpy(user[0..remote_creds.ufrag.len], remote_creds.ufrag);
    user[remote_creds.ufrag.len] = ':';
    @memcpy(
        user[remote_creds.ufrag.len + 1 ..][0..local_creds.ufrag.len],
        local_creds.ufrag,
    );
    try enc.add(
        stun.Attr.username,
        user[0 .. remote_creds.ufrag.len + 1 + local_creds.ufrag.len],
    );
    var pb: [4]u8 = undefined;
    std.mem.writeInt(u32, &pb, local.priority, .big);
    try enc.add(stun.Attr.priority, &pb);
    var tb: [8]u8 = undefined;
    std.mem.writeInt(u64, &tb, tiebreaker, .big);
    try enc.add(
        if (role == .controlling) stun.Attr.ice_controlling else stun.Attr.ice_controlled,
        &tb,
    );
    if (nominate) try enc.add(stun.Attr.use_candidate, &[_]u8{});
    try enc.addIntegrity(remote_creds.pwd);
    try enc.addFingerprint();
    return enc.bytes();
}

fn sendCheck(
    g: *Gathered,
    p: *Pair,
    local_creds: Credentials,
    remote_creds: Credentials,
    role: Role,
    tiebreaker: u64,
    nominate: bool,
) Error!void {
    var buf: [512]u8 = undefined;
    const trid = stun.randomTrid();
    const msg = try buildCheck(
        &buf,
        trid,
        g.socks[p.sock_index],
        local_creds,
        remote_creds,
        role,
        tiebreaker,
        nominate,
    );
    try sendTo(g.fds[p.sock_index], p.remote.addr, msg);
    p.check_trid = trid;
    p.has_pending = true;
    p.last_check_ms = nowMs();
}

fn sendSuccess(
    g: *Gathered,
    sock_index: usize,
    to: IpAddress,
    req_trid: stun.Trid,
    local_pwd: []const u8,
) Error!void {
    // Port of Agent.sendBindingSuccess: XOR-MAPPED + local-pwd integrity.
    var buf: [512]u8 = undefined;
    var enc = try stun.Encoder.init(&buf, stun.MessageType.binding_success, req_trid);
    const port: u16 = switch (to) {
        .ip4 => |a| a.port,
        .ip6 => |a| a.port,
    };
    try stun.XorAddr.encode(&enc, stun.Attr.xor_mapped_address, req_trid, to, port);
    try enc.addIntegrity(local_pwd);
    try enc.addFingerprint();
    try sendTo(g.fds[sock_index], to, enc.bytes());
}

fn sendRoleConflict(
    g: *Gathered,
    sock_index: usize,
    to: IpAddress,
    req_trid: stun.Trid,
    local_pwd: []const u8,
) Error!void {
    var buf: [512]u8 = undefined;
    var enc = try stun.Encoder.init(&buf, stun.MessageType.binding_error, req_trid);
    try stun.ErrorCode.encode(&enc, stun.ErrorCode.role_conflict, "Role Conflict");
    try enc.addIntegrity(local_pwd);
    try enc.addFingerprint();
    try sendTo(g.fds[sock_index], to, enc.bytes());
}

fn sortPairs(pairs: []Pair) void {
    std.mem.sort(Pair, pairs, {}, struct {
        fn less(_: void, a: Pair, b: Pair) bool {
            return a.priority > b.priority;
        }
    }.less);
}

/// Run connectivity checks until a pair is selected or the overall timeout
/// hits. Port of the worker_ice/agentDial shape: controlling side nominates
/// the best valid pair (aggressive nomination like pion's controlling
/// selector); controlled side selects on USE-CANDIDATE. Returns the selected
/// pair; the socket stays open in Gathered for data.
pub fn connect(
    g: *Gathered,
    local_creds: Credentials,
    remote_creds: Credentials,
    remotes: []const RemoteCandidate,
    role_in: Role,
    tiebreaker: u64,
    opts: ConnectOptions,
) Error!Selected {
    var role = role_in;
    var pairs_buf: [max_pairs]Pair = undefined;
    var n_pairs: usize = 0;
    for (g.socks[0..g.n_socks], 0..) |s, si| {
        for (remotes) |r| {
            if (!sameFamily(s.addr, r.addr)) continue;
            if (n_pairs >= max_pairs) break;
            pairs_buf[n_pairs] = .{
                .sock_index = si,
                .local = s,
                .remote = r,
                .priority = pairPriority(role == .controlling, s.priority, r.priority),
            };
            n_pairs += 1;
        }
    }
    if (n_pairs == 0) return Error.NoCandidates;
    var pairs = pairs_buf[0..n_pairs];
    sortPairs(pairs);

    const deadline = nowMs() + opts.overall_timeout_ms;
    // First round immediately on every pair (paced 20ms like pion's default).
    var nominated_idx: ?usize = null;

    for (pairs, 0..) |*p, i| {
        _ = i;
        sendCheck(g, p, local_creds, remote_creds, role, tiebreaker, false) catch |err| {
            if (err == Error.SendFailed) {
                p.dead = true;
                continue;
            }
            return err;
        };
    }

    var pfds: [max_sockets]linux.pollfd = undefined;
    var rbuf: [2048]u8 = undefined;
    while (true) {
        const now = nowMs();
        if (now >= deadline) return Error.Timeout;
        // Retransmit unanswered pairs, plus the in-flight nomination.
        for (pairs) |*p| {
            if (p.dead) continue;
            if (p.valid) {
                if (role == .controlling) {
                    if (nominated_idx) |ni| {
                        if (&pairs[ni] == p and now - p.last_check_ms >= opts.check_rto_ms) {
                            sendCheck(g, p, local_creds, remote_creds, role, tiebreaker, true) catch {};
                        }
                    }
                }
                continue;
            }
            if (now - p.last_check_ms >= opts.check_rto_ms) {
                sendCheck(g, p, local_creds, remote_creds, role, tiebreaker, false) catch {};
            }
        }
        for (g.fds[0..g.n_socks], 0..) |fd, i| {
            pfds[i] = .{ .fd = fd, .events = linux.POLL.IN };
        }
        const wait_ms: i32 = @intCast(@min(@as(i64, opts.check_rto_ms), deadline - now));
        const prc = linux.poll(pfds[0..g.n_socks].ptr, g.n_socks, wait_ms);
        if (failed(prc)) return Error.RecvFailed;
        if (prc == 0) continue;
        for (0..g.n_socks) |si| {
            if (pfds[si].revents & linux.POLL.IN == 0) continue;
            var sab = SockAddrBuf{};
            var slen: linux.socklen_t = @sizeOf(linux.sockaddr.in6);
            const n = linux.recvfrom(
                g.fds[si],
                &rbuf,
                rbuf.len,
                0,
                @ptrCast(@alignCast(&sab.buf)),
                &slen,
            );
            if (failed(n) or n == 0) continue;
            const pkt = rbuf[0..n];
            if (!stun.isMessage(pkt)) continue; // data before selection: ignore.
            const d = stun.decode(pkt) catch continue;
            if (d.msg_type.method != .binding) continue;
            const src = sab.toIp(slen) catch continue;

            if (d.msg_type.class == .request) {
                // Port of Agent.handleInbound request branch.
                const user = d.get(stun.Attr.username) catch continue;
                var want_user: [128]u8 = undefined;
                if (local_creds.ufrag.len + 1 + remote_creds.ufrag.len > want_user.len) continue;
                @memcpy(want_user[0..local_creds.ufrag.len], local_creds.ufrag);
                want_user[local_creds.ufrag.len] = ':';
                @memcpy(
                    want_user[local_creds.ufrag.len + 1 ..][0..remote_creds.ufrag.len],
                    remote_creds.ufrag,
                );
                const want = want_user[0 .. local_creds.ufrag.len + 1 + remote_creds.ufrag.len];
                if (!std.mem.eql(u8, user, want)) continue;
                stun.checkIntegrity(pkt, &d, local_creds.pwd) catch continue;
                // Role conflict? Port of handleRoleConflict.
                const they_controlling = d.contains(stun.Attr.ice_controlling);
                const they_controlled = d.contains(stun.Attr.ice_controlled);
                if ((they_controlling and role == .controlling) or
                    (they_controlled and role == .controlled))
                {
                    const attr = if (they_controlling) stun.Attr.ice_controlling else stun.Attr.ice_controlled;
                    const raw = d.get(attr) catch continue;
                    if (raw.len != 8) continue;
                    const theirs = std.mem.readInt(u64, raw[0..8], .big);
                    const flip = (role == .controlling and tiebreaker < theirs) or
                        (role == .controlled and tiebreaker >= theirs);
                    if (!flip) {
                        sendRoleConflict(g, si, src, d.trid, local_creds.pwd) catch {};
                        continue;
                    }
                    role = if (role == .controlling) .controlled else .controlling;
                    nominated_idx = null;
                    for (pairs) |*p| {
                        p.has_pending = false;
                        p.priority = pairPriority(
                            role == .controlling,
                            p.local.priority,
                            p.remote.priority,
                        );
                    }
                    sortPairs(pairs);
                }
                // Find or add (prflx) the pair, then answer.
                var pidx: ?usize = null;
                for (pairs, 0..) |*p, i| {
                    if (p.sock_index == si and sameAddr(p.remote.addr, src)) {
                        pidx = i;
                        break;
                    }
                }
                if (pidx == null) {
                    if (n_pairs >= max_pairs) continue;
                    // Unknown source with valid credentials: peer-reflexive.
                    var prio: u32 = 0;
                    if (d.get(stun.Attr.priority)) |raw| {
                        if (raw.len == 4) prio = std.mem.readInt(u32, raw[0..4], .big);
                    } else |_| {}
                    pairs_buf[n_pairs] = .{
                        .sock_index = si,
                        .local = g.socks[si],
                        .remote = .{ .ctype = .prflx, .addr = src, .priority = prio },
                        .priority = pairPriority(
                            role == .controlling,
                            g.socks[si].priority,
                            prio,
                        ),
                    };
                    pidx = n_pairs;
                    n_pairs += 1;
                    pairs = pairs_buf[0..n_pairs];
                }
                sendSuccess(g, si, src, d.trid, local_creds.pwd) catch {};
                if (d.contains(stun.Attr.use_candidate) and role == .controlled) {
                    const p = &pairs[pidx.?];
                    return .{
                        .sock_index = p.sock_index,
                        .local = p.local,
                        .remote = p.remote,
                    };
                }
            } else if (d.msg_type.class == .success) {
                var pidx: ?usize = null;
                for (pairs, 0..) |*p, i| {
                    if (p.sock_index == si and p.has_pending and
                        std.mem.eql(u8, &p.check_trid, &d.trid))
                    {
                        pidx = i;
                        break;
                    }
                }
                if (pidx == null) continue;
                stun.checkIntegrity(pkt, &d, remote_creds.pwd) catch continue;
                const p = &pairs[pidx.?];
                p.has_pending = false;
                p.valid = true;
                if (role == .controlling) {
                    if (nominated_idx) |ni| {
                        if (ni == pidx.?) {
                            return .{
                                .sock_index = p.sock_index,
                                .local = p.local,
                                .remote = p.remote,
                            };
                        }
                    }
                    // Aggressive nomination: nominate the best valid pair.
                    var best: ?usize = null;
                    for (pairs, 0..) |*q, i| {
                        if (q.valid and !q.dead) {
                            best = i;
                            break;
                        }
                    }
                    if (best) |bi| {
                        // Nominate once per best pair: re-nominating on every
                        // new valid churns the transaction ID and orphans the
                        // in-flight nomination's response.
                        const same = if (nominated_idx) |ni|
                            pairs[ni].sock_index == pairs[bi].sock_index and
                                sameAddr(pairs[ni].remote.addr, pairs[bi].remote.addr)
                        else
                            false;
                        if (!same) {
                            nominated_idx = bi;
                            sendCheck(
                                g,
                                &pairs[bi],
                                local_creds,
                                remote_creds,
                                role,
                                tiebreaker,
                                true,
                            ) catch {};
                        }
                    }
                }
            } else if (d.msg_type.class == .err) {
                var pidx: ?usize = null;
                for (pairs, 0..) |*p, i| {
                    if (p.sock_index == si and p.has_pending and
                        std.mem.eql(u8, &p.check_trid, &d.trid))
                    {
                        pidx = i;
                        break;
                    }
                }
                if (pidx == null) continue;
                const ec = stun.ErrorCode.decode(&d) catch continue;
                if (ec.code == stun.ErrorCode.role_conflict) {
                    // They think we must switch; flip and re-check.
                    role = if (role == .controlling) .controlled else .controlling;
                    nominated_idx = null;
                    for (pairs) |*p| {
                        p.has_pending = false;
                        p.valid = false;
                        p.priority = pairPriority(
                            role == .controlling,
                            p.local.priority,
                            p.remote.priority,
                        );
                    }
                    sortPairs(pairs);
                } else {
                    pairs[pidx.?].dead = true;
                }
            }
        }
    }
}
