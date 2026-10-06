// Minimal rtnetlink over a raw NETLINK_ROUTE socket: link up/down, IPv4
// address add/delete, route add/delete, ifindex lookup. Raw syscalls only
// (socket, bind, sendto, recvfrom, ioctl — all pre-4.9).
// UAPI values from linux/rtnetlink.h (stable ABI); std only provides
// NETLINK.ROUTE and NLM_F_*.
// Reference behavior: netbird routemanager/systemops (via vishvananda
// netlink) and `ip addr/route` semantics.

const std = @import("std");
const linux = std.os.linux;

pub const nlmsg_error: u16 = 2;
pub const rtm_newlink: u16 = 16;
pub const rtm_newaddr: u16 = 20;
pub const rtm_deladdr: u16 = 21;
pub const rtm_newroute: u16 = 24;
pub const rtm_delroute: u16 = 25;
pub const ifa_address: u16 = 1;
pub const ifa_local: u16 = 2;
pub const rta_dst: u16 = 1;
pub const rta_oif: u16 = 4;
pub const rta_gateway: u16 = 5;
pub const rt_table_main: u8 = 254;
pub const rtprot_boot: u8 = 3;
pub const rt_scope_universe: u8 = 0;
pub const rt_scope_link: u8 = 253;
pub const rtn_unicast: u8 = 1;
pub const iff_up: u32 = 0x1;

pub const nlmsghdr_len = 16;
pub const ifinfomsg_len = 16;
pub const ifaddrmsg_len = 8;
pub const rtmsg_len = 12;
pub const rtattr_len = 4;

pub const sockaddr_nl = extern struct {
    family: u16 = linux.AF.NETLINK,
    pad: u16 = 0,
    pid: u32 = 0,
    groups: u32 = 0,
};

pub const Error = error{
    SocketFailed,
    BindFailed,
    SendFailed,
    RecvFailed,
    BadAck,
    NetlinkError,
    Exists,
    NoSuchLink,
    NoSuchAddr,
    NoSuchRoute,
};

pub const RouteSock = struct {
    fd: linux.fd_t,
    seq: u32 = 0,
    pid: u32,

    pub fn open() Error!RouteSock {
        const s = linux.socket(
            linux.AF.NETLINK,
            linux.SOCK.RAW | linux.SOCK.CLOEXEC,
            linux.NETLINK.ROUTE,
        );
        if (s > 0xfffffffffffff000) return Error.SocketFailed;
        const fd: linux.fd_t = @intCast(s);
        errdefer _ = linux.close(fd);
        const pid: u32 = @intCast(linux.getpid());
        var addr = sockaddr_nl{ .pid = pid };
        const rc = linux.bind(fd, @ptrCast(&addr), @sizeOf(sockaddr_nl));
        if (rc > 0xfffffffffffff000) return Error.BindFailed;
        return .{ .fd = fd, .pid = pid };
    }

    pub fn close(s: *RouteSock) void {
        _ = linux.close(s.fd);
        s.fd = -1;
    }

    /// Send one request, read the ACK. Replies to our seq only.
    fn transact(s: *RouteSock, msg_type: u16, flags: u16, body: []const u8) Error!void {
        s.seq += 1;
        var req: [512]u8 = undefined;
        const total = nlmsghdr_len + body.len;
        if (total > req.len) return Error.SendFailed;
        std.mem.writeInt(u32, req[0..4], @intCast(total), .native);
        std.mem.writeInt(u16, req[4..6], msg_type, .native);
        std.mem.writeInt(u16, req[6..8], flags, .native);
        std.mem.writeInt(u32, req[8..12], s.seq, .native);
        std.mem.writeInt(u32, req[12..16], s.pid, .native);
        @memcpy(req[16..total], body);
        var kaddr = sockaddr_nl{};
        const sent = linux.sendto(s.fd, req[0..total].ptr, total, 0, @ptrCast(&kaddr), @sizeOf(sockaddr_nl));
        if (sent > 0xfffffffffffff000 or sent != total) return Error.SendFailed;
        var reply: [8192]u8 = undefined;
        const n = linux.recvfrom(s.fd, &reply, reply.len, 0, null, null);
        if (n > 0xfffffffffffff000 or n < 20) return Error.RecvFailed;
        const rlen = std.mem.readInt(u32, reply[0..4], .native);
        const rtype = std.mem.readInt(u16, reply[4..6], .native);
        const rseq = std.mem.readInt(u32, reply[8..12], .native);
        if (rlen > n or rtype != nlmsg_error or rseq != s.seq) return Error.BadAck;
        const err_code = std.mem.readInt(i32, reply[16..20], .native);
        if (err_code == 0) return;
        return switch (-err_code) {
            17 => Error.Exists, // EEXIST
            19 => Error.NoSuchLink, // ENODEV
            99 => Error.NoSuchAddr, // EADDRNOTAVAIL
            3 => Error.NoSuchRoute, // ESRCH
            else => Error.NetlinkError,
        };
    }

    /// Append one rtattr (header + value, padded to 4). Returns new end.
    fn putAttr(buf: []u8, end: usize, attr_type: u16, value: []const u8) usize {
        std.mem.writeInt(u16, buf[end..][0..2], @intCast(rtattr_len + value.len), .native);
        std.mem.writeInt(u16, buf[end..][2..4], attr_type, .native);
        @memcpy(buf[end + rtattr_len ..][0..value.len], value);
        const padded = (rtattr_len + value.len + 3) & ~@as(usize, 3);
        @memset(buf[end + rtattr_len + value.len .. end + padded], 0);
        return end + padded;
    }

    /// RTM_NEWLINK with IFF_UP in flags+change (up) or change only (down).
    pub fn linkSetUp(s: *RouteSock, ifindex: u32, up: bool) Error!void {
        var body: [ifinfomsg_len]u8 = std.mem.zeroes([ifinfomsg_len]u8);
        body[0] = linux.AF.UNSPEC;
        std.mem.writeInt(i32, body[4..8], @intCast(ifindex), .native);
        std.mem.writeInt(u32, body[8..12], if (up) iff_up else 0, .native);
        std.mem.writeInt(u32, body[12..16], iff_up, .native);
        try s.transact(rtm_newlink, linux.NLM_F_REQUEST | linux.NLM_F_ACK, &body);
    }

    fn addrMsg(s: *RouteSock, msg_type: u16, flags: u16, ifindex: u32, addr: [4]u8, prefixlen: u8) Error!void {
        var body: [64]u8 = undefined;
        body[0] = linux.AF.INET;
        body[1] = prefixlen;
        body[2] = 0;
        body[3] = rt_scope_universe;
        std.mem.writeInt(u32, body[4..8], ifindex, .native);
        var end: usize = ifaddrmsg_len;
        end = putAttr(&body, end, ifa_local, &addr);
        end = putAttr(&body, end, ifa_address, &addr);
        try s.transact(msg_type, flags, body[0..end]);
    }

    /// RTM_NEWADDR (like `ip addr add`).
    pub fn addrAdd(s: *RouteSock, ifindex: u32, addr: [4]u8, prefixlen: u8) Error!void {
        const f = linux.NLM_F_REQUEST | linux.NLM_F_ACK | linux.NLM_F_CREATE | linux.NLM_F_EXCL;
        try s.addrMsg(rtm_newaddr, f, ifindex, addr, prefixlen);
    }

    /// RTM_DELADDR (like `ip addr del`).
    pub fn addrDel(s: *RouteSock, ifindex: u32, addr: [4]u8, prefixlen: u8) Error!void {
        try s.addrMsg(rtm_deladdr, linux.NLM_F_REQUEST | linux.NLM_F_ACK, ifindex, addr, prefixlen);
    }

    fn routeMsg(
        s: *RouteSock,
        msg_type: u16,
        flags: u16,
        dst: [4]u8,
        dst_len: u8,
        oif: u32,
        gateway: ?[4]u8,
    ) Error!void {
        var body: [128]u8 = undefined;
        body[0] = linux.AF.INET;
        body[1] = dst_len;
        body[2] = 0;
        body[3] = 0;
        body[4] = rt_table_main;
        body[5] = rtprot_boot;
        body[6] = if (gateway == null) rt_scope_link else rt_scope_universe;
        body[7] = rtn_unicast;
        std.mem.writeInt(u32, body[8..12], 0, .native);
        var end: usize = rtmsg_len;
        if (dst_len > 0) end = putAttr(&body, end, rta_dst, &dst);
        if (oif != 0) {
            var oif_bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &oif_bytes, oif, .native);
            end = putAttr(&body, end, rta_oif, &oif_bytes);
        }
        if (gateway) |gw| end = putAttr(&body, end, rta_gateway, &gw);
        try s.transact(msg_type, flags, body[0..end]);
    }

    /// RTM_NEWROUTE (like `ip route add`; gateway null = link route).
    pub fn routeAdd(s: *RouteSock, dst: [4]u8, dst_len: u8, oif: u32, gateway: ?[4]u8) Error!void {
        const f = linux.NLM_F_REQUEST | linux.NLM_F_ACK | linux.NLM_F_CREATE | linux.NLM_F_EXCL;
        try s.routeMsg(rtm_newroute, f, dst, dst_len, oif, gateway);
    }

    /// RTM_DELROUTE (like `ip route del`).
    pub fn routeDel(s: *RouteSock, dst: [4]u8, dst_len: u8, oif: u32, gateway: ?[4]u8) Error!void {
        try s.routeMsg(rtm_delroute, linux.NLM_F_REQUEST | linux.NLM_F_ACK, dst, dst_len, oif, gateway);
    }

    /// Interface index by name via SIOCGIFINDEX.
    pub fn linkIndex(name: []const u8) Error!u32 {
        if (name.len >= 16) return Error.NoSuchLink;
        const fd_usize = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
        if (fd_usize > 0xfffffffffffff000) return Error.SocketFailed;
        const fd: linux.fd_t = @intCast(fd_usize);
        defer _ = linux.close(fd);
        var ifr: [40]u8 = std.mem.zeroes([40]u8);
        @memcpy(ifr[0..name.len], name);
        const rc = linux.ioctl(fd, linux.SIOCGIFINDEX, @intFromPtr(&ifr));
        if (rc > 0xfffffffffffff000) return Error.NoSuchLink;
        return std.mem.readInt(u32, ifr[16..20], .native);
    }
};
