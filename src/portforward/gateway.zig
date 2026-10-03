// Port of the go-netroute Route lookups go-nat uses (v0.79.0), BSD-3-Clause:
// default gateway + local source address for the 0.0.0.1 / ::2 probes.
const std = @import("std");
const linux = std.os.linux;

pub const Error = error{
    SocketFailed,
    SendFailed,
    RecvFailed,
    NoGateway,
};

fn failed(rc: usize) bool {
    return rc > 0xfffffffffffff000;
}

const SockAddrNl = extern struct {
    family: u16 = linux.AF.NETLINK,
    pad: u16 = 0,
    pid: u32 = 0,
    groups: u32 = 0,
};

pub const Route4 = struct {
    gateway: [4]u8,
    local: [4]u8,
};

pub const Route6 = struct {
    gateway: [16]u8,
    local: [16]u8,
    ifindex: u32,
};

/// One RTM_GETROUTE query; family is AF_INET or AF_INET6, dst is the
/// 4- or 16-byte probe destination. Replies fill gateway/local/ifindex.
fn queryRoute(family: u8, dst: []const u8, gw_out: []u8, local_out: []u8, ifindex_out: *u32) Error!void {
    const s = linux.socket(linux.AF.NETLINK, linux.SOCK.RAW | linux.SOCK.CLOEXEC, linux.NETLINK.ROUTE);
    if (failed(s)) return Error.SocketFailed;
    const fd: linux.fd_t = @intCast(s);
    defer _ = linux.close(fd);
    const pid: u32 = @intCast(linux.getpid());
    var addr = SockAddrNl{ .pid = pid };
    if (failed(linux.bind(fd, @ptrCast(&addr), @sizeOf(SockAddrNl)))) return Error.SocketFailed;
    // nlmsghdr(16) + rtmsg(12) + rtattr(4 + dst, padded to 4).
    var req: [64]u8 = std.mem.zeroes([64]u8);
    const attr_len: usize = 4 + dst.len;
    const reqlen: u32 = @intCast(16 + 12 + attr_len);
    std.mem.writeInt(u32, req[0..4], reqlen, .native);
    std.mem.writeInt(u16, req[4..6], 26, .native); // RTM_GETROUTE
    std.mem.writeInt(u16, req[6..8], linux.NLM_F_REQUEST, .native);
    std.mem.writeInt(u32, req[8..12], 1, .native);
    std.mem.writeInt(u32, req[12..16], pid, .native);
    req[16] = family;
    req[17] = if (family == linux.AF.INET) 32 else 128; // dst_len
    var kaddr = SockAddrNl{};
    std.mem.writeInt(u16, req[28..30], @intCast(attr_len), .native);
    std.mem.writeInt(u16, req[30..32], 1, .native); // RTA_DST
    @memcpy(req[32..][0..dst.len], dst);
    const sent = linux.sendto(fd, &req, reqlen, 0, @ptrCast(&kaddr), @sizeOf(SockAddrNl));
    if (failed(sent) or sent != reqlen) return Error.SendFailed;
    var reply: [4096]u8 = undefined;
    const n = linux.recvfrom(fd, &reply, reply.len, 0, null, null);
    if (failed(n) or n < 16) return Error.RecvFailed;
    const mtype = std.mem.readInt(u16, reply[4..6], .native);
    if (mtype == 2) return Error.NoGateway; // NLMSG_ERROR: no route
    if (mtype != 24) return Error.RecvFailed; // RTM_NEWROUTE
    const mlen: usize = std.mem.readInt(u32, reply[0..4], .native);
    if (mlen < 28 or mlen > n) return Error.RecvFailed;
    var found_gw = false;
    var found_local = false;
    var aoff: usize = 28; // past nlmsghdr + rtmsg
    const aend = mlen;
    while (aoff + 4 <= aend) {
        const alen: usize = std.mem.readInt(u16, reply[aoff..][0..2], .native);
        const atype = std.mem.readInt(u16, reply[aoff..][2..4], .native);
        if (alen < 4 or aoff + alen > aend) break;
        const val = reply[aoff + 4 .. aoff + alen];
        if (atype == 5 and val.len == gw_out.len) { // RTA_GATEWAY
            @memcpy(gw_out, val);
            found_gw = true;
        } else if (atype == 7 and val.len == local_out.len) { // RTA_PREFSRC
            @memcpy(local_out, val);
            found_local = true;
        } else if (atype == 4 and val.len == 4) { // RTA_OIF
            ifindex_out.* = std.mem.readInt(u32, val[0..4], .native);
        }
        aoff += (alen + 3) & ~@as(usize, 3);
    }
    if (!found_gw) return Error.NoGateway;
    if (!found_local) return Error.NoGateway;
}

/// Port of defaultRouteProbe4 + Route: gateway and source for 0.0.0.1.
pub fn defaultRouteV4() Error!Route4 {
    var gw: [4]u8 = undefined;
    var local: [4]u8 = undefined;
    var ifindex: u32 = 0;
    const dst = [_]u8{ 0, 0, 0, 1 };
    try queryRoute(linux.AF.INET, &dst, &gw, &local, &ifindex);
    return .{ .gateway = gw, .local = local };
}

/// Port of defaultRouteProbe6 + Route: gateway, source and ifindex for ::2.
pub fn defaultRouteV6() Error!Route6 {
    var gw: [16]u8 = undefined;
    var local: [16]u8 = undefined;
    var ifindex: u32 = 0;
    const dst = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };
    try queryRoute(linux.AF.INET6, &dst, &gw, &local, &ifindex);
    return .{ .gateway = gw, .local = local, .ifindex = ifindex };
}
