// DNS server listeners: UDP + TCP on one address, queries dispatched through
// the handler chain. Port of the netbird client/internal/dns serving surface
// used on Linux (server.go, service_listener.go, tcpstack.go subset;
// v0.79.0, BSD-3-Clause — upstream delegates the sockets to miekg/dns):
// - a datagram with no question is dropped
// - a reply larger than the client's advertised EDNS0 size (or 512 bytes)
//   is truncated: TC bit, question + OPT only (miekg Msg.Truncate subset)
// - TCP is 2-byte length-prefixed, no truncation below 64 KiB
// Raw syscalls only (socket/bind/listen/accept4/recvfrom/sendto/poll —
// all pre-4.9).

const std = @import("std");
const linux = std.os.linux;
const msg = @import("msg.zig");
const chain_mod = @import("chain.zig");

pub const default_udp_size: u16 = 512; // RFC 1035 when no EDNS0
pub const poll_slice_ms: i32 = 100; // stop-latency of serveLoop

fn failed(rc: usize) bool {
    return rc > 0xfffffffffffff000;
}

pub const Error = msg.Error || error{
    SocketFailed,
    BindFailed,
    ListenFailed,
    RecvFailed,
    SendFailed,
    AcceptFailed,
    Timeout,
    BadQuery,
};

pub const Server = struct {
    chain: *chain_mod.Chain,
    udp_fd: linux.fd_t,
    tcp_fd: linux.fd_t,
    stop_flag: std.atomic.Value(bool) = .init(false),

    /// Bind UDP and TCP listeners on `addr` (port 0 lets the kernel choose,
    /// read it back with localPort()). Both listeners share one port: the TCP
    /// socket binds to the port the kernel gave the UDP socket.
    pub fn bind(addr: std.Io.net.IpAddress, chain: *chain_mod.Chain) Error!Server {
        const domain: u32 = switch (addr) {
            .ip4 => linux.AF.INET,
            .ip6 => linux.AF.INET6,
        };

        const udp_usize = linux.socket(domain, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
        if (failed(udp_usize)) return Error.SocketFailed;
        const udp_fd: linux.fd_t = @intCast(udp_usize);
        errdefer _ = linux.close(udp_fd);
        try bindAddr(udp_fd, addr);

        var bind_addr = addr;
        const requested_any = switch (bind_addr) {
            .ip4 => |a| a.port == 0,
            .ip6 => |a| a.port == 0,
        };
        if (requested_any) {
            var got: linux.sockaddr.in6 align(@alignOf(linux.sockaddr.in6)) = undefined;
            var glen: linux.socklen_t = @sizeOf(linux.sockaddr.in6);
            if (failed(linux.getsockname(udp_fd, @ptrCast(&got), &glen))) return Error.BindFailed;
            const udp_port = switch (got.family) {
                linux.AF.INET => blk: {
                    const sa_in: *const linux.sockaddr.in = @ptrCast(&got);
                    break :blk std.mem.bigToNative(u16, sa_in.port);
                },
                else => blk: {
                    const sa_in6: *const linux.sockaddr.in6 = @ptrCast(&got);
                    break :blk std.mem.bigToNative(u16, sa_in6.port);
                },
            };
            switch (bind_addr) {
                .ip4 => |*a| a.port = udp_port,
                .ip6 => |*a| a.port = udp_port,
            }
        }

        const tcp_usize = linux.socket(domain, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
        if (failed(tcp_usize)) return Error.SocketFailed;
        const tcp_fd: linux.fd_t = @intCast(tcp_usize);
        errdefer _ = linux.close(tcp_fd);
        const one: i32 = 1;
        _ = linux.setsockopt(tcp_fd, linux.SOL.SOCKET, linux.SO.REUSEADDR, std.mem.asBytes(&one), @sizeOf(i32));
        try bindAddr(tcp_fd, bind_addr);
        if (failed(linux.listen(tcp_fd, 16))) return Error.ListenFailed;

        return .{ .chain = chain, .udp_fd = udp_fd, .tcp_fd = tcp_fd };
    }

    fn bindAddr(fd: linux.fd_t, addr: std.Io.net.IpAddress) Error!void {
        var sa_buf: [@sizeOf(linux.sockaddr.in6)]u8 align(@alignOf(linux.sockaddr.in6)) = undefined;
        const sa_len: linux.socklen_t = switch (addr) {
            .ip4 => |a| blk: {
                const sa: *linux.sockaddr.in = @ptrCast(@alignCast(&sa_buf));
                sa.family = linux.AF.INET;
                sa.port = std.mem.nativeToBig(u16, a.port);
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
        if (failed(linux.bind(fd, @ptrCast(&sa_buf), sa_len))) return Error.BindFailed;
    }

    pub fn close(s: *Server) void {
        _ = linux.close(s.udp_fd);
        _ = linux.close(s.tcp_fd);
        s.udp_fd = -1;
        s.tcp_fd = -1;
    }

    /// The bound port (getsockname) — for port-0 binds in tests.
    pub fn localPort(s: *Server) !u16 {
        var sa: linux.sockaddr.in = undefined;
        var len: linux.socklen_t = @sizeOf(linux.sockaddr.in);
        if (failed(linux.getsockname(s.udp_fd, @ptrCast(&sa), &len))) return Error.SocketFailed;
        return std.mem.bigToNative(u16, sa.port);
    }

    pub fn requestStop(s: *Server) void {
        s.stop_flag.store(true, .release);
    }

    /// Serve until requestStop(); polls both listeners, handles queries
    /// inline (one caller thread — the router runs one resolver loop).
    pub fn serveLoop(s: *Server) void {
        while (!s.stop_flag.load(.acquire)) {
            _ = s.serveOnce(1000) catch continue;
        }
    }

    /// Wait for and handle one query (UDP datagram or TCP connection).
    /// `timeout_ms` bounds the poll wait; returns false when nothing arrived.
    pub fn serveOnce(s: *Server, timeout_ms: i32) Error!bool {
        var pfds = [_]linux.pollfd{
            .{ .fd = s.udp_fd, .events = linux.POLL.IN, .revents = 0 },
            .{ .fd = s.tcp_fd, .events = linux.POLL.IN, .revents = 0 },
        };
        const n = linux.poll(&pfds, 2, timeout_ms);
        if (failed(n)) return Error.RecvFailed;
        if (n == 0) return false;

        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();

        if (pfds[0].revents & linux.POLL.IN != 0) {
            try s.handleUdp(arena.allocator());
            return true;
        }
        if (pfds[1].revents & linux.POLL.IN != 0) {
            try s.handleTcp(arena.allocator());
            return true;
        }
        return false;
    }

    fn handleUdp(s: *Server, arena: std.mem.Allocator) Error!void {
        var client_sa: [128]u8 align(@alignOf(linux.sockaddr.in6)) = undefined;
        var client_len: linux.socklen_t = client_sa.len;
        const buf = try arena.alloc(u8, 65535);
        const n = linux.recvfrom(s.udp_fd, buf.ptr, buf.len, 0, @ptrCast(&client_sa), &client_len);
        if (failed(n) or n == 0) return Error.RecvFailed;
        const raw = buf[0..n];

        const query = msg.unpack(arena, raw) catch return; // malformed → drop
        if (query.question.len == 0) return; // nothing to answer

        const result = try s.chain.dispatch(arena, &query, .udp);
        const reply = switch (result) {
            .drop => return,
            .response => |m| m,
        };

        const out_buf = try arena.alloc(u8, 65535);
        var packed_reply = msg.pack(arena, &reply, out_buf) catch |err| switch (err) {
            error.NoSpaceLeft => blk: {
                // should not happen with a 64 KiB buffer, but keep the TC path
                var tc = reply;
                tc.header.truncated = true;
                tc.answer = &.{};
                tc.ns = &.{};
                break :blk try msg.pack(arena, &tc, out_buf);
            },
            else => |e| return e,
        };

        // UDP size cap: truncate to the client's advertised EDNS0 size
        const max_size: usize = if (query.isEdns0()) |opt| @max(opt.class, @as(u16, 512)) else default_udp_size;
        if (packed_reply.len > max_size) {
            var tc = reply;
            tc.header.truncated = true;
            tc.answer = &.{};
            tc.ns = &.{};
            packed_reply = try msg.pack(arena, &tc, out_buf);
        }

        const dest: *const linux.sockaddr = @ptrCast(@alignCast(&client_sa));
        const sent = linux.sendto(s.udp_fd, packed_reply.ptr, packed_reply.len, 0, dest, client_len);
        if (failed(sent)) return Error.SendFailed;
    }

    fn handleTcp(s: *Server, arena: std.mem.Allocator) Error!void {
        const conn_usize = linux.accept4(s.tcp_fd, null, null, linux.SOCK.CLOEXEC);
        if (failed(conn_usize)) return Error.AcceptFailed;
        const conn: linux.fd_t = @intCast(conn_usize);
        defer _ = linux.close(conn);

        const len_hdr = try readExact(arena, conn, 2);
        const qlen = std.mem.readInt(u16, len_hdr[0..2], .big);
        const raw = try readExact(arena, conn, qlen);

        const query = msg.unpack(arena, raw) catch return Error.BadQuery;
        if (query.question.len == 0) return;

        const result = try s.chain.dispatch(arena, &query, .tcp);
        const reply = switch (result) {
            .drop => return,
            .response => |m| m,
        };

        const out_buf = try arena.alloc(u8, 65535);
        const packed_reply = try msg.pack(arena, &reply, out_buf);
        var framed: [2]u8 = undefined;
        std.mem.writeInt(u16, &framed, @intCast(packed_reply.len), .big);

        var sent = linux.write(conn, &framed, 2);
        if (failed(sent) or sent != 2) return Error.SendFailed;
        sent = linux.write(conn, packed_reply.ptr, packed_reply.len);
        if (failed(sent) or sent != packed_reply.len) return Error.SendFailed;
    }

    fn readExact(arena: std.mem.Allocator, fd: linux.fd_t, want: usize) Error![]u8 {
        const out = try arena.alloc(u8, want);
        var got: usize = 0;
        while (got < want) {
            var pfd = [_]linux.pollfd{.{ .fd = fd, .events = linux.POLL.IN }};
            const prc = linux.poll(&pfd, 1, 5000);
            if (failed(prc)) return Error.RecvFailed;
            if (prc == 0) return Error.Timeout;
            const n = linux.recvfrom(fd, out.ptr + got, want - got, 0, null, null);
            if (failed(n)) return Error.RecvFailed;
            if (n == 0) return Error.BadQuery; // EOF mid-message
            got += n;
        }
        return out;
    }
};
