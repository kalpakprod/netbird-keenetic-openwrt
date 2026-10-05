// Port of netbird client/internal/dns/upstream.go (v0.80.0), BSD-3-Clause —
// the M7 subset: one ordered upstream list (a single "race" group — servers
// tried in order, the next only on failure), per-upstream timeout, UDP
// exchange with TCP retry on truncation (ExchangeWithFallback), TCP straight
// away when the request came in over TCP, EDNS0 advertised upstream and the
// OPT record stripped from the reply when the client sent none.
//
// Not ported (later milestones): multi-group racing of overlapping
// nameserver groups, UpstreamHealth projection,
// tunnel-bound client routing.

const std = @import("std");
const linux = std.os.linux;
const msg = @import("msg.zig");
const chain_mod = @import("chain.zig");
const Mutex = @import("mutex.zig").Mutex;

pub const upstream_timeout_ms: u32 = 4000; // UpstreamTimeout
pub const client_timeout_ms: u32 = 5000; // ClientTimeout, > upstream timeout
pub const default_mtu: u16 = 1280;
pub const advertised_udp_size: u16 = default_mtu - 68;

pub const rcode_servfail: u16 = 2;
pub const rcode_refused: u16 = 5;

fn failed(rc: usize) bool {
    return rc > 0xfffffffffffff000;
}

pub const Error = error{
    SocketFailed,
    SendFailed,
    RecvFailed,
    ConnectFailed,
    Timeout,
    BadResponse,
    IdMismatch,
} || msg.Error;

pub const Upstream = struct {
    alloc: std.mem.Allocator,
    mu: Mutex = .{},
    servers: std.ArrayListUnmanaged(std.Io.net.IpAddress) = .empty,
    timeout_ms: u32 = upstream_timeout_ms,
    mtu: u16 = default_mtu,

    pub fn init(alloc: std.mem.Allocator) Upstream {
        return .{ .alloc = alloc };
    }

    pub fn deinit(u: *Upstream) void {
        u.servers.deinit(u.alloc);
    }

    /// Add one upstream; order matters — the first is tried first, later
    /// entries are fallbacks.
    pub fn addServer(u: *Upstream, addr: std.Io.net.IpAddress) !void {
        u.mu.lock();
        defer u.mu.unlock();
        try u.servers.append(u.alloc, addr);
    }

    pub fn serverCount(u: *Upstream) usize {
        u.mu.lock();
        defer u.mu.unlock();
        return u.servers.items.len;
    }

    /// chain.Handler adapter (Go upstreamResolverBase: MatchSubdomains true).
    pub fn handler(u: *Upstream) chain_mod.Handler {
        return .{ .ctx = u, .match_subdomains = true, .serveFn = serveFn };
    }

    fn serveFn(ctx: *anyopaque, arena: std.mem.Allocator, req: *const msg.Message, transport: chain_mod.Transport) chain_mod.ServeError!chain_mod.Outcome {
        const u: *Upstream = @ptrCast(@alignCast(ctx));

        u.mu.lock();
        const servers = u.servers.items;
        const timeout_ms = u.timeout_ms;
        u.mu.unlock();

        // tryUpstreamServers, single-race form: walk in order, fail over on
        // transport error, timeout, no response, SERVFAIL and REFUSED.
        for (servers) |srv| {
            var res = u.exchange(arena, srv, req, transport, timeout_ms) catch continue;
            if (!res.header.response) continue; // not a response
            // Valid SERVFAIL/REFUSED are reachable per-question outcomes.
            // Health projection is separate; retry unless EDE is definitive.
            if ((res.header.rcode == rcode_servfail or res.header.rcode == rcode_refused) and !nonRetryableEde(&res)) continue;
            // clear the Zero bit: upstream servers must not be able to
            // trigger our internal fallthrough signaling (writeSuccessResponse)
            res.header.zero = false;
            if (req.isEdns0() == null) stripOpt(arena, &res);
            return .{ .response = res };
        }
        // writeErrorResponse: all upstreams failed
        var fail = msg.Message{};
        fail.setRcode(req, rcode_servfail);
        return .{ .response = fail };
    }

    /// One upstream exchange: pack (+EDNS0), UDP, TCP retry on truncation.
    /// Errors are upstream failures (fail over); a parsed reply is returned.
    pub fn exchange(u: *Upstream, arena: std.mem.Allocator, addr: std.Io.net.IpAddress, req: *const msg.Message, transport: chain_mod.Transport, timeout_ms: u32) Error!msg.Message {
        const udp_size: u16 = if (u.mtu > 68) u.mtu - 68 else 512;
        // Advertise EDNS0 so the upstream may send EDE and large replies
        // (Go queryUpstream SetEdns0); strip it again on the way back when
        // the client had none.
        const had_edns = req.isEdns0() != null;
        var q = req.*;
        if (!had_edns) {
            const extra = try arena.alloc(msg.RR, 1);
            extra[0] = msg.makeOpt(udp_size, false);
            q.extra = extra;
        }
        // queryUpstream adds OPT before ExchangeWithFallback computes this limit.
        const client_max = q.isEdns0().?.class;
        if (transport == .udp) {
            const extra = try arena.dupe(msg.RR, q.extra);
            for (extra) |*rr| {
                if (rr.type == .opt and rr.class > udp_size) rr.class = udp_size;
            }
            q.extra = extra;
        }
        const wire_buf = try arena.alloc(u8, 16384);
        const wire = try msg.pack(arena, &q, wire_buf);

        switch (transport) {
            .tcp => return exchangeTcp(arena, addr, wire, timeout_ms),
            .udp => {
                const res = try exchangeUdp(arena, addr, wire, timeout_ms);
                if (res.header.truncated) {
                    var retried = try exchangeTcp(arena, addr, wire, timeout_ms);
                    try truncateReply(arena, &retried, client_max);
                    return retried;
                }
                return res;
            },
        }
    }

    fn unpackReply(arena: std.mem.Allocator, raw: []const u8) Error!msg.Message {
        const parsed = try msg.unpack(arena, raw);
        if (!parsed.header.response) return Error.BadResponse;
        return parsed;
    }

    fn exchangeUdp(arena: std.mem.Allocator, addr: std.Io.net.IpAddress, wire: []const u8, timeout_ms: u32) Error!msg.Message {
        const domain: u32 = switch (addr) {
            .ip4 => linux.AF.INET,
            .ip6 => linux.AF.INET6,
        };
        const sock_usize = linux.socket(domain, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
        if (failed(sock_usize)) return Error.SocketFailed;
        const sock: linux.fd_t = @intCast(sock_usize);
        defer _ = linux.close(sock);

        // Connected UDP accepts datagrams only from the selected upstream.
        try connectNonblock(sock, addr, timeout_ms);
        const sent = linux.write(sock, wire.ptr, wire.len);
        if (failed(sent) or sent != wire.len) return Error.SendFailed;
        var start: linux.timespec = undefined;
        _ = linux.clock_gettime(linux.CLOCK.MONOTONIC, &start);
        const deadline = @as(i128, start.sec) * 1000 + @divTrunc(start.nsec, 1000000) + timeout_ms;
        const resp = try arena.alloc(u8, 65535);
        while (true) {
            var now: linux.timespec = undefined;
            _ = linux.clock_gettime(linux.CLOCK.MONOTONIC, &now);
            const remaining = deadline - (@as(i128, now.sec) * 1000 + @divTrunc(now.nsec, 1000000));
            if (remaining <= 0) return Error.Timeout;
            var pfd = [_]linux.pollfd{.{ .fd = sock, .events = linux.POLL.IN }};
            const prc = linux.poll(&pfd, 1, @intCast(remaining));
            if (failed(prc)) return Error.RecvFailed;
            if (prc == 0) return Error.Timeout;
            const n = linux.recvfrom(sock, resp.ptr, resp.len, 0, null, null);
            if (failed(n) or n == 0) return Error.RecvFailed;
            const parsed = try unpackReply(arena, resp[0..n]);
            if (parsed.header.id != std.mem.readInt(u16, wire[0..2], .big)) continue;
            return parsed;
        }
    }

    fn exchangeTcp(arena: std.mem.Allocator, addr: std.Io.net.IpAddress, wire: []const u8, timeout_ms: u32) Error!msg.Message {
        const domain: u32 = switch (addr) {
            .ip4 => linux.AF.INET,
            .ip6 => linux.AF.INET6,
        };
        const sock_usize = linux.socket(domain, linux.SOCK.STREAM | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK, 0);
        if (failed(sock_usize)) return Error.SocketFailed;
        const sock: linux.fd_t = @intCast(sock_usize);
        defer _ = linux.close(sock);

        // nonblocking connect + poll (works on kernel 4.9, no ETIMEDOUT race)
        try connectNonblock(sock, addr, timeout_ms);

        // 2-byte length prefix framing
        var framed_len: [2]u8 = undefined;
        std.mem.writeInt(u16, &framed_len, @intCast(wire.len), .big);
        var pfd = [_]linux.pollfd{.{ .fd = sock, .events = linux.POLL.OUT }};
        const wrc = linux.poll(&pfd, 1, @intCast(timeout_ms));
        if (failed(wrc) or wrc == 0) return Error.Timeout;
        const n1 = linux.write(sock, &framed_len, 2);
        if (failed(n1) or n1 != 2) return Error.SendFailed;
        const n2 = linux.write(sock, wire.ptr, wire.len);
        if (failed(n2) or n2 != wire.len) return Error.SendFailed;

        const len_hdr = try readExact(arena, sock, 2, timeout_ms);
        const resp_len = std.mem.readInt(u16, len_hdr[0..2], .big);
        const resp = try readExact(arena, sock, resp_len, timeout_ms);
        const parsed = try unpackReply(arena, resp);
        if (parsed.header.id != std.mem.readInt(u16, wire[0..2], .big)) return Error.IdMismatch;
        return parsed;
    }

    fn readExact(arena: std.mem.Allocator, sock: linux.fd_t, want: usize, timeout_ms: u32) Error![]u8 {
        const out = try arena.alloc(u8, want);
        var got: usize = 0;
        while (got < want) {
            var pfd = [_]linux.pollfd{.{ .fd = sock, .events = linux.POLL.IN }};
            const prc = linux.poll(&pfd, 1, @intCast(timeout_ms));
            if (failed(prc)) return Error.RecvFailed;
            if (prc == 0) return Error.Timeout;
            const n = linux.recvfrom(sock, out.ptr + got, want - got, 0, null, null);
            if (failed(n)) return Error.RecvFailed;
            if (n == 0) return Error.BadResponse; // EOF mid-message
            got += n;
        }
        return out;
    }
};

fn connectNonblock(sock: linux.fd_t, addr: std.Io.net.IpAddress, timeout_ms: u32) Error!void {
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
    const rc = linux.connect(sock, @ptrCast(&sa_buf), sa_len);
    if (rc == 0) return;
    if (linux.errno(rc) != .INPROGRESS) return Error.ConnectFailed;
    var pfd = [_]linux.pollfd{.{ .fd = sock, .events = linux.POLL.OUT }};
    const prc = linux.poll(&pfd, 1, @intCast(timeout_ms));
    if (failed(prc) or prc == 0) return Error.Timeout;
    var so_err: i32 = 0;
    var optlen: linux.socklen_t = @sizeOf(i32);
    const grc = linux.getsockopt(sock, linux.SOL.SOCKET, linux.SO.ERROR, @ptrCast(&so_err), &optlen);
    if (failed(grc) or so_err != 0) return Error.ConnectFailed;
}

fn sendToAddr(sock: linux.fd_t, addr: std.Io.net.IpAddress, wire: []const u8) Error!void {
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
    const dest: *const linux.sockaddr = @ptrCast(@alignCast(&sa_buf));
    const sent = linux.sendto(sock, wire.ptr, wire.len, 0, dest, sa_len);
    if (failed(sent) or sent != wire.len) return Error.SendFailed;
}

/// Remove the OPT pseudo-record from extra (Go resutil.StripOPT).
pub fn stripOpt(arena: std.mem.Allocator, m: *msg.Message) void {
    var kept: usize = 0;
    for (m.extra) |rr| {
        if (rr.type != .opt) kept += 1;
    }
    if (kept == m.extra.len) return;
    const out = arena.alloc(msg.RR, kept) catch return;
    var i: usize = 0;
    for (m.extra) |rr| {
        if (rr.type != .opt) {
            out[i] = rr;
            i += 1;
        }
    }
    m.extra = out;
}

fn nonRetryableEde(response: *const msg.Message) bool {
    const opt = response.isEdns0() orelse return false;
    for (opt.data.opt) |option| {
        if (option.code != 15 or option.data.len < 2) continue;
        const code = std.mem.readInt(u16, option.data[0..2], .big);
        switch (code) {
            1, 2, 5...12, 15...18 => return true,
            else => {},
        }
    }
    return false;
}

// miekg Msg.Truncate: retain ordered prefixes, reserve OPT, stop at first
// overflowing record, and preserve TC. Codec packing supplies compression.
fn truncateReply(arena: std.mem.Allocator, response: *msg.Message, requested: u16) Error!void {
    const limit = @max(@as(usize, 512), requested);
    const buf = try arena.alloc(u8, 65535);
    if ((try msg.pack(arena, response, buf)).len <= limit) return;
    const original = response.*;
    const opt = original.isEdns0();
    response.answer = &.{};
    response.ns = &.{};
    response.extra = if (opt) |rr| try arena.dupe(msg.RR, &.{rr.*}) else &.{};
    var overflow = false;
    for ([_][]const msg.RR{original.answer, original.ns, original.extra}, 0..) |records, section| {
        if (overflow) break;
        var kept: std.ArrayListUnmanaged(msg.RR) = .empty;
        for (records) |rr| {
            if (section == 2 and rr.type == .opt) continue;
            try kept.append(arena, rr);
            const previous = response.*;
            switch (section) {
                0 => response.answer = kept.items,
                1 => response.ns = kept.items,
                2 => {
                    const extra = try arena.alloc(msg.RR, kept.items.len + @as(usize, if (opt != null) 1 else 0));
                    @memcpy(extra[0..kept.items.len], kept.items);
                    if (opt) |o| extra[kept.items.len] = o.*;
                    response.extra = extra;
                },
                else => unreachable,
            }
            if ((try msg.pack(arena, response, buf)).len > limit) {
                response.* = previous;
                overflow = true;
                break;
            }
        }
    }
    response.header.truncated = true;
}
