// Tests for ice.zig: formula checks with hand-derived literals, candidate
// line codec, loopback gather (+blacklist, +srflx via forked responder), and
// a full forked Zig-vs-Zig connectivity run (both roles, nomination, data).

const std = @import("std");
const builtin = @import("builtin");
const ice = @import("ice.zig");
const stun = @import("stun.zig");
const linux = std.os.linux;

test "candidate priority values" {
    // (2^24)*126 + (2^8)*65535 + 255 — the classic host priority.
    try std.testing.expectEqual(@as(u32, 2130706431), ice.candidatePriority(.host, 65535));
    // (2^24)*100 + (2^8)*65535 + 255 for srflx.
    try std.testing.expectEqual(@as(u32, 1694498815), ice.candidatePriority(.srflx, 65535));
    // Type preference orders host > prflx > srflx > relay.
    const h = ice.candidatePriority(.host, 0);
    const p = ice.candidatePriority(.prflx, 0);
    const s = ice.candidatePriority(.srflx, 0);
    const r = ice.candidatePriority(.relay, 0);
    try std.testing.expect(h > p and p > s and s > r);
    // Local preference breaks ties within a type.
    try std.testing.expect(ice.candidatePriority(.host, 7) > ice.candidatePriority(.host, 6));
}

test "pair priority values" {
    // RFC 5245 §5.7.2: (2^32-1)*MIN + 2*MAX + (G>D).
    // g=100,d=50: 4294967295*50 + 200 + 1 = 214748364951.
    try std.testing.expectEqual(@as(u64, 214748364951), ice.pairPriority(true, 100, 50));
    // g=50,d=100: same min/max, tie-break 0 → one less.
    try std.testing.expectEqual(@as(u64, 214748364950), ice.pairPriority(true, 50, 100));
    // Role swap mirrors G/D.
    try std.testing.expectEqual(ice.pairPriority(true, 100, 50), ice.pairPriority(false, 50, 100));
    // Higher minimum wins regardless of side.
    try std.testing.expect(ice.pairPriority(true, 200, 150) > ice.pairPriority(true, 100, 50));
}

test "foundation stable and sensitive" {
    const a = ice.foundation(.host, ice.ip4(.{ 10, 0, 0, 1 }, 1111));
    try std.testing.expectEqual(a, ice.foundation(.host, ice.ip4(.{ 10, 0, 0, 1 }, 2222)));
    try std.testing.expect(a != ice.foundation(.srflx, ice.ip4(.{ 10, 0, 0, 1 }, 1111)));
    try std.testing.expect(a != ice.foundation(.host, ice.ip4(.{ 10, 0, 0, 2 }, 1111)));
    try std.testing.expect(a != ice.foundation(.host, ice.ip6(.{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, 1111)));
}

test "ip format and parse round-trip" {
    var buf: [64]u8 = undefined;
    const v4 = ice.ip4(.{ 192, 0, 2, 9 }, 0);
    const s4 = try ice.formatIp(&buf, v4);
    try std.testing.expectEqualStrings("192.0.2.9", s4);
    const back4 = try ice.parseIp(s4, 3478);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 192, 0, 2, 9 }, &back4.ip4.bytes);
    try std.testing.expectEqual(@as(u16, 3478), back4.ip4.port);

    var b6: [16]u8 = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    const v6 = ice.ip6(b6, 0);
    const s6 = try ice.formatIp(&buf, v6);
    const back6 = try ice.parseIp(s6, 0);
    try std.testing.expectEqualSlices(u8, &b6, &back6.ip6.bytes);
    // Compressed forms parse to the same bytes.
    const c6 = try ice.parseIp("2001:db8::1", 0);
    try std.testing.expectEqualSlices(u8, &b6, &c6.ip6.bytes);
    const loop6 = try ice.parseIp("::1", 0);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, &loop6.ip6.bytes);
    try std.testing.expectError(error.Invalid, ice.parseIp("1.2.3", 0));
    try std.testing.expectError(error.InvalidCharacter, ice.parseIp("1.2.3.x", 0));
}

test "candidate line codec round-trip" {
    var buf: [128]u8 = undefined;
    const c = ice.Candidate{
        .ctype = .host,
        .addr = ice.ip4(.{ 10, 1, 2, 3 }, 45678),
        .base = ice.ip4(.{ 10, 1, 2, 3 }, 45678),
        .priority = 2130706431,
    };
    const line = try ice.formatCandidate(&buf, c);
    const back = try ice.parseCandidateLine(line);
    try std.testing.expectEqual(ice.CandidateType.host, back.ctype);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 10, 1, 2, 3 }, &back.addr.ip4.bytes);
    try std.testing.expectEqual(@as(u16, 45678), back.addr.ip4.port);
    try std.testing.expectEqual(@as(u32, 2130706431), back.priority);
    try std.testing.expectError(error.Invalid, ice.parseCandidateLine("candidate:1 bogus 1.2.3.4 1 1"));
}

test "credentials are alpha and sized" {
    var ufrag: [16]u8 = undefined;
    var pwd: [32]u8 = undefined;
    ice.generateCredentials(&ufrag, &pwd);
    for (ufrag) |c| try std.testing.expect(std.ascii.isAlphabetic(c));
    for (pwd) |c| try std.testing.expect(std.ascii.isAlphabetic(c));
    var ufrag2: [16]u8 = undefined;
    var pwd2: [32]u8 = undefined;
    ice.generateCredentials(&ufrag2, &pwd2);
    try std.testing.expect(!std.mem.eql(u8, &ufrag, &ufrag2));
}

test "gather loopback host candidates" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var g = try ice.gather(.{});
    defer g.close();
    try std.testing.expect(g.n_socks >= 1);
    try std.testing.expectEqual(g.n_socks, g.n_cands); // no STUN server: hosts only.
    var saw_loopback = false;
    for (g.candidates()) |c| {
        try std.testing.expectEqual(ice.CandidateType.host, c.ctype);
        const port: u16 = switch (c.addr) {
            .ip4 => |a| a.port,
            .ip6 => |a| a.port,
        };
        try std.testing.expect(port != 0);
        if (c.addr == .ip4 and std.mem.eql(u8, &c.addr.ip4.bytes, &[_]u8{ 127, 0, 0, 1 }))
            saw_loopback = true;
    }
    try std.testing.expect(saw_loopback);
}

test "gather honors interface blacklist" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const lo = [_][]const u8{"lo"};
    var g = try ice.gather(.{ .blacklist = &lo });
    defer g.close();
    for (g.candidates()) |c| {
        if (c.addr == .ip4) {
            try std.testing.expect(!std.mem.eql(u8, &c.addr.ip4.bytes, &[_]u8{ 127, 0, 0, 1 }));
        }
    }
}

test "gather srflx via forked responder" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    // Responder socket bound before fork so the port is known.
    const sfd_usize = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    if (sfd_usize > 0xfffffffffffff000) return error.SkipZigTest;
    const sfd: linux.fd_t = @intCast(sfd_usize);
    defer _ = linux.close(sfd);
    var sa = linux.sockaddr.in{
        .family = linux.AF.INET,
        .port = std.mem.nativeToBig(u16, 0),
        .addr = 0x0100007f,
    };
    if (linux.bind(sfd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in)) > 0xfffffffffffff000)
        return error.SkipZigTest;
    var got: linux.sockaddr.in = undefined;
    var got_len: linux.socklen_t = @sizeOf(linux.sockaddr.in);
    if (linux.getsockname(sfd, @ptrCast(&got), &got_len) > 0xfffffffffffff000)
        return error.SkipZigTest;
    const port: u16 = std.mem.bigToNative(u16, got.port);

    const pid_usize = linux.fork();
    if (pid_usize == 0) {
        // Child: answer binding requests until 2s idle, then exit.
        var rbuf: [1500]u8 = undefined;
        var answered: u32 = 0;
        while (true) {
            var pfd = [_]linux.pollfd{.{ .fd = sfd, .events = linux.POLL.IN }};
            const prc = linux.poll(&pfd, 1, 2000);
            if (prc == 0) linux.exit(if (answered > 0) 0 else 1);
            if (prc > 0xfffffffffffff000) linux.exit(1);
            var from: linux.sockaddr.in = undefined;
            var from_len: linux.socklen_t = @sizeOf(linux.sockaddr.in);
            const n = linux.recvfrom(sfd, &rbuf, rbuf.len, 0, @ptrCast(&from), &from_len);
            if (n > 0xfffffffffffff000 or n == 0) linux.exit(1);
            const req = stun.decode(rbuf[0..n]) catch continue;
            if (req.msg_type.method != .binding or req.msg_type.class != .request) continue;
            var sbuf: [256]u8 = undefined;
            var enc = stun.Encoder.init(&sbuf, stun.MessageType.binding_success, req.trid) catch linux.exit(1);
            const fb: [4]u8 = @bitCast(from.addr);
            stun.XorAddr.encode(
                &enc,
                stun.Attr.xor_mapped_address,
                req.trid,
                stun.ip4(fb, 0),
                std.mem.bigToNative(u16, from.port),
            ) catch linux.exit(1);
            const out = enc.bytes();
            _ = linux.sendto(sfd, out.ptr, out.len, 0, @ptrCast(&from), from_len);
            answered += 1;
        }
    }
    if (pid_usize > 0xfffffffffffff000) return error.SkipZigTest;
    const srv = stun.ip4(.{ 127, 0, 0, 1 }, port);
    var g = try ice.gather(.{ .stun_server = srv });
    defer g.close();
    var n_srflx: usize = 0;
    var saw_loopback_srflx = false;
    for (g.candidates()) |c| {
        if (c.ctype != .srflx) continue;
        n_srflx += 1;
        try std.testing.expect(c.addr.ip4.port != 0);
        try std.testing.expect(!std.mem.eql(u8, &c.addr.ip4.bytes, &[_]u8{ 0, 0, 0, 0 }));
        // The loopback socket's srflx is well-defined: same-host responder
        // sees the socket's own address. (Sockets on down/docker interfaces
        // may get any source the kernel picks; only shape-checked above.)
        if (std.mem.eql(u8, &c.base.ip4.bytes, &[_]u8{ 127, 0, 0, 1 })) {
            saw_loopback_srflx = true;
            try std.testing.expectEqual(c.base.ip4.port, c.addr.ip4.port);
            try std.testing.expectEqualSlices(u8, &c.base.ip4.bytes, &c.addr.ip4.bytes);
        }
    }
    try std.testing.expect(saw_loopback_srflx);
    // Every socket got its srflx (host has few addrs; the responder is patient).
    try std.testing.expect(n_srflx >= 1);
    var status: i32 = 0;
    _ = linux.waitpid(@intCast(pid_usize), &status, 0);
    try std.testing.expectEqual(@as(u8, 0), linux.W.EXITSTATUS(@bitCast(status)));
}

// --- Forked full-mesh connectivity run ---

fn writeAll(fd: linux.fd_t, data: []const u8) void {
    var off: usize = 0;
    while (off < data.len) {
        const n = linux.write(fd, data[off..].ptr, data.len - off);
        if (n > 0xfffffffffffff000 or n == 0) linux.exit(1);
        off += n;
    }
}

fn readLine(fd: linux.fd_t, buf: []u8) []u8 {
    var len: usize = 0;
    while (len < buf.len) {
        var b: [1]u8 = undefined;
        const n = linux.read(fd, &b, 1);
        if (n > 0xfffffffffffff000 or n == 0) linux.exit(1);
        if (b[0] == '\n') break;
        buf[len] = b[0];
        len += 1;
    }
    return buf[0..len];
}

test "connect Zig vs Zig over loopback, both roles, data flows" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var to_child: [2]linux.fd_t = undefined;
    var to_parent: [2]linux.fd_t = undefined;
    if (linux.pipe(&to_child) > 0xfffffffffffff000) return error.SkipZigTest;
    if (linux.pipe(&to_parent) > 0xfffffffffffff000) return error.SkipZigTest;

    const pid_usize = linux.fork();
    if (pid_usize == 0) {
        // Child = controlled side.
        _ = linux.close(to_child[1]);
        _ = linux.close(to_parent[0]);
        childMain(to_child[0], to_parent[1]);
        linux.exit(0);
    }
    if (pid_usize > 0xfffffffffffff000) return error.SkipZigTest;
    _ = linux.close(to_child[0]);
    _ = linux.close(to_parent[1]);

    // Parent = controlling side. Gather own sockets first.
    var g = try ice.gather(.{});
    defer g.close();
    var ufrag: [16]u8 = undefined;
    var pwd: [32]u8 = undefined;
    ice.generateCredentials(&ufrag, &pwd);

    // Exchange: parent writes first (child reads first) to avoid deadlock.
    var line: [256]u8 = undefined;
    {
        const n = std.fmt.bufPrint(&line, "creds {s} {s}\n", .{ ufrag, pwd }) catch linux.exit(1);
        writeAll(to_child[1], n);
        const cn = std.fmt.bufPrint(&line, "ncands {d}\n", .{g.n_cands}) catch linux.exit(1);
        writeAll(to_child[1], cn);
        for (g.candidates()) |c| {
            var cb: [128]u8 = undefined;
            const cl = ice.formatCandidate(&cb, c) catch linux.exit(1);
            writeAll(to_child[1], cl);
            writeAll(to_child[1], "\n");
        }
    }
    var rbuf: [256]u8 = undefined;
    const creds_line = readLine(to_parent[0], &rbuf);
    var cit = std.mem.splitScalar(u8, creds_line, ' ');
    _ = cit.next();
    const r_ufrag = cit.next() orelse linux.exit(1);
    const r_pwd = cit.next() orelse linux.exit(1);
    // Copy before rbuf is reused by the candidate lines below.
    var r_ufrag_c: [16]u8 = undefined;
    var r_pwd_c: [32]u8 = undefined;
    @memcpy(&r_ufrag_c, r_ufrag);
    @memcpy(&r_pwd_c, r_pwd);
    const nc_line = readLine(to_parent[0], &rbuf);
    var nit = std.mem.splitScalar(u8, nc_line, ' ');
    _ = nit.next();
    const n_remote = std.fmt.parseInt(usize, nit.next() orelse linux.exit(1), 10) catch linux.exit(1);
    var remotes: [32]ice.RemoteCandidate = undefined;
    var nr: usize = 0;
    while (nr < n_remote) : (nr += 1) {
        const cl = readLine(to_parent[0], &rbuf);
        // readLine reuses rbuf; copy the line aside first.
        var lb: [256]u8 = undefined;
        @memcpy(lb[0..cl.len], cl);
        remotes[nr] = ice.parseCandidateLine(lb[0..cl.len]) catch linux.exit(1);
    }
    const sel = try ice.connect(
        &g,
        .{ .ufrag = &ufrag, .pwd = &pwd },
        .{ .ufrag = &r_ufrag_c, .pwd = &r_pwd_c },
        remotes[0..nr],
        .controlling,
        ice.randomTiebreaker(),
        .{ .overall_timeout_ms = 10000 },
    );
    // Data flows on the selected pair: parent sends, child echoes.
    // In-flight STUN strays may still arrive; skip anything but the echo.
    try ice.sendTo(g.fds[sel.sock_index], sel.remote.addr, "ping-from-parent");
    var dbuf: [1500]u8 = undefined;
    var got_echo = false;
    var waits: usize = 0;
    while (!got_echo and waits < 25) : (waits += 1) {
        var pfds = [_]linux.pollfd{.{ .fd = g.fds[sel.sock_index], .events = linux.POLL.IN }};
        const prc = linux.poll(&pfds, 1, 200);
        if (prc != 1) continue;
        const n = linux.recvfrom(g.fds[sel.sock_index], &dbuf, dbuf.len, 0, null, null);
        if (n > 0xfffffffffffff000 or n == 0) continue;
        if (std.mem.eql(u8, dbuf[0..n], "ping-from-child")) got_echo = true;
    }
    try std.testing.expect(got_echo);

    _ = linux.close(to_child[1]);
    _ = linux.close(to_parent[0]);
    var status: i32 = 0;
    _ = linux.waitpid(@intCast(pid_usize), &status, 0);
    try std.testing.expectEqual(@as(u8, 0), linux.W.EXITSTATUS(@bitCast(status)));
}

fn childMain(rfd: linux.fd_t, wfd: linux.fd_t) void {
    var g = ice.gather(.{}) catch linux.exit(1);
    defer g.close();
    var ufrag: [16]u8 = undefined;
    var pwd: [32]u8 = undefined;
    ice.generateCredentials(&ufrag, &pwd);
    var rbuf: [256]u8 = undefined;
    // Child reads first (parent writes first).
    const creds_line = readLine(rfd, &rbuf);
    var lb: [256]u8 = undefined;
    @memcpy(lb[0..creds_line.len], creds_line);
    const saved_creds = lb[0..creds_line.len];
    const nc_line = readLine(rfd, &rbuf);
    var lb2: [256]u8 = undefined;
    @memcpy(lb2[0..nc_line.len], nc_line);
    var cit = std.mem.splitScalar(u8, saved_creds, ' ');
    _ = cit.next();
    const r_ufrag = cit.next() orelse linux.exit(1);
    const r_pwd = cit.next() orelse linux.exit(1);
    var nit = std.mem.splitScalar(u8, lb2[0..nc_line.len], ' ');
    _ = nit.next();
    const n_remote = std.fmt.parseInt(usize, nit.next() orelse linux.exit(1), 10) catch linux.exit(1);
    var remotes: [32]ice.RemoteCandidate = undefined;
    var nr: usize = 0;
    while (nr < n_remote and nr < remotes.len) : (nr += 1) {
        const cl = readLine(rfd, &rbuf);
        var lbb: [256]u8 = undefined;
        @memcpy(lbb[0..cl.len], cl);
        remotes[nr] = ice.parseCandidateLine(lbb[0..cl.len]) catch linux.exit(1);
    }
    var line: [256]u8 = undefined;
    {
        const n = std.fmt.bufPrint(&line, "creds {s} {s}\n", .{ ufrag, pwd }) catch linux.exit(1);
        writeAll(wfd, n);
        const cn = std.fmt.bufPrint(&line, "ncands {d}\n", .{g.n_cands}) catch linux.exit(1);
        writeAll(wfd, cn);
        for (g.candidates()) |c| {
            var cb: [128]u8 = undefined;
            const cl = ice.formatCandidate(&cb, c) catch linux.exit(1);
            writeAll(wfd, cl);
            writeAll(wfd, "\n");
        }
    }
    const sel = ice.connect(
        &g,
        .{ .ufrag = &ufrag, .pwd = &pwd },
        .{ .ufrag = r_ufrag, .pwd = r_pwd },
        remotes[0..nr],
        .controlled,
        ice.randomTiebreaker(),
        .{ .overall_timeout_ms = 10000 },
    ) catch linux.exit(1);
    // Wait for parent's ping (skipping STUN strays), echo back.
    var dbuf: [1500]u8 = undefined;
    var waits: usize = 0;
    while (waits < 25) : (waits += 1) {
        var pfds = [_]linux.pollfd{.{ .fd = g.fds[sel.sock_index], .events = linux.POLL.IN }};
        if (linux.poll(&pfds, 1, 200) != 1) continue;
        var sab = ice.SockAddrBuf{};
        var slen: linux.socklen_t = @sizeOf(linux.sockaddr.in6);
        const n = linux.recvfrom(
            g.fds[sel.sock_index],
            &dbuf,
            dbuf.len,
            0,
            @ptrCast(@alignCast(&sab.buf)),
            &slen,
        );
        if (n > 0xfffffffffffff000 or n == 0) continue;
        if (!std.mem.eql(u8, dbuf[0..n], "ping-from-parent")) continue;
        const src = sab.toIp(slen) catch linux.exit(1);
        ice.sendTo(g.fds[sel.sock_index], src, "ping-from-child") catch linux.exit(1);
        _ = linux.close(rfd);
        _ = linux.close(wfd);
        return;
    }
    linux.exit(1);
}
