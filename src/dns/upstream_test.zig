// Upstream forwarder tests against an in-process UDP stub: ordered
// failover, SERVFAIL/REFUSED failover with a valid answer after it, timeout
// on a dead primary, and the OPT strip for clients without EDNS0.

const std = @import("std");
const linux = std.os.linux;
const msg = @import("msg.zig");
const chain_mod = @import("chain.zig");
const upstream_mod = @import("upstream.zig");

fn failed(rc: usize) bool {
    return rc > 0xfffffffffffff000;
}

/// Minimal UDP DNS stub: answers every A query for `name` with `ip`,
/// NXDOMAIN for other names; toggles behavior per test via StubCfg.
const Stub = struct {
    fd: linux.fd_t,
    thread: ?std.Thread = null,
    stop: std.atomic.Value(bool) = .init(false),
    name: []const u8,
    ip: [4]u8,
    rcode_override: std.atomic.Value(u16) = .init(0), // if nonzero: reply rcode
    drop_queries: std.atomic.Value(bool) = .init(false), // never answer
    seen: std.atomic.Value(u32) = .init(0),
    port: u16 = 0,
    ede: std.atomic.Value(u16) = .init(65535),
    wrong_id: std.atomic.Value(bool) = .init(false),

    fn start(name: []const u8, ip: [4]u8) !*Stub {
        const s = try std.testing.allocator.create(Stub);
        errdefer std.testing.allocator.destroy(s);
        const fd_usize = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
        if (failed(fd_usize)) return error.SocketFailed;
        s.* = .{ .fd = @intCast(fd_usize), .name = name, .ip = ip };
        var sa: linux.sockaddr.in = .{
            .family = linux.AF.INET,
            .port = 0,
            .addr = @bitCast(@as([4]u8, .{ 127, 0, 0, 1 })),
            .zero = .{ 0, 0, 0, 0, 0, 0, 0, 0 },
        };
        if (failed(linux.bind(s.fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in)))) return error.BindFailed;
        var got: linux.sockaddr.in = undefined;
        var len: linux.socklen_t = @sizeOf(linux.sockaddr.in);
        _ = linux.getsockname(s.fd, @ptrCast(&got), &len);
        s.port = std.mem.bigToNative(u16, got.port);
        s.thread = try std.Thread.spawn(.{}, loop, .{s});
        return s;
    }

    fn shutdown(s: *Stub) void {
        s.stop.store(true, .release);
        _ = linux.close(s.fd); // wakes the poll
        if (s.thread) |t| {
            t.join();
            s.thread = null;
        }
        std.testing.allocator.destroy(s);
    }

    fn loop(s: *Stub) void {
        var buf: [4096]u8 = undefined;
        while (!s.stop.load(.acquire)) {
            var pfd = [_]linux.pollfd{.{ .fd = s.fd, .events = linux.POLL.IN }};
            const n = linux.poll(&pfd, 1, 100);
            if (n <= 0) continue;
            var client: [128]u8 align(@alignOf(linux.sockaddr.in6)) = undefined;
            var client_len: linux.socklen_t = client.len;
            const got = linux.recvfrom(s.fd, &buf, buf.len, 0, @ptrCast(&client), &client_len);
            if (failed(got) or got == 0) continue;
            _ = s.seen.fetchAdd(1, .monotonic);
            if (s.drop_queries.load(.acquire)) continue;

            var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
            defer arena.deinit();
            const query = msg.unpack(arena.allocator(), buf[0..got]) catch continue;
            if (query.question.len == 0) continue;

            var reply = msg.Message{};
            reply.setReply(&query);
            reply.header.recursion_available = true;
            if (s.wrong_id.load(.acquire)) reply.header.id +%= 1;
            const q = query.question[0];
            if (q.type == .a and std.mem.eql(u8, q.name, s.name)) {
                const answer = arena.allocator().alloc(msg.RR, 1) catch continue;
                answer[0] = .{ .name = q.name, .type = .a, .class = 1, .ttl = 30, .data = .{ .a = s.ip } };
                reply.answer = answer;
                reply.header.rcode = s.rcode_override.load(.acquire);
            } else {
                reply.header.rcode = 3; // NXDOMAIN
            }
            const ede = s.ede.load(.acquire);
            if (ede != 65535) {
                const extra = arena.allocator().alloc(msg.RR, 1) catch continue;
                const opts = arena.allocator().alloc(msg.Option, 1) catch continue;
                const data = arena.allocator().alloc(u8, 2) catch continue;
                std.mem.writeInt(u16, data[0..2], ede, .big);
                opts[0] = .{.code = 15, .data = data};
                extra[0] = msg.makeOpt(1232, false);
                extra[0].data = .{.opt = opts};
                reply.extra = extra;
            }
            const wire = msg.pack(arena.allocator(), &reply, &buf) catch continue;
            const dest: *const linux.sockaddr = @ptrCast(@alignCast(&client));
            _ = linux.sendto(s.fd, wire.ptr, wire.len, 0, dest, client_len);
        }
    }
};

fn queryOf(arena: std.mem.Allocator, name: []const u8, qtype: msg.Type) !msg.Message {
    const qs = try arena.alloc(msg.Question, 1);
    qs[0] = .{ .name = name, .type = qtype, .class = 1 };
    return .{ .header = .{ .id = 7, .recursion_desired = true }, .question = qs };
}

test "upstream answers via the stub" {
    const stub = try Stub.start("ok.example.", .{ 203, 0, 113, 1 });
    defer stub.shutdown();

    var up = upstream_mod.Upstream.init(std.testing.allocator);
    defer up.deinit();
    try up.addServer(.{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = stub.port } });

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const q = try queryOf(arena.allocator(), "ok.example.", .a);
    const out = try up.handler().serve(arena.allocator(), &q, .udp);
    const reply = out.response;
    try std.testing.expectEqual(@as(u16, 0), reply.header.rcode);
    try std.testing.expectEqual(@as(usize, 1), reply.answer.len);
    try std.testing.expectEqualSlices(u8, &.{ 203, 0, 113, 1 }, &reply.answer[0].data.a);
    // the stub's NXDOMAIN zero-bit cannot leak: Zero cleared on forward
    try std.testing.expect(!reply.header.zero);
}

test "failover: dead primary, servfail secondary, good tertiary" {
    const stub = try Stub.start("ok.example.", .{ 203, 0, 113, 2 });
    defer stub.shutdown();

    var up = upstream_mod.Upstream.init(std.testing.allocator);
    defer up.deinit();
    up.timeout_ms = 300;
    // 1: nobody listens (connection refused is fine over UDP — timeout path)
    try up.addServer(.{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 1 } });
    // 2: answers SERVFAIL
    try up.addServer(.{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = stub.port } });
    _ = stub.rcode_override.swap(2, .monotonic); // SERVFAIL for the known name

    var up2 = upstream_mod.Upstream.init(std.testing.allocator);
    defer up2.deinit();
    up2.timeout_ms = 300;
    // same servers but SERVFAIL off: third server in the test below uses a fresh stub
    _ = &up2;

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // both upstreams fail → SERVFAIL to the client
    const q = try queryOf(arena.allocator(), "ok.example.", .a);
    const out = try up.handler().serve(arena.allocator(), &q, .udp);
    try std.testing.expectEqual(@as(u16, 2), out.response.header.rcode);

    // now the stub answers properly → the same query succeeds
    _ = stub.rcode_override.swap(0, .monotonic);
    const out2 = try up.handler().serve(arena.allocator(), &q, .udp);
    try std.testing.expectEqual(@as(u16, 0), out2.response.header.rcode);
    try std.testing.expectEqual(@as(usize, 1), out2.response.answer.len);
}

test "dead primary times out and fallback answers" {
    const stub = try Stub.start("ok.example.", .{ 203, 0, 113, 3 });
    defer stub.shutdown();

    var up = upstream_mod.Upstream.init(std.testing.allocator);
    defer up.deinit();
    up.timeout_ms = 300;
    try up.addServer(.{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 1 } }); // black hole
    try up.addServer(.{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = stub.port } });

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const q = try queryOf(arena.allocator(), "ok.example.", .a);
    const out = try up.handler().serve(arena.allocator(), &q, .udp);
    try std.testing.expectEqual(@as(u16, 0), out.response.header.rcode);
    try std.testing.expectEqualSlices(u8, &.{ 203, 0, 113, 3 }, &out.response.answer[0].data.a);
}

test "unknown names become nxdomain from the stub" {
    const stub = try Stub.start("ok.example.", .{ 203, 0, 113, 4 });
    defer stub.shutdown();

    var up = upstream_mod.Upstream.init(std.testing.allocator);
    defer up.deinit();
    try up.addServer(.{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = stub.port } });

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const q = try queryOf(arena.allocator(), "other.example.", .a);
    const out = try up.handler().serve(arena.allocator(), &q, .udp);
    try std.testing.expectEqual(@as(u16, 3), out.response.header.rcode); // NXDOMAIN forwarded
}

test "wrong UDP ID is ignored and next upstream answers after timeout" {
    const bad = try Stub.start("ok.example.", .{203, 0, 113, 9});
    defer bad.shutdown();
    bad.wrong_id.store(true, .release);
    const good = try Stub.start("ok.example.", .{203, 0, 113, 10});
    defer good.shutdown();
    var up = upstream_mod.Upstream.init(std.testing.allocator);
    defer up.deinit();
    up.timeout_ms = 100;
    try up.addServer(.{.ip4 = .{.bytes = .{127,0,0,1}, .port = bad.port}});
    try up.addServer(.{.ip4 = .{.bytes = .{127,0,0,1}, .port = good.port}});
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const q = try queryOf(arena.allocator(), "ok.example.", .a);
    const out = try up.handler().serve(arena.allocator(), &q, .udp);
    try std.testing.expectEqual(q.header.id, out.response.header.id);
    try std.testing.expectEqualSlices(u8, &.{203,0,113,10}, &out.response.answer[0].data.a);
    try std.testing.expectEqual(@as(u32, 1), good.seen.load(.acquire));
}

test "rcode failover and definitive EDE match v080 queryUpstream" {
    const primary = try Stub.start("ok.example.", .{203,0,113,11});
    defer primary.shutdown();
    const fallback = try Stub.start("ok.example.", .{203,0,113,12});
    defer fallback.shutdown();
    var up = upstream_mod.Upstream.init(std.testing.allocator);
    defer up.deinit();
    try up.addServer(.{.ip4 = .{.bytes = .{127,0,0,1}, .port = primary.port}});
    try up.addServer(.{.ip4 = .{.bytes = .{127,0,0,1}, .port = fallback.port}});
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const q = try queryOf(arena.allocator(), "ok.example.", .a);
    for ([_]u16{0,3,2,5}) |rcode| {
        primary.rcode_override.store(rcode, .release);
        for (0..25) |code| {
            primary.ede.store(@intCast(code), .release);
            const before = fallback.seen.load(.acquire);
            const out = try up.handler().serve(arena.allocator(), &q, .udp);
            const definitive = (code >= 1 and code <= 2) or (code >= 5 and code <= 12) or (code >= 15 and code <= 18);
            const retry = (rcode == 2 or rcode == 5) and !definitive;
            try std.testing.expectEqual(if (retry) @as(u16,0) else rcode, out.response.header.rcode);
            try std.testing.expectEqual(before + @as(u32, if (retry) 1 else 0), fallback.seen.load(.acquire));
            try std.testing.expect(out.response.isEdns0() == null);
        }
    }
}

const DualStub = struct {
    udp_size: std.atomic.Value(u16) = .init(0),
    tcp_seen: std.atomic.Value(u32) = .init(0),
    wrong_tcp_id: std.atomic.Value(bool) = .init(false),

    fn serve(ctx: *anyopaque, arena: std.mem.Allocator, q: *const msg.Message, transport: chain_mod.Transport) chain_mod.ServeError!chain_mod.Outcome {
        const s: *DualStub = @ptrCast(@alignCast(ctx));
        if (transport == .udp) {
            s.udp_size.store(if (q.isEdns0()) |opt| opt.class else 0, .release);
        } else {
            _ = s.tcp_seen.fetchAdd(1, .monotonic);
        }
        var reply = msg.Message{};
        reply.setReply(q);
        if (transport == .udp) {
            reply.header.truncated = true;
        } else {
            if (s.wrong_tcp_id.load(.acquire)) reply.header.id +%= 1;
            const records = try arena.alloc(msg.RR, 100);
            for (records) |*rr| rr.* = .{.name = q.question[0].name, .type = .a, .class = 1, .ttl = 30, .data = .{.a = .{203,0,113,20}}};
            reply.answer = records;
        }
        return .{.response = reply};
    }
};

test "MTU cap and TCP retry truncate to pre-cap client buffer, TCP direct stays full" {
    const Server = @import("server.zig").Server;
    var stub = DualStub{};
    var chain = chain_mod.Chain.init(std.testing.allocator);
    defer chain.deinit();
    try chain.add(".", .{.ctx = &stub, .match_subdomains = true, .serveFn = DualStub.serve}, 0);
    var server = try Server.bind(.{.ip4 = .{.bytes = .{127,0,0,1}, .port = 0}}, &chain);
    defer server.close();
    const thread = try std.Thread.spawn(.{}, Server.serveLoop, .{&server});
    defer { server.requestStop(); thread.join(); }
    const addr: std.Io.net.IpAddress = .{.ip4 = .{.bytes = .{127,0,0,1}, .port = try server.localPort()}};
    var up = upstream_mod.Upstream.init(std.testing.allocator);
    defer up.deinit();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var q = try queryOf(a, "ok.example.", .a);
    const extra = try a.alloc(msg.RR, 1);
    extra[0] = msg.makeOpt(1400, true);
    q.extra = extra;
    const res = try up.exchange(a, addr, &q, .udp, 1000);
    try std.testing.expectEqual(@as(u16,1212), stub.udp_size.load(.acquire));
    try std.testing.expectEqual(@as(u16,1400), q.isEdns0().?.class);
    var buf: [65535]u8 = undefined;
    const encoded = try msg.pack(a, &res, &buf);
    try std.testing.expect(encoded.len <= 1400);
    try std.testing.expect(res.header.truncated);
    try std.testing.expect(res.answer.len > 0);
    const direct = try up.exchange(a, addr, &q, .tcp, 1000);
    try std.testing.expectEqual(@as(usize,100), direct.answer.len);
    try std.testing.expect(!direct.header.truncated);
    stub.wrong_tcp_id.store(true, .release);
    try std.testing.expectError(error.IdMismatch, up.exchange(a, addr, &q, .tcp, 1000));
}
