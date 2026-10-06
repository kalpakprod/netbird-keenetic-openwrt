// DNS server tests: full dispatch over real sockets on 127.0.0.1 (kernel-
// chosen high port), verified with dig (skipped when dig is absent). The
// upstream forwarder path uses an in-process UDP stub; the dead-primary
// fallback exercises the ordered failover.

const std = @import("std");
const linux = std.os.linux;
const msg = @import("msg.zig");
const chain_mod = @import("chain.zig");
const local_mod = @import("local.zig");
const upstream_mod = @import("upstream.zig");
const server_mod = @import("server.zig");

const Server = server_mod.Server;

fn failed(rc: usize) bool {
    return rc > 0xfffffffffffff000;
}

// --- in-process upstream stub: forwarded.example. → A 203.0.113.9 ---
const Stub = struct {
    fd: linux.fd_t,
    port: u16 = 0,
    thread: ?std.Thread = null,
    stop: std.atomic.Value(bool) = .init(false),

    fn start() !*Stub {
        const s = try std.testing.allocator.create(Stub);
        errdefer std.testing.allocator.destroy(s);
        const fd_usize = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
        if (failed(fd_usize)) return error.SocketFailed;
        s.* = .{ .fd = @intCast(fd_usize) };
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
        _ = linux.close(s.fd);
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

            var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
            defer arena.deinit();
            const query = msg.unpack(arena.allocator(), buf[0..got]) catch continue;
            if (query.question.len == 0) continue;

            var reply = msg.Message{};
            reply.setReply(&query);
            const q = query.question[0];
            if (q.type == .a and std.mem.eql(u8, q.name, "forwarded.example.")) {
                const answer = arena.allocator().alloc(msg.RR, 1) catch continue;
                answer[0] = .{ .name = q.name, .type = .a, .class = 1, .ttl = 30, .data = .{ .a = .{ 203, 0, 113, 9 } } };
                reply.answer = answer;
            } else {
                reply.header.rcode = 3; // NXDOMAIN
            }
            const wire = msg.pack(arena.allocator(), &reply, &buf) catch continue;
            const dest: *const linux.sockaddr = @ptrCast(@alignCast(&client));
            _ = linux.sendto(s.fd, wire.ptr, wire.len, 0, dest, client_len);
        }
    }
};

const Fixture = struct {
    arena: *std.heap.ArenaAllocator,
    resolver: local_mod.Resolver,
    upstream: upstream_mod.Upstream,
    chain: chain_mod.Chain,
    server: Server,
    stub: *Stub,
    thread: ?std.Thread = null,

    fn start() !*Fixture {
        const stub = try Stub.start();
        errdefer stub.shutdown();

        const f = try std.testing.allocator.create(Fixture);
        errdefer std.testing.allocator.destroy(f);

        const arena = try std.testing.allocator.create(std.heap.ArenaAllocator);
        arena.* = std.heap.ArenaAllocator.init(std.testing.allocator);
        errdefer std.testing.allocator.destroy(arena);

        f.* = .{
            .arena = arena,
            .resolver = local_mod.Resolver.init(std.testing.allocator, arena),
            .upstream = upstream_mod.Upstream.init(std.testing.allocator),
            .chain = chain_mod.Chain.init(std.testing.allocator),
            .server = undefined,
            .stub = stub,
        };
        errdefer f.resolver.deinit();

        // local zone: peer.example. → 100.64.0.1; then *.wild.example. →
        // 100.64.0.2 (second update() replaces, so both zones re-registered).
        // Static records: update() resets the resolver's store arena, so the
        // caller's zones must not live in it.
        const peer_a = [_]msg.RR{.{ .name = "peer.example.", .type = .a, .class = 1, .ttl = 60, .data = .{ .a = .{ 100, 64, 0, 1 } } }};
        const wild_a = [_]msg.RR{.{ .name = "*.wild.example.", .type = .a, .class = 1, .ttl = 60, .data = .{ .a = .{ 100, 64, 0, 2 } } }};
        // Management-provided zones are non-authoritative: an NXDOMAIN inside
        // them must fall through to the next handler (the upstream here).
        const zones = [_]local_mod.Zone{
            .{ .domain = "example.", .non_authoritative = true, .records = &peer_a },
            .{ .domain = "wild.example.", .non_authoritative = true, .records = &wild_a },
        };
        try f.resolver.update(&zones);

        // upstream: dead primary on a black-hole port, then the stub
        try f.upstream.addServer(.{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 1 } });
        try f.upstream.addServer(.{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = stub.port } });
        f.upstream.timeout_ms = 500;

        try f.chain.add("wild.example.", f.resolver.handler(), chain_mod.Priority.local);
        try f.chain.add("example.", f.resolver.handler(), chain_mod.Priority.local);
        try f.chain.add(".", f.upstream.handler(), chain_mod.Priority.upstream);

        f.server = try Server.bind(.{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } }, &f.chain);
        errdefer f.server.close();
        f.thread = try std.Thread.spawn(.{}, Server.serveLoop, .{&f.server});
        return f;
    }

    fn stopF(f: *Fixture) void {
        f.server.requestStop();
        f.server.close();
        if (f.thread) |t| {
            t.join();
            f.thread = null;
        }
        f.resolver.deinit();
        f.upstream.deinit();
        f.chain.deinit();
        f.stub.shutdown();
        const arena = f.arena;
        arena.deinit();
        std.testing.allocator.destroy(arena);
        std.testing.allocator.destroy(f);
    }
};

const tio = std.testing.io;

fn readAllPipe(arena: std.mem.Allocator, file: std.Io.File) ![]u8 {
    var read_buf: [65536]u8 = undefined;
    var reader = file.readerStreaming(tio, &read_buf);
    var out: std.ArrayListUnmanaged(u8) = .empty;
    var chunk: [4096]u8 = undefined;
    while (true) {
        const n = reader.interface.readSliceShort(&chunk) catch break;
        if (n == 0) break;
        try out.appendSlice(arena, chunk[0..n]);
    }
    return out.items;
}

fn dig(arena: std.mem.Allocator, port: u16, args: []const []const u8) !struct { stdout: []u8, code: u32 } {
    var argv: std.ArrayListUnmanaged([]const u8) = .empty;
    try argv.appendSlice(arena, &.{ "dig", "+time=3", "+tries=1", "-p", try std.fmt.allocPrint(arena, "{d}", .{port}), "@127.0.0.1" });
    try argv.appendSlice(arena, args);

    var child = try std.process.spawn(tio, .{
        .argv = argv.items,
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .pipe,
    });
    const stdout = try readAllPipe(arena, child.stdout.?);
    _ = try readAllPipe(arena, child.stderr.?);
    const term = try child.wait(tio);
    return .{ .stdout = stdout, .code = switch (term) {
        .exited => |c| c,
        else => 1,
    } };
}

test "dig against the zig resolver: local, wildcard, forwarded, refused, tcp" {
    // skip the suite when dig is absent
    {
        var probe = std.process.spawn(tio, .{
            .argv = &.{ "dig", "-v" },
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .ignore,
        }) catch return error.SkipZigTest;
        _ = probe.wait(tio) catch return error.SkipZigTest;
    }

    const f = try Fixture.start();
    defer f.stopF();
    const port = try f.server.localPort();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // 1. local record
    {
        const r = try dig(a, port, &.{ "peer.example.", "A" });
        try std.testing.expectEqual(@as(u32, 0), r.code);
        try std.testing.expect(std.mem.indexOf(u8, r.stdout, "100.64.0.1") != null);
        try std.testing.expect(std.mem.indexOf(u8, r.stdout, "NOERROR") != null);
    }
    // 2. wildcard
    {
        const r = try dig(a, port, &.{ "name.wild.example.", "A" });
        try std.testing.expectEqual(@as(u32, 0), r.code);
        try std.testing.expect(std.mem.indexOf(u8, r.stdout, "100.64.0.2") != null);
    }
    // 3. forwarded through the fallback chain (dead primary first)
    {
        const r = try dig(a, port, &.{ "forwarded.example.", "A" });
        try std.testing.expectEqual(@as(u32, 0), r.code);
        try std.testing.expect(std.mem.indexOf(u8, r.stdout, "203.0.113.9") != null);
    }
    // 4. unknown name → NXDOMAIN from the stub
    {
        const r = try dig(a, port, &.{ "nothere.example.", "A" });
        try std.testing.expectEqual(@as(u32, 0), r.code);
        try std.testing.expect(std.mem.indexOf(u8, r.stdout, "NXDOMAIN") != null);
    }
    // 5. same over TCP
    {
        const r = try dig(a, port, &.{ "+tcp", "peer.example.", "A" });
        try std.testing.expectEqual(@as(u32, 0), r.code);
        try std.testing.expect(std.mem.indexOf(u8, r.stdout, "100.64.0.1") != null);
    }
    // 6. a name outside the local zones reaches the "." upstream handler
    //    (the REFUSED tail only fires when no handler at all matches)
    {
        const r = try dig(a, port, &.{ "elsewhere.invalid.", "A" });
        try std.testing.expectEqual(@as(u32, 0), r.code);
        try std.testing.expect(std.mem.indexOf(u8, r.stdout, "NXDOMAIN") != null);
    }
}
