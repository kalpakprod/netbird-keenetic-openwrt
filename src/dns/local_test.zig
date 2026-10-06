// Local record resolver tests (Go local/local_test.go semantics, reduced).

const std = @import("std");
const msg = @import("msg.zig");
const chain_mod = @import("chain.zig");
const local_mod = @import("local.zig");

const Resolver = local_mod.Resolver;

fn aRR(name: []const u8, ip: [4]u8, ttl: u32) msg.RR {
    return .{ .name = name, .type = .a, .class = 1, .ttl = ttl, .data = .{ .a = ip } };
}

fn cnameRR(name: []const u8, target: []const u8) msg.RR {
    return .{ .name = name, .type = .cname, .class = 1, .ttl = 300, .data = .{ .cname = target } };
}

const Harness = struct {
    arena: *std.heap.ArenaAllocator,
    resolver: Resolver,

    fn init() !Harness {
        const arena = try std.testing.allocator.create(std.heap.ArenaAllocator);
        errdefer std.testing.allocator.destroy(arena);
        arena.* = std.heap.ArenaAllocator.init(std.testing.allocator);
        return .{ .arena = arena, .resolver = Resolver.init(std.testing.allocator, arena) };
    }

    fn deinit(h: *Harness) void {
        h.resolver.deinit();
        const arena = h.arena;
        arena.deinit();
        std.testing.allocator.destroy(arena);
    }
};

fn queryOf(arena: std.mem.Allocator, name: []const u8, qtype: msg.Type) !msg.Message {
    const qs = try arena.alloc(msg.Question, 1);
    qs[0] = .{ .name = name, .type = qtype, .class = 1 };
    return .{ .header = .{ .id = 9, .recursion_desired = true }, .question = qs };
}

test "local record answers with RA and authoritative" {
    var h = try Harness.init();
    defer h.deinit();

    const records = [_]msg.RR{aRR("peer.example.", .{ 100, 64, 0, 1 }, 60)};
    const zones = [_]local_mod.Zone{.{ .domain = "example.", .records = &records }};
    try h.resolver.update(&zones);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const q = try queryOf(arena.allocator(), "peer.example.", .a);
    const out = try h.resolver.handler().serve(arena.allocator(), &q, .udp);
    const reply = out.response;
    try std.testing.expectEqual(local_mod.rcode_success, reply.header.rcode);
    try std.testing.expect(reply.header.recursion_available);
    try std.testing.expect(reply.header.authoritative);
    try std.testing.expectEqual(@as(usize, 1), reply.answer.len);
    try std.testing.expectEqualSlices(u8, &.{ 100, 64, 0, 1 }, &reply.answer[0].data.a);
    try std.testing.expectEqualStrings("peer.example.", reply.answer[0].name);
}

test "nxdata for existing domain with other type, nxdomain otherwise" {
    var h = try Harness.init();
    defer h.deinit();

    const records = [_]msg.RR{aRR("peer.example.", .{ 100, 64, 0, 1 }, 60)};
    const zones = [_]local_mod.Zone{.{ .domain = "example.", .records = &records }};
    try h.resolver.update(&zones);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    // NODATA: domain exists, type does not
    const q_nodata = try queryOf(arena.allocator(), "peer.example.", .txt);
    const out_nodata = try h.resolver.handler().serve(arena.allocator(), &q_nodata, .udp);
    try std.testing.expectEqual(local_mod.rcode_success, out_nodata.response.header.rcode);
    try std.testing.expectEqual(@as(usize, 0), out_nodata.response.answer.len);

    // NXDOMAIN: inside the managed zone but the name does not exist
    const q_nx = try queryOf(arena.allocator(), "missing.example.", .a);
    const out_nx = try h.resolver.handler().serve(arena.allocator(), &q_nx, .udp);
    try std.testing.expectEqual(local_mod.rcode_name_error, out_nx.response.header.rcode);

    // authoritative zone → no fallthrough even on NXDOMAIN
    try std.testing.expect(!h.resolver.shouldFallthrough("missing.example."));
}

test "wildcard records answer absent names only" {
    var h = try Harness.init();
    defer h.deinit();

    const records = [_]msg.RR{
        aRR("*.wild.example.", .{ 100, 64, 0, 2 }, 60),
        aRR("real.wild.example.", .{ 100, 64, 0, 3 }, 60),
    };
    const zones = [_]local_mod.Zone{.{ .domain = "example.", .records = &records }};
    try h.resolver.update(&zones);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    // wildcard match, owner rewritten to the queried name
    const q = try queryOf(arena.allocator(), "any.wild.example.", .a);
    const out = try h.resolver.handler().serve(arena.allocator(), &q, .udp);
    try std.testing.expectEqual(local_mod.rcode_success, out.response.header.rcode);
    try std.testing.expectEqualStrings("any.wild.example.", out.response.answer[0].name);
    try std.testing.expectEqualSlices(u8, &.{ 100, 64, 0, 2 }, &out.response.answer[0].data.a);

    // existing name is never shadowed by the wildcard (RFC 4592)
    const q2 = try queryOf(arena.allocator(), "real.wild.example.", .a);
    const out2 = try h.resolver.handler().serve(arena.allocator(), &q2, .udp);
    try std.testing.expectEqualSlices(u8, &.{ 100, 64, 0, 3 }, &out2.response.answer[0].data.a);
}

test "cname chain resolves the target in the same zone" {
    var h = try Harness.init();
    defer h.deinit();

    const records = [_]msg.RR{
        cnameRR("alias.example.", "peer.example."),
        aRR("peer.example.", .{ 100, 64, 0, 1 }, 60),
    };
    const zones = [_]local_mod.Zone{.{ .domain = "example.", .records = &records }};
    try h.resolver.update(&zones);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const q = try queryOf(arena.allocator(), "alias.example.", .a);
    const out = try h.resolver.handler().serve(arena.allocator(), &q, .udp);
    try std.testing.expectEqual(local_mod.rcode_success, out.response.header.rcode);
    try std.testing.expectEqual(@as(usize, 2), out.response.answer.len);
    try std.testing.expectEqual(msg.Type.cname, out.response.answer[0].type);
    try std.testing.expectEqualStrings("peer.example.", out.response.answer[0].data.cname);
    try std.testing.expectEqual(msg.Type.a, out.response.answer[1].type);
}

test "non-authoritative zone falls through on nxdomain" {
    var h = try Harness.init();
    defer h.deinit();

    const records = [_]msg.RR{aRR("peer.ext.example.", .{ 100, 64, 0, 1 }, 60)};
    const zones = [_]local_mod.Zone{
        .{ .domain = "ext.example.", .non_authoritative = true, .records = &records },
    };
    try h.resolver.update(&zones);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // name inside the zone but no record → NXDOMAIN + continue signal
    const q = try queryOf(arena.allocator(), "other.ext.example.", .a);
    const out = try h.resolver.handler().serve(arena.allocator(), &q, .udp);
    try std.testing.expect(out == .continue_chain);

    // a registered name in the non-authoritative zone still answers
    const q2 = try queryOf(arena.allocator(), "peer.ext.example.", .a);
    const out2 = try h.resolver.handler().serve(arena.allocator(), &q2, .udp);
    try std.testing.expectEqual(local_mod.rcode_success, out2.response.header.rcode);
}

test "external cname target goes to the injected lookup" {
    var h = try Harness.init();
    defer h.deinit();

    var ext_called: usize = 0;
    const Ext = struct {
        fn lookup(ctx: *anyopaque, arena: std.mem.Allocator, name: []const u8, qtype: u16) local_mod.LookupError!local_mod.ExternalResult {
            const counter: *usize = @ptrCast(@alignCast(ctx));
            counter.* += 1;
            if (!std.mem.eql(u8, name, "outer.example.org.") or qtype != 1) return error.BadRdata;
            const addrs = try arena.alloc([]const u8, 1);
            addrs[0] = "203.0.113.9";
            return .{ .addrs = addrs };
        }
    };
    h.resolver.external = .{ .ctx = &ext_called, .lookupFn = Ext.lookup };

    const records = [_]msg.RR{cnameRR("alias.example.", "outer.example.org.")};
    const zones = [_]local_mod.Zone{.{ .domain = "example.", .records = &records }};
    try h.resolver.update(&zones);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const q = try queryOf(arena.allocator(), "alias.example.", .a);
    const out = try h.resolver.handler().serve(arena.allocator(), &q, .udp);
    try std.testing.expectEqual(@as(usize, 1), ext_called);
    try std.testing.expectEqual(local_mod.rcode_success, out.response.header.rcode);
    try std.testing.expectEqual(@as(usize, 2), out.response.answer.len); // cname + a
    try std.testing.expectEqualSlices(u8, &.{ 203, 0, 113, 9 }, &out.response.answer[1].data.a);
    // external data → not authoritative (Go hasExternalData)
    try std.testing.expect(!out.response.header.authoritative);
}

test "round robin rotates multi-record answers" {
    var h = try Harness.init();
    defer h.deinit();

    const records = [_]msg.RR{
        aRR("pool.example.", .{ 100, 64, 0, 1 }, 60),
        aRR("pool.example.", .{ 100, 64, 0, 2 }, 60),
    };
    const zones = [_]local_mod.Zone{.{ .domain = "example.", .records = &records }};
    try h.resolver.update(&zones);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const q = try queryOf(arena.allocator(), "pool.example.", .a);
    const out1 = try h.resolver.handler().serve(arena.allocator(), &q, .udp);
    const out2 = try h.resolver.handler().serve(arena.allocator(), &q, .udp);

    const first1 = out1.response.answer[0].data.a;
    const first2 = out2.response.answer[0].data.a;
    try std.testing.expect(!std.mem.eql(u8, &first1, &first2)); // rotated
    // both answers carry both records
    try std.testing.expectEqual(@as(usize, 2), out1.response.answer.len);
    try std.testing.expectEqual(@as(usize, 2), out2.response.answer.len);
}
