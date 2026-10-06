// Handler chain tests (Go handler_chain_test.go semantics, reduced to the
// ported surface).

const std = @import("std");
const msg = @import("msg.zig");
const chain_mod = @import("chain.zig");

const Chain = chain_mod.Chain;

// test handler answering with a fixed rcode
const Echo = struct {
    rcode: u16,
    want_pattern: []const u8 = "",
    continue_on: u16 = 0xFFFF, // rcode that maps to .continue_chain

    fn serveFn(ctx: *anyopaque, arena: std.mem.Allocator, req: *const msg.Message, transport: chain_mod.Transport) chain_mod.ServeError!chain_mod.Outcome {
        _ = arena;
        _ = transport;
        const e: *Echo = @ptrCast(@alignCast(ctx));
        if (e.want_pattern.len > 0 and !std.mem.eql(u8, req.question[0].name, e.want_pattern)) {
            return chain_mod.Outcome.continue_chain;
        }
        var reply = msg.Message{};
        reply.setRcode(req, e.rcode);
        if (reply.header.rcode == e.continue_on) return .continue_chain;
        return .{ .response = reply };
    }

    fn handler(e: *Echo) chain_mod.Handler {
        return .{ .ctx = e, .serveFn = serveFn };
    }
};

fn query(arena: std.mem.Allocator, name: []const u8, qtype: msg.Type) !msg.Message {
    const qs = try arena.alloc(msg.Question, 1);
    qs[0] = .{ .name = name, .type = qtype, .class = 1 };
    return .{ .header = .{ .id = 1, .recursion_desired = true }, .question = qs };
}

test "priority order and specificity" {
    var chain = Chain.init(std.testing.allocator);
    defer chain.deinit();
    var lo = Echo{ .rcode = 0 };
    var hi = Echo{ .rcode = 2 };
    var specific = Echo{ .rcode = 3 };
    try chain.add("example.com.", lo.handler(), chain_mod.Priority.upstream);
    try chain.add("example.com.", hi.handler(), chain_mod.Priority.local);
    try chain.add("a.b.example.com.", specific.handler(), chain_mod.Priority.local);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    // higher priority wins
    {
        const q = try query(arena.allocator(), "example.com.", .a);
        const res = try chain.dispatch(arena.allocator(), &q, .udp);
        try std.testing.expectEqual(@as(u16, 2), res.response.header.rcode);
    }
    // same priority: the more specific pattern first
    {
        const q = try query(arena.allocator(), "a.b.example.com.", .a);
        const res = try chain.dispatch(arena.allocator(), &q, .udp);
        try std.testing.expectEqual(@as(u16, 3), res.response.header.rcode);
    }
}

test "wildcard and subdomain matching" {
    var chain = Chain.init(std.testing.allocator);
    defer chain.deinit();
    var wild = Echo{ .rcode = 0 };
    var sub = Echo{ .rcode = 1 };
    var exact = Echo{ .rcode = 2 };
    // "*.wild.example." pattern, stored stripped
    try chain.add("*.wild.example.", wild.handler(), chain_mod.Priority.local);
    try chain.addExact("exact.example.", exact.handler(), chain_mod.Priority.local);
    const sub_handler = chain_mod.Handler{ .ctx = &sub, .match_subdomains = true, .serveFn = Echo.serveFn };
    try chain.add("sub.example.", sub_handler, chain_mod.Priority.local);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    // wildcard matches any single leading label chain
    for ([_][]const u8{ "x.wild.example.", "a.b.wild.example." }) |name| {
        const q = try query(arena.allocator(), name, .a);
        const res = try chain.dispatch(arena.allocator(), &q, .udp);
        try std.testing.expectEqual(@as(u16, 0), res.response.header.rcode);
    }
    // wildcard does not match the zone itself: no handler -> REFUSED
    {
        const q = try query(arena.allocator(), "wild.example.", .a);
        const res = try chain.dispatch(arena.allocator(), &q, .udp);
        try std.testing.expectEqual(@as(u16, 5), res.response.header.rcode);
    }
    // subdomain matcher: the name itself and deeper names
    for ([_][]const u8{ "sub.example.", "deep.sub.example." }) |name| {
        const q = try query(arena.allocator(), name, .a);
        const res = try chain.dispatch(arena.allocator(), &q, .udp);
        try std.testing.expectEqual(@as(u16, 1), res.response.header.rcode);
    }
    // exact matcher: only the exact name
    {
        const q = try query(arena.allocator(), "exact.example.", .a);
        const res = try chain.dispatch(arena.allocator(), &q, .udp);
        try std.testing.expectEqual(@as(u16, 2), res.response.header.rcode);
    }
    {
        const q = try query(arena.allocator(), "other.exact.example.", .a);
        const res = try chain.dispatch(arena.allocator(), &q, .udp);
        try std.testing.expectEqual(@as(u16, 5), res.response.header.rcode);
    }
}

test "root pattern matches everything" {
    var chain = Chain.init(std.testing.allocator);
    defer chain.deinit();
    var root = Echo{ .rcode = 0 };
    try chain.add(".", root.handler(), chain_mod.Priority.upstream);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const q = try query(arena.allocator(), "anything.else.", .txt);
    const res = try chain.dispatch(arena.allocator(), &q, .udp);
    try std.testing.expectEqual(@as(u16, 0), res.response.header.rcode);
}

test "continue chain on nxdomain signal then refusal" {
    var chain = Chain.init(std.testing.allocator);
    defer chain.deinit();
    var first = Echo{ .rcode = 3, .continue_on = 3 }; // always continues
    var second = Echo{ .rcode = 0 };
    try chain.add("example.com.", first.handler(), chain_mod.Priority.local);
    try chain.add("example.com.", second.handler(), chain_mod.Priority.upstream);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const q = try query(arena.allocator(), "example.com.", .a);
    const res = try chain.dispatch(arena.allocator(), &q, .udp);
    try std.testing.expectEqual(@as(u16, 0), res.response.header.rcode);
}

test "no match refused, no question dropped" {
    var chain = Chain.init(std.testing.allocator);
    defer chain.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const q = try query(arena.allocator(), "nothing.here.", .a);
    const res = try chain.dispatch(arena.allocator(), &q, .udp);
    try std.testing.expectEqual(@as(u16, 5), res.response.header.rcode); // REFUSED

    const empty = msg.Message{ .header = .{ .id = 2 } };
    const res2 = try chain.dispatch(arena.allocator(), &empty, .udp);
    try std.testing.expect(res2 == .drop);
}

test "replace removes same pattern and priority" {
    var chain = Chain.init(std.testing.allocator);
    defer chain.deinit();
    var a = Echo{ .rcode = 0 };
    var b = Echo{ .rcode = 1 };
    try chain.add("example.com.", a.handler(), chain_mod.Priority.local);
    try chain.add("example.com.", b.handler(), chain_mod.Priority.local); // replaces
    try std.testing.expectEqual(@as(usize, 1), chain.entries.items.len);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const q = try query(arena.allocator(), "example.com.", .a);
    const res = try chain.dispatch(arena.allocator(), &q, .udp);
    try std.testing.expectEqual(@as(u16, 1), res.response.header.rcode);

    chain.remove("example.com.", chain_mod.Priority.local);
    try std.testing.expectEqual(@as(usize, 0), chain.entries.items.len);
}
