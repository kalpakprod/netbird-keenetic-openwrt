// Port of netbird client/internal/dns/handler_chain.go (v0.79.0), BSD-3-Clause.
// Prioritized chain of DNS handlers: entries sorted by priority (higher
// first), then by domain specificity (more labels first). The first matching
// handler that does not ask to continue wins; no match answers REFUSED.
//
// Go signals "continue to next handler" by writing an NXDOMAIN reply with
// the Zero header bit set (intercepted in ResponseWriterChain.WriteMsg);
// here handlers return .continue_chain directly — same chain semantics,
// without encoding the signal into a message.

const std = @import("std");
const msg = @import("msg.zig");
const Mutex = @import("mutex.zig").Mutex;

pub const Priority = struct {
    pub const mgmt_cache: i32 = 150;
    pub const dns_route: i32 = 100;
    pub const local: i32 = 75;
    pub const upstream: i32 = 50;
    pub const default: i32 = 1;
    pub const fallback: i32 = -100;
};

pub const ServeError = msg.Error;

/// How the request was received, mirrored to upstream exchanges
/// (Go: contextWithDNSProtocol).
pub const Transport = enum { udp, tcp };

/// What a handler did with a query.
pub const Outcome = union(enum) {
    response: msg.Message,
    continue_chain,
};

pub const Handler = struct {
    ctx: *anyopaque,
    match_subdomains: bool = false,
    serveFn: *const fn (ctx: *anyopaque, arena: std.mem.Allocator, req: *const msg.Message, transport: Transport) ServeError!Outcome,

    pub fn serve(h: *const Handler, arena: std.mem.Allocator, req: *const msg.Message, transport: Transport) ServeError!Outcome {
        return h.serveFn(h.ctx, arena, req, transport);
    }
};

pub const Entry = struct {
    handler: Handler,
    pattern: []u8, // lowercase FQDN, wildcard prefix stripped; owned by the chain
    orig_pattern: []u8, // lowercase FQDN as registered; owned by the chain
    priority: i32,
    is_wildcard: bool,
    match_subdomains: bool,
};

pub const Chain = struct {
    alloc: std.mem.Allocator,
    mu: Mutex = .{},
    entries: std.ArrayListUnmanaged(Entry) = .empty,

    pub fn init(alloc: std.mem.Allocator) Chain {
        return .{ .alloc = alloc };
    }

    pub fn deinit(c: *Chain) void {
        for (c.entries.items) |e| {
            c.alloc.free(e.pattern);
            c.alloc.free(e.orig_pattern);
        }
        c.entries.deinit(c.alloc);
    }

    /// AddHandler: lowercases the FQDN pattern, detects the "*." wildcard
    /// prefix, replaces an entry with the same pattern+priority and inserts
    /// by priority desc, then specificity (label count) desc.
    pub fn add(c: *Chain, pattern: []const u8, handler: Handler, priority: i32) !void {
        try c.addInner(pattern, handler, priority, true);
    }

    /// AddHandlerNoSubdomains: same, but the handler only answers exact
    /// names (no subdomain suffix match).
    pub fn addExact(c: *Chain, pattern: []const u8, handler: Handler, priority: i32) !void {
        try c.addInner(pattern, handler, priority, false);
    }

    fn addInner(c: *Chain, pattern: []const u8, handler: Handler, priority: i32, match_subdomains: bool) !void {
        const lowered = try lowercaseFqdn(c.alloc, pattern);
        errdefer c.alloc.free(lowered);

        c.mu.lock();
        defer c.mu.unlock();

        // replace: drop any existing entry with the same orig pattern+priority
        var i: usize = c.entries.items.len;
        while (i > 0) {
            i -= 1;
            const e = c.entries.items[i];
            if (e.priority == priority and std.ascii.eqlIgnoreCase(e.orig_pattern, lowered)) {
                c.alloc.free(e.pattern);
                c.alloc.free(e.orig_pattern);
                _ = c.entries.orderedRemove(i);
                break;
            }
        }

        var pat = lowered;
        const orig = try c.alloc.dupe(u8, lowered);
        errdefer c.alloc.free(orig);
        var is_wildcard = false;
        if (std.mem.startsWith(u8, pat, "*.")) {
            is_wildcard = true;
            const stripped = try c.alloc.dupe(u8, pat[2..]);
            c.alloc.free(pat);
            pat = stripped;
        }

        const entry = Entry{
            .handler = handler,
            .pattern = pat,
            .orig_pattern = orig,
            .priority = priority,
            .is_wildcard = is_wildcard,
            .match_subdomains = match_subdomains,
        };
        const pos = c.findPosition(entry);
        try c.entries.insert(c.alloc, pos, entry);
    }

    fn findPosition(c: *Chain, new_entry: Entry) usize {
        for (c.entries.items, 0..) |h, i| {
            if (h.priority < new_entry.priority) return i;
            if (h.priority == new_entry.priority and
                std.mem.count(u8, new_entry.pattern, ".") > std.mem.count(u8, h.pattern, "."))
            {
                return i;
            }
        }
        return c.entries.items.len;
    }

    /// RemoveHandler for the given pattern and priority (no-op when absent).
    pub fn remove(c: *Chain, pattern: []const u8, priority: i32) void {
        c.mu.lock();
        defer c.mu.unlock();
        var i: usize = c.entries.items.len;
        while (i > 0) {
            i -= 1;
            const e = c.entries.items[i];
            if (e.priority == priority and std.ascii.eqlIgnoreCase(e.orig_pattern, pattern)) {
                c.alloc.free(e.pattern);
                c.alloc.free(e.orig_pattern);
                _ = c.entries.orderedRemove(i);
                break;
            }
        }
    }

    pub const DispatchResult = union(enum) {
        response: msg.Message, // pack and send
        drop, // no question — nothing to answer
    };

    /// dispatch: run matching handlers in chain order; the first response
    /// wins, .continue_chain moves to the next handler; none matched or all
    /// continued → REFUSED (Go dispatch tail).
    pub fn dispatch(c: *Chain, arena: std.mem.Allocator, req: *const msg.Message, transport: Transport) ServeError!DispatchResult {
        if (req.question.len == 0) return .drop;
        const qname = try lowercaseFqdnArena(arena, req.question[0].name);

        c.mu.lock();
        defer c.mu.unlock();

        for (c.entries.items) |*entry| {
            if (!isHandlerMatch(qname, entry)) continue;
            switch (try entry.handler.serve(arena, req, transport)) {
                .response => |m| return .{ .response = m },
                .continue_chain => continue,
            }
        }
        var refused = msg.Message{};
        refused.setRcode(req, 5);
        return .{ .response = refused };
    }

    fn isHandlerMatch(qname: []const u8, entry: *const Entry) bool {
        if (std.mem.eql(u8, entry.pattern, ".")) return true;
        if (entry.is_wildcard) {
            return matchSuffix(qname, entry.pattern);
        }
        if (entry.match_subdomains) {
            return std.ascii.eqlIgnoreCase(qname, entry.pattern) or matchSuffix(qname, entry.pattern);
        }
        return std.ascii.eqlIgnoreCase(qname, entry.pattern);
    }

    fn matchSuffix(qname: []const u8, pattern: []const u8) bool {
        if (qname.len <= pattern.len) return false;
        const tail = qname[qname.len - pattern.len - 1 ..];
        if (tail[0] != '.') return false;
        return std.ascii.eqlIgnoreCase(tail[1..], pattern);
    }
};

/// Lowercase + ensure the trailing dot (Go: strings.ToLower(dns.Fqdn(p))).
pub fn lowercaseFqdn(alloc: std.mem.Allocator, pattern: []const u8) ![]u8 {
    var out = try alloc.dupe(u8, pattern);
    errdefer alloc.free(out);
    for (out) |*ch| ch.* = std.ascii.toLower(ch.*);
    if (out.len > 0 and out[out.len - 1] != '.') {
        const with_dot = try alloc.realloc(out, out.len + 1);
        with_dot[out.len] = '.';
        out = with_dot;
    }
    return out;
}

fn lowercaseFqdnArena(alloc: std.mem.Allocator, name: []const u8) ![]u8 {
    return lowercaseFqdn(alloc, name);
}
