// Port of netbird client/internal/dns/local/local.go (v0.79.0), BSD-3-Clause:
// the local record resolver. Serves registered records from the management
// netmap (custom zones), follows CNAME chains (musl expects full answer
// chains), resolves wildcard names (RFC 4592), round-robins multi-record
// answers and falls through to the next handler for non-authoritative
// zones it cannot answer.
//
// Not ported (engine wiring, later milestone): PeerConnectivity filtering of
// answers pointing at disconnected peers, PeerActivator lazy-connection
// warm-up. External resolution of out-of-zone CNAME targets goes through an
// injected lookup callback (Go: net.DefaultResolver) — the engine wires the
// system resolver or the upstream forwarder.

const std = @import("std");
const msg = @import("msg.zig");
const chain_mod = @import("chain.zig");
const Mutex = @import("mutex.zig").Mutex;

pub const external_resolution_timeout_ms: u32 = 4000; // Go externalResolutionTimeout
const max_cname_depth = 8;
const external_record_ttl = 60;

pub const rcode_success: u16 = 0;
pub const rcode_server_failure: u16 = 2;
pub const rcode_name_error: u16 = 3;
pub const rcode_not_implemented: u16 = 4;
const rcode_keep_following: i32 = -1;

/// A management-provided DNS zone with its records (nbdns.CustomZone).
pub const Zone = struct {
    domain: []const u8,
    non_authoritative: bool = false,
    records: []const msg.RR = &.{},
};

/// External lookup result (resutil.LookupIP subset: only the parts the
/// local resolver consumes).
pub const ExternalResult = struct {
    rcode: u16 = rcode_success,
    addrs: []const []const u8 = &.{}, // dotted-quad or IPv6 text (parsed by caller into RR)
};

pub const LookupError = error{OutOfMemory} || msg.Error;

pub const ExternalLookup = struct {
    ctx: *anyopaque,
    lookupFn: *const fn (ctx: *anyopaque, arena: std.mem.Allocator, name: []const u8, qtype: u16) LookupError!ExternalResult,
};

pub const Resolver = struct {
    alloc: std.mem.Allocator,
    store: *std.heap.ArenaAllocator,
    mu: Mutex = .{},
    records: std.StringHashMapUnmanaged(std.ArrayListUnmanaged(msg.RR)) = .empty,
    domains: std.StringHashMapUnmanaged(void) = .empty,
    zones: std.StringHashMapUnmanaged(bool) = .empty,
    external: ?ExternalLookup = null,

    pub fn init(alloc: std.mem.Allocator, store: *std.heap.ArenaAllocator) Resolver {
        return .{ .alloc = alloc, .store = store };
    }

    /// Stop: drop all state (Go Resolver.Stop; no context to cancel here).
    pub fn deinit(r: *Resolver) void {
        r.records.deinit(r.alloc);
        r.domains.deinit(r.alloc);
        r.zones.deinit(r.alloc);
    }

    /// Update replaces all zones and their records (Go Resolver.Update).
    pub fn update(r: *Resolver, zones: []const Zone) !void {
        r.mu.lock();
        defer r.mu.unlock();
        _ = r.store.reset(.retain_capacity);
        r.records.clearRetainingCapacity();
        r.domains.clearRetainingCapacity();
        r.zones.clearRetainingCapacity();
        for (zones) |zone| {
            const zone_domain = try chain_mod.lowercaseFqdn(r.store.allocator(), zone.domain);
            try r.zones.put(r.alloc, zone_domain, zone.non_authoritative);
            for (zone.records) |rec| {
                // a record the codec cannot represent is skipped (Go logs
                // and continues with the rest of the zone)
                r.registerLocked(rec) catch {};
            }
        }
    }

    /// RegisterRecord appends one record (Go Resolver.RegisterRecord).
    pub fn registerRecord(r: *Resolver, rr: msg.RR) !void {
        r.mu.lock();
        defer r.mu.unlock();
        try r.registerLocked(rr);
    }

    fn registerLocked(r: *Resolver, rr: msg.RR) !void {
        const a = r.store.allocator();
        const name = try chain_mod.lowercaseFqdn(a, rr.name);
        const key = try std.fmt.allocPrint(a, "{s}|{d}|{d}", .{ name, @intFromEnum(rr.type), rr.class });
        const gop = try r.records.getOrPut(r.alloc, key);
        if (!gop.found_existing) gop.value_ptr.* = .empty;
        try gop.value_ptr.append(a, try dupRR(a, rr, name));
        try r.domains.put(r.alloc, try a.dupe(u8, name), {});
    }

    /// chain.Handler adapter.
    pub fn handler(r: *Resolver) chain_mod.Handler {
        return .{ .ctx = r, .match_subdomains = true, .serveFn = serveFn };
    }

    fn serveFn(ctx: *anyopaque, arena: std.mem.Allocator, req: *const msg.Message, transport: chain_mod.Transport) chain_mod.ServeError!chain_mod.Outcome {
        _ = transport;
        const r: *Resolver = @ptrCast(@alignCast(ctx));
        if (req.question.len == 0) return .continue_chain; // nothing to answer
        const question = req.question[0];
        const name = try chain_mod.lowercaseFqdn(arena, question.name);

        const result = try r.lookupRecords(arena, name, @intFromEnum(question.type), question.class);

        var reply = msg.Message{};
        reply.setReply(req);
        reply.header.recursion_available = true;
        reply.header.authoritative = !result.has_external_data;
        reply.answer = result.records;
        reply.header.rcode = r.determineRcode(name, @intFromEnum(question.type), result);

        if (reply.header.rcode == rcode_name_error and r.shouldFallthrough(name)) {
            return .continue_chain;
        }
        return .{ .response = reply };
    }

    const LookupResult = struct {
        records: []const msg.RR = &.{},
        rcode: i32 = rcode_success,
        has_external_data: bool = false,
    };

    /// lookupRecords fetches all records matching the name+type, trying the
    /// wildcard form for absent names (RFC 4592: wildcard only matches when
    /// the name itself does not exist), then CNAME chains.
    fn lookupRecords(r: *Resolver, arena: std.mem.Allocator, name: []const u8, qtype: u16, qclass: u16) !LookupResult {
        r.mu.lock();
        const found = r.getRecordsLocked(arena, name, qtype, qclass) catch |err| {
            r.mu.unlock();
            return err;
        };
        var using_wildcard = false;
        var records = found;
        var wild_name: []const u8 = "";
        if (records.len == 0 and supportsWildcard(qtype)) {
            const domain_exists = r.domains.contains(name);
            if (!domain_exists) {
                wild_name = try wildcardOf(arena, name);
                records = try r.getRecordsLocked(arena, wild_name, qtype, qclass);
                using_wildcard = records.len > 0;
            }
        }
        if (records.len == 0) {
            r.mu.unlock();
            if (qtype != qtype_cname) {
                return r.lookupCNAMEChain(arena, name, qtype, qclass);
            }
            return .{ .rcode = rcode_name_error };
        }

        // round-robin: rotate the stored list when more than one record; the
        // answer is always deep-copied into the query arena (detached from
        // the store so a concurrent update cannot invalidate it)
        var answer = records;
        if (records.len > 1) {
            // rotate the stored list (orderedRemove+append rewrites the same
            // backing array the stale `records` slice points at)
            const key = if (using_wildcard)
                try std.fmt.allocPrint(arena, "{s}|{d}|{d}", .{ wild_name, qtype, qclass })
            else
                try std.fmt.allocPrint(arena, "{s}|{d}|{d}", .{ name, qtype, qclass });
            if (r.records.getPtr(key)) |list| {
                if (list.items.len > 1) {
                    const first = list.orderedRemove(0);
                    try list.append(r.store.allocator(), first);
                }
            }
            // detach the answer from the store: a concurrent update must not
            // invalidate it while the caller packs the response
            const detached = try arena.alloc(msg.RR, records.len);
            @memcpy(detached, records);
            answer = detached;
        }
        r.mu.unlock();

        const answer_name = if (using_wildcard) name else answer[0].name;
        const copies = try arena.alloc(msg.RR, answer.len);
        for (answer, 0..) |rr, i| copies[i] = try dupRR(arena, rr, answer_name);
        return .{ .records = copies, .rcode = rcode_success };
    }

    fn getRecordsLocked(r: *Resolver, arena: std.mem.Allocator, name: []const u8, qtype: u16, qclass: u16) ![]const msg.RR {
        const key = try std.fmt.allocPrint(arena, "{s}|{d}|{d}", .{ name, qtype, qclass });
        if (r.records.get(key)) |list| return list.items;
        return &.{};
    }

    /// Follow a CNAME chain and return the chain records plus the final
    /// record of the requested type (musl needs the full chain).
    fn lookupCNAMEChain(r: *Resolver, arena: std.mem.Allocator, name: []const u8, qtype: u16, qclass: u16) !LookupResult {
        var cname_records_list: std.ArrayListUnmanaged(msg.RR) = .empty;
        var current = name;
        for (0..max_cname_depth) |_| {
            r.mu.lock();
            var cname_records = r.getRecordsLocked(arena, current, qtype_cname, qclass) catch |err| {
                r.mu.unlock();
                return err;
            };
            if (cname_records.len == 0 and supportsWildcard(qtype)) {
                const wild = try wildcardOf(arena, current);
                cname_records = r.getRecordsLocked(arena, wild, qtype_cname, qclass) catch |err| {
                    r.mu.unlock();
                    return err;
                };
                if (cname_records.len > 0) {
                    const rewritten = try arena.alloc(msg.RR, cname_records.len);
                    for (cname_records, 0..) |rr, i| rewritten[i] = try dupRR(arena, rr, current);
                    cname_records = rewritten;
                }
            }
            r.mu.unlock();

            if (cname_records.len == 0) break;
            try cname_records_list.appendSlice(arena, cname_records);

            const target = try chain_mod.lowercaseFqdn(arena, cname_records[0].data.cname);
            const target_result = try r.resolveCnameTarget(arena, target, qtype);

            if (target_result.rcode == rcode_keep_following) {
                current = target;
                continue;
            }
            // buildChainResult
            var records = cname_records_list.items;
            if (target_result.records.len > 0) {
                const all = try arena.alloc(msg.RR, records.len + target_result.records.len);
                @memcpy(all[0..records.len], records);
                @memcpy(all[records.len..], target_result.records);
                records = all;
            }
            if (target_result.has_external_data and target_result.rcode == rcode_server_failure) {
                return .{ .records = records, .rcode = rcode_server_failure, .has_external_data = true };
            }
            return .{ .records = records, .rcode = target_result.rcode, .has_external_data = target_result.has_external_data };
        }

        if (cname_records_list.items.len > 0) {
            return .{ .records = cname_records_list.items, .rcode = rcode_success };
        }
        return .{ .rcode = rcode_success };
    }

    /// resolveCnameTarget: -1 rcode signals "keep following the chain".
    fn resolveCnameTarget(r: *Resolver, arena: std.mem.Allocator, target: []const u8, qtype: u16) !LookupResult {
        r.mu.lock();
        const recs = r.getRecordsLocked(arena, target, qtype, class_inet) catch |err| {
            r.mu.unlock();
            return err;
        };
        if (recs.len > 0) {
            r.mu.unlock();
            return .{ .records = recs, .rcode = rcode_success };
        }
        const cname_key = try std.fmt.allocPrint(arena, "{s}|{d}|{d}", .{ target, qtype_cname, class_inet });
        const has_cname = r.records.contains(cname_key);
        const nodata = r.hasRecordsForDomainLocked(target, qtype);
        r.mu.unlock();
        if (has_cname) return .{ .rcode = rcode_keep_following };
        if (nodata) return .{ .rcode = rcode_success };
        if (r.isInManagedZone(target)) return .{ .rcode = rcode_name_error };
        return r.resolveExternal(arena, target, qtype);
    }

    /// resolveExternal: resolve a name that points outside our zones through
    /// the injected resolver (Go uses net.DefaultResolver).
    fn resolveExternal(r: *Resolver, arena: std.mem.Allocator, name: []const u8, qtype: u16) !LookupResult {
        const external = r.external orelse return .{ .rcode = rcode_success };
        if (qtype != qtype_a and qtype != qtype_aaaa) return .{ .rcode = rcode_not_implemented };
        const result = external.lookupFn(external.ctx, arena, name, qtype) catch {
            return .{ .rcode = rcode_server_failure, .has_external_data = true };
        };
        if (result.rcode != rcode_success) {
            return .{ .rcode = result.rcode, .has_external_data = true };
        }
        var rrs: std.ArrayListUnmanaged(msg.RR) = .empty;
        for (result.addrs) |addr_text| {
            const rr = addrToRR(arena, name, addr_text, external_record_ttl) catch continue;
            try rrs.append(arena, rr);
        }
        return .{ .records = rrs.items, .rcode = rcode_success, .has_external_data = true };
    }

    /// determineRcode: the lookup rcode, NODATA as NOERROR, else NXDOMAIN.
    fn determineRcode(r: *Resolver, name: []const u8, qtype: u16, result: LookupResult) u16 {
        if (result.rcode != 0) return @intCast(result.rcode);
        r.mu.lock();
        defer r.mu.unlock();
        if (r.hasRecordsForDomainLocked(name, qtype)) return rcode_success;
        return rcode_name_error;
    }

    fn hasRecordsForDomainLocked(r: *Resolver, name: []const u8, qtype: u16) bool {
        if (r.domains.contains(name)) return true;
        if (supportsWildcard(qtype)) {
            var buf: [300]u8 = undefined;
            const wild = wildcardOfBuf(&buf, name) orelse return false;
            return r.domains.contains(wild);
        }
        return false;
    }

    /// shouldFallthrough: the queried name belongs to a non-authoritative
    /// zone (Go Resolver.shouldFallthrough).
    pub fn shouldFallthrough(r: *Resolver, qname: []const u8) bool {
        r.mu.lock();
        defer r.mu.unlock();
        const found = r.findZoneLocked(qname) orelse return false;
        return found;
    }

    /// findZone: reverse suffix lookup; returns non_authoritative.
    fn findZoneLocked(r: *Resolver, qname: []const u8) ?bool {
        var name = qname;
        while (true) {
            if (r.zones.get(name)) |non_auth| return non_auth;
            const idx = std.mem.indexOfScalar(u8, name, '.') orelse return null;
            if (idx == name.len - 1) return null;
            name = name[idx + 1 ..];
        }
    }

    pub fn isInManagedZone(r: *Resolver, name: []const u8) bool {
        r.mu.lock();
        defer r.mu.unlock();
        return r.findZoneLocked(name) != null;
    }
};

const qtype_a: u16 = 1;
const qtype_cname: u16 = 5;
const qtype_ptr: u16 = 12;
const qtype_aaaa: u16 = 28;
const class_inet: u16 = 1;

fn supportsWildcard(qtype: u16) bool {
    return qtype != 2 and qtype != 6; // NS, SOA
}

/// "*." ++ name minus its first label (Go transformDomainToWildcard).
fn wildcardOf(arena: std.mem.Allocator, name: []const u8) ![]const u8 {
    const dot = std.mem.indexOfScalar(u8, name, '.') orelse return error.BadRdata;
    return std.fmt.allocPrint(arena, "*.{s}", .{name[dot + 1 ..]});
}

fn wildcardOfBuf(buf: []u8, name: []const u8) ?[]const u8 {
    const dot = std.mem.indexOfScalar(u8, name, '.') orelse return null;
    return std.fmt.bufPrint(buf, "*.{s}", .{name[dot + 1 ..]}) catch null;
}

/// Copy an RR into the given allocator, renaming the owner. Rdata slices
/// are duplicated (arena-friendly).
fn dupRR(alloc: std.mem.Allocator, rr: msg.RR, new_name: []const u8) !msg.RR {
    const name = try alloc.dupe(u8, new_name);
    var out = rr;
    out.name = name;
    switch (rr.data) {
        .cname => |t| out.data = .{ .cname = try alloc.dupe(u8, t) },
        .ptr => |t| out.data = .{ .ptr = try alloc.dupe(u8, t) },
        .srv => |srv| out.data = .{ .srv = .{
            .priority = srv.priority,
            .weight = srv.weight,
            .port = srv.port,
            .target = try alloc.dupe(u8, srv.target),
        } },
        .txt => |strings| {
            const copies = try alloc.alloc([]const u8, strings.len);
            for (strings, 0..) |s, i| copies[i] = try alloc.dupe(u8, s);
            out.data = .{ .txt = copies };
        },
        else => {},
    }
    return out;
}

/// Build an A/AAAA record from a text address (resutil.IPsToRRs subset).
/// The name slice comes from the caller's arena unchanged.
fn addrToRR(arena: std.mem.Allocator, name: []const u8, addr_text: []const u8, ttl: u32) !msg.RR {
    _ = arena;
    const ip = std.Io.net.IpAddress.parse(addr_text, 0) catch return error.BadRdata;
    return switch (ip) {
        .ip4 => |v| .{ .name = name, .type = .a, .class = class_inet, .ttl = ttl, .data = .{ .a = v.bytes } },
        .ip6 => |v| .{ .name = name, .type = .aaaa, .class = class_inet, .ttl = ttl, .data = .{ .aaaa = v.bytes } },
    };
}
