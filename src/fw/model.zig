// Port of netbird client/firewall/manager/{firewall,protocol,port,routerpair}.go
// and client/internal/acl/id/id.go (v0.79.0), BSD-3-Clause.
// Rule model for the iptables backend: protocols, ports, actions, networks,
// router pairs, tracked-rule records and deterministic rule IDs.
const std = @import("std");

pub const Error = error{
    InvalidPrefix,
    InvalidBits,
    InvalidPort,
    NoSources,
    IpsetRequired,
    OutOfMemory,
};

pub const Protocol = enum {
    tcp,
    udp,
    icmp,
    all,

    pub fn str(p: Protocol) []const u8 {
        return switch (p) {
            .tcp => "tcp",
            .udp => "udp",
            .icmp => "icmp",
            .all => "all",
        };
    }

    /// protoForFamily: ip6tables wants "ipv6-icmp" instead of "icmp".
    pub fn forFamily(p: Protocol, v6: bool) []const u8 {
        if (v6 and p == .icmp) return "ipv6-icmp";
        return p.str();
    }

    pub fn parse(text: []const u8) ?Protocol {
        if (std.mem.eql(u8, text, "tcp")) return .tcp;
        if (std.mem.eql(u8, text, "udp")) return .udp;
        if (std.mem.eql(u8, text, "icmp")) return .icmp;
        if (std.mem.eql(u8, text, "all")) return .all;
        return null;
    }
};

pub const Action = enum {
    accept,
    drop,

    pub fn str(a: Action) []const u8 {
        return switch (a) {
            .accept => "ACCEPT",
            .drop => "DROP",
        };
    }

    /// Numeric value matching the Go iota (accept=0, drop=1), used in rule IDs.
    pub fn num(a: Action) u8 {
        return switch (a) {
            .accept => 0,
            .drop => 1,
        };
    }
};

pub const Port = struct {
    /// True when values holds exactly [start, end] of a range.
    /// (Upstream applyPort treats a port as a range only when
    /// IsRange is set and there are exactly 2 values.)
    is_range: bool,
    values: []const u16,

    /// Go Port.String(), used only for rule-ID hashing: values joined
    /// with ",", prefixed with "range:" when is_range is set.
    pub fn hashText(p: Port, alloc: std.mem.Allocator) Error![]u8 {
        var buf: std.ArrayListUnmanaged(u8) = .empty;
        errdefer buf.deinit(alloc);
        if (p.is_range) try buf.appendSlice(alloc, "range:");
        for (p.values, 0..) |v, i| {
            if (i > 0) try buf.append(alloc, ',');
            var tmp: [8]u8 = undefined;
            const s = std.fmt.bufPrint(&tmp, "{d}", .{v}) catch unreachable;
            try buf.appendSlice(alloc, s);
        }
        return buf.toOwnedSlice(alloc);
    }
};

pub const Prefix = struct {
    /// Original text ("10.0.0.1/24"), passed through to -s/-d. Caller-owned.
    text: []const u8,
    /// Parsed address bytes (v4 in bytes[0..4]).
    bytes: [16]u8,
    is_v6: bool,
    bits: u8,

    pub fn parse(text: []const u8) Error!Prefix {
        const slash = std.mem.indexOfScalar(u8, text, '/') orelse return Error.InvalidPrefix;
        const addr = std.Io.net.IpAddress.parse(text[0..slash], 0) catch return Error.InvalidPrefix;
        const bits = std.fmt.parseInt(u8, text[slash + 1 ..], 10) catch return Error.InvalidBits;
        switch (addr) {
            .ip4 => |a| {
                if (bits > 32) return Error.InvalidBits;
                var bytes: [16]u8 = std.mem.zeroes([16]u8);
                bytes[0..4].* = a.bytes;
                return .{ .text = text, .bytes = bytes, .is_v6 = false, .bits = bits };
            },
            .ip6 => |a| {
                if (bits > 128) return Error.InvalidBits;
                return .{ .text = text, .bytes = a.bytes, .is_v6 = true, .bits = bits };
            },
        }
    }

    /// A /0 prefix is the explicit "match any" (upstream sourceNetwork).
    pub fn isWildcard(p: Prefix) bool {
        return p.bits == 0;
    }

    /// Sort order matching manager.SortPrefixes: by address, then longest first.
    /// (netip.Addr.Compare sorts v4 before v6.)
    pub fn lessThan(a: Prefix, b: Prefix) bool {
        if (a.is_v6 != b.is_v6) return !a.is_v6;
        const n: usize = if (a.is_v6) 16 else 4;
        const ord = std.mem.order(u8, a.bytes[0..n], b.bytes[0..n]);
        if (ord != .eq) return ord == .lt;
        return a.bits > b.bits;
    }
};

/// Named address set (domain-based route destination). Upstream implements
/// sets with ipset hash:net; the router has no ipset, so a rule carrying a
/// destination set is rejected with IpsetRequired (same as upstream
/// applyNetwork when ipsetSupported is false).
pub const Set = struct {
    name: []const u8,
};

pub const Network = union(enum) {
    none,
    prefix: Prefix,
    set: Set,

    pub fn isZero(n: Network) bool {
        return n == .none;
    }

    pub fn isPrefix(n: Network) bool {
        return n == .prefix;
    }

    pub fn isSet(n: Network) bool {
        return n == .set;
    }

    /// Go Network.String(). The "none" network is the peer-rule sentinel.
    pub fn str(n: Network) []const u8 {
        return switch (n) {
            .none => "<invalid network>",
            .prefix => |p| p.text,
            .set => |s| s.name,
        };
    }
};

pub const forwarding_format_prefix = "netbird-fwd-";

pub const RouterPair = struct {
    id: []const u8,
    source: Network,
    destination: Network,
    masquerade: bool,
    inverse: bool,
    dynamic: bool,

    pub fn inversePair(p: RouterPair) RouterPair {
        return .{
            .id = p.id,
            .source = p.destination,
            .destination = p.source,
            .masquerade = p.masquerade,
            .inverse = true,
            .dynamic = p.dynamic,
        };
    }

    /// Go RouterPair.GenKey: format is "netbird-nat-%s-%t" or "netbird-fwd-%s-%t".
    pub fn genKey(p: RouterPair, alloc: std.mem.Allocator, prefix: []const u8) Error![]u8 {
        return std.fmt.allocPrint(alloc, "{s}{s}-{s}", .{
            prefix,
            p.id,
            if (p.inverse) "true" else "false",
        }) catch Error.OutOfMemory;
    }

    pub fn natKey(p: RouterPair, alloc: std.mem.Allocator) Error![]u8 {
        return p.genKey(alloc, "netbird-nat-");
    }

    pub fn fwdKey(p: RouterPair, alloc: std.mem.Allocator) Error![]u8 {
        return p.genKey(alloc, forwarding_format_prefix);
    }
};

/// One installed iptables rule: owned argv-style arg list (every element owned).
pub const Spec = [][]u8;

pub const ExtraSpec = struct {
    specs: Spec,
    mangle_specs: ?Spec,
};

/// Tracked filter rule (upstream iptables.Rule, without the ipset fields).
/// Stored in Manager.filters keyed by owned id.
pub const FilterRule = struct {
    chain: []const u8, // static chain name, not owned
    specs: Spec,
    mangle_specs: ?Spec,
    extra: []ExtraSpec, // owned (empty slice when none)

    pub fn free(r: *FilterRule, alloc: std.mem.Allocator) void {
        freeSpec(alloc, r.specs);
        if (r.mangle_specs) |s| freeSpec(alloc, s);
        for (r.extra) |*e| {
            freeSpec(alloc, e.specs);
            if (e.mangle_specs) |s| freeSpec(alloc, s);
        }
        if (r.extra.len > 0) alloc.free(r.extra);
        r.* = undefined;
    }
};

/// Tracked NAT/legacy rule: where it was installed plus the exact spec.
/// Stored in Manager.tracked keyed by owned GenKey.
pub const TrackedRule = struct {
    table: []const u8, // static table name, not owned
    chain: []const u8, // static chain name, not owned
    spec: Spec,

    pub fn free(r: *TrackedRule, alloc: std.mem.Allocator) void {
        freeSpec(alloc, r.spec);
        r.* = undefined;
    }
};

pub fn freeSpec(alloc: std.mem.Allocator, spec: Spec) void {
    for (spec) |arg| alloc.free(arg);
    alloc.free(spec);
}

/// Copy an owned Spec into a caller buffer as const args for the runner.
pub fn constArgs(spec: Spec, buf: [][]const u8) []const []const u8 {
    std.debug.assert(buf.len >= spec.len);
    for (spec, 0..) |a, i| buf[i] = a;
    return buf[0..spec.len];
}

/// Builds an owned Spec from static and formatted args. On success the
/// Spec owns every arg; on error everything is freed.
pub const SpecBuilder = struct {
    alloc: std.mem.Allocator,
    args: std.ArrayListUnmanaged([]u8) = .empty,

    pub fn init(alloc: std.mem.Allocator) SpecBuilder {
        return .{ .alloc = alloc };
    }

    /// Deinit frees a builder whose Spec was never built (error paths).
    /// After build() the builder holds nothing.
    pub fn deinit(b: *SpecBuilder) void {
        for (b.args.items) |a| b.alloc.free(a);
        b.args.deinit(b.alloc);
    }

    pub fn arg(b: *SpecBuilder, text: []const u8) Error!void {
        const owned = b.alloc.dupe(u8, text) catch return Error.OutOfMemory;
        errdefer b.alloc.free(owned);
        b.args.append(b.alloc, owned) catch {
            b.alloc.free(owned);
            return Error.OutOfMemory;
        };
    }

    pub fn argf(b: *SpecBuilder, comptime fmt: []const u8, values: anytype) Error!void {
        const owned = std.fmt.allocPrint(b.alloc, fmt, values) catch return Error.OutOfMemory;
        errdefer b.alloc.free(owned);
        b.args.append(b.alloc, owned) catch {
            b.alloc.free(owned);
            return Error.OutOfMemory;
        };
    }

    pub fn appendSpec(b: *SpecBuilder, spec: []const []const u8) Error!void {
        for (spec) |a| try b.arg(a);
    }

    pub fn appendOwned(b: *SpecBuilder, spec: Spec) Error!void {
        for (spec) |a| try b.arg(a);
    }

    pub fn build(b: *SpecBuilder) Error!Spec {
        const out = b.args.toOwnedSlice(b.alloc) catch return Error.OutOfMemory;
        return out;
    }

    pub fn len(b: *const SpecBuilder) usize {
        return b.args.items.len;
    }
};

/// Go nbid.GenerateRuleID: "<destination>-<sha256hex[:16]>" over the
/// canonical serialization (sources sorted).
pub fn generateRuleID(
    alloc: std.mem.Allocator,
    sources: []const Prefix,
    destination: Network,
    proto: Protocol,
    s_port: ?Port,
    d_port: ?Port,
    action: Action,
) Error![]u8 {
    const sorted = alloc.dupe(Prefix, sources) catch return Error.OutOfMemory;
    defer alloc.free(sorted);
    std.mem.sort(Prefix, sorted, {}, struct {
        fn lt(_: void, a: Prefix, b: Prefix) bool {
            return a.lessThan(b);
        }
    }.lt);

    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("sources:");
    for (sorted) |s| {
        h.update(s.text);
        h.update(",");
    }
    h.update("destination:");
    h.update(destination.str());
    h.update("proto:");
    h.update(proto.str());
    h.update("sPort:");
    if (s_port) |p| {
        const t = try p.hashText(alloc);
        defer alloc.free(t);
        h.update(t);
    } else h.update("<nil>");
    h.update("dPort:");
    if (d_port) |p| {
        const t = try p.hashText(alloc);
        defer alloc.free(t);
        h.update(t);
    } else h.update("<nil>");
    h.update("action:");
    var num: [4]u8 = undefined;
    const num_text = std.fmt.bufPrint(&num, "{d}", .{action.num()}) catch unreachable;
    h.update(num_text);
    const digest = h.finalResult();
    const hex: [64]u8 = std.fmt.bytesToHex(digest, .lower);
    return std.fmt.allocPrint(alloc, "{s}-{s}", .{ destination.str(), hex[0..16] }) catch Error.OutOfMemory;
}
