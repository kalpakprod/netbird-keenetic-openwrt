// Port of netbirdio/go-nat gateway discovery (v0.79.0), BSD-3-Clause:
// nat.go selectGateway (PCP preferred, first fallback wins, PCPv6 pinhole
// attached independently), the upnp/natpmp/pcp probers, and state.go
// defaultDiscoverGateway/reserveForPinhole (IPv6-only PCP fallback).
//
// Adaptation: Go races the probers concurrently; here they run sequentially
// under the same budgets (PCP wins ties either way). Worst case on an empty
// network is still the 10s discovery budget.
const std = @import("std");
const linux = std.os.linux;
const natpmp = @import("natpmp.zig");
const pcp = @import("pcp.zig");
const upnp = @import("upnp.zig");
const gateway = @import("gateway.zig");

pub const discovery_timeout_ms: i64 = 10000;
pub const pinhole_reserve_ms: i64 = 3000;
pub const pcp_probe_ms: i64 = 2000;
pub const natpmp_probe_ms: i64 = 2000;
pub const unicast_window_ms: i64 = 2000;
pub const multicast_wait_s: u8 = 5;
pub const pinhole_op_ms: i64 = 5000;

pub const Error = natpmp.Error || pcp.Error || upnp.Error || gateway.Error || error{
    NoGateway,
    NoSpace,
    NoHealthCheck,
    InvalidProtocol,
};

fn nowMs() i64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return ts.sec * 1000 + @divTrunc(ts.nsec, 1_000_000);
}

fn mapProto(proto: []const u8) Error!struct { pm: natpmp.Protocol, num: u8 } {
    if (std.mem.eql(u8, proto, "udp")) return .{ .pm = .udp, .num = pcp.proto_udp };
    if (std.mem.eql(u8, proto, "tcp")) return .{ .pm = .tcp, .num = pcp.proto_tcp };
    return Error.InvalidProtocol;
}

/// Port of go-nat natpmpNAT: protocol client plus the external-port cache.
/// Delete is a cache drop only (mappings expire by lifetime).
pub const NatpmpGw = struct {
    client: natpmp.Client,
    ports: [8]struct { internal: u16, external: u16 } = undefined,
    n_ports: usize = 0,

    pub fn close(g: *NatpmpGw) void {
        g.client.close();
    }

    fn cachedExt(g: *NatpmpGw, internal: u16) ?u16 {
        for (g.ports[0..g.n_ports]) |e| {
            if (e.internal == internal) return e.external;
        }
        return null;
    }

    fn storeExt(g: *NatpmpGw, internal: u16, external: u16) void {
        for (g.ports[0..g.n_ports]) |*e| {
            if (e.internal == internal) {
                e.external = external;
                return;
            }
        }
        if (g.n_ports < g.ports.len) {
            g.ports[g.n_ports] = .{ .internal = internal, .external = external };
            g.n_ports += 1;
        }
    }

    fn dropExt(g: *NatpmpGw, internal: u16) void {
        for (g.ports[0..g.n_ports], 0..) |e, i| {
            if (e.internal == internal) {
                g.ports[i] = g.ports[g.n_ports - 1];
                g.n_ports -= 1;
                return;
            }
        }
    }

    /// Cached external port first, then 3 random tries, like Go.
    pub fn addPortMapping(g: *NatpmpGw, proto: natpmp.Protocol, internal: u16, ttl_s: u32, timeout_ms: i64) Error!u16 {
        g.client.timeout_ms = @intCast(@max(timeout_ms, 1));
        if (g.cachedExt(internal)) |ext| {
            if (g.client.addPortMapping(proto, internal, ext, ttl_s)) |m| {
                return m.external_port;
            } else |_| {}
        }
        var tries: usize = 0;
        while (tries < 3) : (tries += 1) {
            const want = upnp.randomPort();
            if (g.client.addPortMapping(proto, internal, want, ttl_s)) |m| {
                g.storeExt(internal, m.external_port);
                return m.external_port;
            } else |_| {}
        }
        return Error.MapFailed;
    }
};

pub const UpnpGw = struct {
    client: upnp.Client,
    type_buf: [32]u8 = undefined,
    type_len: usize = 0,

    pub fn typeString(g: *const UpnpGw) []const u8 {
        return g.type_buf[0..g.type_len];
    }
};

/// Short service name for the UPnP type string ("UPnP unicast (IP2)").
pub fn shortService(urn: []const u8) []const u8 {
    if (std.mem.indexOf(u8, urn, "WANIPConnection:2") != null) return "IP2";
    if (std.mem.indexOf(u8, urn, "WANIPConnection:1") != null) return "IP1";
    if (std.mem.indexOf(u8, urn, "WANPPPConnection") != null) return "PPP1";
    return "?";
}

pub const V4Gateway = union(enum) {
    natpmp: NatpmpGw,
    pcp: pcp.Client,
    upnp: UpnpGw,

    pub fn close(g: *V4Gateway) void {
        switch (g.*) {
            .natpmp => |*n| n.close(),
            .pcp, .upnp => {},
        }
    }

    pub fn typeString(g: *const V4Gateway) []const u8 {
        return switch (g.*) {
            .natpmp => "NAT-PMP",
            .pcp => "PCP",
            .upnp => |*u| u.typeString(),
        };
    }
};

/// Port of natWithPCPIPv6: best-effort PCPv6 pinholes alongside IPv4.
pub const DualGw = struct {
    v4: V4Gateway,
    pcp6: pcp.Client,
    pinhole_failed: bool = false,
};

pub const Gateway = union(enum) {
    natpmp: NatpmpGw,
    pcp: pcp.Client,
    upnp: UpnpGw,
    dual: DualGw,
    pcp6only: pcp.Client,

    pub fn close(g: *Gateway) void {
        switch (g.*) {
            .natpmp => |*n| n.close(),
            .dual => |*d| d.v4.close(),
            .pcp, .upnp, .pcp6only => {},
        }
    }

    /// Port of NAT.Type, including the +PCPv6 suffix (written into out).
    pub fn typeString(g: *const Gateway, out: []u8) Error![]u8 {
        switch (g.*) {
            .natpmp => return @constCast("NAT-PMP"),
            .pcp, .pcp6only => return @constCast("PCP"),
            .upnp => |*u| return @constCast(u.typeString()),
            .dual => |*d| {
                const v4t = d.v4.typeString();
                const suffix = "+PCPv6";
                if (v4t.len + suffix.len > out.len) return Error.NoSpace;
                @memcpy(out[0..v4t.len], v4t);
                @memcpy(out[v4t.len..][0..suffix.len], suffix);
                return out[0 .. v4t.len + suffix.len];
            },
        }
    }

    pub fn supportsHealth(g: *const Gateway) bool {
        return switch (g.*) {
            .pcp, .dual, .pcp6only => true,
            .natpmp, .upnp => false,
        };
    }

    fn v4Add(g: *V4Gateway, proto: []const u8, internal: u16, desc: []const u8, ttl_s: u32, timeout_ms: i64) Error!u16 {
        const mp = try mapProto(proto);
        switch (g.*) {
            .natpmp => |*n| return n.addPortMapping(mp.pm, internal, ttl_s, timeout_ms),
            .pcp => |*c| {
                c.timeout_ms = @intCast(@max(timeout_ms, 1));
                const m = try c.addPortMapping(mp.num, internal, ttl_s);
                return m.external_port;
            },
            .upnp => |*u| {
                u.client.timeout_ms = @intCast(@max(timeout_ms, 1));
                return u.client.addPortMapping(proto, internal, desc, ttl_s);
            },
        }
    }

    fn v4Delete(g: *V4Gateway, proto: []const u8, internal: u16, timeout_ms: i64) Error!void {
        const mp = try mapProto(proto);
        switch (g.*) {
            // Go's natpmpNAT.DeletePortMapping only drops the cache.
            .natpmp => |*n| n.dropExt(internal),
            .pcp => |*c| {
                c.timeout_ms = @intCast(@max(timeout_ms, 1));
                try c.deletePortMapping(mp.num, internal);
            },
            .upnp => |*u| {
                u.client.timeout_ms = @intCast(@max(timeout_ms, 1));
                try u.client.deletePortMapping(proto, internal);
            },
        }
    }

    pub fn addPortMapping(g: *Gateway, proto: []const u8, internal: u16, desc: []const u8, ttl_s: u32, timeout_ms: i64) Error!u16 {
        switch (g.*) {
            .natpmp => |*n| {
                const mp = try mapProto(proto);
                return n.addPortMapping(mp.pm, internal, ttl_s, timeout_ms);
            },
            .pcp => |*c| {
                const mp = try mapProto(proto);
                c.timeout_ms = @intCast(@max(timeout_ms, 1));
                const m = try c.addPortMapping(mp.num, internal, ttl_s);
                return m.external_port;
            },
            .upnp => |*u| {
                u.client.timeout_ms = @intCast(@max(timeout_ms, 1));
                return u.client.addPortMapping(proto, internal, desc, ttl_s);
            },
            .pcp6only => |*c| {
                const mp = try mapProto(proto);
                c.timeout_ms = @intCast(@max(timeout_ms, 1));
                const m = try c.addPortMapping(mp.num, internal, ttl_s);
                return m.external_port;
            },
            .dual => |*d| {
                // Go opens the pinhole concurrently; sequential here, same
                // outcome: best effort, never fails the call on its own.
                const mp = try mapProto(proto);
                d.pcp6.timeout_ms = @intCast(pinhole_op_ms);
                const perr: ?Error = blk: {
                    _ = d.pcp6.addPortMapping(mp.num, internal, ttl_s) catch |e| break :blk e;
                    break :blk null;
                };
                const port = v4Add(&d.v4, proto, internal, desc, ttl_s, timeout_ms) catch |e| {
                    if (perr == null) {
                        // Roll back the orphaned pinhole on its own budget.
                        d.pcp6.timeout_ms = @intCast(pinhole_op_ms);
                        d.pcp6.deletePortMapping(mp.num, internal) catch {};
                    }
                    d.pinhole_failed = true;
                    return e;
                };
                d.pinhole_failed = perr != null;
                return port;
            },
        }
    }

    pub fn deletePortMapping(g: *Gateway, proto: []const u8, internal: u16, timeout_ms: i64) Error!void {
        switch (g.*) {
            .natpmp => |*n| {
                _ = try mapProto(proto);
                n.dropExt(internal);
            },
            .pcp => |*c| {
                const mp = try mapProto(proto);
                c.timeout_ms = @intCast(@max(timeout_ms, 1));
                try c.deletePortMapping(mp.num, internal);
            },
            .upnp => |*u| {
                u.client.timeout_ms = @intCast(@max(timeout_ms, 1));
                try u.client.deletePortMapping(proto, internal);
            },
            .pcp6only => |*c| {
                const mp = try mapProto(proto);
                c.timeout_ms = @intCast(@max(timeout_ms, 1));
                try c.deletePortMapping(mp.num, internal);
            },
            .dual => |*d| {
                const mp = try mapProto(proto);
                d.pcp6.timeout_ms = @intCast(pinhole_op_ms);
                d.pcp6.deletePortMapping(mp.num, internal) catch {
                    d.pinhole_failed = true;
                };
                try v4Delete(&d.v4, proto, internal, timeout_ms);
            },
        }
    }

    pub const ExtAddr = struct {
        ip16: [16]u8,
        is_v6: bool,
    };

    fn v4External(g: *V4Gateway, timeout_ms: i64) Error!ExtAddr {
        switch (g.*) {
            .natpmp => |*n| {
                n.client.timeout_ms = @intCast(@max(timeout_ms, 1));
                const ip = try n.client.externalAddress();
                return .{ .ip16 = pcp.mapV4(ip), .is_v6 = false };
            },
            .pcp => |*c| {
                c.timeout_ms = @intCast(@max(timeout_ms, 1));
                const ip = try c.externalAddress();
                return .{ .ip16 = ip, .is_v6 = !pcp.isMappedV4(ip) };
            },
            .upnp => |*u| {
                u.client.timeout_ms = @intCast(@max(timeout_ms, 1));
                const ip = try u.client.externalAddress();
                return .{ .ip16 = pcp.mapV4(ip), .is_v6 = false };
            },
        }
    }

    pub fn externalAddress(g: *Gateway, timeout_ms: i64) Error!ExtAddr {
        switch (g.*) {
            .natpmp => |*n| {
                n.client.timeout_ms = @intCast(@max(timeout_ms, 1));
                const ip = try n.client.externalAddress();
                return .{ .ip16 = pcp.mapV4(ip), .is_v6 = false };
            },
            .pcp => |*c| {
                c.timeout_ms = @intCast(@max(timeout_ms, 1));
                const ip = try c.externalAddress();
                return .{ .ip16 = ip, .is_v6 = !pcp.isMappedV4(ip) };
            },
            .upnp => |*u| {
                u.client.timeout_ms = @intCast(@max(timeout_ms, 1));
                const ip = try u.client.externalAddress();
                return .{ .ip16 = pcp.mapV4(ip), .is_v6 = false };
            },
            .pcp6only => |*c| {
                c.timeout_ms = @intCast(@max(timeout_ms, 1));
                const ip = try c.externalAddress();
                return .{ .ip16 = ip, .is_v6 = true };
            },
            .dual => |*d| return v4External(&d.v4, timeout_ms),
        }
    }

    /// Port of CheckServerHealth: ANNOUNCE the PCP stacks, report the epoch
    /// and whether either restarted. Only call when supportsHealth.
    pub fn healthCheck(g: *Gateway, timeout_ms: i64) Error!struct { epoch: u32, restarted: bool } {
        switch (g.*) {
            .pcp => |*c| {
                c.timeout_ms = @intCast(@max(timeout_ms, 1));
                const epoch = try c.announce();
                return .{ .epoch = epoch, .restarted = c.epochStateLost() };
            },
            .pcp6only => |*c| {
                c.timeout_ms = @intCast(@max(timeout_ms, 1));
                const epoch = try c.announce();
                return .{ .epoch = epoch, .restarted = c.epochStateLost() };
            },
            .dual => |*d| {
                d.pcp6.timeout_ms = @intCast(pinhole_op_ms);
                const e6 = d.pcp6.announce() catch null;
                const r6 = if (e6 != null) d.pcp6.epochStateLost() else false;
                if (d.v4 == .pcp) {
                    d.v4.pcp.timeout_ms = @intCast(@max(timeout_ms, 1));
                    const e4 = d.v4.pcp.announce() catch null;
                    if (e4 == null and e6 == null) return Error.Timeout;
                    if (e4 == null) return .{ .epoch = e6.?, .restarted = r6 };
                    const r4 = d.v4.pcp.epochStateLost();
                    return .{ .epoch = e4.?, .restarted = r4 or r6 };
                }
                if (e6 == null) return Error.Timeout;
                return .{ .epoch = e6.?, .restarted = r6 };
            },
            .natpmp, .upnp => return Error.NoHealthCheck,
        }
    }
};

// --- Discovery ---

fn tryPcp4(gw: [4]u8, local: [4]u8, timeout_ms: i64) ?pcp.Client {
    if (timeout_ms <= 0) return null;
    var c = pcp.Client{};
    c.setGateway4(gw);
    c.setLocal4(local);
    c.timeout_ms = @intCast(@min(timeout_ms, std.math.maxInt(i32)));
    _ = c.announce() catch return null;
    return c;
}

fn tryNatpmp(gw: [4]u8, timeout_ms: i64) ?NatpmpGw {
    if (timeout_ms <= 0) return null;
    var client = natpmp.open(gw) catch return null;
    client.timeout_ms = @intCast(@min(@max(timeout_ms, 1), std.math.maxInt(i32)));
    _ = client.externalAddress() catch {
        client.close();
        return null;
    };
    return .{ .client = client };
}

fn tryUpnpLocation(location: []const u8, discovery: []const u8, timeout_ms: i64) ?UpnpGw {
    if (timeout_ms <= 100) return null;
    const tmo: i32 = @intCast(@min(timeout_ms, std.math.maxInt(i32)));
    const disc = upnp.clientFromLocation(location, tmo) catch return null;
    var g = UpnpGw{ .client = disc.client };
    const short = shortService(disc.service);
    const t = std.fmt.bufPrint(&g.type_buf, "UPnP {s} ({s})", .{ discovery, short }) catch return null;
    g.type_len = t.len;
    return g;
}

fn tryUpnpUnicast(gw: [4]u8, deadline_ms: i64) ?UpnpGw {
    var locations: [4][128]u8 = undefined;
    for ([_][]const u8{ upnp.st_igdv2, upnp.st_igdv1, upnp.st_all }) |target| {
        const left = deadline_ms - nowMs();
        if (left <= 100) return null;
        const window: i32 = @intCast(@min(left, unicast_window_ms));
        const n = upnp.searchUnicast(gw, target, &locations, window) catch continue;
        for (locations[0..n]) |*slot| {
            const loc = std.mem.sliceTo(slot, 0);
            if (!upnp.locationHasAddr(loc, gw)) continue;
            if (tryUpnpLocation(loc, "unicast", deadline_ms - nowMs())) |g| return g;
        }
    }
    return null;
}

fn tryUpnpMulticast(deadline_ms: i64) ?UpnpGw {
    const left = deadline_ms - nowMs();
    if (left <= 1000) return null;
    const wait_s: u8 = @intCast(@min(@divTrunc(left, 1000), multicast_wait_s));
    if (wait_s == 0) return null;
    var locations: [8][128]u8 = undefined;
    var sts: [8][128]u8 = undefined;
    const n = upnp.searchMulticast(&locations, &sts, wait_s) catch return null;
    for (locations[0..n], sts[0..n]) |*lslot, *sslot| {
        // Go's GenIGDev only follows InternetGatewayDevice answers.
        const st = std.mem.sliceTo(sslot, 0);
        if (std.mem.indexOf(u8, st, "InternetGatewayDevice") == null) continue;
        const loc = std.mem.sliceTo(lslot, 0);
        if (tryUpnpLocation(loc, "multicast", deadline_ms - nowMs())) |g| return g;
    }
    return null;
}

/// PCPv6 pinhole client for an explicit v6 gateway (dual attach or v6-only).
fn tryPinholeWith(gw6: [16]u8, local6: [16]u8, timeout_ms: i64) ?pcp.Client {
    if (timeout_ms <= 0) return null;
    var c = pcp.Client{};
    c.setGateway6(gw6);
    c.setLocal6(local6);
    c.timeout_ms = @intCast(@min(timeout_ms, std.math.maxInt(i32)));
    _ = c.announce() catch return null;
    return c;
}

/// Default-route PCPv6 probe (state.go discoverPCPPinhole path).
fn tryPinholeRoute(timeout_ms: i64) ?pcp.Client {
    if (timeout_ms <= 0) return null;
    const r = gateway.defaultRouteV6() catch return null;
    return tryPinholeWith(r.gateway, r.local, timeout_ms);
}

/// Sequential v4 discovery: PCP, NAT-PMP, UPnP unicast, UPnP multicast.
fn discoverV4(gw: [4]u8, local: [4]u8, deadline_ms: i64) ?V4Gateway {
    const now = nowMs();
    if (now >= deadline_ms) return null;
    if (tryPcp4(gw, local, @min(pcp_probe_ms, deadline_ms - now))) |c| {
        return .{ .pcp = c };
    }
    if (tryNatpmp(gw, @min(natpmp_probe_ms, deadline_ms - nowMs()))) |n| {
        return .{ .natpmp = n };
    }
    if (tryUpnpUnicast(gw, deadline_ms)) |u| {
        return .{ .upnp = u };
    }
    if (tryUpnpMulticast(deadline_ms)) |u| {
        return .{ .upnp = u };
    }
    return null;
}

/// Port of reserveForPinhole: hold the pinhole slice back from the gateway
/// budget; a budget too small to divide goes to gateway discovery whole.
fn reserveForPinhole(deadline_ms: i64) i64 {
    const left = deadline_ms - nowMs();
    if (left <= pinhole_reserve_ms) return deadline_ms;
    return deadline_ms - pinhole_reserve_ms;
}

pub const V6Pair = struct {
    gateway: [16]u8,
    local: [16]u8,
};

/// Discovery against explicit gateways (test seam mirroring Go's
/// discoverNATPMPWithAddr/discoverUPNPUnicastWithAddr). v6 == null skips
/// the pinhole entirely, so tests stay deterministic.
pub fn discoverWithGateways(gw4: [4]u8, local4: [4]u8, v6: ?V6Pair, deadline_ms: i64) Error!Gateway {
    const gw_deadline = reserveForPinhole(deadline_ms);
    if (discoverV4(gw4, local4, gw_deadline)) |v4| {
        if (v6) |p| {
            const left = deadline_ms - nowMs();
            if (left > 0) {
                if (tryPinholeWith(p.gateway, p.local, @min(pcp_probe_ms, left))) |c6| {
                    return .{ .dual = .{ .v4 = v4, .pcp6 = c6 } };
                }
            }
        }
        return switch (v4) {
            .natpmp => |n| Gateway{ .natpmp = n },
            .pcp => |c| Gateway{ .pcp = c },
            .upnp => |u| Gateway{ .upnp = u },
        };
    }
    // No IPv4 gateway: IPv6 pinhole alone (state.go fallback).
    if (v6) |p| {
        const left = deadline_ms - nowMs();
        if (left > 0) {
            if (tryPinholeWith(p.gateway, p.local, left)) |c6| {
                return .{ .pcp6only = c6 };
            }
        }
    }
    return Error.NoGateway;
}

/// Full discovery: default-route gateways, 10s budget, pinhole attached.
pub fn discover(deadline_ms: i64) Error!Gateway {
    const gw_deadline = reserveForPinhole(deadline_ms);
    const r4 = gateway.defaultRouteV4() catch null;
    if (r4) |r| {
        if (discoverV4(r.gateway, r.local, gw_deadline)) |v4| {
            const left = deadline_ms - nowMs();
            if (left > 0) {
                if (tryPinholeRoute(@min(pcp_probe_ms, left))) |c6| {
                    return .{ .dual = .{ .v4 = v4, .pcp6 = c6 } };
                }
            }
            return switch (v4) {
                .natpmp => |n| Gateway{ .natpmp = n },
                .pcp => |c| Gateway{ .pcp = c },
                .upnp => |u| Gateway{ .upnp = u },
            };
        }
    }
    const left = deadline_ms - nowMs();
    if (left > 0) {
        if (tryPinholeRoute(left)) |c6| {
            return .{ .pcp6only = c6 };
        }
    }
    return Error.NoGateway;
}
