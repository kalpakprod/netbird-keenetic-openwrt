// Port of NetBird NAT-PMP usage (v0.79.0), BSD-3-Clause for NetBird files.
// Reference: upstream/netbird/vendor/github.com/jackpal/go-nat-pmp/natpmp.go
// and network.go (wire codec, resend loop, response validation),
// upstream/netbird/vendor/github.com/netbirdio/go-nat/natpmp.go
// (protocol mapping, UDP+TCP delete).
// Scope: IPv4 client (external address, add/delete UDP and TCP mappings) over
// one UDP socket. No server side.
// Deviation: default timeout is 10s, not jackpal's ~128s; the manager never
// waits longer than its own discovery budgets anyway.

const std = @import("std");
const linux = std.os.linux;

pub const port: u16 = 5351;
pub const version: u8 = 0;
pub const default_timeout_ms: i32 = 10000;
pub const resend_base_ms: i32 = 250;

pub const Error = error{
    SocketFailed,
    SendFailed,
    RecvFailed,
    Timeout,
    BadResponse,
    BadVersion,
    ResultFailed,
    NoSpace,
};

pub const Protocol = enum(u8) {
    udp = 1,
    tcp = 2,
};

pub const result_strings = [_][]const u8{
    "Success",
    "Unsupported version",
    "Not authorized / Refused (e.g. box supports mapping, but user has turned feature off)",
    "Network failure (e.g. NAT box itself has not obtained a DHCP lease)",
    "Out of resources (NAT box cannot create any more mappings at this time)",
    "Client error",
    "Server error",
};

pub fn resultString(code: u16) []const u8 {
    if (code < result_strings.len) return result_strings[code];
    return "Unknown error";
}

pub const Mapping = struct {
    internal_port: u16,
    external_port: u16,
    lifetime_s: u32,
};

fn failed(rc: usize) bool {
    return rc > 0xfffffffffffff000;
}

fn nowMs() i64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return ts.sec * 1000 + @divTrunc(ts.nsec, 1_000_000);
}

/// Encode an external-address request. Port of GetExternalAddress's msg.
pub fn encodeExternalRequest(buf: *[2]u8) []u8 {
    buf[0] = version;
    buf[1] = 0;
    return buf;
}

/// Encode a map request (lifetime 0 deletes). Port of AddPortMapping's msg.
pub fn encodeMapRequest(buf: *[12]u8, proto: Protocol, internal: u16, external_want: u16, lifetime_s: u32) []u8 {
    buf[0] = version;
    buf[1] = @intFromEnum(proto);
    buf[2] = 0;
    buf[3] = 0;
    std.mem.writeInt(u16, buf[4..6], internal, .big);
    std.mem.writeInt(u16, buf[6..8], external_want, .big);
    std.mem.writeInt(u32, buf[8..12], lifetime_s, .big);
    return buf;
}

pub const ExtResponse = struct {
    result: u16,
    epoch_s: u32,
    external: [4]u8,
};

pub const MapResponse = struct {
    result: u16,
    epoch_s: u32,
    internal_port: u16,
    external_port: u16,
    lifetime_s: u32,
};

/// Port of GetExternalAddressResult parsing (network.go GetExternalAddress).
pub fn decodeExtResponse(data: []const u8) Error!ExtResponse {
    if (data.len < 12) return Error.BadResponse;
    if (data[0] != version) return Error.BadVersion;
    if (data[1] != 128) return Error.BadResponse;
    return .{
        .result = std.mem.readInt(u16, data[2..4], .big),
        .epoch_s = std.mem.readInt(u32, data[4..8], .big),
        .external = data[8..12].*,
    };
}

/// Port of AddPortMappingResult parsing.
pub fn decodeMapResponse(data: []const u8, proto: Protocol) Error!MapResponse {
    if (data.len < 16) return Error.BadResponse;
    if (data[0] != version) return Error.BadVersion;
    if (data[1] != 128 + @as(u8, @intFromEnum(proto))) return Error.BadResponse;
    return .{
        .result = std.mem.readInt(u16, data[2..4], .big),
        .epoch_s = std.mem.readInt(u32, data[4..8], .big),
        .internal_port = std.mem.readInt(u16, data[8..10], .big),
        .external_port = std.mem.readInt(u16, data[10..12], .big),
        .lifetime_s = std.mem.readInt(u32, data[12..16], .big),
    };
}

pub const Client = struct {
    fd: linux.fd_t,
    gateway: [4]u8,
    timeout_ms: i32 = default_timeout_ms,
    last_result: u16 = 0,
    last_epoch: u32 = 0,

    pub fn close(c: *Client) void {
        _ = linux.close(c.fd);
        c.fd = -1;
    }

    fn dest(c: *const Client) struct { sa: linux.sockaddr.in, len: linux.socklen_t } {
        return .{
            .sa = .{
                .family = linux.AF.INET,
                .port = std.mem.nativeToBig(u16, port),
                .addr = @bitCast(c.gateway),
            },
            .len = @sizeOf(linux.sockaddr.in),
        };
    }

    fn sendReq(c: *Client, req: []const u8) Error!void {
        var d = c.dest();
        const n = linux.sendto(c.fd, req.ptr, req.len, 0, @ptrCast(&d.sa), d.len);
        if (failed(n) or n != req.len) return Error.SendFailed;
    }

    /// One transaction: resend on jackpal's growing schedule (250ms + 250ms
    /// per attempt) until a datagram arrives or the timeout hits.
    fn transact(c: *Client, req: []const u8, resp_buf: []u8) Error!usize {
        const deadline = nowMs() + c.timeout_ms;
        try c.sendReq(req);
        var resend_ms: i32 = resend_base_ms;
        while (true) {
            const left = deadline - nowMs();
            if (left <= 0) return Error.Timeout;
            var pfd = [_]linux.pollfd{.{ .fd = c.fd, .events = linux.POLL.IN }};
            const wait_ms: i32 = @intCast(@min(left, @as(i64, resend_ms)));
            const prc = linux.poll(&pfd, 1, wait_ms);
            if (failed(prc)) return Error.RecvFailed;
            if (prc == 0) {
                // Resend like the jackpal goroutine, then back off.
                try c.sendReq(req);
                resend_ms += resend_base_ms;
                continue;
            }
            var from: linux.sockaddr.in = undefined;
            var from_len: linux.socklen_t = @sizeOf(linux.sockaddr.in);
            const n = linux.recvfrom(c.fd, resp_buf.ptr, resp_buf.len, 0, @ptrCast(&from), &from_len);
            if (failed(n) or n == 0) return Error.RecvFailed;
            // NAT-PMP replies are accepted only from the configured gateway and
            // protocol port. Ignore unrelated datagrams without resetting the
            // transaction deadline or retransmission schedule.
            if (from_len < @sizeOf(linux.sockaddr.in) or
                from.family != linux.AF.INET or
                from.port != std.mem.nativeToBig(u16, port) or
                from.addr != @as(u32, @bitCast(c.gateway))) continue;
            return n;
        }
    }

    /// Port of GetExternalAddress: single request/response transaction.
    pub fn externalAddress(c: *Client) Error![4]u8 {
        var req: [2]u8 = undefined;
        var resp: [64]u8 = undefined;
        const n = try c.transact(encodeExternalRequest(&req), &resp);
        const r = try decodeExtResponse(resp[0..n]);
        c.last_result = r.result;
        if (r.result != 0) return Error.ResultFailed;
        c.last_epoch = r.epoch_s;
        return r.external;
    }

    pub fn addPortMapping(
        c: *Client,
        proto: Protocol,
        internal: u16,
        external_want: u16,
        lifetime_s: u32,
    ) Error!Mapping {
        var req: [12]u8 = undefined;
        var resp: [64]u8 = undefined;
        const n = try c.transact(encodeMapRequest(&req, proto, internal, external_want, lifetime_s), &resp);
        const m = try decodeMapResponse(resp[0..n], proto);
        c.last_result = m.result;
        if (m.result != 0) return Error.ResultFailed;
        c.last_epoch = m.epoch_s;
        return .{
            .internal_port = m.internal_port,
            .external_port = m.external_port,
            .lifetime_s = m.lifetime_s,
        };
    }

    /// Port of DeletePortMapping: map with lifetime 0.
    pub fn deletePortMapping(c: *Client, proto: Protocol, internal: u16) Error!void {
        _ = try c.addPortMapping(proto, internal, 0, 0);
    }
};

/// Open a client on an ephemeral UDP socket. Port of NewClient's dial.
pub fn open(gateway: [4]u8) Error!Client {
    const s = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    if (failed(s)) return Error.SocketFailed;
    return .{ .fd = @intCast(s), .gateway = gateway };
}
