// Port of NetBird UPnP IGD usage (v0.79.0), BSD-3-Clause for NetBird files.
// Reference: upstream/netbird/vendor/github.com/netbirdio/go-nat/upnp.go
// (unicast SSDP to the gateway with IGDv2/IGDv1/ssdp:all, multicast
// ssdp:all search, service preference IP2>IP1>PPP1, NAT-status gate,
// random-port mapping with renew, internal address via UDP dial),
// huin/goupnp (SOAP envelope/escaping/headers), koron/go-ssdp (multicast
// M-SEARCH bytes).
// Scope: IPv4 IGD client over unicast or multicast SSDP. Minimal HTTP/1.1
// (Content-Length responses only, no chunked) and minimal XML scan tuned to
// UPnP device/SOAP shapes. Single-threaded.

const std = @import("std");
const linux = std.os.linux;

pub const ssdp_port: u16 = 1900;
pub const multicast_ip: [4]u8 = .{ 239, 255, 255, 250 };
pub const search_repeats = 3;
pub const unicast_timeout_ms: i32 = 2000;
pub const multicast_wait_s: u8 = 5;
pub const device_timeout_ms: i32 = 10000;

pub const urn_ip2 = "urn:schemas-upnp-org:service:WANIPConnection:2";
pub const urn_ip1 = "urn:schemas-upnp-org:service:WANIPConnection:1";
pub const urn_ppp1 = "urn:schemas-upnp-org:service:WANPPPConnection:1";
pub const st_igdv2 = "urn:schemas-upnp-org:device:InternetGatewayDevice:2";
pub const st_igdv1 = "urn:schemas-upnp-org:device:InternetGatewayDevice:1";
pub const st_all = "ssdp:all";

pub const Error = error{
    SocketFailed,
    SendFailed,
    RecvFailed,
    ConnectFailed,
    Timeout,
    NoSpace,
    BadResponse,
    BadStatus,
    BadUrl,
    BadXml,
    NoService,
    NoLocation,
    SoapFault,
    /// UPnP error 725: the gateway only supports permanent leases.
    PermanentLeaseOnly,
    NatDisabled,
    InvalidProtocol,
    NoInternalAddress,
    MapFailed,
};

fn failed(rc: usize) bool {
    return rc > 0xfffffffffffff000;
}

fn nowMs() i64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return ts.sec * 1000 + @divTrunc(ts.nsec, 1_000_000);
}

fn randomU16() u16 {
    var b: [2]u8 = undefined;
    var off: usize = 0;
    while (off < 2) {
        const n = linux.getrandom(b[off..].ptr, 2 - off, 0);
        if (n > 0xfffffffffffff000 or n == 0) break;
        off += n;
    }
    if (off < 2) {
        const t: u64 = @bitCast(nowMs());
        b[off] ^= @truncate(t >> (@as(u6, @intCast(off)) * 8));
        if (off == 0) b[1] ^= @truncate(t >> 32);
    }
    return std.mem.readInt(u16, &b, .little);
}

/// Port of go-nat randomPort: 10000 + rand(65535-10000).
pub fn randomPort() u16 {
    return 10000 + randomU16() % (65535 - 10000);
}

/// Byte-exact M-SEARCH builder (httpu.Do / koron buildSearch shape).
pub fn buildMSearch(buf: []u8, host: []const u8, mx: u8, target: []const u8) Error![]u8 {
    return std.fmt.bufPrint(
        buf,
        "M-SEARCH * HTTP/1.1\r\nHOST: {s}\r\nMAN: \"ssdp:discover\"\r\nMX: {d}\r\nST: {s}\r\n\r\n",
        .{ host, mx, target },
    ) catch Error.NoSpace;
}

fn eqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (std.ascii.toLower(x) != std.ascii.toLower(y)) return false;
    }
    return true;
}

/// Parse an SSDP search response: 200 status, LOCATION and ST headers.
/// Header names match case-insensitively (devices vary; Go canonicalizes).
pub fn parseSSDPResponse(data: []const u8) Error!struct { location: []const u8, st: []const u8 } {
    var lines = std.mem.splitSequence(u8, data, "\r\n");
    const status = lines.next() orelse return Error.BadResponse;
    if (!std.mem.startsWith(u8, status, "HTTP/1.") or std.mem.indexOf(u8, status, " 200 ") == null)
        return Error.BadStatus;
    var location: ?[]const u8 = null;
    var st: ?[]const u8 = null;
    while (lines.next()) |line| {
        if (line.len == 0) break;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const name = line[0..colon];
        const val = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (eqlIgnoreCase(name, "location")) location = val;
        if (eqlIgnoreCase(name, "st")) st = val;
    }
    return .{
        .location = location orelse return Error.NoLocation,
        .st = st orelse "",
    };
}

pub const Url = struct {
    host: []const u8,
    port: u16,
    path: []const u8,
};

/// Parse an http:// URL (no userinfo, no query kept). Port of the url.Parse
/// uses in go-nat (location + deviceHostPort default-port rule).
pub fn parseUrl(s: []const u8) Error!Url {
    const rest = if (std.mem.startsWith(u8, s, "http://"))
        s["http://".len..]
    else
        return Error.BadUrl;
    const slash = std.mem.indexOfScalar(u8, rest, '/');
    const authority = if (slash) |i| rest[0..i] else rest;
    const path = if (slash) |i| rest[i..] else "/";
    if (authority.len == 0) return Error.BadUrl;
    // Last colon splits the port (no IPv6 literals on IGD links here).
    if (std.mem.lastIndexOfScalar(u8, authority, ':')) |ci| {
        const port = std.fmt.parseInt(u16, authority[ci + 1 ..], 10) catch return Error.BadUrl;
        return .{ .host = authority[0..ci], .port = port, .path = path };
    }
    return .{ .host = authority, .port = 80, .path = path };
}

/// Port of locationHasAddr: the description URL must name the gateway IP
/// (literal, no host names — nothing on the link could resolve them).
pub fn locationHasAddr(location: []const u8, gw: [4]u8) bool {
    const u = parseUrl(location) catch return false;
    var octets: [4]u8 = undefined;
    var it = std.mem.splitScalar(u8, u.host, '.');
    for (0..4) |i| {
        const part = it.next() orelse return false;
        octets[i] = std.fmt.parseInt(u8, part, 10) catch return false;
    }
    if (it.next() != null) return false;
    return std.mem.eql(u8, &octets, &gw);
}

pub const Service = struct {
    service_type: []const u8,
    control_url: []const u8,
};

/// Scan a device description for <service> entries. Copies the two fields we
/// need into store; services slice borrows store.
pub fn parseServices(
    xml: []const u8,
    store: []u8,
    services: []Service,
) Error!struct { base: []const u8, n: usize } {
    var base: []const u8 = "";
    if (findTag(xml, "URLBase")) |b| {
        if (b.len > store.len) return Error.NoSpace;
        @memcpy(store[0..b.len], b);
        base = store[0..b.len];
    }
    var off: usize = if (base.len > 0) base.len else 0;
    var n: usize = 0;
    var rest = xml;
    while (std.mem.indexOf(u8, rest, "<service>")) |si| {
        const end = std.mem.indexOf(u8, rest, "</service>") orelse break;
        if (end < si) break;
        const blk = rest[si..end];
        const typ = findTag(blk, "serviceType");
        const ctl = findTag(blk, "controlURL");
        if (typ != null and ctl != null and n < services.len) {
            const need = typ.?.len + ctl.?.len;
            if (off + need > store.len) return Error.NoSpace;
            @memcpy(store[off..][0..typ.?.len], typ.?);
            const t = store[off..][0..typ.?.len];
            off += typ.?.len;
            @memcpy(store[off..][0..ctl.?.len], ctl.?);
            const c = store[off..][0..ctl.?.len];
            off += ctl.?.len;
            services[n] = .{ .service_type = t, .control_url = c };
            n += 1;
        }
        rest = rest[end + "</service>".len ..];
    }
    return .{ .base = base, .n = n };
}

fn findTag(xml: []const u8, name: []const u8) ?[]const u8 {
    var ob: [64]u8 = undefined;
    var cb: [64]u8 = undefined;
    const open = std.fmt.bufPrint(&ob, "<{s}>", .{name}) catch return null;
    const close = std.fmt.bufPrint(&cb, "</{s}>", .{name}) catch return null;
    const si = std.mem.indexOf(u8, xml, open) orelse return null;
    const after = si + open.len;
    const ei = std.mem.indexOfPos(u8, xml, after, close) orelse return null;
    return xml[after..ei];
}

/// Port of go-nat service preference: IP2 > IP1 > PPP1.
pub fn serviceRank(service_type: []const u8) u8 {
    if (std.mem.eql(u8, service_type, urn_ip2)) return 3;
    if (std.mem.eql(u8, service_type, urn_ip1)) return 2;
    if (std.mem.eql(u8, service_type, urn_ppp1)) return 1;
    return 0;
}

/// Resolve a controlURL against the description base/location.
/// Absolute URLs pass through; absolute paths join the location host.
pub fn resolveControlUrl(base: []const u8, location: []const u8, control: []const u8, out: []u8) Error![]u8 {
    if (std.mem.startsWith(u8, control, "http://")) {
        if (control.len > out.len) return Error.NoSpace;
        @memcpy(out[0..control.len], control);
        return out[0..control.len];
    }
    const root = if (base.len > 0) base else location;
    // Strip to scheme://authority.
    const auth_end = blk: {
        const after_scheme = std.mem.indexOf(u8, root, "://") orelse return Error.BadUrl;
        const rest = root[after_scheme + 3 ..];
        if (std.mem.indexOfScalar(u8, rest, '/')) |i| {
            break :blk after_scheme + 3 + i;
        }
        break :blk root.len;
    };
    const root_auth = root[0..auth_end];
    if (!std.mem.startsWith(u8, control, "/")) return Error.BadUrl;
    const total = root_auth.len + control.len;
    if (total > out.len) return Error.NoSpace;
    @memcpy(out[0..root_auth.len], root_auth);
    @memcpy(out[root_auth.len..total], control);
    return out[0..total];
}

fn escapeXmlLen(s: []const u8) usize {
    var n: usize = 0;
    for (s) |ch| {
        n += switch (ch) {
            '<' => 4, // &lt;
            '>' => 4, // &gt;
            '&' => 5, // &amp;
            else => 1,
        };
    }
    return n;
}

/// Port of goupnp escapeXMLText: only <, >, & (routers choke on &quot;).
fn escapeXml(dst: []u8, s: []const u8) []u8 {
    var o: usize = 0;
    for (s) |ch| {
        switch (ch) {
            '<' => {
                @memcpy(dst[o..][0..4], "&lt;");
                o += 4;
            },
            '>' => {
                @memcpy(dst[o..][0..4], "&gt;");
                o += 4;
            },
            '&' => {
                @memcpy(dst[o..][0..5], "&amp;");
                o += 5;
            },
            else => {
                dst[o] = ch;
                o += 1;
            },
        }
    }
    return dst[0..o];
}

pub const SoapArg = struct {
    name: []const u8,
    val: []const u8,
};

const soap_prefix = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" ++
    "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body>";

/// Port of goupnp encodeRequestAction.
pub fn buildSoapCall(buf: []u8, urn: []const u8, action: []const u8, args: []const SoapArg) Error![]u8 {
    var len: usize = 0;
    const parts: []const []const u8 = &.{ soap_prefix, "<u:", action, " xmlns:u=\"", urn, "\">" };
    for (parts) |p| {
        if (len + p.len > buf.len) return Error.NoSpace;
        @memcpy(buf[len..][0..p.len], p);
        len += p.len;
    }
    for (args) |a| {
        const open_extra = 2 + a.name.len; // <name>
        const close_extra = 3 + a.name.len; // </name>
        const need = open_extra + escapeXmlLen(a.val) + close_extra;
        if (len + need > buf.len) return Error.NoSpace;
        buf[len] = '<';
        @memcpy(buf[len + 1 ..][0..a.name.len], a.name);
        buf[len + 1 + a.name.len] = '>';
        len += open_extra;
        const esc = escapeXml(buf[len..], a.val);
        len += esc.len;
        buf[len] = '<';
        buf[len + 1] = '/';
        @memcpy(buf[len + 2 ..][0..a.name.len], a.name);
        buf[len + 2 + a.name.len] = '>';
        len += close_extra;
    }
    const tail_parts: []const []const u8 = &.{ "</u:", action, "></s:Body></s:Envelope>" };
    for (tail_parts) |p| {
        if (len + p.len > buf.len) return Error.NoSpace;
        @memcpy(buf[len..][0..p.len], p);
        len += p.len;
    }
    return buf[0..len];
}

pub fn hasSoapFault(xml: []const u8) bool {
    return std.mem.indexOf(u8, xml, "<s:Fault>") != null or
        std.mem.indexOf(u8, xml, "<SOAP-ENV:Fault>") != null;
}

/// Port of upstream's upnpErrPermanentLeaseOnly
/// (`<errorCode>\s*725\s*</errorCode>`): error 725 means the gateway only
/// supports permanent leases, so the manager retries with lease 0.
pub fn isPermanentLeaseOnly(xml: []const u8) bool {
    var rest = xml;
    while (std.mem.indexOf(u8, rest, "<errorCode>")) |i| {
        rest = rest[i + "<errorCode>".len ..];
        var j: usize = 0;
        while (j < rest.len and (rest[j] == ' ' or rest[j] == '\t' or rest[j] == '\r' or rest[j] == '\n')) j += 1;
        if (j + 3 <= rest.len and std.mem.eql(u8, rest[j .. j + 3], "725")) {
            j += 3;
            while (j < rest.len and (rest[j] == ' ' or rest[j] == '\t' or rest[j] == '\r' or rest[j] == '\n')) j += 1;
            if (std.mem.startsWith(u8, rest[j..], "</errorCode>")) return true;
        }
    }
    return false;
}

/// Extract <name>value</name> from a SOAP body, unescaping entities.
pub fn soapResult(xml: []const u8, name: []const u8, out: []u8) Error![]u8 {
    if (hasSoapFault(xml)) return Error.SoapFault;
    const raw = findTag(xml, name) orelse return Error.BadXml;
    return unescapeXml(raw, out);
}

fn unescapeXml(s: []const u8, out: []u8) Error![]u8 {
    var o: usize = 0;
    var i: usize = 0;
    while (i < s.len) {
        if (s[i] == '&') {
            const semi = std.mem.indexOfPos(u8, s, i, ";") orelse return Error.BadXml;
            const ent = s[i + 1 .. semi];
            const ch: u8 = if (std.mem.eql(u8, ent, "lt"))
                '<'
            else if (std.mem.eql(u8, ent, "gt"))
                '>'
            else if (std.mem.eql(u8, ent, "amp"))
                '&'
            else if (std.mem.eql(u8, ent, "quot"))
                '"'
            else if (std.mem.eql(u8, ent, "apos"))
                '\''
            else
                return Error.BadXml;
            if (o >= out.len) return Error.NoSpace;
            out[o] = ch;
            o += 1;
            i = semi + 1;
        } else {
            if (o >= out.len) return Error.NoSpace;
            out[o] = s[i];
            o += 1;
            i += 1;
        }
    }
    return out[0..o];
}

pub fn parseBoolSoap(s: []const u8) Error!bool {
    // Port of soap.UnmarshalBoolean: 1/true yes, 0/false no.
    if (std.mem.eql(u8, s, "1") or eqlIgnoreCase(s, "true")) return true;
    if (std.mem.eql(u8, s, "0") or eqlIgnoreCase(s, "false")) return false;
    const n = std.fmt.parseInt(i64, s, 10) catch return Error.BadXml;
    return n != 0;
}

pub fn parseIpv4(s: []const u8) Error![4]u8 {
    var out: [4]u8 = undefined;
    var it = std.mem.splitScalar(u8, s, '.');
    for (0..4) |i| {
        const part = it.next() orelse return Error.BadXml;
        out[i] = std.fmt.parseInt(u8, part, 10) catch return Error.BadXml;
    }
    if (it.next() != null) return Error.BadXml;
    return out;
}

// --- Minimal HTTP/1.1 over TCP (Content-Length bodies only) ---

/// O_NONBLOCK is 00004000 on every Linux arch (incl. aarch64 target).
const o_nonblock: usize = 0o4000;

fn tcpConnect(host: []const u8, port: u16, timeout_ms: i32) Error!linux.fd_t {
    const ip = parseIpv4(host) catch return Error.BadUrl;
    const s = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (failed(s)) return Error.SocketFailed;
    const fd: linux.fd_t = @intCast(s);
    errdefer _ = linux.close(fd);
    // Non-blocking connect + poll for the timeout (like Go's Dialer).
    const flags = linux.fcntl(fd, linux.F.GETFL, 0);
    if (failed(flags)) return Error.SocketFailed;
    if (failed(linux.fcntl(fd, linux.F.SETFL, flags | o_nonblock))) return Error.SocketFailed;
    var sa = linux.sockaddr.in{
        .family = linux.AF.INET,
        .port = std.mem.nativeToBig(u16, port),
        .addr = @bitCast(ip),
    };
    const rc = linux.connect(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in));
    if (!failed(rc)) {
        _ = linux.fcntl(fd, linux.F.SETFL, flags);
        return fd;
    }
    // -errno sits in rc; EINPROGRESS is the expected async outcome.
    const errno: usize = @bitCast(-%@as(isize, @bitCast(rc)));
    if (errno != @intFromEnum(linux.E.INPROGRESS)) return Error.ConnectFailed;
    var pfd = [_]linux.pollfd{.{ .fd = fd, .events = linux.POLL.OUT }};
    const prc = linux.poll(&pfd, 1, timeout_ms);
    if (failed(prc) or prc == 0) return Error.ConnectFailed;
    var so_err: u32 = 0;
    var so_len: linux.socklen_t = 4;
    if (failed(linux.getsockopt(fd, linux.SOL.SOCKET, linux.SO.ERROR, @ptrCast(&so_err), &so_len))) return Error.ConnectFailed;
    if (so_err != 0) return Error.ConnectFailed;
    if (failed(linux.fcntl(fd, linux.F.SETFL, flags))) return Error.ConnectFailed;
    return fd;
}

fn httpRoundTrip(
    host: []const u8,
    port: u16,
    request: []const u8,
    resp_buf: []u8,
    timeout_ms: i32,
) Error!struct { status: u16, body: []u8 } {
    const fd = try tcpConnect(host, port, timeout_ms);
    defer _ = linux.close(fd);
    var off: usize = 0;
    while (off < request.len) {
        const n = linux.sendto(fd, request[off..].ptr, request.len - off, 0, null, 0);
        if (failed(n) or n == 0) return Error.SendFailed;
        off += n;
    }
    const deadline = nowMs() + timeout_ms;
    var len: usize = 0;
    var header_end: ?usize = null;
    var content_len: ?usize = null;
    var status: u16 = 0;
    while (true) {
        const left = deadline - nowMs();
        if (left <= 0) return Error.Timeout;
        var pfd = [_]linux.pollfd{.{ .fd = fd, .events = linux.POLL.IN }};
        const prc = linux.poll(&pfd, 1, @intCast(left));
        if (failed(prc)) return Error.RecvFailed;
        if (prc == 0) return Error.Timeout;
        if (len >= resp_buf.len) return Error.NoSpace;
        const n = linux.recvfrom(fd, resp_buf[len..].ptr, resp_buf.len - len, 0, null, null);
        if (failed(n)) return Error.RecvFailed;
        if (n == 0) {
            // EOF: body is whatever followed the header (close-delimited).
            if (header_end) |he| return .{ .status = status, .body = resp_buf[he..len] };
            return Error.BadResponse;
        }
        len += n;
        if (header_end == null) {
            if (std.mem.indexOf(u8, resp_buf[0..len], "\r\n\r\n")) |hi| {
                header_end = hi + 4;
                const head = resp_buf[0..hi];
                var hlines = std.mem.splitSequence(u8, head, "\r\n");
                const status_line = hlines.next() orelse return Error.BadResponse;
                // "HTTP/1.1 200 OK"
                var sp = std.mem.splitScalar(u8, status_line, ' ');
                _ = sp.next();
                status = std.fmt.parseInt(u16, sp.next() orelse return Error.BadResponse, 10) catch return Error.BadResponse;
                while (hlines.next()) |hl| {
                    const ci = std.mem.indexOfScalar(u8, hl, ':') orelse continue;
                    if (eqlIgnoreCase(hl[0..ci], "content-length")) {
                        content_len = std.fmt.parseInt(usize, std.mem.trim(u8, hl[ci + 1 ..], " \t"), 10) catch return Error.BadResponse;
                    }
                }
            }
        }
        if (header_end) |he| {
            if (content_len) |cl| {
                if (len - he >= cl) return .{ .status = status, .body = resp_buf[he .. he + cl] };
            }
        }
    }
}

/// GET a device description. Port of goupnp.DeviceByURLCtx (GET + read all).
pub fn httpGet(url: []const u8, req_buf: []u8, resp_buf: []u8, timeout_ms: i32) Error![]u8 {
    const u = try parseUrl(url);
    const req = std.fmt.bufPrint(
        req_buf,
        "GET {s} HTTP/1.1\r\nHost: {s}\r\nConnection: close\r\n\r\n",
        .{ u.path, u.host },
    ) catch return Error.NoSpace;
    const r = try httpRoundTrip(u.host, u.port, req, resp_buf, timeout_ms);
    if (r.status != 200) return Error.BadStatus;
    return r.body;
}

/// POST a SOAP action. Port of goupnp PerformActionCtx (headers + body read).
pub fn httpPostSoap(
    control_url: []const u8,
    urn: []const u8,
    action: []const u8,
    body: []const u8,
    req_buf: []u8,
    resp_buf: []u8,
    timeout_ms: i32,
) Error![]u8 {
    const u = try parseUrl(control_url);
    const head = std.fmt.bufPrint(
        req_buf,
        "POST {s} HTTP/1.1\r\nHost: {s}\r\nSOAPACTION: \"{s}#{s}\"\r\nCONTENT-TYPE: text/xml; charset=\"utf-8\"\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n",
        .{ u.path, u.host, urn, action, body.len },
    ) catch return Error.NoSpace;
    if (head.len + body.len > req_buf.len) return Error.NoSpace;
    @memcpy(req_buf[head.len..][0..body.len], body);
    const r = try httpRoundTrip(u.host, u.port, req_buf[0 .. head.len + body.len], resp_buf, timeout_ms);
    // goupnp reads the body even on SOAP faults (HTTP 500 with a body).
    if (r.status != 200 and r.body.len == 0) return Error.BadStatus;
    return r.body;
}

// --- SSDP discovery ---

/// Unicast M-SEARCH to one gateway:port across all three targets, collecting
/// description URLs. Port of searchUPNPUnicast (3 sends, full-window reads).
pub fn searchUnicast(
    gw: [4]u8,
    target: []const u8,
    locations: [][128]u8,
    timeout_ms: i32,
) Error!usize {
    const s = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    if (failed(s)) return Error.SocketFailed;
    const fd: linux.fd_t = @intCast(s);
    defer _ = linux.close(fd);
    var host_buf: [32]u8 = undefined;
    const host = std.fmt.bufPrint(&host_buf, "{d}.{d}.{d}.{d}:{d}", .{ gw[0], gw[1], gw[2], gw[3], ssdp_port }) catch return Error.NoSpace;
    var req_buf: [512]u8 = undefined;
    const mx: u8 = @intCast(@max(@divTrunc(timeout_ms, 1000), 1));
    const req = try buildMSearch(&req_buf, host, mx, target);
    var sa = linux.sockaddr.in{
        .family = linux.AF.INET,
        .port = std.mem.nativeToBig(u16, ssdp_port),
        .addr = @bitCast(gw),
    };
    var n_loc: usize = 0;
    const deadline = nowMs() + timeout_ms;
    var sends: usize = 0;
    while (sends < search_repeats) : (sends += 1) {
        const n = linux.sendto(fd, req.ptr, req.len, 0, @ptrCast(&sa), @sizeOf(linux.sockaddr.in));
        if (failed(n) or n != req.len) return Error.SendFailed;
        // Drain everything that arrives before the next send.
        while (true) {
            const left = deadline - nowMs();
            if (left <= 0) break;
            var pfd = [_]linux.pollfd{.{ .fd = fd, .events = linux.POLL.IN }};
            const prc = linux.poll(&pfd, 1, @intCast(@min(left, @as(i64, 50))));
            if (failed(prc)) return Error.RecvFailed;
            if (prc == 0) break;
            var rbuf: [2048]u8 = undefined;
            const rn = linux.recvfrom(fd, &rbuf, rbuf.len, 0, null, null);
            if (failed(rn) or rn == 0) continue;
            const parsed = parseSSDPResponse(rbuf[0..rn]) catch continue;
            if (parsed.location.len == 0 or parsed.location.len > 127) continue;
            var dup = false;
            for (locations[0..n_loc]) |*slot| {
                if (std.mem.eql(u8, std.mem.sliceTo(slot, 0), parsed.location)) dup = true;
            }
            if (dup or n_loc >= locations.len) continue;
            @memcpy(locations[n_loc][0..parsed.location.len], parsed.location);
            locations[n_loc][parsed.location.len] = 0;
            n_loc += 1;
        }
        var ts = linux.timespec{ .sec = 0, .nsec = 5 * 1_000_000 };
        _ = linux.nanosleep(&ts, null);
    }
    // Final drain until the deadline.
    while (true) {
        const left = deadline - nowMs();
        if (left <= 0) break;
        var pfd = [_]linux.pollfd{.{ .fd = fd, .events = linux.POLL.IN }};
        const prc = linux.poll(&pfd, 1, @intCast(left));
        if (failed(prc)) return Error.RecvFailed;
        if (prc == 0) break;
        var rbuf: [2048]u8 = undefined;
        const rn = linux.recvfrom(fd, &rbuf, rbuf.len, 0, null, null);
        if (failed(rn) or rn == 0) continue;
        const parsed = parseSSDPResponse(rbuf[0..rn]) catch continue;
        if (parsed.location.len == 0 or parsed.location.len > 127) continue;
        var dup = false;
        for (locations[0..n_loc]) |*slot| {
            if (std.mem.eql(u8, std.mem.sliceTo(slot, 0), parsed.location)) dup = true;
        }
        if (dup or n_loc >= locations.len) continue;
        @memcpy(locations[n_loc][0..parsed.location.len], parsed.location);
        locations[n_loc][parsed.location.len] = 0;
        n_loc += 1;
    }
    return n_loc;
}

/// Local IPv4 addresses via RTM_GETADDR (for multicast output selection).
/// Self-contained minimal dump: family AF_INET addrs only.
pub fn localV4Addrs(out: [][4]u8) Error!usize {
    const s = linux.socket(linux.AF.NETLINK, linux.SOCK.RAW | linux.SOCK.CLOEXEC, linux.NETLINK.ROUTE);
    if (failed(s)) return Error.SocketFailed;
    const fd: linux.fd_t = @intCast(s);
    defer _ = linux.close(fd);
    const SockAddrNl = extern struct {
        family: u16 = linux.AF.NETLINK,
        pad: u16 = 0,
        pid: u32 = 0,
        groups: u32 = 0,
    };
    const pid: u32 = @intCast(linux.getpid());
    var addr = SockAddrNl{ .pid = pid };
    if (failed(linux.bind(fd, @ptrCast(&addr), @sizeOf(SockAddrNl)))) return Error.SocketFailed;
    var req: [24]u8 = std.mem.zeroes([24]u8);
    std.mem.writeInt(u32, req[0..4], 24, .native);
    std.mem.writeInt(u16, req[4..6], 22, .native); // RTM_GETADDR
    std.mem.writeInt(u16, req[6..8], linux.NLM_F_REQUEST | linux.NLM_F_DUMP, .native);
    std.mem.writeInt(u32, req[8..12], 1, .native);
    std.mem.writeInt(u32, req[12..16], pid, .native);
    var kaddr = SockAddrNl{};
    const sent = linux.sendto(fd, &req, req.len, 0, @ptrCast(&kaddr), @sizeOf(SockAddrNl));
    if (failed(sent) or sent != req.len) return Error.SendFailed;
    var n_addrs: usize = 0;
    var reply: [16384]u8 = undefined;
    var done = false;
    while (!done) {
        const n = linux.recvfrom(fd, &reply, reply.len, 0, null, null);
        if (failed(n) or n < 16) return Error.RecvFailed;
        var off: usize = 0;
        while (off + 16 <= n) {
            const mlen: usize = std.mem.readInt(u32, reply[off..][0..4], .native);
            const mtype = std.mem.readInt(u16, reply[off..][4..6], .native);
            if (mlen < 16 or off + mlen > n) break;
            if (mtype == 3) {
                done = true;
                break; // NLMSG_DONE
            }
            if (mtype == 2) return Error.RecvFailed; // NLMSG_ERROR
            if (mtype == 20 and reply[off + 16] == linux.AF.INET) { // RTM_NEWADDR
                var aoff: usize = off + 24;
                const aend = off + mlen;
                while (aoff + 4 <= aend) {
                    const alen: usize = std.mem.readInt(u16, reply[aoff..][0..2], .native);
                    const atype = std.mem.readInt(u16, reply[aoff..][2..4], .native);
                    if (alen < 4 or aoff + alen > aend) break;
                    if ((atype == 1 or atype == 2) and n_addrs < out.len) { // IFA_ADDRESS/IFA_LOCAL
                        const raw = reply[aoff + 4 .. aoff + alen];
                        if (raw.len == 4) {
                            var dup = false;
                            for (out[0..n_addrs]) |prev| {
                                if (std.mem.eql(u8, &prev, raw[0..4])) dup = true;
                            }
                            if (!dup) {
                                @memcpy(&out[n_addrs], raw[0..4]);
                                n_addrs += 1;
                            }
                        }
                    }
                    aoff += (alen + 3) & ~@as(usize, 3);
                }
            }
            off += (mlen + 3) & ~@as(usize, 3);
        }
    }
    return n_addrs;
}

/// Multicast M-SEARCH (koron/go-ssdp Search shape): one send per local
/// address with IP_MULTICAST_IF set, ST ssdp:all, collect for wait_s.
pub fn searchMulticast(
    locations: [][128]u8,
    sts: [][128]u8,
    wait_s: u8,
) Error!usize {
    const s = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    if (failed(s)) return Error.SocketFailed;
    const fd: linux.fd_t = @intCast(s);
    defer _ = linux.close(fd);
    // Multicast TTL 2 (site-local SSDP default).
    const ttl: u8 = 2;
    _ = linux.setsockopt(fd, linux.IPPROTO.IP, linux.IP.MULTICAST_TTL, @ptrCast(&ttl), 1);
    // Loop our sends back like koron's SetMulticastLoopback(true).
    const loop: u8 = 1;
    _ = linux.setsockopt(fd, linux.IPPROTO.IP, linux.IP.MULTICAST_LOOP, @ptrCast(&loop), 1);
    var req_buf: [512]u8 = undefined;
    const req = try buildMSearch(&req_buf, "239.255.255.250:1900", wait_s, st_all);
    var sa = linux.sockaddr.in{
        .family = linux.AF.INET,
        .port = std.mem.nativeToBig(u16, ssdp_port),
        .addr = @bitCast(multicast_ip),
    };
    var addrs: [16][4]u8 = undefined;
    const n_addrs = try localV4Addrs(&addrs);
    if (n_addrs == 0) return Error.NoInternalAddress;
    // Tunnel interfaces (WireGuard etc.) accept MULTICAST_IF but refuse
    // multicast TX, so a failed send only skips its address (koron skips
    // such interfaces up front via the MULTICAST flag).
    var sent: usize = 0;
    for (addrs[0..n_addrs]) |a| {
        // Join the SSDP group per local address (koron's joinGroupIPv4):
        // without a membership the looped-back copy never arrives.
        const mreq = multicast_ip ++ a;
        _ = linux.setsockopt(fd, linux.IPPROTO.IP, linux.IP.ADD_MEMBERSHIP, &mreq, mreq.len);
        // Outgoing interface per local address (like koron's per-if sender).
        const in_addr: u32 = @bitCast(a);
        _ = linux.setsockopt(fd, linux.IPPROTO.IP, linux.IP.MULTICAST_IF, @ptrCast(&in_addr), 4);
        const n = linux.sendto(fd, req.ptr, req.len, 0, @ptrCast(&sa), @sizeOf(linux.sockaddr.in));
        if (!failed(n) and n == req.len) sent += 1;
    }
    if (sent == 0) return Error.SendFailed;
    var n_loc: usize = 0;
    const deadline = nowMs() + @as(i64, wait_s) * 1000;
    while (true) {
        const left = deadline - nowMs();
        if (left <= 0) break;
        var pfd = [_]linux.pollfd{.{ .fd = fd, .events = linux.POLL.IN }};
        const prc = linux.poll(&pfd, 1, @intCast(left));
        if (failed(prc)) return Error.RecvFailed;
        if (prc == 0) break;
        var rbuf: [2048]u8 = undefined;
        const rn = linux.recvfrom(fd, &rbuf, rbuf.len, 0, null, null);
        if (failed(rn) or rn == 0) continue;
        const parsed = parseSSDPResponse(rbuf[0..rn]) catch continue;
        if (parsed.location.len == 0 or parsed.location.len > 127) continue;
        if (n_loc >= locations.len) continue;
        @memcpy(locations[n_loc][0..parsed.location.len], parsed.location);
        locations[n_loc][parsed.location.len] = 0;
        const st_len = @min(parsed.st.len, 127);
        @memcpy(sts[n_loc][0..st_len], parsed.st[0..st_len]);
        sts[n_loc][st_len] = 0;
        n_loc += 1;
    }
    return n_loc;
}

// --- IGD client ---

pub const max_cached_ports = 8;

pub const Client = struct {
    control_url_buf: [256]u8 = undefined,
    control_url_len: usize = 0,
    urn_buf: [80]u8 = undefined,
    urn_len: usize = 0,
    device_host_buf: [64]u8 = undefined,
    device_host_len: usize = 0,
    device_port: u16 = 80,
    timeout_ms: i32 = device_timeout_ms,
    /// Port of upnp_NAT.ports: (proto, internal) -> external.
    cached: [max_cached_ports]struct { is_tcp: bool, internal: u16, external: u16 } = undefined,
    n_cached: usize = 0,

    pub fn controlUrl(c: *const Client) []const u8 {
        return c.control_url_buf[0..c.control_url_len];
    }

    pub fn urn(c: *const Client) []const u8 {
        return c.urn_buf[0..c.urn_len];
    }

    pub fn deviceHost(c: *const Client) []const u8 {
        return c.device_host_buf[0..c.device_host_len];
    }

    fn cachedExt(c: *Client, is_tcp: bool, internal: u16) ?u16 {
        for (c.cached[0..c.n_cached]) |e| {
            if (e.is_tcp == is_tcp and e.internal == internal) return e.external;
        }
        return null;
    }

    fn storeExt(c: *Client, is_tcp: bool, internal: u16, external: u16) void {
        for (c.cached[0..c.n_cached]) |*e| {
            if (e.is_tcp == is_tcp and e.internal == internal) {
                e.external = external;
                return;
            }
        }
        if (c.n_cached < max_cached_ports) {
            c.cached[c.n_cached] = .{ .is_tcp = is_tcp, .internal = internal, .external = external };
            c.n_cached += 1;
        }
    }

    fn dropExt(c: *Client, is_tcp: bool, internal: u16) void {
        for (c.cached[0..c.n_cached], 0..) |e, i| {
            if (e.is_tcp == is_tcp and e.internal == internal) {
                c.cached[i] = c.cached[c.n_cached - 1];
                c.n_cached -= 1;
                return;
            }
        }
    }

    fn soap(
        c: *Client,
        action: []const u8,
        args: []const SoapArg,
        resp_buf: []u8,
    ) Error![]u8 {
        var body_buf: [2048]u8 = undefined;
        const body = try buildSoapCall(&body_buf, c.urn(), action, args);
        var req_buf: [4096]u8 = undefined;
        const resp = try httpPostSoap(c.controlUrl(), c.urn(), action, body, &req_buf, resp_buf, c.timeout_ms);
        // A fault body is an error, not a result (goupnp checks it too);
        // 725 additionally tells the manager to retry with a permanent lease.
        if (hasSoapFault(resp)) {
            if (isPermanentLeaseOnly(resp)) return Error.PermanentLeaseOnly;
            return Error.SoapFault;
        }
        return resp;
    }

    /// Port of GetNATRSIPStatusCtx use: (rsip_available, nat_enabled).
    pub fn natStatus(c: *Client) Error!struct { rsip: bool, nat: bool } {
        var resp_buf: [4096]u8 = undefined;
        const xml = try c.soap("GetNATRSIPStatus", &.{}, &resp_buf);
        var vb: [16]u8 = undefined;
        const rsip_s = try soapResult(xml, "NewRSIPAvailable", &vb);
        const rsip = try parseBoolSoap(rsip_s);
        var vb2: [16]u8 = undefined;
        const nat_s = try soapResult(xml, "NewNATEnabled", &vb2);
        return .{ .rsip = rsip, .nat = try parseBoolSoap(nat_s) };
    }

    pub fn externalAddress(c: *Client) Error![4]u8 {
        var resp_buf: [4096]u8 = undefined;
        const xml = try c.soap("GetExternalIPAddress", &.{}, &resp_buf);
        var vb: [32]u8 = undefined;
        const s = try soapResult(xml, "NewExternalIPAddress", &vb);
        return parseIpv4(s);
    }

    /// Local address the gateway sees us on. Port of internalAddress: UDP
    /// connect (no packets) + getsockname.
    pub fn internalAddress(c: *Client) Error![4]u8 {
        const ip = parseIpv4(c.deviceHost()) catch return Error.NoInternalAddress;
        const s = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
        if (failed(s)) return Error.NoInternalAddress;
        const fd: linux.fd_t = @intCast(s);
        defer _ = linux.close(fd);
        var sa = linux.sockaddr.in{
            .family = linux.AF.INET,
            .port = std.mem.nativeToBig(u16, c.device_port),
            .addr = @bitCast(ip),
        };
        if (failed(linux.connect(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in)))) return Error.NoInternalAddress;
        var got: linux.sockaddr.in = undefined;
        var got_len: linux.socklen_t = @sizeOf(linux.sockaddr.in);
        if (failed(linux.getsockname(fd, @ptrCast(&got), &got_len))) return Error.NoInternalAddress;
        const bytes: [4]u8 = @bitCast(got.addr);
        return bytes;
    }

    fn protoStr(is_tcp: bool) []const u8 {
        return if (is_tcp) "TCP" else "UDP";
    }

    /// Port of upnp_NAT.AddPortMapping: renew the cached external port,
    /// else try 3 random ones.
    pub fn addPortMapping(
        c: *Client,
        protocol: []const u8,
        internal: u16,
        description: []const u8,
        lease_s: u32,
    ) Error!u16 {
        const is_tcp = if (std.mem.eql(u8, protocol, "udp"))
            false
        else if (std.mem.eql(u8, protocol, "tcp"))
            true
        else
            return Error.InvalidProtocol;
        const local = try c.internalAddress();
        var local_buf: [16]u8 = undefined;
        const local_s = std.fmt.bufPrint(&local_buf, "{d}.{d}.{d}.{d}", .{ local[0], local[1], local[2], local[3] }) catch return Error.NoSpace;
        var int_buf: [8]u8 = undefined;
        const int_s = std.fmt.bufPrint(&int_buf, "{d}", .{internal}) catch return Error.NoSpace;
        var lease_buf: [16]u8 = undefined;
        const lease_s_str = std.fmt.bufPrint(&lease_buf, "{d}", .{lease_s}) catch return Error.NoSpace;

        if (c.cachedExt(is_tcp, internal)) |ext| {
            var ext_buf: [8]u8 = undefined;
            const ext_s = std.fmt.bufPrint(&ext_buf, "{d}", .{ext}) catch return Error.NoSpace;
            const args = [_]SoapArg{
                .{ .name = "NewRemoteHost", .val = "" },
                .{ .name = "NewExternalPort", .val = ext_s },
                .{ .name = "NewProtocol", .val = protoStr(is_tcp) },
                .{ .name = "NewInternalPort", .val = int_s },
                .{ .name = "NewInternalClient", .val = local_s },
                .{ .name = "NewEnabled", .val = "1" },
                .{ .name = "NewPortMappingDescription", .val = description },
                .{ .name = "NewLeaseDuration", .val = lease_s_str },
            };
            var resp_buf: [4096]u8 = undefined;
            if (c.soap("AddPortMapping", &args, &resp_buf)) |_| {
                return ext;
            } else |_| {
                // Renew failed: fall through to a fresh random port like Go.
            }
        }

        var tries: usize = 0;
        var last_err: Error = Error.MapFailed;
        while (tries < 3) : (tries += 1) {
            const ext = randomPort();
            var ext_buf: [8]u8 = undefined;
            const ext_s = std.fmt.bufPrint(&ext_buf, "{d}", .{ext}) catch return Error.NoSpace;
            const args = [_]SoapArg{
                .{ .name = "NewRemoteHost", .val = "" },
                .{ .name = "NewExternalPort", .val = ext_s },
                .{ .name = "NewProtocol", .val = protoStr(is_tcp) },
                .{ .name = "NewInternalPort", .val = int_s },
                .{ .name = "NewInternalClient", .val = local_s },
                .{ .name = "NewEnabled", .val = "1" },
                .{ .name = "NewPortMappingDescription", .val = description },
                .{ .name = "NewLeaseDuration", .val = lease_s_str },
            };
            var resp_buf: [4096]u8 = undefined;
            _ = c.soap("AddPortMapping", &args, &resp_buf) catch |err| {
                last_err = err;
                continue;
            };
            c.storeExt(is_tcp, internal, ext);
            return ext;
        }
        return last_err;
    }

    /// Port of upnp_NAT.DeletePortMapping: unknown mappings are a no-op,
    /// the cache drops only on device confirm.
    pub fn deletePortMapping(c: *Client, protocol: []const u8, internal: u16) Error!void {
        const is_tcp = if (std.mem.eql(u8, protocol, "udp"))
            false
        else if (std.mem.eql(u8, protocol, "tcp"))
            true
        else
            return Error.InvalidProtocol;
        const ext = c.cachedExt(is_tcp, internal) orelse return;
        var ext_buf: [8]u8 = undefined;
        const ext_s = std.fmt.bufPrint(&ext_buf, "{d}", .{ext}) catch return Error.NoSpace;
        const args = [_]SoapArg{
            .{ .name = "NewRemoteHost", .val = "" },
            .{ .name = "NewExternalPort", .val = ext_s },
            .{ .name = "NewProtocol", .val = protoStr(is_tcp) },
        };
        var resp_buf: [4096]u8 = undefined;
        _ = try c.soap("DeletePortMapping", &args, &resp_buf);
        c.dropExt(is_tcp, internal);
    }
};

pub const Discovered = struct {
    client: Client,
    service: []const u8,
};

/// Build a client from a description URL: fetch, pick best service, check
/// NAT status. Port of natFromUPNPLocation + natFromUPNPService.
pub fn clientFromLocation(location: []const u8, timeout_ms: i32) Error!Discovered {
    var req_buf: [2048]u8 = undefined;
    var resp_buf: [16384]u8 = undefined;
    const xml = try httpGet(location, &req_buf, &resp_buf, timeout_ms);
    var store: [4096]u8 = undefined;
    var services: [8]Service = undefined;
    const parsed = try parseServices(xml, &store, &services);
    var best: ?Service = null;
    var best_rank: u8 = 0;
    for (services[0..parsed.n]) |s| {
        const r = serviceRank(s.service_type);
        if (r > best_rank) {
            best_rank = r;
            best = s;
        }
    }
    const svc = best orelse return Error.NoService;
    var c = Client{ .timeout_ms = timeout_ms };
    var ctl_buf: [256]u8 = undefined;
    const ctl = try resolveControlUrl(parsed.base, location, svc.control_url, &ctl_buf);
    if (ctl.len > c.control_url_buf.len) return Error.NoSpace;
    @memcpy(c.control_url_buf[0..ctl.len], ctl);
    c.control_url_len = ctl.len;
    if (svc.service_type.len > c.urn_buf.len) return Error.NoSpace;
    @memcpy(c.urn_buf[0..svc.service_type.len], svc.service_type);
    c.urn_len = svc.service_type.len;
    const u = try parseUrl(ctl);
    if (u.host.len > c.device_host_buf.len) return Error.NoSpace;
    @memcpy(c.device_host_buf[0..u.host.len], u.host);
    c.device_host_len = u.host.len;
    c.device_port = u.port;
    const st = try c.natStatus();
    if (!st.nat) return Error.NatDisabled;
    return .{ .client = c, .service = svc.service_type };
}
