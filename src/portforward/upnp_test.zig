// Tests for upnp.zig. Oracles: testdata/upnp_vectors.txt (M-SEARCH and SOAP
// requests produced by huin/goupnp + koron/go-ssdp, responses accepted by
// them — see gen/nat/cmd/upnpvecs + cmd/fakeigd) and a live run against the
// fake IGD via IGD_TEST_ADDR=127.0.0.1:1900,http-port.

const std = @import("std");
const builtin = @import("builtin");
const upnp = @import("upnp.zig");
const linux = std.os.linux;

const vectors_text = @embedFile("testdata/upnp_vectors.txt");
const desc_xml = @embedFile("testdata/igd_desc.xml");

fn vecHex(name: []const u8, out: []u8) []u8 {
    var lines = std.mem.splitScalar(u8, vectors_text, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var parts = std.mem.splitScalar(u8, line, ' ');
        const n = parts.next() orelse continue;
        if (!std.mem.eql(u8, n, name)) continue;
        const h = parts.next() orelse continue;
        const blen = h.len / 2;
        std.debug.assert(blen <= out.len);
        for (0..blen) |i| {
            out[i] = std.fmt.parseInt(u8, h[i * 2 .. i * 2 + 2], 16) catch unreachable;
        }
        return out[0..blen];
    }
    unreachable;
}

test "msearch matches goupnp bytes" {
    var buf: [1024]u8 = undefined;
    var out: [1024]u8 = undefined;
    const want = vecHex("ssdp_msearch_igdv2", &buf);
    const got = try upnp.buildMSearch(&out, "127.0.0.1:1900", 2, upnp.st_igdv2);
    try std.testing.expectEqualSlices(u8, want, got);
    const want_mc = vecHex("ssdp_msearch_multicast", &buf);
    const got_mc = try upnp.buildMSearch(&out, "239.255.255.250:1900", 5, upnp.st_all);
    try std.testing.expectEqualSlices(u8, want_mc, got_mc);
}

test "ssdp response parse" {
    // Same shape the fake emits (Go http stack accepted it).
    const resp =
        "HTTP/1.1 200 OK\r\n" ++
        "CACHE-CONTROL: max-age=1800\r\n" ++
        "LOCATION: http://127.0.0.1:54321/desc.xml\r\n" ++
        "SERVER: FakeIGD/1.0 UPnP/1.1\r\n" ++
        "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:2\r\n" ++
        "USN: uuid:fake-igd-0001::urn:schemas-upnp-org:device:InternetGatewayDevice:2\r\n\r\n";
    const p = try upnp.parseSSDPResponse(resp);
    try std.testing.expectEqualStrings("http://127.0.0.1:54321/desc.xml", p.location);
    try std.testing.expectEqualStrings(upnp.st_igdv2, p.st);
    // Header case does not matter; non-200 rejected.
    const lower =
        "HTTP/1.1 200 OK\r\nlocation: http://127.0.0.1:1/d.xml\r\nst: ssdp:all\r\n\r\n";
    const pl = try upnp.parseSSDPResponse(lower);
    try std.testing.expectEqualStrings("http://127.0.0.1:1/d.xml", pl.location);
    try std.testing.expectError(upnp.Error.BadStatus, upnp.parseSSDPResponse("HTTP/1.1 404 NF\r\n\r\n"));
}

test "location must name the gateway" {
    try std.testing.expect(upnp.locationHasAddr("http://127.0.0.1:54321/desc.xml", .{ 127, 0, 0, 1 }));
    try std.testing.expect(!upnp.locationHasAddr("http://10.9.9.9/desc.xml", .{ 127, 0, 0, 1 }));
    try std.testing.expect(!upnp.locationHasAddr("http://evil.example/desc.xml", .{ 127, 0, 0, 1 }));
    try std.testing.expect(!upnp.locationHasAddr("not a url", .{ 127, 0, 0, 1 }));
}

test "description parse and service rank" {
    var store: [4096]u8 = undefined;
    var services: [8]upnp.Service = undefined;
    const p = try upnp.parseServices(desc_xml, &store, &services);
    try std.testing.expectEqualStrings("http://127.0.0.1:54321/", p.base);
    try std.testing.expectEqual(@as(usize, 2), p.n);
    try std.testing.expectEqual(@as(u8, 3), upnp.serviceRank(services[0].service_type));
    try std.testing.expectEqual(@as(u8, 2), upnp.serviceRank(services[1].service_type));
    try std.testing.expectEqual(@as(u8, 0), upnp.serviceRank("urn:schemas-upnp-org:service:Layer3Forwarding:1"));
    var out: [256]u8 = undefined;
    const ctl = try upnp.resolveControlUrl(p.base, "http://127.0.0.1:54321/desc.xml", services[0].control_url, &out);
    try std.testing.expectEqualStrings("http://127.0.0.1:54321/ctl/ip2", ctl);
}

test "soap add matches goupnp bytes" {
    var buf: [2048]u8 = undefined;
    var out: [2048]u8 = undefined;
    const want = vecHex("soap_AddPortMapping_req", &buf);
    const args = [_]upnp.SoapArg{
        .{ .name = "NewRemoteHost", .val = "" },
        .{ .name = "NewExternalPort", .val = "51820" },
        .{ .name = "NewProtocol", .val = "UDP" },
        .{ .name = "NewInternalPort", .val = "51820" },
        .{ .name = "NewInternalClient", .val = "127.0.0.1" },
        .{ .name = "NewEnabled", .val = "1" },
        .{ .name = "NewPortMappingDescription", .val = "netbird" },
        .{ .name = "NewLeaseDuration", .val = "3600" },
    };
    const got = try upnp.buildSoapCall(&out, upnp.urn_ip2, "AddPortMapping", &args);
    try std.testing.expectEqualSlices(u8, want, got);
}

test "soap responses parse" {
    var buf: [2048]u8 = undefined;
    var val: [128]u8 = undefined;
    const ext = vecHex("soap_GetExternalIPAddress_resp", &buf);
    const ip_s = try upnp.soapResult(ext, "NewExternalIPAddress", &val);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 203, 0, 113, 9 }, &(try upnp.parseIpv4(ip_s)));
    const nat = vecHex("soap_GetNATRSIPStatus_resp", &buf);
    var v2: [16]u8 = undefined;
    try std.testing.expect(try upnp.parseBoolSoap(try upnp.soapResult(nat, "NewRSIPAvailable", &v2)));
    var v3: [16]u8 = undefined;
    try std.testing.expect(try upnp.parseBoolSoap(try upnp.soapResult(nat, "NewNATEnabled", &v3)));
    // Faults surface as errors, unknown tags as BadXml.
    const fault = "<s:Envelope><s:Body><s:Fault><faultstring>err</faultstring></s:Fault></s:Body></s:Envelope>";
    try std.testing.expectError(upnp.Error.SoapFault, upnp.soapResult(fault, "X", &val));
    try std.testing.expectError(upnp.Error.BadXml, upnp.soapResult(ext, "NoSuchTag", &val));
}

test "soap escaping only touches angle brackets and ampersand" {
    var out: [1024]u8 = undefined;
    const args = [_]upnp.SoapArg{.{ .name = "D", .val = "a<b>&\"'c" }};
    const got = try upnp.buildSoapCall(&out, upnp.urn_ip2, "T", &args);
    try std.testing.expect(std.mem.indexOf(u8, got, "<D>a&lt;b&gt;&amp;\"'c</D>") != null);
}

const tio = std.testing.io;

fn testEnv(out: []u8) ?[]u8 {
    var file = std.Io.Dir.openFileAbsolute(tio, "/proc/self/environ", .{ .mode = .read_only }) catch return null;
    defer file.close(tio);
    var ebuf: [65536]u8 = undefined;
    const n = file.readPositionalAll(tio, &ebuf, 0) catch return null;
    var entries = std.mem.splitScalar(u8, ebuf[0..n], 0);
    const prefix = "IGD_TEST_ADDR=";
    while (entries.next()) |e| {
        if (std.mem.startsWith(u8, e, prefix)) {
            const v = e[prefix.len..];
            if (v.len == 0 or v.len > out.len) return null;
            @memcpy(out[0..v.len], v);
            return out[0..v.len];
        }
    }
    return null;
}

test "live unicast discover and map via fake IGD" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var env_buf: [64]u8 = undefined;
    const env = testEnv(&env_buf) orelse return error.SkipZigTest;
    _ = env;
    // Gateway is always loopback in this test; the env only gates execution.
    const gw: [4]u8 = .{ 127, 0, 0, 1 };
    var locations: [4][128]u8 = undefined;
    var keep: [128]u8 = undefined;
    var found_len: usize = 0;
    for ([_][]const u8{ upnp.st_igdv2, upnp.st_igdv1, upnp.st_all }) |target| {
        const n = try upnp.searchUnicast(gw, target, &locations, 2000);
        for (locations[0..n]) |*slot| {
            const loc = std.mem.sliceTo(slot, 0);
            if (upnp.locationHasAddr(loc, gw)) {
                @memcpy(keep[0..loc.len], loc);
                found_len = loc.len;
                break;
            }
        }
        if (found_len > 0) break;
    }
    if (found_len == 0) return error.SkipZigTest;
    const location = keep[0..found_len];
    var disc = try upnp.clientFromLocation(location, 5000);
    const ext = try disc.client.externalAddress();
    try std.testing.expectEqualSlices(u8, &[_]u8{ 203, 0, 113, 9 }, &ext);
    const mapped = try disc.client.addPortMapping("udp", 51820, "netbird", 3600);
    try std.testing.expect(mapped >= 10000);
    // Renew hits the cached external port (same value back).
    try std.testing.expectEqual(mapped, try disc.client.addPortMapping("udp", 51820, "netbird", 3600));
    try disc.client.deletePortMapping("udp", 51820);
    // Deleting twice is a no-op, unknown protocol is an error.
    try disc.client.deletePortMapping("udp", 51820);
    try std.testing.expectError(upnp.Error.InvalidProtocol, disc.client.addPortMapping("sctp", 1, "x", 1));
}

test "live multicast discover finds fake IGD" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var env_buf: [64]u8 = undefined;
    if (testEnv(&env_buf) == null) return error.SkipZigTest;
    var locations: [8][128]u8 = undefined;
    var sts: [8][128]u8 = undefined;
    const n = try upnp.searchMulticast(&locations, &sts, 2);
    // The fake answers with a loopback LOCATION; real LAN IGDs never do,
    // so this proves the multicast round trip reached the fake.
    var saw_fake = false;
    for (locations[0..n]) |*slot| {
        const loc = std.mem.sliceTo(slot, 0);
        _ = try upnp.parseUrl(loc);
        if (std.mem.indexOf(u8, loc, "127.0.0.1") != null) saw_fake = true;
    }
    try std.testing.expect(n >= 1 and saw_fake);
}

test "relative control URL resolves against authority" {
    var out: [256]u8 = undefined;
    try std.testing.expectEqualStrings("http://127.0.0.1:54321/ctl/ip2", try upnp.resolveControlUrl("", "http://127.0.0.1:54321/desc.xml", "ctl/ip2", &out));
}

fn fixtureEnv(out: []u8) ?[]u8 {
    var file = std.Io.Dir.openFileAbsolute(tio, "/proc/self/environ", .{ .mode = .read_only }) catch return null;
    defer file.close(tio);
    var ebuf: [65536]u8 = undefined;
    const n = file.readPositionalAll(tio, &ebuf, 0) catch return null;
    var entries = std.mem.splitScalar(u8, ebuf[0..n], 0);
    const prefix = "L18_HTTP_FIXTURE=";
    while (entries.next()) |e| {
        if (std.mem.startsWith(u8, e, prefix)) {
            const v = e[prefix.len..];
            if (v.len == 0 or v.len > out.len) return null;
            @memcpy(out[0..v.len], v);
            return out[0..v.len];
        }
    }
    return null;
}

test "description retries disabled higher rank" {
    var env_buf: [64]u8 = undefined;
    _ = fixtureEnv(&env_buf) orelse return error.SkipZigTest;
    const disc = try upnp.clientFromLocation("http://127.0.0.1:54321/desc.xml", 1000);
    try std.testing.expectEqualStrings(upnp.urn_ip1, disc.client.urn_buf[0..disc.client.urn_len]);
}



test "discovered service survives allocator transfer" {
    var env_buf: [64]u8 = undefined;
    _ = fixtureEnv(&env_buf) orelse return error.SkipZigTest;
    const owned = try std.testing.allocator.create(upnp.Discovered);
    defer std.testing.allocator.destroy(owned);
    owned.* = try upnp.clientFromLocation("http://127.0.0.1:54321/desc.xml", 1000);
    // Supported URNs are immutable, so copying the result must not retain a stack slice.
    try std.testing.expect(owned.service.ptr == upnp.urn_ip2.ptr);
    try std.testing.expectEqualStrings(upnp.urn_ip2, owned.service);
}

test "SOAP non200 valid envelope is rejected" {
    var gate_buf: [64]u8 = undefined;
    if (regressionEnv(&gate_buf) == null) return error.SkipZigTest;
    var req: [4096]u8 = undefined;
    var resp: [4096]u8 = undefined;
    try std.testing.expectError(error.BadStatus, upnp.httpPostSoap("http://127.0.0.1:54321/ctl/ip2", upnp.urn_ip2, "AddPortMapping", "", &req, &resp, 1000));
}

fn regressionEnv(out: []u8) ?[]u8 {
    var file = std.Io.Dir.openFileAbsolute(tio, "/proc/self/environ", .{ .mode = .read_only }) catch return null;
    defer file.close(tio);
    var ebuf: [65536]u8 = undefined;
    const n = file.readPositionalAll(tio, &ebuf, 0) catch return null;
    var entries = std.mem.splitScalar(u8, ebuf[0..n], 0);
    const prefix = "L20_FIXTURE=";
    while (entries.next()) |e| {
        if (std.mem.startsWith(u8, e, prefix)) {
            const v = e[prefix.len..];
            if (v.len == 0 or v.len > out.len) return null;
            @memcpy(out[0..v.len], v);
            return out[0..v.len];
        }
    }
    return null;
}

test "gateway mapping shares caller budget" {
    var gate_buf: [64]u8 = undefined;
    if (regressionEnv(&gate_buf) == null) return error.SkipZigTest;
    var c = upnp.Client{ .timeout_ms = 100 };
    const url = "http://127.0.0.1:54321/ctl/ip2";
    @memcpy(c.control_url_buf[0..url.len], url); c.control_url_len = url.len;
    @memcpy(c.urn_buf[0..upnp.urn_ip2.len], upnp.urn_ip2); c.urn_len = upnp.urn_ip2.len;
    const host = "127.0.0.1";
    @memcpy(c.device_host_buf[0..host.len], host); c.device_host_len = host.len; c.device_port = 54321;
    var before: linux.timespec = undefined; var after: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &before);
    _ = c.addPortMapping("udp", 12345, "budget regression", 3600) catch {};
    _ = linux.clock_gettime(.MONOTONIC, &after);
    const elapsed = (after.sec - before.sec) * 1000 + @divTrunc(after.nsec - before.nsec, 1_000_000);
    std.debug.print("caller_timeout_ms=100 mapping_elapsed_ms={d}\n", .{elapsed});
    try std.testing.expect(elapsed <= 130);
}

test "relative control URL normalizes dot segments and preserves query" {
    var out: [256]u8 = undefined;
    const base = "http://127.0.0.1:54321/";
    try std.testing.expectEqualStrings("http://127.0.0.1:54321/ip2", try upnp.resolveControlUrl(base, base, "ctl/../ip2", &out));
    try std.testing.expectEqualStrings("http://127.0.0.1:54321/ctl/ip2", try upnp.resolveControlUrl(base, base, "./ctl/ip2", &out));
    try std.testing.expectEqualStrings("http://127.0.0.1:54321/ip2?q=../x", try upnp.resolveControlUrl(base, base, "/ctl/../ip2?q=../x", &out));
}

test "HTTP 500 preserves permanent lease fault body" {
    var gate_buf: [64]u8 = undefined;
    if (regressionEnv(&gate_buf) == null) return error.SkipZigTest;
    var req: [4096]u8 = undefined;
    var resp: [4096]u8 = undefined;
    const body = try upnp.httpPostSoap("http://127.0.0.1:54321/fault/725", upnp.urn_ip2, "AddPortMapping", "", &req, &resp, 1000);
    try std.testing.expect(std.mem.indexOf(u8, body, "<s:Fault>") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "<errorCode>725</errorCode>") != null);
}
