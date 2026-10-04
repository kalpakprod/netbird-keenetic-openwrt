// Management client tests: wgbox unit tests + live tests against a fake Go
// ManagementService (gen/mgmt_fake: real grpc-go, upstream proto, NaCl box).
// Sits at src/ because build.zig discovery gives each suite no named
// imports: only relative imports within the suite file's directory work.
// MGMT_HELPER env or $HOME/.cache/netbird-zig-context/gen/mgmt_fake/mgmt_fake;
// missing helper skips the live tests.

const std = @import("std");
const builtin = @import("builtin");
const h2 = @import("net/h2/conn.zig");
const mgmt = @import("mgmt/client.zig");
const messages = @import("mgmt/messages.zig");
const wgbox = @import("mgmt/wgbox.zig");

const tio = std.testing.io;

test "wgbox key format round-trips" {
    const alloc = std.testing.allocator;
    const priv = wgbox.generatePrivateKey(tio);
    const pubkey = wgbox.publicKey(priv);
    const s = try wgbox.allocString(alloc, pubkey);
    defer alloc.free(s);
    try std.testing.expectEqual(@as(usize, 44), s.len);
    const back = try wgbox.parseKey(s);
    try std.testing.expectEqualSlices(u8, &pubkey, &back);
    try std.testing.expectError(wgbox.Error.InvalidBase64, wgbox.parseKey("!!!"));
    try std.testing.expectError(wgbox.Error.IncorrectKeySize, wgbox.parseKey("aGVsbG8="));
}

test "wgbox box round-trips, wrong key fails" {
    const alloc = std.testing.allocator;
    const a_priv = wgbox.generatePrivateKey(tio);
    const b_priv = wgbox.generatePrivateKey(tio);
    const a_pub = wgbox.publicKey(a_priv);
    const b_pub = wgbox.publicKey(b_priv);
    const msg = "hello box";
    const enc = try wgbox.encrypt(alloc, msg, b_pub, a_priv, tio);
    defer alloc.free(enc);
    try std.testing.expectEqual(msg.len + 40, enc.len);
    const dec = try wgbox.decrypt(alloc, enc, a_pub, b_priv);
    defer alloc.free(dec);
    try std.testing.expectEqualStrings(msg, dec);
    const other = wgbox.generatePrivateKey(tio);
    const bad = wgbox.decrypt(alloc, enc, a_pub, other);
    try std.testing.expectError(wgbox.Error.AuthenticationFailed, bad);
    try std.testing.expectError(wgbox.Error.MessageTooShort, wgbox.decrypt(alloc, "short", a_pub, b_priv));
}

fn getenv(allocator: std.mem.Allocator, key: []const u8) !?[]u8 {
    var file = std.Io.Dir.openFileAbsolute(tio, "/proc/self/environ", .{ .mode = .read_only }) catch return null;
    defer file.close(tio);
    var buf: [16384]u8 = undefined;
    const n = file.readPositionalAll(tio, &buf, 0) catch return null;
    var rest = buf[0..n];
    while (rest.len > 0) {
        const end = std.mem.indexOfScalar(u8, rest, 0) orelse break;
        const entry = rest[0..end];
        rest = rest[end + 1 ..];
        const eq = std.mem.indexOfScalar(u8, entry, '=') orelse continue;
        if (std.mem.eql(u8, entry[0..eq], key)) {
            return try allocator.dupe(u8, entry[eq + 1 ..]);
        }
    }
    return null;
}

fn helperPath(allocator: std.mem.Allocator) ![]u8 {
    if (try getenv(allocator, "MGMT_HELPER")) |p| return p;
    const home = (try getenv(allocator, "HOME")) orelse return error.SkipZigTest;
    defer allocator.free(home);
    const def = try std.fmt.allocPrint(allocator, "{s}/.cache/netbird-zig-context/gen/mgmt_fake/mgmt_fake", .{home});
    errdefer allocator.free(def);
    var f = std.Io.Dir.openFileAbsolute(tio, def, .{ .mode = .read_only }) catch return error.SkipZigTest;
    f.close(tio);
    return def;
}

const Live = struct {
    child: std.process.Child,
    stream: std.Io.net.Stream,
    rdr: std.Io.net.Stream.Reader,
    wtr: std.Io.net.Stream.Writer,
    rx_buf: [16384]u8,
    tx_buf: [16384]u8,
    conn: h2.Conn,
    tctx: Ctx,
    authority: []u8,

    const Ctx = struct {
        reader: *std.Io.Reader,
        writer: *std.Io.Writer,
    };

    fn readFn(ctx: *anyopaque, buf: []u8) h2.Transport.ReadError!usize {
        const c: *Ctx = @ptrCast(@alignCast(ctx));
        c.reader.readSliceAll(buf) catch return error.Closed;
        return buf.len;
    }

    fn writeFn(ctx: *anyopaque, buf: []const u8) h2.Transport.WriteError!void {
        const c: *Ctx = @ptrCast(@alignCast(ctx));
        c.writer.writeAll(buf) catch return error.Closed;
        c.writer.flush() catch return error.Closed;
    }

    fn connect(allocator: std.mem.Allocator, port: u16) !*Live {
        const self = try allocator.create(Live);
        errdefer allocator.destroy(self);
        const helper = try helperPath(allocator);
        defer allocator.free(helper);
        const addr_str = try std.fmt.allocPrint(allocator, "127.0.0.1:{d}", .{port});
        errdefer allocator.free(addr_str);
        const argv = [_][]const u8{ helper, addr_str };
        self.child = try std.process.spawn(tio, .{
            .argv = &argv,
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .ignore,
        });
        errdefer self.child.kill(tio);
        var addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(port) };
        var i: usize = 0;
        const stream = while (i < 200000) : (i += 1) {
            if (addr.connect(tio, .{ .mode = .stream })) |s| break s else |_| {}
        } else return error.ConnectTimeout;
        self.stream = stream;
        self.authority = addr_str;
        self.rdr = std.Io.net.Stream.Reader.init(stream, tio, &self.rx_buf);
        self.wtr = stream.writer(tio, &self.tx_buf);
        self.tctx = .{ .reader = &self.rdr.interface, .writer = &self.wtr.interface };
        self.conn = h2.Conn.init(.{ .ctx = &self.tctx, .readFn = readFn, .writeFn = writeFn });
        try self.conn.handshake();
        return self;
    }

    fn close(self: *Live, allocator: std.mem.Allocator) void {
        self.stream.close(tio);
        self.child.kill(tio);
        allocator.free(self.authority);
        allocator.destroy(self);
    }
};

fn testMeta() messages.PeerSystemMeta {
    return .{
        .hostname = "zig-fake-peer",
        .go_os = "linux",
        .netbird_version = "0.79.0-test",
        .capabilities = &.{ .source_prefixes, .ipv6_overlay },
    };
}

test "mgmt get server key" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    const live = try Live.connect(alloc, 18601);
    defer live.close(alloc);
    var c = mgmt.Client{
        .conn = &live.conn,
        .alloc = alloc,
        .authority = live.authority,
        .io = tio,
        .key = wgbox.generatePrivateKey(tio),
    };
    defer c.deinit();
    const key = try c.getServerKey();
    const s = try wgbox.allocString(alloc, key);
    defer alloc.free(s);
    try std.testing.expectEqual(@as(usize, 44), s.len);
    // Cached: second call returns the same key without error.
    const key2 = try c.getServerKey();
    try std.testing.expectEqualSlices(u8, &key, &key2);
}

test "mgmt login with setup key" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    const live = try Live.connect(alloc, 18602);
    defer live.close(alloc);
    var c = mgmt.Client{
        .conn = &live.conn,
        .alloc = alloc,
        .authority = live.authority,
        .io = tio,
        .key = wgbox.generatePrivateKey(tio),
    };
    defer c.deinit();
    var resp = try c.register("test-setup-key", "", testMeta(), "ssh-test-key", &.{});
    defer resp.deinit(alloc);
    const pc = resp.peer_config orelse return error.NoPeerConfig;
    try std.testing.expectEqualStrings("100.120.0.1/16", pc.address);
    try std.testing.expectEqualStrings("zig-fake-peer.netbird.cloud", pc.fqdn);
    try std.testing.expectEqual(@as(i32, 1280), pc.mtu);
    try std.testing.expectEqualStrings("ssh-test-key", pc.ssh_config.?.ssh_pub_key);
    try std.testing.expectEqualStrings("test-issuer", pc.ssh_config.?.jwt_config.?.issuer);
    try std.testing.expectEqual(@as(usize, 2), pc.ssh_config.?.jwt_config.?.audiences.items.len);
    try std.testing.expectEqual(@as(usize, 17), pc.address_v6.len);
    const nb = resp.netbird_config orelse return error.NoNetbirdConfig;
    try std.testing.expectEqualStrings("signal.netbird.io:443", nb.signal.?.uri);
    try std.testing.expectEqual(messages.HostProtocol.https, nb.signal.?.protocol);
    try std.testing.expectEqualStrings("stun:stun.netbird.io:3478", nb.stuns.items[0].uri);
    try std.testing.expectEqualStrings("turnuser", nb.turns.items[0].user);
    try std.testing.expect(nb.flow.?.enabled);
    try std.testing.expect(nb.metrics.?.enabled);
    try std.testing.expectEqualStrings("/usr/bin/test-file", resp.checks.items[0].files.items[0]);
}

test "mgmt login bad setup key denied" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    const live = try Live.connect(alloc, 18603);
    defer live.close(alloc);
    var c = mgmt.Client{
        .conn = &live.conn,
        .alloc = alloc,
        .authority = live.authority,
        .io = tio,
        .key = wgbox.generatePrivateKey(tio),
    };
    defer c.deinit();
    try std.testing.expectError(mgmt.Error.MgmtStatus, c.register("wrong-key", "", testMeta(), "", &.{}));
    try std.testing.expectEqual(@as(u32, 7), c.last_status_code);
    try std.testing.expect(std.mem.indexOf(u8, c.last_status_msg.items, "setup") != null);
}

test "mgmt sync receives network map" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    const live = try Live.connect(alloc, 18604);
    defer live.close(alloc);
    var c = mgmt.Client{
        .conn = &live.conn,
        .alloc = alloc,
        .authority = live.authority,
        .io = tio,
        .key = wgbox.generatePrivateKey(tio),
    };
    defer c.deinit();
    var stream = try c.sync(testMeta());
    defer stream.deinit();
    var serials: [2]u64 = undefined;
    var n: usize = 0;
    while (try stream.next()) |resp| : (n += 1) {
        var r = resp;
        defer r.deinit(alloc);
        if (n >= 2) return error.TooManyUpdates;
        const nm = r.network_map orelse return error.NoNetworkMap;
        serials[n] = nm.serial;
        if (n == 0) {
            try std.testing.expectEqualStrings("100.120.0.1/16", nm.peer_config.?.address);
            const rp = nm.remote_peers.items[0];
            try std.testing.expectEqualStrings("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", rp.wg_pub_key);
            try std.testing.expectEqualStrings("100.120.0.2/32", rp.allowed_ips.items[0]);
            try std.testing.expectEqualStrings("remote-peer.netbird.cloud", rp.fqdn);
            try std.testing.expectEqual(messages.LazyState.lazy, rp.lazy_state);
            const rt = nm.routes.items[0];
            try std.testing.expectEqualStrings("10.0.0.0/8", rt.network);
            try std.testing.expectEqualStrings("example.com", rt.domains.items[0]);
            try std.testing.expect(nm.dns_config.?.service_enable);
            const grp = nm.dns_config.?.name_server_groups.items[0];
            try std.testing.expectEqualStrings("1.1.1.1", grp.name_servers.items[0].ip);
            try std.testing.expectEqualStrings("host.custom.local", nm.dns_config.?.custom_zones.items[0].records.items[0].name);
            const fw = nm.firewall_rules.items[0];
            try std.testing.expectEqual(messages.RuleProtocol.tcp, fw.protocol);
            try std.testing.expectEqual(@as(u32, 22), fw.port_info.?.port.?);
            try std.testing.expectEqualSlices(u8, &.{ 100, 120, 0, 2, 32 }, fw.source_prefixes.items[0]);
            const rf = nm.routes_firewall_rules.items[0];
            try std.testing.expectEqual(@as(u32, 8000), rf.port_info.?.range.?.start);
            try std.testing.expectEqual(@as(u32, 9000), rf.port_info.?.range.?.end);
            try std.testing.expectEqualStrings("route-1", rf.route_id);
            const fwd = nm.forwarding_rules.items[0];
            try std.testing.expectEqualSlices(u8, &.{ 10, 1, 2, 3 }, fwd.translated_address);
            try std.testing.expectEqualStrings("sub", nm.ssh_auth.?.user_id_claim);
            try std.testing.expectEqualStrings("user-hash-1", nm.ssh_auth.?.authorized_users.items[0]);
            try std.testing.expectEqualStrings("machine-1", nm.ssh_auth.?.machine_users.items[0].key);
            try std.testing.expectEqualSlices(u32, &.{0}, nm.ssh_auth.?.machine_users.items[0].value.indexes.items);
        }
    }
    try std.testing.expectEqual(@as(usize, 2), n);
    try std.testing.expectEqualSlices(u64, &.{ 7, 8 }, &serials);
}
