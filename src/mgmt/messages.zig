// Port of netbird shared/management/proto/management.proto messages (v0.79.0), BSD-3-Clause.
// Hand codecs over src/proto/wire.zig. Encode: exactly the request messages
// the client sends (Empty, EncryptedMessage, LoginRequest, SyncRequest).
// Decode: exactly the response messages the client reads (ServerKeyResponse,
// LoginResponse, SyncResponse + the full legacy NetworkMap tree). Unknown
// fields are skipped; unknown enum values map to the zero variant. The
// component NetworkMap envelope (field 8) is never advertised and skipped.

const std = @import("std");
const wire = @import("../proto/wire.zig");

pub const Error = wire.Error || error{ OutOfMemory, WireTypeMismatch };

fn expect(typ: wire.Type, want: wire.Type) Error!void {
    if (typ != want) return Error.WireTypeMismatch;
}

// --- encode helpers (proto3: omit zero/empty) ---

fn sizeStr(num: wire.Number, s: []const u8) usize {
    if (s.len == 0) return 0;
    return wire.sizeTag(num) + wire.sizeBytes(s.len);
}

fn sizeVarint(num: wire.Number, v: u64) usize {
    if (v == 0) return 0;
    return wire.sizeTag(num) + wire.sizeVarint(v);
}

fn sizeBool(num: wire.Number, b: bool) usize {
    return if (b) wire.sizeTag(num) + 1 else 0;
}

fn sizeMsg(num: wire.Number, child: ?[]const u8) usize {
    const c = child orelse return 0;
    return wire.sizeTag(num) + wire.sizeBytes(c.len);
}

fn putStr(enc: *wire.Encoder, num: wire.Number, s: []const u8) Error!void {
    if (s.len == 0) return;
    try enc.appendTag(num, .bytes);
    try enc.appendBytes(s);
}

fn putVarint(enc: *wire.Encoder, num: wire.Number, v: u64) Error!void {
    if (v == 0) return;
    try enc.appendTag(num, .varint);
    try enc.appendVarint(v);
}

fn putBool(enc: *wire.Encoder, num: wire.Number, b: bool) Error!void {
    if (!b) return;
    try enc.appendTag(num, .varint);
    try enc.appendVarint(@intFromBool(b));
}

fn putMsg(enc: *wire.Encoder, num: wire.Number, child: ?[]const u8) Error!void {
    const c = child orelse return;
    try enc.appendTag(num, .bytes);
    try enc.appendBytes(c);
}

// --- decode helpers ---

fn getStr(alloc: std.mem.Allocator, d: *wire.Decoder) Error![]u8 {
    return try alloc.dupe(u8, try d.consumeBytes());
}

fn getI32(d: *wire.Decoder) Error!i32 {
    return @bitCast(@as(u32, @truncate(try d.consumeVarint())));
}

fn getI64(d: *wire.Decoder) Error!i64 {
    return @bitCast(try d.consumeVarint());
}

fn getU32(d: *wire.Decoder) Error!u32 {
    return @truncate(try d.consumeVarint());
}

fn skip(d: *wire.Decoder, num: wire.Number, typ: wire.Type) Error!void {
    _ = try d.skipField(num, typ);
}

fn finish(enc: *const wire.Encoder, out: []u8) void {
    std.debug.assert(enc.bytes().len == out.len);
}

// --- google.protobuf.Timestamp / Duration ---

pub const Timestamp = struct {
    seconds: i64 = 0,
    nanos: i32 = 0,

    pub fn decode(alloc: std.mem.Allocator, buf: []const u8) Error!Timestamp {
        _ = alloc;
        var m = Timestamp{};
        var d = wire.Decoder.init(buf);
        while (!d.done()) {
            const t = try d.consumeTag();
            switch (t.num) {
                1 => {
                    try expect(t.typ, .varint);
                    m.seconds = try getI64(&d);
                },
                2 => {
                    try expect(t.typ, .varint);
                    m.nanos = try getI32(&d);
                },
                else => try skip(&d, t.num, t.typ),
            }
        }
        return m;
    }
};

pub const Duration = struct {
    seconds: i64 = 0,
    nanos: i32 = 0,

    pub fn decode(alloc: std.mem.Allocator, buf: []const u8) Error!Duration {
        _ = alloc;
        var m = Duration{};
        var d = wire.Decoder.init(buf);
        while (!d.done()) {
            const t = try d.consumeTag();
            switch (t.num) {
                1 => {
                    try expect(t.typ, .varint);
                    m.seconds = try getI64(&d);
                },
                2 => {
                    try expect(t.typ, .varint);
                    m.nanos = try getI32(&d);
                },
                else => try skip(&d, t.num, t.typ),
            }
        }
        return m;
    }
};

// --- Empty ---

pub const Empty = struct {
    pub fn encode(alloc: std.mem.Allocator) Error![]u8 {
        return try alloc.alloc(u8, 0);
    }
};

// --- EncryptedMessage ---

pub const EncryptedMessage = struct {
    wg_pub_key: []const u8 = "",
    body: []const u8 = "",
    version: i32 = 0,
    owned: bool = false,

    pub fn deinit(m: *EncryptedMessage, alloc: std.mem.Allocator) void {
        if (!m.owned) return;
        alloc.free(m.wg_pub_key);
        alloc.free(m.body);
        m.owned = false;
    }

    pub fn encode(m: *const EncryptedMessage, alloc: std.mem.Allocator) Error![]u8 {
        const n = sizeStr(1, m.wg_pub_key) + sizeStr(2, m.body) +
            sizeVarint(3, @bitCast(@as(i64, m.version)));
        const out = try alloc.alloc(u8, n);
        errdefer alloc.free(out);
        var enc = wire.Encoder.init(out);
        try putStr(&enc, 1, m.wg_pub_key);
        try putStr(&enc, 2, m.body);
        try putVarint(&enc, 3, @bitCast(@as(i64, m.version)));
        finish(&enc, out);
        return out;
    }

    pub fn decode(alloc: std.mem.Allocator, buf: []const u8) Error!EncryptedMessage {
        var m = EncryptedMessage{ .owned = true };
        errdefer m.deinit(alloc);
        var d = wire.Decoder.init(buf);
        while (!d.done()) {
            const t = try d.consumeTag();
            switch (t.num) {
                1 => {
                    try expect(t.typ, .bytes);
                    alloc.free(m.wg_pub_key);
                    m.wg_pub_key = try getStr(alloc, &d);
                },
                2 => {
                    try expect(t.typ, .bytes);
                    alloc.free(m.body);
                    m.body = try getStr(alloc, &d);
                },
                3 => {
                    try expect(t.typ, .varint);
                    m.version = try getI32(&d);
                },
                else => try skip(&d, t.num, t.typ),
            }
        }
        return m;
    }
};

// --- PeerKeys ---

pub const PeerKeys = struct {
    ssh_pub_key: []const u8 = "",
    wg_pub_key: []const u8 = "",

    pub fn encode(m: *const PeerKeys, alloc: std.mem.Allocator) Error![]u8 {
        const n = sizeStr(1, m.ssh_pub_key) + sizeStr(2, m.wg_pub_key);
        const out = try alloc.alloc(u8, n);
        errdefer alloc.free(out);
        var enc = wire.Encoder.init(out);
        try putStr(&enc, 1, m.ssh_pub_key);
        try putStr(&enc, 2, m.wg_pub_key);
        finish(&enc, out);
        return out;
    }
};

// --- PeerSystemMeta tree (encode only) ---

pub const NetworkAddress = struct {
    net_ip: []const u8 = "",
    mac: []const u8 = "",

    pub fn encode(m: *const NetworkAddress, alloc: std.mem.Allocator) Error![]u8 {
        const n = sizeStr(1, m.net_ip) + sizeStr(2, m.mac);
        const out = try alloc.alloc(u8, n);
        errdefer alloc.free(out);
        var enc = wire.Encoder.init(out);
        try putStr(&enc, 1, m.net_ip);
        try putStr(&enc, 2, m.mac);
        finish(&enc, out);
        return out;
    }
};

pub const Environment = struct {
    cloud: []const u8 = "",
    platform: []const u8 = "",

    pub fn encode(m: *const Environment, alloc: std.mem.Allocator) Error![]u8 {
        const n = sizeStr(1, m.cloud) + sizeStr(2, m.platform);
        const out = try alloc.alloc(u8, n);
        errdefer alloc.free(out);
        var enc = wire.Encoder.init(out);
        try putStr(&enc, 1, m.cloud);
        try putStr(&enc, 2, m.platform);
        finish(&enc, out);
        return out;
    }
};

pub const MetaFile = struct {
    path: []const u8 = "",
    exist: bool = false,
    process_is_running: bool = false,

    pub fn encode(m: *const MetaFile, alloc: std.mem.Allocator) Error![]u8 {
        const n = sizeStr(1, m.path) + sizeBool(2, m.exist) + sizeBool(3, m.process_is_running);
        const out = try alloc.alloc(u8, n);
        errdefer alloc.free(out);
        var enc = wire.Encoder.init(out);
        try putStr(&enc, 1, m.path);
        try putBool(&enc, 2, m.exist);
        try putBool(&enc, 3, m.process_is_running);
        finish(&enc, out);
        return out;
    }
};

pub const Flags = struct {
    rosenpass_enabled: bool = false,
    rosenpass_permissive: bool = false,
    server_ssh_allowed: bool = false,
    disable_client_routes: bool = false,
    disable_server_routes: bool = false,
    disable_dns: bool = false,
    disable_firewall: bool = false,
    block_lan_access: bool = false,
    block_inbound: bool = false,
    lazy_connection_enabled: bool = false,
    enable_ssh_root: bool = false,
    enable_ssh_sftp: bool = false,
    enable_ssh_local_port_forwarding: bool = false,
    enable_ssh_remote_port_forwarding: bool = false,
    disable_ssh_auth: bool = false,
    disable_ipv6: bool = false,
    remote_jobs_allowed: bool = false,

    pub fn encode(m: *const Flags, alloc: std.mem.Allocator) Error![]u8 {
        const b = [_]bool{
            m.rosenpass_enabled,         m.rosenpass_permissive,
            m.server_ssh_allowed,        m.disable_client_routes,
            m.disable_server_routes,     m.disable_dns,
            m.disable_firewall,          m.block_lan_access,
            m.block_inbound,             m.lazy_connection_enabled,
            m.enable_ssh_root,           m.enable_ssh_sftp,
            m.enable_ssh_local_port_forwarding, m.enable_ssh_remote_port_forwarding,
            m.disable_ssh_auth,          m.disable_ipv6,
            m.remote_jobs_allowed,
        };
        var n: usize = 0;
        for (b, 0..) |v, i| n += sizeBool(@intCast(i + 1), v);
        const out = try alloc.alloc(u8, n);
        errdefer alloc.free(out);
        var enc = wire.Encoder.init(out);
        for (b, 0..) |v, i| try putBool(&enc, @intCast(i + 1), v);
        finish(&enc, out);
        return out;
    }
};

pub const Capability = enum(u32) {
    unknown = 0,
    source_prefixes = 1,
    ipv6_overlay = 2,
    component_network_map = 3,
};

pub const PeerSystemMeta = struct {
    hostname: []const u8 = "",
    go_os: []const u8 = "",
    kernel: []const u8 = "",
    core: []const u8 = "",
    platform: []const u8 = "",
    os: []const u8 = "",
    netbird_version: []const u8 = "",
    ui_version: []const u8 = "",
    kernel_version: []const u8 = "",
    os_version: []const u8 = "",
    network_addresses: []const NetworkAddress = &.{},
    sys_serial_number: []const u8 = "",
    sys_product_name: []const u8 = "",
    sys_manufacturer: []const u8 = "",
    environment: ?Environment = null,
    files: []const MetaFile = &.{},
    flags: ?Flags = null,
    capabilities: []const Capability = &.{},
    sync_message_version: i32 = 0,

    pub fn encode(m: *const PeerSystemMeta, alloc: std.mem.Allocator) Error![]u8 {
        var env_buf: ?[]u8 = null;
        if (m.environment) |*e| env_buf = try e.encode(alloc);
        defer if (env_buf) |b| alloc.free(b);
        var flags_buf: ?[]u8 = null;
        if (m.flags) |*f| flags_buf = try f.encode(alloc);
        defer if (flags_buf) |b| alloc.free(b);
        var n: usize = 0;
        n += sizeStr(1, m.hostname);
        n += sizeStr(2, m.go_os);
        n += sizeStr(3, m.kernel);
        n += sizeStr(4, m.core);
        n += sizeStr(5, m.platform);
        n += sizeStr(6, m.os);
        n += sizeStr(7, m.netbird_version);
        n += sizeStr(8, m.ui_version);
        n += sizeStr(9, m.kernel_version);
        n += sizeStr(10, m.os_version);
        const addr_bufs = try alloc.alloc([]u8, m.network_addresses.len);
        defer {
            for (addr_bufs) |b| alloc.free(b);
            alloc.free(addr_bufs);
        }
        for (m.network_addresses, 0..) |*a, i| {
            addr_bufs[i] = try a.encode(alloc);
            n += sizeMsg(11, addr_bufs[i]);
        }
        n += sizeStr(12, m.sys_serial_number);
        n += sizeStr(13, m.sys_product_name);
        n += sizeStr(14, m.sys_manufacturer);
        n += sizeMsg(15, env_buf);
        const file_bufs = try alloc.alloc([]u8, m.files.len);
        defer {
            for (file_bufs) |b| alloc.free(b);
            alloc.free(file_bufs);
        }
        for (m.files, 0..) |*f, i| {
            file_bufs[i] = try f.encode(alloc);
            n += sizeMsg(16, file_bufs[i]);
        }
        n += sizeMsg(17, flags_buf);
        // Packed repeated enum, like Go.
        var caps_len: usize = 0;
        for (m.capabilities) |c| caps_len += wire.sizeVarint(@intFromEnum(c));
        if (caps_len > 0) n += wire.sizeTag(18) + wire.sizeBytes(caps_len);
        n += sizeVarint(19, @bitCast(@as(i64, m.sync_message_version)));
        const out = try alloc.alloc(u8, n);
        errdefer alloc.free(out);
        var enc = wire.Encoder.init(out);
        try putStr(&enc, 1, m.hostname);
        try putStr(&enc, 2, m.go_os);
        try putStr(&enc, 3, m.kernel);
        try putStr(&enc, 4, m.core);
        try putStr(&enc, 5, m.platform);
        try putStr(&enc, 6, m.os);
        try putStr(&enc, 7, m.netbird_version);
        try putStr(&enc, 8, m.ui_version);
        try putStr(&enc, 9, m.kernel_version);
        try putStr(&enc, 10, m.os_version);
        for (addr_bufs) |b| try putMsg(&enc, 11, b);
        try putStr(&enc, 12, m.sys_serial_number);
        try putStr(&enc, 13, m.sys_product_name);
        try putStr(&enc, 14, m.sys_manufacturer);
        try putMsg(&enc, 15, env_buf);
        for (file_bufs) |b| try putMsg(&enc, 16, b);
        try putMsg(&enc, 17, flags_buf);
        if (caps_len > 0) {
            try enc.appendTag(18, .bytes);
            var lb: [10]u8 = undefined;
            var le = wire.Encoder.init(&lb);
            try le.appendVarint(caps_len);
            try enc.appendRaw(le.bytes());
            for (m.capabilities) |c| try enc.appendVarint(@intFromEnum(c));
        }
        try putVarint(&enc, 19, @bitCast(@as(i64, m.sync_message_version)));
        finish(&enc, out);
        return out;
    }
};

// --- LoginRequest / SyncRequest ---

pub const LoginRequest = struct {
    setup_key: []const u8 = "",
    meta: ?PeerSystemMeta = null,
    jwt_token: []const u8 = "",
    peer_keys: ?PeerKeys = null,
    dns_labels: []const []const u8 = &.{},

    pub fn encode(m: *const LoginRequest, alloc: std.mem.Allocator) Error![]u8 {
        var meta_buf: ?[]u8 = null;
        if (m.meta) |*mt| meta_buf = try mt.encode(alloc);
        defer if (meta_buf) |b| alloc.free(b);
        var keys_buf: ?[]u8 = null;
        if (m.peer_keys) |*k| keys_buf = try k.encode(alloc);
        defer if (keys_buf) |b| alloc.free(b);
        var n: usize = 0;
        n += sizeStr(1, m.setup_key);
        n += sizeMsg(2, meta_buf);
        n += sizeStr(3, m.jwt_token);
        n += sizeMsg(4, keys_buf);
        for (m.dns_labels) |l| n += sizeStr(5, l);
        const out = try alloc.alloc(u8, n);
        errdefer alloc.free(out);
        var enc = wire.Encoder.init(out);
        try putStr(&enc, 1, m.setup_key);
        try putMsg(&enc, 2, meta_buf);
        try putStr(&enc, 3, m.jwt_token);
        try putMsg(&enc, 4, keys_buf);
        for (m.dns_labels) |l| try putStr(&enc, 5, l);
        finish(&enc, out);
        return out;
    }
};

pub const SyncRequest = struct {
    meta: ?PeerSystemMeta = null,

    pub fn encode(m: *const SyncRequest, alloc: std.mem.Allocator) Error![]u8 {
        var meta_buf: ?[]u8 = null;
        if (m.meta) |*mt| meta_buf = try mt.encode(alloc);
        defer if (meta_buf) |b| alloc.free(b);
        const n = sizeMsg(1, meta_buf);
        const out = try alloc.alloc(u8, n);
        errdefer alloc.free(out);
        var enc = wire.Encoder.init(out);
        try putMsg(&enc, 1, meta_buf);
        finish(&enc, out);
        return out;
    }
};

// --- ServerKeyResponse ---

pub const ServerKeyResponse = struct {
    key: []u8 = &.{},
    expires_at: ?Timestamp = null,
    version: i32 = 0,

    pub fn deinit(m: *ServerKeyResponse, alloc: std.mem.Allocator) void {
        alloc.free(m.key);
    }

    pub fn decode(alloc: std.mem.Allocator, buf: []const u8) Error!ServerKeyResponse {
        var m = ServerKeyResponse{};
        errdefer m.deinit(alloc);
        var d = wire.Decoder.init(buf);
        while (!d.done()) {
            const t = try d.consumeTag();
            switch (t.num) {
                1 => {
                    try expect(t.typ, .bytes);
                    alloc.free(m.key);
                    m.key = try getStr(alloc, &d);
                },
                2 => {
                    try expect(t.typ, .bytes);
                    m.expires_at = try Timestamp.decode(alloc, try d.consumeBytes());
                },
                3 => {
                    try expect(t.typ, .varint);
                    m.version = try getI32(&d);
                },
                else => try skip(&d, t.num, t.typ),
            }
        }
        return m;
    }
};

// --- NetbirdConfig tree (decode only) ---

pub const HostProtocol = enum(u32) {
    udp = 0,
    tcp = 1,
    http = 2,
    https = 3,
    dtls = 4,

    fn fromWire(v: u32) HostProtocol {
        return switch (v) {
            0 => .udp,
            1 => .tcp,
            2 => .http,
            3 => .https,
            4 => .dtls,
            else => .udp,
        };
    }
};

pub const HostConfig = struct {
    uri: []u8 = &.{},
    protocol: HostProtocol = .udp,

    pub fn deinit(m: *HostConfig, alloc: std.mem.Allocator) void {
        alloc.free(m.uri);
    }

    pub fn decode(alloc: std.mem.Allocator, buf: []const u8) Error!HostConfig {
        var m = HostConfig{};
        errdefer m.deinit(alloc);
        var d = wire.Decoder.init(buf);
        while (!d.done()) {
            const t = try d.consumeTag();
            switch (t.num) {
                1 => {
                    try expect(t.typ, .bytes);
                    alloc.free(m.uri);
                    m.uri = try getStr(alloc, &d);
                },
                2 => {
                    try expect(t.typ, .varint);
                    m.protocol = HostProtocol.fromWire(try getU32(&d));
                },
                else => try skip(&d, t.num, t.typ),
            }
        }
        return m;
    }
};

pub const ProtectedHostConfig = struct {
    host_config: ?HostConfig = null,
    user: []u8 = &.{},
    password: []u8 = &.{},

    pub fn deinit(m: *ProtectedHostConfig, alloc: std.mem.Allocator) void {
        if (m.host_config) |*h| h.deinit(alloc);
        alloc.free(m.user);
        alloc.free(m.password);
    }

    pub fn decode(alloc: std.mem.Allocator, buf: []const u8) Error!ProtectedHostConfig {
        var m = ProtectedHostConfig{};
        errdefer m.deinit(alloc);
        var d = wire.Decoder.init(buf);
        while (!d.done()) {
            const t = try d.consumeTag();
            switch (t.num) {
                1 => {
                    try expect(t.typ, .bytes);
                    if (m.host_config) |*h| h.deinit(alloc);
                    m.host_config = try HostConfig.decode(alloc, try d.consumeBytes());
                },
                2 => {
                    try expect(t.typ, .bytes);
                    alloc.free(m.user);
                    m.user = try getStr(alloc, &d);
                },
                3 => {
                    try expect(t.typ, .bytes);
                    alloc.free(m.password);
                    m.password = try getStr(alloc, &d);
                },
                else => try skip(&d, t.num, t.typ),
            }
        }
        return m;
    }
};

pub const RelayConfig = struct {
    urls: std.ArrayList([]u8) = .empty,
    token_payload: []u8 = &.{},
    token_signature: []u8 = &.{},

    pub fn deinit(m: *RelayConfig, alloc: std.mem.Allocator) void {
        for (m.urls.items) |u| alloc.free(u);
        m.urls.deinit(alloc);
        alloc.free(m.token_payload);
        alloc.free(m.token_signature);
    }

    pub fn decode(alloc: std.mem.Allocator, buf: []const u8) Error!RelayConfig {
        var m = RelayConfig{};
        errdefer m.deinit(alloc);
        var d = wire.Decoder.init(buf);
        while (!d.done()) {
            const t = try d.consumeTag();
            switch (t.num) {
                1 => {
                    try expect(t.typ, .bytes);
                    try m.urls.append(alloc, try getStr(alloc, &d));
                },
                2 => {
                    try expect(t.typ, .bytes);
                    alloc.free(m.token_payload);
                    m.token_payload = try getStr(alloc, &d);
                },
                3 => {
                    try expect(t.typ, .bytes);
                    alloc.free(m.token_signature);
                    m.token_signature = try getStr(alloc, &d);
                },
                else => try skip(&d, t.num, t.typ),
            }
        }
        return m;
    }
};

pub const FlowConfig = struct {
    url: []u8 = &.{},
    token_payload: []u8 = &.{},
    token_signature: []u8 = &.{},
    interval: ?Duration = null,
    enabled: bool = false,
    counters: bool = false,
    exit_node_collection: bool = false,
    dns_collection: bool = false,

    pub fn deinit(m: *FlowConfig, alloc: std.mem.Allocator) void {
        alloc.free(m.url);
        alloc.free(m.token_payload);
        alloc.free(m.token_signature);
    }

    pub fn decode(alloc: std.mem.Allocator, buf: []const u8) Error!FlowConfig {
        var m = FlowConfig{};
        errdefer m.deinit(alloc);
        var d = wire.Decoder.init(buf);
        while (!d.done()) {
            const t = try d.consumeTag();
            switch (t.num) {
                1 => {
                    try expect(t.typ, .bytes);
                    alloc.free(m.url);
                    m.url = try getStr(alloc, &d);
                },
                2 => {
                    try expect(t.typ, .bytes);
                    alloc.free(m.token_payload);
                    m.token_payload = try getStr(alloc, &d);
                },
                3 => {
                    try expect(t.typ, .bytes);
                    alloc.free(m.token_signature);
                    m.token_signature = try getStr(alloc, &d);
                },
                4 => {
                    try expect(t.typ, .bytes);
                    m.interval = try Duration.decode(alloc, try d.consumeBytes());
                },
                5 => {
                    try expect(t.typ, .varint);
                    m.enabled = (try d.consumeVarint()) != 0;
                },
                6 => {
                    try expect(t.typ, .varint);
                    m.counters = (try d.consumeVarint()) != 0;
                },
                7 => {
                    try expect(t.typ, .varint);
                    m.exit_node_collection = (try d.consumeVarint()) != 0;
                },
                8 => {
                    try expect(t.typ, .varint);
                    m.dns_collection = (try d.consumeVarint()) != 0;
                },
                else => try skip(&d, t.num, t.typ),
            }
        }
        return m;
    }
};

pub const MetricsConfig = struct {
    enabled: bool = false,

    pub fn decode(alloc: std.mem.Allocator, buf: []const u8) Error!MetricsConfig {
        _ = alloc;
        var m = MetricsConfig{};
        var d = wire.Decoder.init(buf);
        while (!d.done()) {
            const t = try d.consumeTag();
            switch (t.num) {
                1 => {
                    try expect(t.typ, .varint);
                    m.enabled = (try d.consumeVarint()) != 0;
                },
                else => try skip(&d, t.num, t.typ),
            }
        }
        return m;
    }
};

pub const NetbirdConfig = struct {
    stuns: std.ArrayList(HostConfig) = .empty,
    turns: std.ArrayList(ProtectedHostConfig) = .empty,
    signal: ?HostConfig = null,
    relay: ?RelayConfig = null,
    flow: ?FlowConfig = null,
    metrics: ?MetricsConfig = null,

    pub fn deinit(m: *NetbirdConfig, alloc: std.mem.Allocator) void {
        for (m.stuns.items) |*s| s.deinit(alloc);
        m.stuns.deinit(alloc);
        for (m.turns.items) |*t| t.deinit(alloc);
        m.turns.deinit(alloc);
        if (m.signal) |*s| s.deinit(alloc);
        if (m.relay) |*r| r.deinit(alloc);
        if (m.flow) |*f| f.deinit(alloc);
    }

    pub fn decode(alloc: std.mem.Allocator, buf: []const u8) Error!NetbirdConfig {
        var m = NetbirdConfig{};
        errdefer m.deinit(alloc);
        var d = wire.Decoder.init(buf);
        while (!d.done()) {
            const t = try d.consumeTag();
            switch (t.num) {
                1 => {
                    try expect(t.typ, .bytes);
                    try m.stuns.append(alloc, try HostConfig.decode(alloc, try d.consumeBytes()));
                },
                2 => {
                    try expect(t.typ, .bytes);
                    try m.turns.append(alloc, try ProtectedHostConfig.decode(alloc, try d.consumeBytes()));
                },
                3 => {
                    try expect(t.typ, .bytes);
                    if (m.signal) |*s| s.deinit(alloc);
                    m.signal = try HostConfig.decode(alloc, try d.consumeBytes());
                },
                4 => {
                    try expect(t.typ, .bytes);
                    if (m.relay) |*r| r.deinit(alloc);
                    m.relay = try RelayConfig.decode(alloc, try d.consumeBytes());
                },
                5 => {
                    try expect(t.typ, .bytes);
                    if (m.flow) |*f| f.deinit(alloc);
                    m.flow = try FlowConfig.decode(alloc, try d.consumeBytes());
                },
                6 => {
                    try expect(t.typ, .bytes);
                    m.metrics = try MetricsConfig.decode(alloc, try d.consumeBytes());
                },
                else => try skip(&d, t.num, t.typ),
            }
        }
        return m;
    }
};

// --- PeerConfig tree (decode only) ---

pub const JWTConfig = struct {
    issuer: []u8 = &.{},
    audience: []u8 = &.{},
    keys_location: []u8 = &.{},
    max_token_age: i64 = 0,
    audiences: std.ArrayList([]u8) = .empty,

    pub fn deinit(m: *JWTConfig, alloc: std.mem.Allocator) void {
        alloc.free(m.issuer);
        alloc.free(m.audience);
        alloc.free(m.keys_location);
        for (m.audiences.items) |a| alloc.free(a);
        m.audiences.deinit(alloc);
    }

    pub fn decode(alloc: std.mem.Allocator, buf: []const u8) Error!JWTConfig {
        var m = JWTConfig{};
        errdefer m.deinit(alloc);
        var d = wire.Decoder.init(buf);
        while (!d.done()) {
            const t = try d.consumeTag();
            switch (t.num) {
                1 => {
                    try expect(t.typ, .bytes);
                    alloc.free(m.issuer);
                    m.issuer = try getStr(alloc, &d);
                },
                2 => {
                    try expect(t.typ, .bytes);
                    alloc.free(m.audience);
                    m.audience = try getStr(alloc, &d);
                },
                3 => {
                    try expect(t.typ, .bytes);
                    alloc.free(m.keys_location);
                    m.keys_location = try getStr(alloc, &d);
                },
                4 => {
                    try expect(t.typ, .varint);
                    m.max_token_age = try getI64(&d);
                },
                5 => {
                    try expect(t.typ, .bytes);
                    try m.audiences.append(alloc, try getStr(alloc, &d));
                },
                else => try skip(&d, t.num, t.typ),
            }
        }
        return m;
    }
};

pub const SSHConfig = struct {
    ssh_enabled: bool = false,
    ssh_pub_key: []u8 = &.{},
    jwt_config: ?JWTConfig = null,

    pub fn deinit(m: *SSHConfig, alloc: std.mem.Allocator) void {
        alloc.free(m.ssh_pub_key);
        if (m.jwt_config) |*j| j.deinit(alloc);
    }

    pub fn decode(alloc: std.mem.Allocator, buf: []const u8) Error!SSHConfig {
        var m = SSHConfig{};
        errdefer m.deinit(alloc);
        var d = wire.Decoder.init(buf);
        while (!d.done()) {
            const t = try d.consumeTag();
            switch (t.num) {
                1 => {
                    try expect(t.typ, .varint);
                    m.ssh_enabled = (try d.consumeVarint()) != 0;
                },
                2 => {
                    try expect(t.typ, .bytes);
                    alloc.free(m.ssh_pub_key);
                    m.ssh_pub_key = try getStr(alloc, &d);
                },
                3 => {
                    try expect(t.typ, .bytes);
                    if (m.jwt_config) |*j| j.deinit(alloc);
                    m.jwt_config = try JWTConfig.decode(alloc, try d.consumeBytes());
                },
                else => try skip(&d, t.num, t.typ),
            }
        }
        return m;
    }
};

pub const AutoUpdateSettings = struct {
    version: []u8 = &.{},
    always_update: bool = false,

    pub fn deinit(m: *AutoUpdateSettings, alloc: std.mem.Allocator) void {
        alloc.free(m.version);
    }

    pub fn decode(alloc: std.mem.Allocator, buf: []const u8) Error!AutoUpdateSettings {
        var m = AutoUpdateSettings{};
        errdefer m.deinit(alloc);
        var d = wire.Decoder.init(buf);
        while (!d.done()) {
            const t = try d.consumeTag();
            switch (t.num) {
                1 => {
                    try expect(t.typ, .bytes);
                    alloc.free(m.version);
                    m.version = try getStr(alloc, &d);
                },
                2 => {
                    try expect(t.typ, .varint);
                    m.always_update = (try d.consumeVarint()) != 0;
                },
                else => try skip(&d, t.num, t.typ),
            }
        }
        return m;
    }
};

pub const PeerConfig = struct {
    address: []u8 = &.{},
    dns: []u8 = &.{},
    ssh_config: ?SSHConfig = null,
    fqdn: []u8 = &.{},
    routing_peer_dns_resolution_enabled: bool = false,
    lazy_connection_enabled: bool = false,
    mtu: i32 = 0,
    auto_update: ?AutoUpdateSettings = null,
    address_v6: []u8 = &.{},

    pub fn deinit(m: *PeerConfig, alloc: std.mem.Allocator) void {
        alloc.free(m.address);
        alloc.free(m.dns);
        if (m.ssh_config) |*s| s.deinit(alloc);
        alloc.free(m.fqdn);
        if (m.auto_update) |*a| a.deinit(alloc);
        alloc.free(m.address_v6);
    }

    pub fn decode(alloc: std.mem.Allocator, buf: []const u8) Error!PeerConfig {
        var m = PeerConfig{};
        errdefer m.deinit(alloc);
        var d = wire.Decoder.init(buf);
        while (!d.done()) {
            const t = try d.consumeTag();
            switch (t.num) {
                1 => {
                    try expect(t.typ, .bytes);
                    alloc.free(m.address);
                    m.address = try getStr(alloc, &d);
                },
                2 => {
                    try expect(t.typ, .bytes);
                    alloc.free(m.dns);
                    m.dns = try getStr(alloc, &d);
                },
                3 => {
                    try expect(t.typ, .bytes);
                    if (m.ssh_config) |*s| s.deinit(alloc);
                    m.ssh_config = try SSHConfig.decode(alloc, try d.consumeBytes());
                },
                4 => {
                    try expect(t.typ, .bytes);
                    alloc.free(m.fqdn);
                    m.fqdn = try getStr(alloc, &d);
                },
                5 => {
                    try expect(t.typ, .varint);
                    m.routing_peer_dns_resolution_enabled = (try d.consumeVarint()) != 0;
                },
                6 => {
                    try expect(t.typ, .varint);
                    m.lazy_connection_enabled = (try d.consumeVarint()) != 0;
                },
                7 => {
                    try expect(t.typ, .varint);
                    m.mtu = try getI32(&d);
                },
                8 => {
                    try expect(t.typ, .bytes);
                    if (m.auto_update) |*a| a.deinit(alloc);
                    m.auto_update = try AutoUpdateSettings.decode(alloc, try d.consumeBytes());
                },
                9 => {
                    try expect(t.typ, .bytes);
                    alloc.free(m.address_v6);
                    m.address_v6 = try getStr(alloc, &d);
                },
                else => try skip(&d, t.num, t.typ),
            }
        }
        return m;
    }
};

pub const Checks = struct {
    files: std.ArrayList([]u8) = .empty,

    pub fn deinit(m: *Checks, alloc: std.mem.Allocator) void {
        for (m.files.items) |f| alloc.free(f);
        m.files.deinit(alloc);
    }

    pub fn decode(alloc: std.mem.Allocator, buf: []const u8) Error!Checks {
        var m = Checks{};
        errdefer m.deinit(alloc);
        var d = wire.Decoder.init(buf);
        while (!d.done()) {
            const t = try d.consumeTag();
            switch (t.num) {
                1 => {
                    try expect(t.typ, .bytes);
                    try m.files.append(alloc, try getStr(alloc, &d));
                },
                else => try skip(&d, t.num, t.typ),
            }
        }
        return m;
    }
};

// --- LoginResponse ---

pub const LoginResponse = struct {
    netbird_config: ?NetbirdConfig = null,
    peer_config: ?PeerConfig = null,
    checks: std.ArrayList(Checks) = .empty,
    session_expires_at: ?Timestamp = null,

    pub fn deinit(m: *LoginResponse, alloc: std.mem.Allocator) void {
        if (m.netbird_config) |*c| c.deinit(alloc);
        if (m.peer_config) |*p| p.deinit(alloc);
        for (m.checks.items) |*c| c.deinit(alloc);
        m.checks.deinit(alloc);
    }

    pub fn decode(alloc: std.mem.Allocator, buf: []const u8) Error!LoginResponse {
        var m = LoginResponse{};
        errdefer m.deinit(alloc);
        var d = wire.Decoder.init(buf);
        while (!d.done()) {
            const t = try d.consumeTag();
            switch (t.num) {
                1 => {
                    try expect(t.typ, .bytes);
                    if (m.netbird_config) |*c| c.deinit(alloc);
                    m.netbird_config = try NetbirdConfig.decode(alloc, try d.consumeBytes());
                },
                2 => {
                    try expect(t.typ, .bytes);
                    if (m.peer_config) |*p| p.deinit(alloc);
                    m.peer_config = try PeerConfig.decode(alloc, try d.consumeBytes());
                },
                3 => {
                    try expect(t.typ, .bytes);
                    try m.checks.append(alloc, try Checks.decode(alloc, try d.consumeBytes()));
                },
                4 => {
                    try expect(t.typ, .bytes);
                    m.session_expires_at = try Timestamp.decode(alloc, try d.consumeBytes());
                },
                else => try skip(&d, t.num, t.typ),
            }
        }
        return m;
    }
};

// --- NetworkMap tree (decode only) ---

pub const LazyState = enum(u32) {
    default = 0,
    lazy = 1,
    eager = 2,

    fn fromWire(v: u32) LazyState {
        return switch (v) {
            0 => .default,
            1 => .lazy,
            2 => .eager,
            else => .default,
        };
    }
};

pub const RemotePeerConfig = struct {
    wg_pub_key: []u8 = &.{},
    allowed_ips: std.ArrayList([]u8) = .empty,
    ssh_config: ?SSHConfig = null,
    fqdn: []u8 = &.{},
    agent_version: []u8 = &.{},
    lazy_state: LazyState = .default,

    pub fn deinit(m: *RemotePeerConfig, alloc: std.mem.Allocator) void {
        alloc.free(m.wg_pub_key);
        for (m.allowed_ips.items) |a| alloc.free(a);
        m.allowed_ips.deinit(alloc);
        if (m.ssh_config) |*s| s.deinit(alloc);
        alloc.free(m.fqdn);
        alloc.free(m.agent_version);
    }

    pub fn decode(alloc: std.mem.Allocator, buf: []const u8) Error!RemotePeerConfig {
        var m = RemotePeerConfig{};
        errdefer m.deinit(alloc);
        var d = wire.Decoder.init(buf);
        while (!d.done()) {
            const t = try d.consumeTag();
            switch (t.num) {
                1 => {
                    try expect(t.typ, .bytes);
                    alloc.free(m.wg_pub_key);
                    m.wg_pub_key = try getStr(alloc, &d);
                },
                2 => {
                    try expect(t.typ, .bytes);
                    try m.allowed_ips.append(alloc, try getStr(alloc, &d));
                },
                3 => {
                    try expect(t.typ, .bytes);
                    if (m.ssh_config) |*s| s.deinit(alloc);
                    m.ssh_config = try SSHConfig.decode(alloc, try d.consumeBytes());
                },
                4 => {
                    try expect(t.typ, .bytes);
                    alloc.free(m.fqdn);
                    m.fqdn = try getStr(alloc, &d);
                },
                5 => {
                    try expect(t.typ, .bytes);
                    alloc.free(m.agent_version);
                    m.agent_version = try getStr(alloc, &d);
                },
                6 => {
                    try expect(t.typ, .varint);
                    m.lazy_state = LazyState.fromWire(try getU32(&d));
                },
                else => try skip(&d, t.num, t.typ),
            }
        }
        return m;
    }
};

pub const Route = struct {
    id: []u8 = &.{},
    network: []u8 = &.{},
    network_type: i64 = 0,
    peer: []u8 = &.{},
    metric: i64 = 0,
    masquerade: bool = false,
    net_id: []u8 = &.{},
    domains: std.ArrayList([]u8) = .empty,
    keep_route: bool = false,
    skip_auto_apply: bool = false,

    pub fn deinit(m: *Route, alloc: std.mem.Allocator) void {
        alloc.free(m.id);
        alloc.free(m.network);
        alloc.free(m.peer);
        alloc.free(m.net_id);
        for (m.domains.items) |x| alloc.free(x);
        m.domains.deinit(alloc);
    }

    pub fn decode(alloc: std.mem.Allocator, buf: []const u8) Error!Route {
        var m = Route{};
        errdefer m.deinit(alloc);
        var d = wire.Decoder.init(buf);
        while (!d.done()) {
            const t = try d.consumeTag();
            switch (t.num) {
                1 => {
                    try expect(t.typ, .bytes);
                    alloc.free(m.id);
                    m.id = try getStr(alloc, &d);
                },
                2 => {
                    try expect(t.typ, .bytes);
                    alloc.free(m.network);
                    m.network = try getStr(alloc, &d);
                },
                3 => {
                    try expect(t.typ, .varint);
                    m.network_type = try getI64(&d);
                },
                4 => {
                    try expect(t.typ, .bytes);
                    alloc.free(m.peer);
                    m.peer = try getStr(alloc, &d);
                },
                5 => {
                    try expect(t.typ, .varint);
                    m.metric = try getI64(&d);
                },
                6 => {
                    try expect(t.typ, .varint);
                    m.masquerade = (try d.consumeVarint()) != 0;
                },
                7 => {
                    try expect(t.typ, .bytes);
                    alloc.free(m.net_id);
                    m.net_id = try getStr(alloc, &d);
                },
                8 => {
                    try expect(t.typ, .bytes);
                    try m.domains.append(alloc, try getStr(alloc, &d));
                },
                9 => {
                    try expect(t.typ, .varint);
                    m.keep_route = (try d.consumeVarint()) != 0;
                },
                10 => {
                    try expect(t.typ, .varint);
                    m.skip_auto_apply = (try d.consumeVarint()) != 0;
                },
                else => try skip(&d, t.num, t.typ),
            }
        }
        return m;
    }
};

pub const SimpleRecord = struct {
    name: []u8 = &.{},
    rec_type: i64 = 0,
    class: []u8 = &.{},
    ttl: i64 = 0,
    rdata: []u8 = &.{},

    pub fn deinit(m: *SimpleRecord, alloc: std.mem.Allocator) void {
        alloc.free(m.name);
        alloc.free(m.class);
        alloc.free(m.rdata);
    }

    pub fn decode(alloc: std.mem.Allocator, buf: []const u8) Error!SimpleRecord {
        var m = SimpleRecord{};
        errdefer m.deinit(alloc);
        var d = wire.Decoder.init(buf);
        while (!d.done()) {
            const t = try d.consumeTag();
            switch (t.num) {
                1 => {
                    try expect(t.typ, .bytes);
                    alloc.free(m.name);
                    m.name = try getStr(alloc, &d);
                },
                2 => {
                    try expect(t.typ, .varint);
                    m.rec_type = try getI64(&d);
                },
                3 => {
                    try expect(t.typ, .bytes);
                    alloc.free(m.class);
                    m.class = try getStr(alloc, &d);
                },
                4 => {
                    try expect(t.typ, .varint);
                    m.ttl = try getI64(&d);
                },
                5 => {
                    try expect(t.typ, .bytes);
                    alloc.free(m.rdata);
                    m.rdata = try getStr(alloc, &d);
                },
                else => try skip(&d, t.num, t.typ),
            }
        }
        return m;
    }
};

pub const CustomZone = struct {
    domain: []u8 = &.{},
    records: std.ArrayList(SimpleRecord) = .empty,
    search_domain_disabled: bool = false,
    non_authoritative: bool = false,

    pub fn deinit(m: *CustomZone, alloc: std.mem.Allocator) void {
        alloc.free(m.domain);
        for (m.records.items) |*r| r.deinit(alloc);
        m.records.deinit(alloc);
    }

    pub fn decode(alloc: std.mem.Allocator, buf: []const u8) Error!CustomZone {
        var m = CustomZone{};
        errdefer m.deinit(alloc);
        var d = wire.Decoder.init(buf);
        while (!d.done()) {
            const t = try d.consumeTag();
            switch (t.num) {
                1 => {
                    try expect(t.typ, .bytes);
                    alloc.free(m.domain);
                    m.domain = try getStr(alloc, &d);
                },
                2 => {
                    try expect(t.typ, .bytes);
                    try m.records.append(alloc, try SimpleRecord.decode(alloc, try d.consumeBytes()));
                },
                3 => {
                    try expect(t.typ, .varint);
                    m.search_domain_disabled = (try d.consumeVarint()) != 0;
                },
                4 => {
                    try expect(t.typ, .varint);
                    m.non_authoritative = (try d.consumeVarint()) != 0;
                },
                else => try skip(&d, t.num, t.typ),
            }
        }
        return m;
    }
};

pub const NameServer = struct {
    ip: []u8 = &.{},
    ns_type: i64 = 0,
    port: i64 = 0,

    pub fn deinit(m: *NameServer, alloc: std.mem.Allocator) void {
        alloc.free(m.ip);
    }

    pub fn decode(alloc: std.mem.Allocator, buf: []const u8) Error!NameServer {
        var m = NameServer{};
        errdefer m.deinit(alloc);
        var d = wire.Decoder.init(buf);
        while (!d.done()) {
            const t = try d.consumeTag();
            switch (t.num) {
                1 => {
                    try expect(t.typ, .bytes);
                    alloc.free(m.ip);
                    m.ip = try getStr(alloc, &d);
                },
                2 => {
                    try expect(t.typ, .varint);
                    m.ns_type = try getI64(&d);
                },
                3 => {
                    try expect(t.typ, .varint);
                    m.port = try getI64(&d);
                },
                else => try skip(&d, t.num, t.typ),
            }
        }
        return m;
    }
};

pub const NameServerGroup = struct {
    name_servers: std.ArrayList(NameServer) = .empty,
    primary: bool = false,
    domains: std.ArrayList([]u8) = .empty,
    search_domains_enabled: bool = false,

    pub fn deinit(m: *NameServerGroup, alloc: std.mem.Allocator) void {
        for (m.name_servers.items) |*n| n.deinit(alloc);
        m.name_servers.deinit(alloc);
        for (m.domains.items) |x| alloc.free(x);
        m.domains.deinit(alloc);
    }

    pub fn decode(alloc: std.mem.Allocator, buf: []const u8) Error!NameServerGroup {
        var m = NameServerGroup{};
        errdefer m.deinit(alloc);
        var d = wire.Decoder.init(buf);
        while (!d.done()) {
            const t = try d.consumeTag();
            switch (t.num) {
                1 => {
                    try expect(t.typ, .bytes);
                    try m.name_servers.append(alloc, try NameServer.decode(alloc, try d.consumeBytes()));
                },
                2 => {
                    try expect(t.typ, .varint);
                    m.primary = (try d.consumeVarint()) != 0;
                },
                3 => {
                    try expect(t.typ, .bytes);
                    try m.domains.append(alloc, try getStr(alloc, &d));
                },
                4 => {
                    try expect(t.typ, .varint);
                    m.search_domains_enabled = (try d.consumeVarint()) != 0;
                },
                else => try skip(&d, t.num, t.typ),
            }
        }
        return m;
    }
};

pub const DNSConfig = struct {
    service_enable: bool = false,
    name_server_groups: std.ArrayList(NameServerGroup) = .empty,
    custom_zones: std.ArrayList(CustomZone) = .empty,
    forwarder_port: i64 = 0,

    pub fn deinit(m: *DNSConfig, alloc: std.mem.Allocator) void {
        for (m.name_server_groups.items) |*g| g.deinit(alloc);
        m.name_server_groups.deinit(alloc);
        for (m.custom_zones.items) |*z| z.deinit(alloc);
        m.custom_zones.deinit(alloc);
    }

    pub fn decode(alloc: std.mem.Allocator, buf: []const u8) Error!DNSConfig {
        var m = DNSConfig{};
        errdefer m.deinit(alloc);
        var d = wire.Decoder.init(buf);
        while (!d.done()) {
            const t = try d.consumeTag();
            switch (t.num) {
                1 => {
                    try expect(t.typ, .varint);
                    m.service_enable = (try d.consumeVarint()) != 0;
                },
                2 => {
                    try expect(t.typ, .bytes);
                    try m.name_server_groups.append(alloc, try NameServerGroup.decode(alloc, try d.consumeBytes()));
                },
                3 => {
                    try expect(t.typ, .bytes);
                    try m.custom_zones.append(alloc, try CustomZone.decode(alloc, try d.consumeBytes()));
                },
                4 => {
                    try expect(t.typ, .varint);
                    m.forwarder_port = try getI64(&d);
                },
                else => try skip(&d, t.num, t.typ),
            }
        }
        return m;
    }
};

pub const RuleProtocol = enum(u32) {
    unknown = 0,
    all = 1,
    tcp = 2,
    udp = 3,
    icmp = 4,
    custom = 5,
    netbird_ssh = 6,

    fn fromWire(v: u32) RuleProtocol {
        return switch (v) {
            0 => .unknown,
            1 => .all,
            2 => .tcp,
            3 => .udp,
            4 => .icmp,
            5 => .custom,
            6 => .netbird_ssh,
            else => .unknown,
        };
    }
};

pub const RuleDirection = enum(u32) {
    in = 0,
    out = 1,

    fn fromWire(v: u32) RuleDirection {
        return if (v == 1) .out else .in;
    }
};

pub const RuleAction = enum(u32) {
    accept = 0,
    drop = 1,

    fn fromWire(v: u32) RuleAction {
        return if (v == 1) .drop else .accept;
    }
};

pub const PortRange = struct {
    start: u32 = 0,
    end: u32 = 0,

    pub fn decode(alloc: std.mem.Allocator, buf: []const u8) Error!PortRange {
        _ = alloc;
        var m = PortRange{};
        var d = wire.Decoder.init(buf);
        while (!d.done()) {
            const t = try d.consumeTag();
            switch (t.num) {
                1 => {
                    try expect(t.typ, .varint);
                    m.start = try getU32(&d);
                },
                2 => {
                    try expect(t.typ, .varint);
                    m.end = try getU32(&d);
                },
                else => try skip(&d, t.num, t.typ),
            }
        }
        return m;
    }
};

pub const PortInfo = struct {
    port: ?u32 = null,
    range: ?PortRange = null,

    pub fn decode(alloc: std.mem.Allocator, buf: []const u8) Error!PortInfo {
        var m = PortInfo{};
        var d = wire.Decoder.init(buf);
        while (!d.done()) {
            const t = try d.consumeTag();
            switch (t.num) {
                1 => {
                    try expect(t.typ, .varint);
                    m.port = try getU32(&d);
                    m.range = null;
                },
                2 => {
                    try expect(t.typ, .bytes);
                    m.range = try PortRange.decode(alloc, try d.consumeBytes());
                    m.port = null;
                },
                else => try skip(&d, t.num, t.typ),
            }
        }
        return m;
    }
};

pub const FirewallRule = struct {
    direction: RuleDirection = .in,
    action: RuleAction = .accept,
    protocol: RuleProtocol = .unknown,
    port: []u8 = &.{},
    port_info: ?PortInfo = null,
    policy_id: []u8 = &.{},
    custom_protocol: u32 = 0,
    source_prefixes: std.ArrayList([]u8) = .empty,

    pub fn deinit(m: *FirewallRule, alloc: std.mem.Allocator) void {
        alloc.free(m.port);
        alloc.free(m.policy_id);
        for (m.source_prefixes.items) |p| alloc.free(p);
        m.source_prefixes.deinit(alloc);
    }

    pub fn decode(alloc: std.mem.Allocator, buf: []const u8) Error!FirewallRule {
        var m = FirewallRule{};
        errdefer m.deinit(alloc);
        var d = wire.Decoder.init(buf);
        while (!d.done()) {
            const t = try d.consumeTag();
            switch (t.num) {
                // 1 (PeerIP) is deprecated; skipped.
                2 => {
                    try expect(t.typ, .varint);
                    m.direction = RuleDirection.fromWire(try getU32(&d));
                },
                3 => {
                    try expect(t.typ, .varint);
                    m.action = RuleAction.fromWire(try getU32(&d));
                },
                4 => {
                    try expect(t.typ, .varint);
                    m.protocol = RuleProtocol.fromWire(try getU32(&d));
                },
                5 => {
                    try expect(t.typ, .bytes);
                    alloc.free(m.port);
                    m.port = try getStr(alloc, &d);
                },
                6 => {
                    try expect(t.typ, .bytes);
                    m.port_info = try PortInfo.decode(alloc, try d.consumeBytes());
                },
                7 => {
                    try expect(t.typ, .bytes);
                    alloc.free(m.policy_id);
                    m.policy_id = try getStr(alloc, &d);
                },
                8 => {
                    try expect(t.typ, .varint);
                    m.custom_protocol = try getU32(&d);
                },
                9 => {
                    try expect(t.typ, .bytes);
                    try m.source_prefixes.append(alloc, try getStr(alloc, &d));
                },
                else => try skip(&d, t.num, t.typ),
            }
        }
        return m;
    }
};

pub const RouteFirewallRule = struct {
    source_ranges: std.ArrayList([]u8) = .empty,
    action: RuleAction = .accept,
    destination: []u8 = &.{},
    protocol: RuleProtocol = .unknown,
    port_info: ?PortInfo = null,
    is_dynamic: bool = false,
    domains: std.ArrayList([]u8) = .empty,
    custom_protocol: u32 = 0,
    policy_id: []u8 = &.{},
    route_id: []u8 = &.{},

    pub fn deinit(m: *RouteFirewallRule, alloc: std.mem.Allocator) void {
        for (m.source_ranges.items) |s| alloc.free(s);
        m.source_ranges.deinit(alloc);
        alloc.free(m.destination);
        for (m.domains.items) |x| alloc.free(x);
        m.domains.deinit(alloc);
        alloc.free(m.policy_id);
        alloc.free(m.route_id);
    }

    pub fn decode(alloc: std.mem.Allocator, buf: []const u8) Error!RouteFirewallRule {
        var m = RouteFirewallRule{};
        errdefer m.deinit(alloc);
        var d = wire.Decoder.init(buf);
        while (!d.done()) {
            const t = try d.consumeTag();
            switch (t.num) {
                1 => {
                    try expect(t.typ, .bytes);
                    try m.source_ranges.append(alloc, try getStr(alloc, &d));
                },
                2 => {
                    try expect(t.typ, .varint);
                    m.action = RuleAction.fromWire(try getU32(&d));
                },
                3 => {
                    try expect(t.typ, .bytes);
                    alloc.free(m.destination);
                    m.destination = try getStr(alloc, &d);
                },
                4 => {
                    try expect(t.typ, .varint);
                    m.protocol = RuleProtocol.fromWire(try getU32(&d));
                },
                5 => {
                    try expect(t.typ, .bytes);
                    m.port_info = try PortInfo.decode(alloc, try d.consumeBytes());
                },
                6 => {
                    try expect(t.typ, .varint);
                    m.is_dynamic = (try d.consumeVarint()) != 0;
                },
                7 => {
                    try expect(t.typ, .bytes);
                    try m.domains.append(alloc, try getStr(alloc, &d));
                },
                8 => {
                    try expect(t.typ, .varint);
                    m.custom_protocol = try getU32(&d);
                },
                9 => {
                    try expect(t.typ, .bytes);
                    alloc.free(m.policy_id);
                    m.policy_id = try getStr(alloc, &d);
                },
                10 => {
                    try expect(t.typ, .bytes);
                    alloc.free(m.route_id);
                    m.route_id = try getStr(alloc, &d);
                },
                else => try skip(&d, t.num, t.typ),
            }
        }
        return m;
    }
};

pub const ForwardingRule = struct {
    protocol: RuleProtocol = .unknown,
    destination_port: ?PortInfo = null,
    translated_address: []u8 = &.{},
    translated_port: ?PortInfo = null,

    pub fn deinit(m: *ForwardingRule, alloc: std.mem.Allocator) void {
        alloc.free(m.translated_address);
    }

    pub fn decode(alloc: std.mem.Allocator, buf: []const u8) Error!ForwardingRule {
        var m = ForwardingRule{};
        errdefer m.deinit(alloc);
        var d = wire.Decoder.init(buf);
        while (!d.done()) {
            const t = try d.consumeTag();
            switch (t.num) {
                1 => {
                    try expect(t.typ, .varint);
                    m.protocol = RuleProtocol.fromWire(try getU32(&d));
                },
                2 => {
                    try expect(t.typ, .bytes);
                    m.destination_port = try PortInfo.decode(alloc, try d.consumeBytes());
                },
                3 => {
                    try expect(t.typ, .bytes);
                    alloc.free(m.translated_address);
                    m.translated_address = try getStr(alloc, &d);
                },
                4 => {
                    try expect(t.typ, .bytes);
                    m.translated_port = try PortInfo.decode(alloc, try d.consumeBytes());
                },
                else => try skip(&d, t.num, t.typ),
            }
        }
        return m;
    }
};

pub const MachineUserIndexes = struct {
    indexes: std.ArrayList(u32) = .empty,

    pub fn deinit(m: *MachineUserIndexes, alloc: std.mem.Allocator) void {
        m.indexes.deinit(alloc);
    }

    pub fn decode(alloc: std.mem.Allocator, buf: []const u8) Error!MachineUserIndexes {
        var m = MachineUserIndexes{};
        errdefer m.deinit(alloc);
        var d = wire.Decoder.init(buf);
        while (!d.done()) {
            const t = try d.consumeTag();
            switch (t.num) {
                1 => {
                    // Packed or unpacked repeated uint32.
                    if (t.typ == .bytes) {
                        var pd = wire.Decoder.init(try d.consumeBytes());
                        while (!pd.done()) {
                            try m.indexes.append(alloc, @truncate(try pd.consumeVarint()));
                        }
                    } else {
                        try expect(t.typ, .varint);
                        try m.indexes.append(alloc, try getU32(&d));
                    }
                },
                else => try skip(&d, t.num, t.typ),
            }
        }
        return m;
    }
};

pub const MachineUserEntry = struct {
    key: []u8,
    value: MachineUserIndexes,

    pub fn deinit(m: *MachineUserEntry, alloc: std.mem.Allocator) void {
        alloc.free(m.key);
        m.value.deinit(alloc);
    }
};

pub const SSHAuth = struct {
    user_id_claim: []u8 = &.{},
    authorized_users: std.ArrayList([]u8) = .empty,
    machine_users: std.ArrayList(MachineUserEntry) = .empty,

    pub fn deinit(m: *SSHAuth, alloc: std.mem.Allocator) void {
        alloc.free(m.user_id_claim);
        for (m.authorized_users.items) |u| alloc.free(u);
        m.authorized_users.deinit(alloc);
        for (m.machine_users.items) |*e| e.deinit(alloc);
        m.machine_users.deinit(alloc);
    }

    pub fn decode(alloc: std.mem.Allocator, buf: []const u8) Error!SSHAuth {
        var m = SSHAuth{};
        errdefer m.deinit(alloc);
        var d = wire.Decoder.init(buf);
        while (!d.done()) {
            const t = try d.consumeTag();
            switch (t.num) {
                1 => {
                    try expect(t.typ, .bytes);
                    alloc.free(m.user_id_claim);
                    m.user_id_claim = try getStr(alloc, &d);
                },
                2 => {
                    try expect(t.typ, .bytes);
                    try m.authorized_users.append(alloc, try getStr(alloc, &d));
                },
                3 => {
                    try expect(t.typ, .bytes);
                    var ed = wire.Decoder.init(try d.consumeBytes());
                    var entry = MachineUserEntry{
                        .key = try alloc.alloc(u8, 0),
                        .value = .{},
                    };
                    errdefer entry.deinit(alloc);
                    while (!ed.done()) {
                        const et = try ed.consumeTag();
                        switch (et.num) {
                            1 => {
                                try expect(et.typ, .bytes);
                                alloc.free(entry.key);
                                entry.key = try getStr(alloc, &ed);
                            },
                            2 => {
                                try expect(et.typ, .bytes);
                                entry.value.deinit(alloc);
                                entry.value = try MachineUserIndexes.decode(alloc, try ed.consumeBytes());
                            },
                            else => try skip(&ed, et.num, et.typ),
                        }
                    }
                    try m.machine_users.append(alloc, entry);
                },
                else => try skip(&d, t.num, t.typ),
            }
        }
        return m;
    }
};

pub const NetworkMap = struct {
    serial: u64 = 0,
    peer_config: ?PeerConfig = null,
    remote_peers: std.ArrayList(RemotePeerConfig) = .empty,
    remote_peers_is_empty: bool = false,
    routes: std.ArrayList(Route) = .empty,
    dns_config: ?DNSConfig = null,
    offline_peers: std.ArrayList(RemotePeerConfig) = .empty,
    firewall_rules: std.ArrayList(FirewallRule) = .empty,
    firewall_rules_is_empty: bool = false,
    routes_firewall_rules: std.ArrayList(RouteFirewallRule) = .empty,
    routes_firewall_rules_is_empty: bool = false,
    forwarding_rules: std.ArrayList(ForwardingRule) = .empty,
    ssh_auth: ?SSHAuth = null,

    pub fn deinit(m: *NetworkMap, alloc: std.mem.Allocator) void {
        if (m.peer_config) |*p| p.deinit(alloc);
        for (m.remote_peers.items) |*p| p.deinit(alloc);
        m.remote_peers.deinit(alloc);
        for (m.routes.items) |*r| r.deinit(alloc);
        m.routes.deinit(alloc);
        if (m.dns_config) |*d| d.deinit(alloc);
        for (m.offline_peers.items) |*p| p.deinit(alloc);
        m.offline_peers.deinit(alloc);
        for (m.firewall_rules.items) |*r| r.deinit(alloc);
        m.firewall_rules.deinit(alloc);
        for (m.routes_firewall_rules.items) |*r| r.deinit(alloc);
        m.routes_firewall_rules.deinit(alloc);
        for (m.forwarding_rules.items) |*r| r.deinit(alloc);
        m.forwarding_rules.deinit(alloc);
        if (m.ssh_auth) |*s| s.deinit(alloc);
    }

    pub fn decode(alloc: std.mem.Allocator, buf: []const u8) Error!NetworkMap {
        var m = NetworkMap{};
        errdefer m.deinit(alloc);
        var d = wire.Decoder.init(buf);
        while (!d.done()) {
            const t = try d.consumeTag();
            switch (t.num) {
                1 => {
                    try expect(t.typ, .varint);
                    m.serial = try d.consumeVarint();
                },
                2 => {
                    try expect(t.typ, .bytes);
                    if (m.peer_config) |*p| p.deinit(alloc);
                    m.peer_config = try PeerConfig.decode(alloc, try d.consumeBytes());
                },
                3 => {
                    try expect(t.typ, .bytes);
                    try m.remote_peers.append(alloc, try RemotePeerConfig.decode(alloc, try d.consumeBytes()));
                },
                4 => {
                    try expect(t.typ, .varint);
                    m.remote_peers_is_empty = (try d.consumeVarint()) != 0;
                },
                5 => {
                    try expect(t.typ, .bytes);
                    try m.routes.append(alloc, try Route.decode(alloc, try d.consumeBytes()));
                },
                6 => {
                    try expect(t.typ, .bytes);
                    if (m.dns_config) |*x| x.deinit(alloc);
                    m.dns_config = try DNSConfig.decode(alloc, try d.consumeBytes());
                },
                7 => {
                    try expect(t.typ, .bytes);
                    try m.offline_peers.append(alloc, try RemotePeerConfig.decode(alloc, try d.consumeBytes()));
                },
                8 => {
                    try expect(t.typ, .bytes);
                    try m.firewall_rules.append(alloc, try FirewallRule.decode(alloc, try d.consumeBytes()));
                },
                9 => {
                    try expect(t.typ, .varint);
                    m.firewall_rules_is_empty = (try d.consumeVarint()) != 0;
                },
                10 => {
                    try expect(t.typ, .bytes);
                    try m.routes_firewall_rules.append(alloc, try RouteFirewallRule.decode(alloc, try d.consumeBytes()));
                },
                11 => {
                    try expect(t.typ, .varint);
                    m.routes_firewall_rules_is_empty = (try d.consumeVarint()) != 0;
                },
                12 => {
                    try expect(t.typ, .bytes);
                    try m.forwarding_rules.append(alloc, try ForwardingRule.decode(alloc, try d.consumeBytes()));
                },
                13 => {
                    try expect(t.typ, .bytes);
                    if (m.ssh_auth) |*s| s.deinit(alloc);
                    m.ssh_auth = try SSHAuth.decode(alloc, try d.consumeBytes());
                },
                else => try skip(&d, t.num, t.typ),
            }
        }
        return m;
    }
};

// --- SyncResponse ---

pub const SyncResponse = struct {
    netbird_config: ?NetbirdConfig = null,
    network_map: ?NetworkMap = null,
    checks: std.ArrayList(Checks) = .empty,
    session_expires_at: ?Timestamp = null,
    version: i32 = 0,

    pub fn deinit(m: *SyncResponse, alloc: std.mem.Allocator) void {
        if (m.netbird_config) |*c| c.deinit(alloc);
        if (m.network_map) |*n| n.deinit(alloc);
        for (m.checks.items) |*c| c.deinit(alloc);
        m.checks.deinit(alloc);
    }

    pub fn decode(alloc: std.mem.Allocator, buf: []const u8) Error!SyncResponse {
        var m = SyncResponse{};
        errdefer m.deinit(alloc);
        var d = wire.Decoder.init(buf);
        while (!d.done()) {
            const t = try d.consumeTag();
            switch (t.num) {
                1 => {
                    try expect(t.typ, .bytes);
                    if (m.netbird_config) |*c| c.deinit(alloc);
                    m.netbird_config = try NetbirdConfig.decode(alloc, try d.consumeBytes());
                },
                // 2-4 (peerConfig, remotePeers, remotePeersIsEmpty) are
                // deprecated; 8 (envelope) is never advertised. Skipped.
                5 => {
                    try expect(t.typ, .bytes);
                    if (m.network_map) |*n| n.deinit(alloc);
                    m.network_map = try NetworkMap.decode(alloc, try d.consumeBytes());
                },
                6 => {
                    try expect(t.typ, .bytes);
                    try m.checks.append(alloc, try Checks.decode(alloc, try d.consumeBytes()));
                },
                7 => {
                    try expect(t.typ, .bytes);
                    m.session_expires_at = try Timestamp.decode(alloc, try d.consumeBytes());
                },
                9 => {
                    try expect(t.typ, .varint);
                    m.version = try getI32(&d);
                },
                else => try skip(&d, t.num, t.typ),
            }
        }
        return m;
    }
};
