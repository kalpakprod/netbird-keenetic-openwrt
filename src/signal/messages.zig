// Port of netbird shared/signal/proto/signalexchange.proto messages (v0.79.0), BSD-3-Clause.
// Hand codecs over src/proto/wire.zig. EncryptedMessage and Body travel both
// directions (client sends and receives them); Message is the local decrypted
// view and never hits the wire. proto3-optional fields keep presence: they
// encode when set even if zero-valued.

const std = @import("std");
const wire = @import("../proto/wire.zig");

pub const Error = wire.Error || error{ OutOfMemory, WireTypeMismatch };

fn expect(typ: wire.Type, want: wire.Type) Error!void {
    if (typ != want) return Error.WireTypeMismatch;
}

fn sizeStr(num: wire.Number, s: []const u8) usize {
    if (s.len == 0) return 0;
    return wire.sizeTag(num) + wire.sizeBytes(s.len);
}

fn sizeVarint(num: wire.Number, v: u64) usize {
    if (v == 0) return 0;
    return wire.sizeTag(num) + wire.sizeVarint(v);
}

fn sizeMsg(num: wire.Number, child: ?[]const u8) usize {
    const c = child orelse return 0;
    return wire.sizeTag(num) + wire.sizeBytes(c.len);
}

fn sizeOptStr(num: wire.Number, v: ?[]const u8) usize {
    const s = v orelse return 0;
    return wire.sizeTag(num) + wire.sizeBytes(s.len);
}

fn sizeOptBool(num: wire.Number, v: ?bool) usize {
    return if (v != null) wire.sizeTag(num) + 1 else 0;
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

fn putMsg(enc: *wire.Encoder, num: wire.Number, child: ?[]const u8) Error!void {
    const c = child orelse return;
    try enc.appendTag(num, .bytes);
    try enc.appendBytes(c);
}

fn putOptStr(enc: *wire.Encoder, num: wire.Number, v: ?[]const u8) Error!void {
    const s = v orelse return;
    try enc.appendTag(num, .bytes);
    try enc.appendBytes(s);
}

fn putOptBool(enc: *wire.Encoder, num: wire.Number, v: ?bool) Error!void {
    const b = v orelse return;
    try enc.appendTag(num, .varint);
    try enc.appendVarint(@intFromBool(b));
}

fn getStr(alloc: std.mem.Allocator, d: *wire.Decoder) Error![]u8 {
    return try alloc.dupe(u8, try d.consumeBytes());
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

fn putPackedU32(enc: *wire.Encoder, num: wire.Number, vs: []const u32) Error!void {
    if (vs.len == 0) return;
    var n: usize = 0;
    for (vs) |v| n += wire.sizeVarint(v);
    try enc.appendTag(num, .bytes);
    var lb: [10]u8 = undefined;
    var le = wire.Encoder.init(&lb);
    try le.appendVarint(n);
    try enc.appendRaw(le.bytes());
    for (vs) |v| try enc.appendVarint(v);
}

fn sizePackedU32(num: wire.Number, vs: []const u32) usize {
    if (vs.len == 0) return 0;
    var n: usize = 0;
    for (vs) |v| n += wire.sizeVarint(v);
    return wire.sizeTag(num) + wire.sizeBytes(n);
}

// --- EncryptedMessage ---

pub const EncryptedMessage = struct {
    key: []const u8 = "",
    remote_key: []const u8 = "",
    body: []const u8 = "",
    owned: bool = false,

    pub fn deinit(m: *EncryptedMessage, alloc: std.mem.Allocator) void {
        if (!m.owned) return;
        alloc.free(m.key);
        alloc.free(m.remote_key);
        alloc.free(m.body);
        m.owned = false;
    }

    pub fn encode(m: *const EncryptedMessage, alloc: std.mem.Allocator) Error![]u8 {
        const n = sizeStr(2, m.key) + sizeStr(3, m.remote_key) + sizeStr(4, m.body);
        const out = try alloc.alloc(u8, n);
        errdefer alloc.free(out);
        var enc = wire.Encoder.init(out);
        try putStr(&enc, 2, m.key);
        try putStr(&enc, 3, m.remote_key);
        try putStr(&enc, 4, m.body);
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
                2 => {
                    try expect(t.typ, .bytes);
                    alloc.free(m.key);
                    m.key = try getStr(alloc, &d);
                },
                3 => {
                    try expect(t.typ, .bytes);
                    alloc.free(m.remote_key);
                    m.remote_key = try getStr(alloc, &d);
                },
                4 => {
                    try expect(t.typ, .bytes);
                    alloc.free(m.body);
                    m.body = try getStr(alloc, &d);
                },
                else => try skip(&d, t.num, t.typ),
            }
        }
        return m;
    }
};

// --- Body ---

pub const BodyType = enum(u32) {
    offer = 0,
    answer = 1,
    candidate = 2,
    mode = 4,
    go_idle = 5,
    heartbeat = 6,

    pub fn fromWire(v: u32) BodyType {
        return switch (v) {
            0 => .offer,
            1 => .answer,
            2 => .candidate,
            4 => .mode,
            5 => .go_idle,
            6 => .heartbeat,
            else => .offer,
        };
    }
};

pub const Mode = struct {
    direct: ?bool = null,

    pub fn encode(m: *const Mode, alloc: std.mem.Allocator) Error![]u8 {
        const n = sizeOptBool(1, m.direct);
        const out = try alloc.alloc(u8, n);
        errdefer alloc.free(out);
        var enc = wire.Encoder.init(out);
        try putOptBool(&enc, 1, m.direct);
        finish(&enc, out);
        return out;
    }

    pub fn decode(alloc: std.mem.Allocator, buf: []const u8) Error!Mode {
        _ = alloc;
        var m = Mode{};
        var d = wire.Decoder.init(buf);
        while (!d.done()) {
            const t = try d.consumeTag();
            switch (t.num) {
                1 => {
                    try expect(t.typ, .varint);
                    m.direct = (try d.consumeVarint()) != 0;
                },
                else => try skip(&d, t.num, t.typ),
            }
        }
        return m;
    }
};

pub const RosenpassConfig = struct {
    rosenpass_pub_key: []const u8 = &.{},
    rosenpass_server_addr: []const u8 = &.{},
    owned: bool = false,

    pub fn deinit(m: *RosenpassConfig, alloc: std.mem.Allocator) void {
        if (!m.owned) return;
        alloc.free(m.rosenpass_pub_key);
        alloc.free(m.rosenpass_server_addr);
        m.owned = false;
    }

    pub fn encode(m: *const RosenpassConfig, alloc: std.mem.Allocator) Error![]u8 {
        const n = sizeStr(1, m.rosenpass_pub_key) + sizeStr(2, m.rosenpass_server_addr);
        const out = try alloc.alloc(u8, n);
        errdefer alloc.free(out);
        var enc = wire.Encoder.init(out);
        try putStr(&enc, 1, m.rosenpass_pub_key);
        try putStr(&enc, 2, m.rosenpass_server_addr);
        finish(&enc, out);
        return out;
    }

    pub fn decode(alloc: std.mem.Allocator, buf: []const u8) Error!RosenpassConfig {
        var m = RosenpassConfig{ .owned = true };
        errdefer m.deinit(alloc);
        var d = wire.Decoder.init(buf);
        while (!d.done()) {
            const t = try d.consumeTag();
            switch (t.num) {
                1 => {
                    try expect(t.typ, .bytes);
                    alloc.free(m.rosenpass_pub_key);
                    m.rosenpass_pub_key = try getStr(alloc, &d);
                },
                2 => {
                    try expect(t.typ, .bytes);
                    alloc.free(m.rosenpass_server_addr);
                    m.rosenpass_server_addr = try getStr(alloc, &d);
                },
                else => try skip(&d, t.num, t.typ),
            }
        }
        return m;
    }
};

pub const Body = struct {
    msg_type: BodyType = .offer,
    payload: []const u8 = "",
    wg_listen_port: u32 = 0,
    netbird_version: []const u8 = "",
    mode: ?Mode = null,
    features_supported: []const u32 = &.{},
    rosenpass_config: ?RosenpassConfig = null,
    relay_server_address: ?[]const u8 = null,
    session_id: ?[]const u8 = null,
    relay_server_ip: ?[]const u8 = null,
    owned: bool = false,

    pub fn deinit(m: *Body, alloc: std.mem.Allocator) void {
        if (!m.owned) return;
        alloc.free(m.payload);
        alloc.free(m.netbird_version);
        alloc.free(m.features_supported);
        if (m.rosenpass_config) |*r| r.deinit(alloc);
        if (m.relay_server_address) |s| alloc.free(s);
        if (m.session_id) |s| alloc.free(s);
        if (m.relay_server_ip) |s| alloc.free(s);
        m.owned = false;
    }

    pub fn encode(m: *const Body, alloc: std.mem.Allocator) Error![]u8 {
        var mode_buf: ?[]u8 = null;
        if (m.mode) |*md| mode_buf = try md.encode(alloc);
        defer if (mode_buf) |b| alloc.free(b);
        var rp_buf: ?[]u8 = null;
        if (m.rosenpass_config) |*rp| rp_buf = try rp.encode(alloc);
        defer if (rp_buf) |b| alloc.free(b);
        const n = sizeVarint(1, @intFromEnum(m.msg_type)) +
            sizeStr(2, m.payload) +
            sizeVarint(3, m.wg_listen_port) +
            sizeStr(4, m.netbird_version) +
            sizeMsg(5, mode_buf) +
            sizePackedU32(6, m.features_supported) +
            sizeMsg(7, rp_buf) +
            sizeOptStr(8, m.relay_server_address) +
            sizeOptStr(10, m.session_id) +
            sizeOptStr(11, m.relay_server_ip);
        const out = try alloc.alloc(u8, n);
        errdefer alloc.free(out);
        var enc = wire.Encoder.init(out);
        try putVarint(&enc, 1, @intFromEnum(m.msg_type));
        try putStr(&enc, 2, m.payload);
        try putVarint(&enc, 3, m.wg_listen_port);
        try putStr(&enc, 4, m.netbird_version);
        try putMsg(&enc, 5, mode_buf);
        try putPackedU32(&enc, 6, m.features_supported);
        try putMsg(&enc, 7, rp_buf);
        try putOptStr(&enc, 8, m.relay_server_address);
        try putOptStr(&enc, 10, m.session_id);
        try putOptStr(&enc, 11, m.relay_server_ip);
        finish(&enc, out);
        return out;
    }

    pub fn decode(alloc: std.mem.Allocator, buf: []const u8) Error!Body {
        var m = Body{ .owned = true };
        errdefer m.deinit(alloc);
        var feats = std.ArrayList(u32).empty;
        errdefer feats.deinit(alloc);
        var d = wire.Decoder.init(buf);
        while (!d.done()) {
            const t = try d.consumeTag();
            switch (t.num) {
                1 => {
                    try expect(t.typ, .varint);
                    m.msg_type = BodyType.fromWire(try getU32(&d));
                },
                2 => {
                    try expect(t.typ, .bytes);
                    alloc.free(m.payload);
                    m.payload = try getStr(alloc, &d);
                },
                3 => {
                    try expect(t.typ, .varint);
                    m.wg_listen_port = try getU32(&d);
                },
                4 => {
                    try expect(t.typ, .bytes);
                    alloc.free(m.netbird_version);
                    m.netbird_version = try getStr(alloc, &d);
                },
                5 => {
                    try expect(t.typ, .bytes);
                    m.mode = try Mode.decode(alloc, try d.consumeBytes());
                },
                6 => {
                    if (t.typ == .bytes) {
                        var pd = wire.Decoder.init(try d.consumeBytes());
                        while (!pd.done()) {
                            try feats.append(alloc, @truncate(try pd.consumeVarint()));
                        }
                    } else {
                        try expect(t.typ, .varint);
                        try feats.append(alloc, try getU32(&d));
                    }
                },
                7 => {
                    try expect(t.typ, .bytes);
                    if (m.rosenpass_config) |*r| r.deinit(alloc);
                    m.rosenpass_config = try RosenpassConfig.decode(alloc, try d.consumeBytes());
                },
                8 => {
                    try expect(t.typ, .bytes);
                    if (m.relay_server_address) |s| alloc.free(s);
                    m.relay_server_address = try getStr(alloc, &d);
                },
                10 => {
                    try expect(t.typ, .bytes);
                    if (m.session_id) |s| alloc.free(s);
                    m.session_id = try getStr(alloc, &d);
                },
                11 => {
                    try expect(t.typ, .bytes);
                    if (m.relay_server_ip) |s| alloc.free(s);
                    m.relay_server_ip = try getStr(alloc, &d);
                },
                else => try skip(&d, t.num, t.typ),
            }
        }
        m.features_supported = try feats.toOwnedSlice(alloc);
        return m;
    }
};

// --- Message: local decrypted view, never on the wire ---

pub const Message = struct {
    key: []const u8 = "",
    remote_key: []const u8 = "",
    body: Body = .{},
    owned: bool = false,

    pub fn deinit(m: *Message, alloc: std.mem.Allocator) void {
        if (!m.owned) return;
        alloc.free(m.key);
        alloc.free(m.remote_key);
        m.body.deinit(alloc);
        m.owned = false;
    }
};
