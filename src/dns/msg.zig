// DNS wire codec: RFC 1035 header/question/RR with compression pointers,
// A/AAAA/CNAME/TXT/SRV/PTR, EDNS0 OPT (RFC 6891) and RFC 3597 opaque rdata
// for every other type. Semantics follow the vendored miekg/dns
// (upstream/netbird/vendor/github.com/miekg/dns, BSD-3-Clause), the library
// NetBird's client/internal/dns stack uses on the wire: same presentation
// escaping, same compression-map rules (per-label inserts at offsets
// < 0x4000, CNAME/PTR targets compressed, SRV targets never compressed).
//
// unpack allocates presentation names/strings on the passed allocator —
// pass an arena and free the whole message at once. Names are FQDNs with a
// trailing dot. pack writes into a caller buffer (NoSpaceLeft when it does
// not fit); like miekg it never mutates the message, the OPT extended-rcode
// bits are computed from Message.header.rcode at pack time.

const std = @import("std");

pub const header_len = 12;
pub const max_compression_offset = 0x4000;
pub const max_name_wire_octets = 255;
pub const max_compression_pointers = (max_name_wire_octets + 1) / 2 - 2; // 126
pub const max_label_len = 63;

pub const Error = error{
    Truncated,
    LongName,
    BadPointer,
    BadRdata,
    BadRcode,
    ExtendedRcodeWithoutOpt,
    NotFqdn,
    NoSpaceLeft,
    OutOfMemory,
};

pub const Type = enum(u16) {
    a = 1,
    ns = 2,
    cname = 5,
    ptr = 12,
    txt = 16,
    aaaa = 28,
    srv = 33,
    opt = 41,
    _,
};

pub const class_inet: u16 = 1;

pub const Header = struct {
    id: u16 = 0,
    response: bool = false,
    opcode: u4 = 0,
    authoritative: bool = false,
    truncated: bool = false,
    recursion_desired: bool = false,
    recursion_available: bool = false,
    zero: bool = false,
    authenticated_data: bool = false,
    checking_disabled: bool = false,
    rcode: u16 = 0, // 0..0xFFF; >15 is an extended rcode and needs an OPT

    /// miekg Msg.SetReply: echo id/opcode/RD/CD and mark the response bit.
    pub fn setReply(h: *Header, req: *const Header) void {
        h.id = req.id;
        h.response = true;
        h.opcode = req.opcode;
        h.recursion_desired = req.recursion_desired;
        h.checking_disabled = req.checking_disabled;
    }
};

pub const Question = struct {
    name: []const u8, // FQDN with trailing dot
    type: Type,
    class: u16,
};

pub const Srv = struct {
    priority: u16,
    weight: u16,
    port: u16,
    target: []const u8, // FQDN
};

pub const Option = struct {
    code: u16,
    data: []const u8, // raw option data
};

pub const RData = union(enum) {
    a: [4]u8,
    aaaa: [16]u8,
    cname: []const u8, // FQDN
    ptr: []const u8, // FQDN
    srv: Srv,
    txt: []const []const u8, // character-strings, presentation-escaped
    opt: []const Option,
    unknown: []const u8, // RFC 3597: opaque rdata, copied verbatim
};

pub const RR = struct {
    name: []const u8, // FQDN
    type: Type,
    class: u16,
    ttl: u32,
    data: RData,
};

pub const Message = struct {
    header: Header = .{},
    question: []const Question = &.{},
    answer: []const RR = &.{},
    ns: []const RR = &.{},
    extra: []const RR = &.{},

    pub fn setReply(m: *Message, req: *const Message) void {
        m.header.setReply(&req.header);
        m.question = req.question;
    }

    /// miekg Msg.SetRcode: SetReply plus the response code.
    pub fn setRcode(m: *Message, req: *const Message, rcode: u16) void {
        m.setReply(req);
        m.header.rcode = rcode;
    }

    /// The OPT pseudo-RR in extra, if any (miekg Msg.IsEdns0).
    pub fn isEdns0(m: *const Message) ?*const RR {
        for (m.extra) |*rr| {
            if (rr.type == .opt) return rr;
        }
        return null;
    }
};

/// Build an EDNS0 OPT RR for extra (miekg Msg.SetEdns0 with no options).
pub fn makeOpt(udp_size: u16, do_bit: bool) RR {
    var ttl: u32 = 0;
    if (do_bit) ttl |= 0x8000;
    return .{ .name = ".", .type = .opt, .class = udp_size, .ttl = ttl, .data = .{ .opt = &.{} } };
}

/// EDNS0 extended-rcode view: header rcode plus the OPT upper TTL bits
/// (miekg keeps the extended rcode in the OPT record, not in the header).
pub fn extendedRcode(m: *const Message) u16 {
    var rcode: u16 = m.header.rcode & 0xF;
    if (m.isEdns0()) |opt| {
        rcode |= @as(u16, @intCast(opt.ttl >> 24)) << 4;
    }
    return rcode;
}

pub const opt_code_ede: u16 = 15;

// ---------------------------------------------------------------------------
// unpack

/// Parse a wire message. All names/strings are allocated on `alloc`
/// (pass an arena); unknown rdata is copied. Trailing bytes after the
/// message are ignored, like miekg.
pub fn unpack(alloc: std.mem.Allocator, msg: []const u8) Error!Message {
    if (msg.len < header_len) return Error.Truncated;
    var m = Message{};
    m.header = unpackHeader(msg[0..header_len]);
    // miekg accepts header-only responses even with nonzero section counts.
    if (msg.len == header_len) return m;
    const qd = std.mem.readInt(u16, msg[4..6], .big);
    const an = std.mem.readInt(u16, msg[6..8], .big);
    const ns = std.mem.readInt(u16, msg[8..10], .big);
    const ar = std.mem.readInt(u16, msg[10..12], .big);
    var off: usize = header_len;

    var qs: std.ArrayListUnmanaged(Question) = .empty;
    errdefer qs.deinit(alloc);
    var i: usize = 0;
    while (i < qd) : (i += 1) {
        const name = try unpackName(alloc, msg, &off);
        const fixed = try readFixed(msg, off, 4);
        off += 4;
        try qs.append(alloc, .{
            .name = name,
            .type = @enumFromInt(std.mem.readInt(u16, fixed[0..2], .big)),
            .class = std.mem.readInt(u16, fixed[2..4], .big),
        });
    }
    m.question = try qs.toOwnedSlice(alloc);

    m.answer = try unpackRRslice(alloc, msg, &off, an);
    m.ns = try unpackRRslice(alloc, msg, &off, ns);
    m.extra = try unpackRRslice(alloc, msg, &off, ar);
    if (m.isEdns0()) |opt| m.header.rcode |= @as(u16, @intCast(opt.ttl >> 24)) << 4;
    return m;
}

fn unpackHeader(h: *const [header_len]u8) Header {
    const bits = std.mem.readInt(u16, h[2..4], .big);
    return .{
        .id = std.mem.readInt(u16, h[0..2], .big),
        .response = bits & (1 << 15) != 0,
        .opcode = @truncate(bits >> 11),
        .authoritative = bits & (1 << 10) != 0,
        .truncated = bits & (1 << 9) != 0,
        .recursion_desired = bits & (1 << 8) != 0,
        .recursion_available = bits & (1 << 7) != 0,
        .zero = bits & (1 << 6) != 0,
        .authenticated_data = bits & (1 << 5) != 0,
        .checking_disabled = bits & (1 << 4) != 0,
        .rcode = bits & 0xF,
    };
}

fn readFixed(msg: []const u8, off: usize, n: usize) Error![]const u8 {
    if (off + n > msg.len) return Error.Truncated;
    return msg[off .. off + n];
}

fn unpackRRslice(alloc: std.mem.Allocator, msg: []const u8, off: *usize, count: u16) Error![]const RR {
    var out: std.ArrayListUnmanaged(RR) = .empty;
    errdefer out.deinit(alloc);
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const rr = try unpackRR(alloc, msg, off);
        try out.append(alloc, rr);
    }
    return out.toOwnedSlice(alloc);
}

fn unpackRR(alloc: std.mem.Allocator, msg: []const u8, off: *usize) Error!RR {
    const name = try unpackName(alloc, msg, off);
    const fixed = try readFixed(msg, off.*, 10);
    off.* += 10;
    const rtype: Type = @enumFromInt(std.mem.readInt(u16, fixed[0..2], .big));
    const class = std.mem.readInt(u16, fixed[2..4], .big);
    const ttl = std.mem.readInt(u32, fixed[4..8], .big);
    const rdlen = std.mem.readInt(u16, fixed[8..10], .big);
    const end = off.* + rdlen;
    if (end > msg.len) return Error.Truncated;

    var rr = RR{ .name = name, .type = rtype, .class = class, .ttl = ttl, .data = .{ .unknown = "" } };
    const start = off.*;

    switch (rtype) {
        .a => {
            const ip = try readFixed(msg, start, 4);
            rr.data = .{ .a = ip[0..4].* };
            off.* = start + 4;
        },
        .aaaa => {
            const ip = try readFixed(msg, start, 16);
            rr.data = .{ .aaaa = ip[0..16].* };
            off.* = start + 16;
        },
        .cname => {
            const target = try unpackName(alloc, msg, off);
            rr.data = .{ .cname = target };
        },
        .ptr => {
            const target = try unpackName(alloc, msg, off);
            rr.data = .{ .ptr = target };
        },
        .srv => {
            const f = try readFixed(msg, start, 6);
            off.* = start + 6;
            const target = try unpackName(alloc, msg, off);
            rr.data = .{ .srv = .{
                .priority = std.mem.readInt(u16, f[0..2], .big),
                .weight = std.mem.readInt(u16, f[2..4], .big),
                .port = std.mem.readInt(u16, f[4..6], .big),
                .target = target,
            } };
        },
        .txt => {
            var strings: std.ArrayListUnmanaged([]const u8) = .empty;
            errdefer strings.deinit(alloc);
            var p = start;
            while (p < end) {
                const l: usize = msg[p];
                if (p + 1 + l > end) return Error.BadRdata;
                try strings.append(alloc, try unpackCharString(alloc, msg[p + 1 .. p + 1 + l]));
                p += 1 + l;
            }
            rr.data = .{ .txt = try strings.toOwnedSlice(alloc) };
            off.* = end;
        },
        .opt => {
            var opts: std.ArrayListUnmanaged(Option) = .empty;
            errdefer opts.deinit(alloc);
            var p = start;
            while (p < end) {
                if (p + 4 > end) return Error.BadRdata;
                const code = std.mem.readInt(u16, msg[p..][0..2], .big);
                const l = std.mem.readInt(u16, msg[p + 2 ..][0..2], .big);
                if (p + 4 + l > end) return Error.BadRdata;
                try opts.append(alloc, .{ .code = code, .data = try alloc.dupe(u8, msg[p + 4 .. p + 4 + l]) });
                p += 4 + l;
            }
            rr.data = .{ .opt = try opts.toOwnedSlice(alloc) };
            off.* = end;
        },
        else => {
            rr.data = .{ .unknown = try alloc.dupe(u8, msg[start..end]) };
            off.* = end;
        },
    }

    // miekg UnpackRRWithHeader: rdata must consume exactly rdlength.
    if (off.* != end) return Error.BadRdata;
    return rr;
}

/// Unpack a domain name into its presentation form (miekg UnpackDomainName):
/// labels joined with dots, special bytes backslash-escaped, unprintables
/// \DDD. On success `off` points past the name on the wire (past the first
/// compression pointer when one was followed).
pub fn unpackName(alloc: std.mem.Allocator, msg: []const u8, off: *usize) Error![]const u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(alloc);
    var budget: i32 = max_name_wire_octets;
    var ptrs: usize = 0;
    var end_off: usize = 0;
    var p = off.*;
    while (true) {
        if (p >= msg.len) return Error.Truncated;
        const c = msg[p];
        p += 1;
        if (c & 0xC0 == 0xC0) {
            if (p >= msg.len) return Error.Truncated;
            const low = msg[p];
            p += 1;
            if (end_off == 0) end_off = p;
            ptrs += 1;
            if (ptrs > max_compression_pointers) return Error.BadPointer;
            p = (@as(usize, c & 0x3F) << 8) | low;
        } else if (c & 0xC0 != 0) {
            return Error.BadRdata; // 0x40/0x80 reserved label kinds
        } else if (c == 0) {
            break;
        } else {
            if (p + c > msg.len) return Error.Truncated;
            budget -= @as(i32, c) + 1;
            if (budget <= 0) return Error.LongName;
            try appendEscapedLabel(alloc, &out, msg[p .. p + c]);
            p += c;
        }
    }
    if (end_off == 0) end_off = p;
    off.* = end_off;
    if (out.items.len == 0) return ".";
    return out.toOwnedSlice(alloc);
}

/// Append one label's bytes in miekg presentation form plus the trailing
/// dot: specials get a backslash, unprintables a zero-padded \DDD.
fn appendEscapedLabel(alloc: std.mem.Allocator, out: *std.ArrayListUnmanaged(u8), raw: []const u8) Error!void {
    for (raw) |b| {
        switch (b) {
            '.', ' ', '\'', '@', ';', '(', ')', '"', '\\' => {
                try out.append(alloc, '\\');
                try out.append(alloc, b);
            },
            else => {
                if (b < ' ' or b > '~') {
                    var buf: [4]u8 = undefined;
                    _ = std.fmt.bufPrint(&buf, "\\{d:0>3}", .{b}) catch unreachable;
                    try out.appendSlice(alloc, &buf);
                } else {
                    try out.append(alloc, b);
                }
            },
        }
    }
    try out.append(alloc, '.');
}

fn unpackCharString(alloc: std.mem.Allocator, raw: []const u8) Error![]const u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(alloc);
    for (raw) |b| {
        switch (b) {
            '"', '\\' => {
                try out.append(alloc, '\\');
                try out.append(alloc, b);
            },
            else => {
                if (b < ' ' or b > '~') {
                    var buf: [4]u8 = undefined;
                    _ = std.fmt.bufPrint(&buf, "\\{d:0>3}", .{b}) catch unreachable;
                    try out.appendSlice(alloc, &buf);
                } else {
                    try out.append(alloc, b);
                }
            },
        }
    }
    return out.toOwnedSlice(alloc);
}

// ---------------------------------------------------------------------------
// pack

/// Message packer with a compression map (miekg Msg.Pack with Compress
/// semantics driven by the `compress` flag: a false flag never emits
/// pointers but still records names for later use, exactly like miekg).
pub const Packer = struct {
    buf: []u8,
    end: usize = 0,
    compress: bool = true,
    map: std.StringHashMapUnmanaged(u15) = .empty,
    alloc: std.mem.Allocator,

    pub fn init(alloc: std.mem.Allocator, buf: []u8) Packer {
        return .{ .buf = buf, .alloc = alloc };
    }

    pub fn deinit(p: *Packer) void {
        p.map.deinit(p.alloc);
    }

    /// Pack `msg`; returns the written prefix of the buffer.
    pub fn pack(p: *Packer, msg: *const Message) Error![]const u8 {
        if (msg.header.rcode > 0xFFF) return Error.BadRcode;
        const has_opt = msg.isEdns0() != null;
        if (msg.header.rcode > 0xF and !has_opt) return Error.ExtendedRcodeWithoutOpt;

        p.end = 0;
        var bits: u16 = @as(u16, msg.header.opcode) << 11 | (msg.header.rcode & 0xF);
        if (msg.header.response) bits |= 1 << 15;
        if (msg.header.authoritative) bits |= 1 << 10;
        if (msg.header.truncated) bits |= 1 << 9;
        if (msg.header.recursion_desired) bits |= 1 << 8;
        if (msg.header.recursion_available) bits |= 1 << 7;
        if (msg.header.zero) bits |= 1 << 6;
        if (msg.header.authenticated_data) bits |= 1 << 5;
        if (msg.header.checking_disabled) bits |= 1 << 4;

        try p.uint16(msg.header.id);
        try p.uint16(bits);
        try p.uint16(@truncate(msg.question.len));
        try p.uint16(@truncate(msg.answer.len));
        try p.uint16(@truncate(msg.ns.len));
        try p.uint16(@truncate(msg.extra.len));

        for (msg.question) |q| {
            try p.packName(q.name, p.compress);
            try p.uint16(@intFromEnum(q.type));
            try p.uint16(q.class);
        }
        for (msg.answer) |rr| try p.packRR(msg, rr);
        for (msg.ns) |rr| try p.packRR(msg, rr);
        for (msg.extra) |rr| try p.packRR(msg, rr);
        return p.buf[0..p.end];
    }

    fn packRR(p: *Packer, msg: *const Message, rr: RR) Error!void {
        // OPT: the extended-rcode upper bits live in the TTL (miekg
        // SetExtendedRcode runs unconditionally at pack time).
        const header_ttl: u32 = if (rr.type == .opt)
            (rr.ttl & 0x00FFFFFF) | (@as(u32, msg.header.rcode >> 4) << 24)
        else
            rr.ttl;
        try p.packName(rr.name, p.compress);
        try p.uint16(@intFromEnum(rr.type));
        try p.uint16(rr.class);
        try p.uint32(header_ttl);
        const rdlen_off = p.end;
        try p.uint16(0); // rdlength placeholder
        const rdata_start = p.end;
        try p.packRData(rr);
        const rdlen = p.end - rdata_start;
        if (rdlen > 0xFFFF) return Error.BadRdata;
        std.mem.writeInt(u16, p.buf[rdlen_off..][0..2], @intCast(rdlen), .big);
    }

    fn packRData(p: *Packer, rr: RR) Error!void {
        switch (rr.data) {
            .a => |ip| try p.raw(&ip),
            .aaaa => |ip| try p.raw(&ip),
            .cname => |target| try p.packName(target, p.compress),
            .ptr => |target| try p.packName(target, p.compress),
            .srv => |srv| {
                try p.uint16(srv.priority);
                try p.uint16(srv.weight);
                try p.uint16(srv.port);
                // miekg packs the SRV target with compression disabled
                // (the name is still recorded for later use).
                try p.packName(srv.target, false);
            },
            .txt => |strings| {
                if (strings.len == 0) try p.uint8(0);
                for (strings) |s| try p.charString(s);
            },
            .opt => |opts| {
                for (opts) |o| {
                    try p.uint16(o.code);
                    try p.uint16(@intCast(o.data.len));
                    try p.raw(o.data);
                }
            },
            .unknown => |raw_data| try p.raw(raw_data),
        }
    }

    /// miekg packDomainName: FQDN required, per-label compression map
    /// inserts at offsets < 0x4000, pointer on first found suffix when
    /// `compress` is on. Label limits are measured after escape decoding.
    fn packName(p: *Packer, name: []const u8, compress: bool) Error!void {
        if (name.len == 0) return; // miekg: empty name packs nothing
        if (name[name.len - 1] != '.') return Error.NotFqdn;
        // Match miekg IsFqdn's strings.LastIndexFunc byte offset exactly.
        const end = name.len - 1;
        var terminal = end;
        while (terminal > 0 and name[terminal - 1] == '\\') terminal -= 1;
        if (terminal != end) {
            // DecodeLastRuneInString: a valid rune ending here has its start
            // at most four bytes back. Invalid UTF-8 consumes a single byte.
            var width: usize = 1;
            if (terminal > 0 and name[terminal - 1] >= 0x80) {
                const limit = @min(terminal, 4);
                var candidate: usize = 2;
                while (candidate <= limit) : (candidate += 1) {
                    const rune = name[terminal - candidate .. terminal];
                    const size = std.unicode.utf8ByteSequenceLength(rune[0]) catch continue;
                    if (size != candidate) continue;
                    _ = std.unicode.utf8Decode(rune) catch continue;
                    width = candidate;
                    break;
                }
            }
            // With no non-backslash rune Go returns index -1.
            const distance = if (terminal == 0) end + 1 else end - terminal + width;
            if (distance % 2 == 0) return Error.NotFqdn;
        }

        var pointer: ?u15 = null;
        var begin: usize = 0; // presentation index of the current label
        var was_dot = false;
        var i: usize = 0;
        var label_bytes: [max_label_len]u8 = undefined;
        var label_len: usize = 0;

        while (i < name.len) : (i += 1) {
            const c = name[i];
            if (c == '\\') {
                // \DDD (wraps like Go's byte arithmetic) or \X
                if (i + 1 >= name.len) return Error.BadRdata;
                const rest = name[i + 1 ..];
                var byte: u8 = undefined;
                var skip: usize = undefined;
                if (rest.len >= 3 and isDigit(rest[0]) and isDigit(rest[1]) and isDigit(rest[2])) {
                    byte = (rest[0] - '0') *% 100 +% (rest[1] - '0') *% 10 +% (rest[2] - '0');
                    skip = 4;
                } else {
                    byte = rest[0];
                    skip = 2;
                }
                if (label_len >= max_label_len) return Error.BadRdata;
                label_bytes[label_len] = byte;
                label_len += 1;
                i += skip - 1;
                was_dot = false;
            } else if (c == '.') {
                if (i == 0 and name.len > 1) return Error.BadRdata; // leading dot
                if (was_dot) return Error.BadRdata; // double dot
                was_dot = true;

                // Compression: the first hit is the longest matching suffix.
                const is_root_suffix = begin == name.len - 1;
                if (!is_root_suffix) {
                    const key = name[begin..];
                    if (p.map.get(key)) |pos| {
                        if (compress) {
                            pointer = pos;
                            break;
                        }
                    } else if (p.end < max_compression_offset) {
                        try p.map.put(p.alloc, key, @intCast(p.end));
                    }
                }

                if (p.end + 1 + label_len > p.buf.len) return Error.NoSpaceLeft;
                p.buf[p.end] = @intCast(label_len);
                @memcpy(p.buf[p.end + 1 .. p.end + 1 + label_len], label_bytes[0..label_len]);
                p.end += 1 + label_len;
                label_len = 0;
                begin = i + 1;
            } else {
                if (label_len >= max_label_len) return Error.BadRdata;
                label_bytes[label_len] = c;
                label_len += 1;
                was_dot = false;
            }
        }

        // Root-only name: the loop already emitted its zero byte.
        if (name.len == 1 and name[0] == '.') return;

        if (pointer) |pos| {
            if (p.end + 2 > p.buf.len) return Error.NoSpaceLeft;
            std.mem.writeInt(u16, p.buf[p.end..][0..2], 0xC000 | @as(u16, pos), .big);
            p.end += 2;
            return;
        }
        try p.uint8(0);
    }

    fn charString(p: *Packer, s: []const u8) Error!void {
        // Presentation-escaped input: decode escapes to wire bytes, at
        // most 255 of them (miekg "string exceeded 255 bytes in txt").
        var tmp: [max_label_len + 1 + 191]u8 = undefined; // 255
        var out_len: usize = 0;
        var i: usize = 0;
        while (i < s.len) : (i += 1) {
            if (out_len >= tmp.len) return Error.BadRdata;
            if (s[i] == '\\') {
                i += 1;
                if (i >= s.len) break;
                if (s.len - i >= 3 and isDigit(s[i]) and isDigit(s[i + 1]) and isDigit(s[i + 2])) {
                    tmp[out_len] = (s[i] - '0') *% 100 +% (s[i + 1] - '0') *% 10 +% (s[i + 2] - '0');
                    i += 2;
                } else {
                    tmp[out_len] = s[i];
                }
            } else {
                tmp[out_len] = s[i];
            }
            out_len += 1;
        }
        if (p.end + 1 + out_len > p.buf.len) return Error.NoSpaceLeft;
        p.buf[p.end] = @intCast(out_len);
        @memcpy(p.buf[p.end + 1 .. p.end + 1 + out_len], tmp[0..out_len]);
        p.end += 1 + out_len;
    }

    fn uint8(p: *Packer, v: u8) Error!void {
        if (p.end + 1 > p.buf.len) return Error.NoSpaceLeft;
        p.buf[p.end] = v;
        p.end += 1;
    }

    fn uint16(p: *Packer, v: u16) Error!void {
        if (p.end + 2 > p.buf.len) return Error.NoSpaceLeft;
        std.mem.writeInt(u16, p.buf[p.end..][0..2], v, .big);
        p.end += 2;
    }

    fn uint32(p: *Packer, v: u32) Error!void {
        if (p.end + 4 > p.buf.len) return Error.NoSpaceLeft;
        std.mem.writeInt(u32, p.buf[p.end..][0..4], v, .big);
        p.end += 4;
    }

    fn raw(p: *Packer, bytes: []const u8) Error!void {
        if (p.end + bytes.len > p.buf.len) return Error.NoSpaceLeft;
        @memcpy(p.buf[p.end .. p.end + bytes.len], bytes);
        p.end += bytes.len;
    }
};

/// One-shot pack with a fresh compression map.
pub fn pack(alloc: std.mem.Allocator, msg: *const Message, buf: []u8) Error![]const u8 {
    var p = Packer.init(alloc, buf);
    defer p.deinit();
    return p.pack(msg);
}

fn isDigit(b: u8) bool {
    return b >= '0' and b <= '9';
}
