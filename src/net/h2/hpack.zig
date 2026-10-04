// Port of golang.org/x/net/http2/hpack (BSD-3-Clause).
// Reference: upstream/netbird/vendor/golang.org/x/net/http2/hpack/
// (hpack.go, encode.go, tables.go, huffman.go, static_table.go).
// Scope: HPACK encoder/decoder over caller-owned slices, no allocator.
// Dynamic tables live in fixed internal arenas sized for the default
// 4096-byte table; larger peer-advertised tables are rejected.

const std = @import("std");

pub const initial_header_table_size: u32 = 4096;
pub const entry_overhead: u32 = 32;

/// Header field. Slices borrow from caller buffers (encoder input,
/// decoder input or internal arenas); see Decoder/Encoder docs.
pub const HeaderField = struct {
    name: []const u8,
    value: []const u8,
    sensitive: bool = false,

    pub fn isPseudo(hf: *const HeaderField) bool {
        return hf.name.len != 0 and hf.name[0] == ':';
    }

    /// Entry size per RFC 7541 section 4.1.
    pub fn size(hf: *const HeaderField) u32 {
        return @intCast(hf.name.len + hf.value.len + entry_overhead);
    }
};

pub const Error = error{
    Truncated,
    InvalidIndex,
    InvalidEncoding,
    VarintOverflow,
    StringTooLong,
    InvalidHuffman,
    TableSizeUpdateNotAtStart,
    TableSizeTooLarge,
    NoSpaceLeft,
    TooManyEntries,
};

pub const StaticEntry = struct { name: []const u8, value: []const u8 };

/// RFC 7541 Appendix A, same order as static_table.go.
pub const static_table: [61]StaticEntry = .{
    .{ .name = ":authority", .value = "" },
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":method", .value = "POST" },
    .{ .name = ":path", .value = "/" },
    .{ .name = ":path", .value = "/index.html" },
    .{ .name = ":scheme", .value = "http" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":status", .value = "200" },
    .{ .name = ":status", .value = "204" },
    .{ .name = ":status", .value = "206" },
    .{ .name = ":status", .value = "304" },
    .{ .name = ":status", .value = "400" },
    .{ .name = ":status", .value = "404" },
    .{ .name = ":status", .value = "500" },
    .{ .name = "accept-charset", .value = "" },
    .{ .name = "accept-encoding", .value = "gzip, deflate" },
    .{ .name = "accept-language", .value = "" },
    .{ .name = "accept-ranges", .value = "" },
    .{ .name = "accept", .value = "" },
    .{ .name = "access-control-allow-origin", .value = "" },
    .{ .name = "age", .value = "" },
    .{ .name = "allow", .value = "" },
    .{ .name = "authorization", .value = "" },
    .{ .name = "cache-control", .value = "" },
    .{ .name = "content-disposition", .value = "" },
    .{ .name = "content-encoding", .value = "" },
    .{ .name = "content-language", .value = "" },
    .{ .name = "content-length", .value = "" },
    .{ .name = "content-location", .value = "" },
    .{ .name = "content-range", .value = "" },
    .{ .name = "content-type", .value = "" },
    .{ .name = "cookie", .value = "" },
    .{ .name = "date", .value = "" },
    .{ .name = "etag", .value = "" },
    .{ .name = "expect", .value = "" },
    .{ .name = "expires", .value = "" },
    .{ .name = "from", .value = "" },
    .{ .name = "host", .value = "" },
    .{ .name = "if-match", .value = "" },
    .{ .name = "if-modified-since", .value = "" },
    .{ .name = "if-none-match", .value = "" },
    .{ .name = "if-range", .value = "" },
    .{ .name = "if-unmodified-since", .value = "" },
    .{ .name = "last-modified", .value = "" },
    .{ .name = "link", .value = "" },
    .{ .name = "location", .value = "" },
    .{ .name = "max-forwards", .value = "" },
    .{ .name = "proxy-authenticate", .value = "" },
    .{ .name = "proxy-authorization", .value = "" },
    .{ .name = "range", .value = "" },
    .{ .name = "referer", .value = "" },
    .{ .name = "refresh", .value = "" },
    .{ .name = "retry-after", .value = "" },
    .{ .name = "server", .value = "" },
    .{ .name = "set-cookie", .value = "" },
    .{ .name = "strict-transport-security", .value = "" },
    .{ .name = "transfer-encoding", .value = "" },
    .{ .name = "user-agent", .value = "" },
    .{ .name = "vary", .value = "" },
    .{ .name = "via", .value = "" },
    .{ .name = "www-authenticate", .value = "" },
};

/// Dynamic table with a fixed arena. Entries are stored oldest-first
/// (like Go's ents); HPACK indices count the newest as index 1 within
/// the dynamic part. Additions copy name/value bytes into the arena.
pub const DynamicTable = struct {
    pub const max_entries = 160;
    pub const arena_size = 4096;

    entries: [max_entries]HeaderField = undefined,
    len: usize = 0,
    arena: [arena_size]u8 = undefined,
    arena_used: usize = 0,
    table_size: u32 = 0,
    max_size: u32 = initial_header_table_size,

    pub fn init(max_size: u32) DynamicTable {
        return .{ .max_size = max_size };
    }

    pub fn setMaxSize(dt: *DynamicTable, v: u32) void {
        dt.max_size = v;
        dt.evict();
    }

    fn entrySize(name: []const u8, value: []const u8) u32 {
        return @intCast(name.len + value.len + entry_overhead);
    }

    pub fn add(dt: *DynamicTable, name: []const u8, value: []const u8) Error!void {
        const need: usize = name.len + value.len;
        // An entry that does not fit the table on its own empties it,
        // like Go (add then evict-all): no error, field still emitted.
        if (entrySize(name, value) > dt.max_size or need > arena_size) {
            dt.evictAll();
            return;
        }
        if (dt.len >= max_entries) return Error.TooManyEntries;
        // Make arena room, evicting oldest first like Go. This only
        // triggers when the size eviction below would also trigger.
        while (dt.arena_used + need > arena_size and dt.len > 0) {
            dt.evictOldestOne();
        }
        const at = dt.arena_used;
        @memcpy(dt.arena[at..][0..name.len], name);
        @memcpy(dt.arena[at + name.len ..][0..value.len], value);
        dt.arena_used += need;
        dt.entries[dt.len] = .{
            .name = dt.arena[at..][0..name.len],
            .value = dt.arena[at + name.len ..][0..value.len],
        };
        dt.len += 1;
        dt.table_size += entrySize(name, value);
        dt.evict();
    }

    fn evictOldestOne(dt: *DynamicTable) void {
        if (dt.len == 0) return;
        const oldest = dt.entries[0];
        dt.table_size -= entrySize(oldest.name, oldest.value);
        // Compact the arena: oldest entry's bytes are at the front.
        const freed: usize = oldest.name.len + oldest.value.len;
        std.mem.copyForwards(u8, dt.arena[0..], dt.arena[freed..dt.arena_used]);
        dt.arena_used -= freed;
        std.mem.copyForwards(HeaderField, dt.entries[0..], dt.entries[1..dt.len]);
        dt.len -= 1;
        dt.repoint();
    }

    /// Fix entry slices after arena compaction.
    fn repoint(dt: *DynamicTable) void {
        var at: usize = 0;
        for (dt.entries[0..dt.len]) |*e| {
            const nl = e.name.len;
            const vl = e.value.len;
            e.name = dt.arena[at..][0..nl];
            e.value = dt.arena[at + nl ..][0..vl];
            at += nl + vl;
        }
    }

    fn evict(dt: *DynamicTable) void {
        while (dt.table_size > dt.max_size and dt.len > 0) {
            dt.evictOldestOne();
        }
    }

    fn evictAll(dt: *DynamicTable) void {
        dt.len = 0;
        dt.arena_used = 0;
        dt.table_size = 0;
    }

    /// Newest-first search, matching headerFieldTable.search: full
    /// name+value match wins; otherwise newest name match; else 0.
    /// Returned index counts the static table first (caller adds the
    /// static offset for dynamic tables).
    pub fn search(dt: *const DynamicTable, name: []const u8, value: []const u8, sensitive: bool) struct {
        index: usize,
        full: bool,
    } {
        var i = dt.len;
        var name_only: usize = 0;
        while (i > 0) {
            i -= 1;
            const e = dt.entries[i];
            if (!sensitive and std.mem.eql(u8, e.name, name) and std.mem.eql(u8, e.value, value)) {
                return .{ .index = dt.len - i, .full = true };
            }
            if (name_only == 0 and std.mem.eql(u8, e.name, name)) {
                name_only = dt.len - i;
            }
        }
        return .{ .index = name_only, .full = false };
    }
};

/// Static table search with Go's newest-wins order (highest index).
pub fn searchStatic(name: []const u8, value: []const u8, sensitive: bool) struct {
    index: usize,
    full: bool,
} {
    var i = static_table.len;
    var name_only: usize = 0;
    while (i > 0) {
        i -= 1;
        const e = static_table[i];
        if (!sensitive and std.mem.eql(u8, e.name, name) and std.mem.eql(u8, e.value, value)) {
            return .{ .index = i + 1, .full = true };
        }
        if (name_only == 0 and std.mem.eql(u8, e.name, name)) {
            name_only = i + 1;
        }
    }
    return .{ .index = name_only, .full = false };
}

/// Huffman codec, tables from tables.go. Decode is a bit-by-bit trie walk
/// with Go's end-of-input rules (RFC 7541 section 5.2): leftover longer
/// than 7 bits is an error, shorter leftovers must be all ones (EOS prefix).
pub const huffman = struct {
// Huffman tables, mechanically extracted from
// vendor/golang.org/x/net/http2/hpack/tables.go (BSD-3-Clause).
    pub const codes: [256]u32 = .{
    0x1ff8, 0x7fffd8, 0xfffffe2, 0xfffffe3, 0xfffffe4, 0xfffffe5, 0xfffffe6, 0xfffffe7,
    0xfffffe8, 0xffffea, 0x3ffffffc, 0xfffffe9, 0xfffffea, 0x3ffffffd, 0xfffffeb, 0xfffffec,
    0xfffffed, 0xfffffee, 0xfffffef, 0xffffff0, 0xffffff1, 0xffffff2, 0x3ffffffe, 0xffffff3,
    0xffffff4, 0xffffff5, 0xffffff6, 0xffffff7, 0xffffff8, 0xffffff9, 0xffffffa, 0xffffffb,
    0x14, 0x3f8, 0x3f9, 0xffa, 0x1ff9, 0x15, 0xf8, 0x7fa,
    0x3fa, 0x3fb, 0xf9, 0x7fb, 0xfa, 0x16, 0x17, 0x18,
    0x0, 0x1, 0x2, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
    0x1e, 0x1f, 0x5c, 0xfb, 0x7ffc, 0x20, 0xffb, 0x3fc,
    0x1ffa, 0x21, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62,
    0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a,
    0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72,
    0xfc, 0x73, 0xfd, 0x1ffb, 0x7fff0, 0x1ffc, 0x3ffc, 0x22,
    0x7ffd, 0x3, 0x23, 0x4, 0x24, 0x5, 0x25, 0x26,
    0x27, 0x6, 0x74, 0x75, 0x28, 0x29, 0x2a, 0x7,
    0x2b, 0x76, 0x2c, 0x8, 0x9, 0x2d, 0x77, 0x78,
    0x79, 0x7a, 0x7b, 0x7ffe, 0x7fc, 0x3ffd, 0x1ffd, 0xffffffc,
    0xfffe6, 0x3fffd2, 0xfffe7, 0xfffe8, 0x3fffd3, 0x3fffd4, 0x3fffd5, 0x7fffd9,
    0x3fffd6, 0x7fffda, 0x7fffdb, 0x7fffdc, 0x7fffdd, 0x7fffde, 0xffffeb, 0x7fffdf,
    0xffffec, 0xffffed, 0x3fffd7, 0x7fffe0, 0xffffee, 0x7fffe1, 0x7fffe2, 0x7fffe3,
    0x7fffe4, 0x1fffdc, 0x3fffd8, 0x7fffe5, 0x3fffd9, 0x7fffe6, 0x7fffe7, 0xffffef,
    0x3fffda, 0x1fffdd, 0xfffe9, 0x3fffdb, 0x3fffdc, 0x7fffe8, 0x7fffe9, 0x1fffde,
    0x7fffea, 0x3fffdd, 0x3fffde, 0xfffff0, 0x1fffdf, 0x3fffdf, 0x7fffeb, 0x7fffec,
    0x1fffe0, 0x1fffe1, 0x3fffe0, 0x1fffe2, 0x7fffed, 0x3fffe1, 0x7fffee, 0x7fffef,
    0xfffea, 0x3fffe2, 0x3fffe3, 0x3fffe4, 0x7ffff0, 0x3fffe5, 0x3fffe6, 0x7ffff1,
    0x3ffffe0, 0x3ffffe1, 0xfffeb, 0x7fff1, 0x3fffe7, 0x7ffff2, 0x3fffe8, 0x1ffffec,
    0x3ffffe2, 0x3ffffe3, 0x3ffffe4, 0x7ffffde, 0x7ffffdf, 0x3ffffe5, 0xfffff1, 0x1ffffed,
    0x7fff2, 0x1fffe3, 0x3ffffe6, 0x7ffffe0, 0x7ffffe1, 0x3ffffe7, 0x7ffffe2, 0xfffff2,
    0x1fffe4, 0x1fffe5, 0x3ffffe8, 0x3ffffe9, 0xffffffd, 0x7ffffe3, 0x7ffffe4, 0x7ffffe5,
    0xfffec, 0xfffff3, 0xfffed, 0x1fffe6, 0x3fffe9, 0x1fffe7, 0x1fffe8, 0x7ffff3,
    0x3fffea, 0x3fffeb, 0x1ffffee, 0x1ffffef, 0xfffff4, 0xfffff5, 0x3ffffea, 0x7ffff4,
    0x3ffffeb, 0x7ffffe6, 0x3ffffec, 0x3ffffed, 0x7ffffe7, 0x7ffffe8, 0x7ffffe9, 0x7ffffea,
    0x7ffffeb, 0xffffffe, 0x7ffffec, 0x7ffffed, 0x7ffffee, 0x7ffffef, 0x7fffff0, 0x3ffffee,
};
    pub const code_lens: [256]u8 = .{
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
    28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6,
    5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10,
    13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6,
    15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5,
    6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28,
    20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
    24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
    22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
    21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
    26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
    19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
    20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
    26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
};

    /// Encode s into out; returns bytes written. Mirrors AppendHuffmanString.
    pub fn encode(out: []u8, s: []const u8) Error!usize {
        var x: u64 = 0;
        var n: u32 = 0;
        var pos: usize = 0;
        for (s) |c| {
            const len: u32 = code_lens[c];
            n += len;
            x <<= @intCast(len);
            x |= codes[c];
            if (n >= 32) {
                n %= 32;
                if (pos + 4 > out.len) return Error.NoSpaceLeft;
                const y: u32 = @truncate(x >> @intCast(n));
                out[pos] = @truncate(y >> 24);
                out[pos + 1] = @truncate(y >> 16);
                out[pos + 2] = @truncate(y >> 8);
                out[pos + 3] = @truncate(y);
                pos += 4;
            }
        }
        // EOS padding to a byte boundary: pad bits are all ones.
        const over: u32 = n % 8;
        if (over != 0) {
            const pad: u32 = 8 - over;
            x <<= @intCast(pad);
            x |= (@as(u64, 0xff) >> @intCast(over)) & 0xff;
            n += pad;
        }
        const tail: usize = n / 8;
        if (pos + tail > out.len) return Error.NoSpaceLeft;
        var i: usize = 0;
        while (i < tail) : (i += 1) {
            out[pos + i] = @truncate(x >> @intCast((tail - 1 - i) * 8));
        }
        return pos + tail;
    }

    pub fn encodedLen(s: []const u8) usize {
        var n: usize = 0;
        for (s) |c| n += code_lens[c];
        return (n + 7) / 8;
    }

    /// Decode v into out; returns bytes written. Bit-by-bit greedy walk
    /// over (code, len): equivalent to Go's 256-ary tree walk (proven in
    /// the review notes: zero-padded completion emits exactly when a code
    /// is a prefix of the remaining bits). End rules match huffmanDecode.
    pub fn decode(out: []u8, v: []const u8) Error!usize {
        var pos: usize = 0;
        var acc: u32 = 0;
        var acc_len: u32 = 0;
        for (v) |b| {
            var bit: u32 = 8;
            while (bit > 0) {
                bit -= 1;
                acc = (acc << 1) | ((b >> @intCast(bit)) & 1);
                acc_len += 1;
                if (matchSymbol(acc, acc_len)) |sym| {
                    if (pos >= out.len) return Error.NoSpaceLeft;
                    out[pos] = sym;
                    pos += 1;
                    acc = 0;
                    acc_len = 0;
                } else if (acc_len > 30) {
                    return Error.InvalidHuffman;
                } else if (!isPrefix(acc, acc_len)) {
                    return Error.InvalidHuffman;
                }
            }
        }
        if (acc_len > 7) return Error.InvalidHuffman;
        if (acc_len > 0) {
            const mask: u32 = (@as(u32, 1) << @intCast(acc_len)) - 1;
            if (acc & mask != mask) return Error.InvalidHuffman;
        }
        return pos;
    }

    fn matchSymbol(acc: u32, len: u32) ?u8 {
        if (len < 5 or len > 30) return null;
        var sym: u32 = 0;
        while (sym < 256) : (sym += 1) {
            if (code_lens[sym] == len and codes[sym] == acc) {
                return @intCast(sym);
            }
        }
        return null;
    }

    fn isPrefix(acc: u32, len: u32) bool {
        var sym: u32 = 0;
        while (sym < 256) : (sym += 1) {
            const l = code_lens[sym];
            if (l >= len and codes[sym] >> @intCast(l - len) == acc) return true;
        }
        return false;
    }
};

/// Integer with n-bit prefix (readVarInt). Returns value + bytes consumed.
pub fn readVarInt(prefix_bits: u4, buf: []const u8) Error!struct { value: u64, len: usize } {
    if (buf.len == 0) return Error.Truncated;
    const n: u6 = prefix_bits;
    var i: u64 = buf[0];
    if (n < 8) {
        i &= (@as(u64, 1) << n) - 1;
    }
    const max: u64 = (@as(u64, 1) << n) - 1;
    if (i < max) {
        return .{ .value = i, .len = 1 };
    }
    var m: u32 = 0;
    var pos: usize = 1;
    while (pos < buf.len) {
        const b = buf[pos];
        pos += 1;
        i +%= @as(u64, b & 127) << @intCast(m);
        if (b & 128 == 0) {
            return .{ .value = i, .len = pos };
        }
        m += 7;
        if (m >= 63) return Error.VarintOverflow;
    }
    return Error.Truncated;
}

/// Integer with n-bit prefix (appendVarInt). Returns bytes written.
pub fn appendVarInt(out: []u8, prefix_bits: u4, value: u64) Error!usize {
    const n: u6 = prefix_bits;
    const k: u64 = (@as(u64, 1) << n) - 1;
    if (out.len == 0) return Error.NoSpaceLeft;
    if (value < k) {
        out[0] = @intCast(value);
        return 1;
    }
    out[0] = @intCast(k);
    var i = value - k;
    var pos: usize = 1;
    while (i >= 128) {
        if (pos >= out.len) return Error.NoSpaceLeft;
        out[pos] = @as(u8, 0x80) | @as(u8, @truncate(i));
        pos += 1;
        i >>= 7;
    }
    if (pos >= out.len) return Error.NoSpaceLeft;
    out[pos] = @truncate(i);
    return pos + 1;
}

pub const DecodedString = struct {
    /// Decoded bytes; valid until the next decode call on the same Decoder.
    bytes: []const u8,
    /// Total encoded length (prefix + payload).
    len: usize,
};

/// HPACK decoder over one connection. Decoded strings borrow the input
/// (raw), the static table, or an internal scratch buffer (huffman,
/// indexed names, and dynamic-sourced emitted fields); dynamic entries
/// own arena copies. Decoded field slices stay valid until the next
/// decodeBlock call on the same decoder.
pub const Decoder = struct {
    dyn_tab: DynamicTable = DynamicTable.init(initial_header_table_size),
    allowed_max_size: u32 = initial_header_table_size,
    scratch: [8192]u8 = undefined,
    scratch_used: usize = 0,
    first_field: bool = true,

    pub fn init(max_dynamic_table_size: u32) Decoder {
        var d = Decoder{};
        d.allowed_max_size = max_dynamic_table_size;
        d.dyn_tab.setMaxSize(max_dynamic_table_size);
        return d;
    }

    pub fn setMaxDynamicTableSize(d: *Decoder, v: u32) void {
        d.dyn_tab.setMaxSize(v);
    }

    /// Decode one header block, calling emit per field.
    pub fn decodeBlock(
        d: *Decoder,
        block: []const u8,
        context: ?*anyopaque,
        emit: *const fn (?*anyopaque, HeaderField) void,
    ) Error!void {
        d.scratch_used = 0;
        d.first_field = true;
        var pos: usize = 0;
        while (pos < block.len) {
            const b = block[pos];
            if (b & 128 != 0) {
                const r = try readVarInt(7, block[pos..]);
                const hf = try d.at(r.value);
                pos += r.len;
                if (r.value > static_table.len) {
                    emit(context, .{
                        .name = try d.stabilize(hf.name),
                        .value = try d.stabilize(hf.value),
                    });
                } else {
                    emit(context, .{ .name = hf.name, .value = hf.value });
                }
            } else if (b & 192 == 64) {
                pos += try d.parseLiteral(block[pos..], 6, .incremental, context, emit);
            } else if (b & 240 == 0) {
                pos += try d.parseLiteral(block[pos..], 4, .without_indexing, context, emit);
            } else if (b & 240 == 16) {
                pos += try d.parseLiteral(block[pos..], 4, .never, context, emit);
            } else if (b & 224 == 32) {
                pos += try d.parseTableSizeUpdate(block[pos..]);
            } else {
                return Error.InvalidEncoding;
            }
            d.first_field = false;
        }
    }

    const Indexing = enum { incremental, without_indexing, never };

    fn parseLiteral(
        d: *Decoder,
        buf: []const u8,
        prefix: u3,
        indexing: Indexing,
        context: ?*anyopaque,
        emit: *const fn (?*anyopaque, HeaderField) void,
    ) Error!usize {
        const r = try readVarInt(prefix, buf);
        var pos = r.len;
        var name: []const u8 = "";
        if (r.value > 0) {
            const hf = try d.at(r.value);
            name = hf.name;
        } else {
            const s = try d.readString(buf[pos..]);
            name = s.bytes;
            pos += s.len;
        }
        const vs = try d.readString(buf[pos..]);
        pos += vs.len;
        if (indexing == .incremental) {
            // A table-borrowed name dangles if add() evicts and compacts its
            // own entry (Go is immune: strings are GC'd). Copy it to the
            // per-block scratch first; values are safe (block or scratch).
            if (r.value > 0) {
                name = try d.stabilize(name);
            }
            try d.dyn_tab.add(name, vs.bytes);
        } else if (r.value > static_table.len) {
            // No add happens here, but a later field in the same block may
            // evict and compact the arena: stabilize the dynamic-borrowed
            // name the same way.
            name = try d.stabilize(name);
        }
        emit(context, .{
            .name = name,
            .value = vs.bytes,
            .sensitive = indexing == .never,
        });
        return pos;
    }

    fn parseTableSizeUpdate(d: *Decoder, buf: []const u8) Error!usize {
        if (!d.first_field and d.dyn_tab.table_size > 0) {
            return Error.TableSizeUpdateNotAtStart;
        }
        const r = try readVarInt(5, buf);
        if (r.value > d.allowed_max_size) {
            return Error.TableSizeTooLarge;
        }
        d.dyn_tab.setMaxSize(@intCast(r.value));
        return r.len;
    }

    /// Copy a dynamic-table-owned slice to per-block scratch so a later
    /// add/evict compaction in the same block cannot overwrite an already
    /// emitted field. Scratch only grows within a block and resets per
    /// block, so copies stay valid until the next decodeBlock call.
    fn stabilize(d: *Decoder, s: []const u8) Error![]const u8 {
        if (d.scratch_used + s.len > d.scratch.len) {
            return Error.StringTooLong;
        }
        const out = d.scratch[d.scratch_used..][0..s.len];
        @memcpy(out, s);
        d.scratch_used += s.len;
        return out;
    }

    fn at(d: *Decoder, i: u64) Error!HeaderField {
        if (i == 0) return Error.InvalidIndex;
        if (i <= static_table.len) {
            const e = static_table[i - 1];
            return .{ .name = e.name, .value = e.value };
        }
        const dyn_idx = i - static_table.len;
        if (dyn_idx > d.dyn_tab.len) return Error.InvalidIndex;
        // Newest entry has the lowest dynamic index.
        return d.dyn_tab.entries[d.dyn_tab.len - dyn_idx];
    }

    fn readString(d: *Decoder, buf: []const u8) Error!DecodedString {
        if (buf.len == 0) return Error.Truncated;
        const is_huff = buf[0] & 128 != 0;
        const r = try readVarInt(7, buf);
        if (buf.len - r.len < r.value) return Error.Truncated;
        const payload = buf[r.len..][0..r.value];
        if (!is_huff) {
            return .{ .bytes = payload, .len = r.len + payload.len };
        }
        if (d.scratch_used + payload.len * 4 > d.scratch.len) {
            // Huffman expands at most ~4x in pathological cases; bound it.
            return Error.StringTooLong;
        }
        const n = try huffman.decode(d.scratch[d.scratch_used..], payload);
        const out = d.scratch[d.scratch_used..][0..n];
        d.scratch_used += n;
        return .{ .bytes = out, .len = r.len + payload.len };
    }
};

/// HPACK encoder. Mirrors Go Encoder: indexes everything that fits and
/// is not sensitive, huffman-codes strings only when strictly shorter,
/// searches static first then dynamic with newest-wins order.
pub const Encoder = struct {
    dyn_tab: DynamicTable = DynamicTable.init(initial_header_table_size),
    min_size: u32 = std.math.maxInt(u32),
    max_size_limit: u32 = initial_header_table_size,
    table_size_update: bool = false,

    pub fn init() Encoder {
        return .{};
    }

    pub fn setMaxDynamicTableSize(e: *Encoder, v: u32) void {
        var capped = v;
        if (capped > e.max_size_limit) capped = e.max_size_limit;
        if (capped < e.min_size) e.min_size = capped;
        e.table_size_update = true;
        e.dyn_tab.setMaxSize(capped);
    }

    fn searchTable(e: *const Encoder, f: HeaderField) struct {
        index: u64,
        full: bool,
    } {
        const s = searchStatic(f.name, f.value, f.sensitive);
        if (s.full) return .{ .index = s.index, .full = true };
        const dd = e.dyn_tab.search(f.name, f.value, f.sensitive);
        const j: u64 = if (dd.index == 0) 0 else dd.index + static_table.len;
        if (dd.full or (s.index == 0 and j != 0)) {
            return .{ .index = j, .full = dd.full };
        }
        return .{ .index = s.index, .full = false };
    }

    fn shouldIndex(e: *const Encoder, f: HeaderField) bool {
        return !f.sensitive and f.size() <= e.dyn_tab.max_size;
    }

    /// Encode one field into out; returns bytes written (WriteField).
    pub fn writeField(e: *Encoder, out: []u8, f: HeaderField) Error!usize {
        var pos: usize = 0;
        if (e.table_size_update) {
            e.table_size_update = false;
            if (e.min_size < e.dyn_tab.max_size) {
                pos += try appendTableSize(out[pos..], e.min_size);
            }
            e.min_size = std.math.maxInt(u32);
            pos += try appendTableSize(out[pos..], e.dyn_tab.max_size);
        }
        const found = e.searchTable(f);
        if (found.full) {
            pos += try appendIndexed(out[pos..], found.index);
            return pos;
        }
        const indexing = e.shouldIndex(f);
        if (indexing) {
            try e.dyn_tab.add(f.name, f.value);
        }
        if (found.index == 0) {
            pos += try appendNewName(out[pos..], f, indexing);
        } else {
            pos += try appendIndexedName(out[pos..], f, found.index, indexing);
        }
        return pos;
    }
};

fn appendIndexed(out: []u8, i: u64) Error!usize {
    const n = try appendVarInt(out, 7, i);
    out[0] |= 0x80;
    return n;
}

fn appendNewName(out: []u8, f: HeaderField, indexing: bool) Error!usize {
    if (out.len == 0) return Error.NoSpaceLeft;
    out[0] = encodeTypeByte(indexing, f.sensitive);
    var pos: usize = 1;
    pos += try appendHpackString(out[pos..], f.name);
    pos += try appendHpackString(out[pos..], f.value);
    return pos;
}

fn appendIndexedName(out: []u8, f: HeaderField, i: u64, indexing: bool) Error!usize {
    const prefix: u3 = if (indexing) 6 else 4;
    const n = try appendVarInt(out, prefix, i);
    out[0] |= encodeTypeByte(indexing, f.sensitive);
    return n + try appendHpackString(out[n..], f.value);
}

fn appendTableSize(out: []u8, v: u32) Error!usize {
    const n = try appendVarInt(out, 5, v);
    out[0] |= 0x20;
    return n;
}

fn appendHpackString(out: []u8, s: []const u8) Error!usize {
    const hlen = huffman.encodedLen(s);
    if (hlen < s.len) {
        // Length prefix first; huffman payload after. Reserve generously.
        const n = try appendVarInt(out, 7, hlen);
        const m = try huffman.encode(out[n..], s);
        std.debug.assert(m == hlen);
        out[0] |= 0x80;
        return n + m;
    }
    const n = try appendVarInt(out, 7, s.len);
    if (n + s.len > out.len) return Error.NoSpaceLeft;
    @memcpy(out[n..][0..s.len], s);
    return n + s.len;
}

fn encodeTypeByte(indexing: bool, sensitive: bool) u8 {
    if (sensitive) return 0x10;
    if (indexing) return 0x40;
    return 0;
}
