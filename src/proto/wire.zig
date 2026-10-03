//! Port of google.golang.org/protobuf/encoding/protowire (BSD-3-Clause).
//!
//! Protobuf wire-format encoder and decoder over plain slices, no allocator.
//! Semantics follow vendor/google.golang.org/protobuf/encoding/protowire/wire.go
//! (v1.36.11): same error conditions as the Go ParseError codes, same handling
//! of the 10-byte varint, denormalized group end markers and the recursion
//! limit for groups.
//! See https://protobuf.dev/programming-guides/encoding.

const std = @import("std");

/// Field number, mirrors protowire.Number (int32).
pub const Number = i32;

pub const min_valid_number: Number = 1;
pub const first_reserved_number: Number = 19000;
pub const last_reserved_number: Number = 19999;
pub const max_valid_number: Number = (1 << 29) - 1;
pub const default_recursion_limit: u32 = 10000;

/// Wire type, mirrors protowire.Type. Non-exhaustive: raw wire types 6 and 7
/// are reserved; they decode into `_` and the decoder reports Reserved when
/// consuming such a field, matching protowire's consumeFieldValueD default case.
pub const Type = enum(u3) {
    varint = 0,
    fixed64 = 1,
    bytes = 2,
    start_group = 3,
    end_group = 4,
    fixed32 = 5,
    _,
};

/// Error set mirroring the Go error codes returned as negative lengths.
/// NoSpaceLeft is the encoder-side equivalent of running out of capacity.
pub const Error = error{
    Truncated, // errCodeTruncated
    FieldNumber, // errCodeFieldNumber
    Overflow, // errCodeOverflow
    Reserved, // errCodeReserved
    EndGroup, // errCodeEndGroup
    RecursionDepth, // errCodeRecursionDepth
    NoSpaceLeft,
};

pub fn isValidNumber(n: Number) bool {
    return min_valid_number <= n and n <= max_valid_number;
}

/// Encoder appends wire-format bytes into a caller-owned fixed buffer.
/// Mirrors the Append* family: on success the bytes() slice grows.
pub const Encoder = struct {
    buf: []u8,
    len: usize = 0,

    pub fn init(buf: []u8) Encoder {
        return .{ .buf = buf };
    }

    pub fn bytes(e: *const Encoder) []u8 {
        return e.buf[0..e.len];
    }

    fn room(e: *const Encoder, n: usize) Error!void {
        if (e.len + n > e.buf.len) return Error.NoSpaceLeft;
    }

    pub fn appendVarint(e: *Encoder, v: u64) Error!void {
        try e.room(sizeVarint(v));
        var x = v;
        while (x >= 0x80) {
            e.buf[e.len] = @as(u8, @truncate(x)) | 0x80;
            e.len += 1;
            x >>= 7;
        }
        e.buf[e.len] = @truncate(x);
        e.len += 1;
    }

    pub fn appendFixed32(e: *Encoder, v: u32) Error!void {
        try e.room(4);
        std.mem.writeInt(u32, e.buf[e.len..][0..4], v, .little);
        e.len += 4;
    }

    pub fn appendFixed64(e: *Encoder, v: u64) Error!void {
        try e.room(8);
        std.mem.writeInt(u64, e.buf[e.len..][0..8], v, .little);
        e.len += 8;
    }

    pub fn appendBytes(e: *Encoder, v: []const u8) Error!void {
        try e.appendVarint(v.len);
        try e.room(v.len);
        @memcpy(e.buf[e.len..][0..v.len], v);
        e.len += v.len;
    }

    pub fn appendTag(e: *Encoder, num: Number, typ: Type) Error!void {
        try e.appendVarint(encodeTag(num, typ));
    }

    /// Appends v as a group value with the trailing end group marker.
    /// The caller's v must not contain the end marker.
    pub fn appendGroup(e: *Encoder, num: Number, v: []const u8) Error!void {
        try e.room(v.len + sizeTag(num));
        @memcpy(e.buf[e.len..][0..v.len], v);
        e.len += v.len;
        try e.appendTag(num, .end_group);
    }

    /// Appends a whole field record: tag plus value. The value's tag selects
    /// the wire type; groups append their own end marker.
    pub fn appendField(e: *Encoder, num: Number, value: FieldValue) Error!void {
        switch (value) {
            .varint => |v| {
                try e.appendTag(num, .varint);
                try e.appendVarint(v);
            },
            .fixed32 => |v| {
                try e.appendTag(num, .fixed32);
                try e.appendFixed32(v);
            },
            .fixed64 => |v| {
                try e.appendTag(num, .fixed64);
                try e.appendFixed64(v);
            },
            .bytes => |v| {
                try e.appendTag(num, .bytes);
                try e.appendBytes(v);
            },
            .start_group => |v| {
                try e.appendTag(num, .start_group);
                try e.appendGroup(num, v);
            },
        }
    }

    pub fn appendRaw(e: *Encoder, v: []const u8) Error!void {
        try e.room(v.len);
        @memcpy(e.buf[e.len..][0..v.len], v);
        e.len += v.len;
    }
};

pub const FieldValue = union(enum) {
    varint: u64,
    fixed32: u32,
    fixed64: u64,
    bytes: []const u8,
    start_group: []const u8,
};

/// A parsed field record: number, wire type and the total consumed length
/// (tag header plus value, including the end group marker for groups).
pub const Field = struct {
    num: Number,
    typ: Type,
    n: usize,
};

/// Decoder reads wire-format bytes from a slice, mirroring the Consume* family.
pub const Decoder = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn init(buf: []const u8) Decoder {
        return .{ .buf = buf };
    }

    pub fn rest(d: *const Decoder) []const u8 {
        return d.buf[d.pos..];
    }

    pub fn done(d: *const Decoder) bool {
        return d.pos >= d.buf.len;
    }

    /// Parses a varint-encoded uint64 (ConsumeVarint).
    pub fn consumeVarint(d: *Decoder) Error!u64 {
        var v: u64 = 0;
        var i: usize = 0;
        while (i < 10) : (i += 1) {
            if (d.pos + i >= d.buf.len) return Error.Truncated;
            const y = d.buf[d.pos + i];
            if (i == 9) {
                // 10th byte: only bit 0 contributes, shifted into bit 63.
                if (y >= 2) return Error.Overflow;
                v += @as(u64, y) << 63;
                d.pos += 10;
                return v;
            }
            v += @as(u64, y & 0x7f) << @intCast(7 * i);
            if (y < 0x80) {
                d.pos += i + 1;
                return v;
            }
        }
        unreachable;
    }

    pub fn consumeFixed32(d: *Decoder) Error!u32 {
        if (d.pos + 4 > d.buf.len) return Error.Truncated;
        const v = std.mem.readInt(u32, d.buf[d.pos..][0..4], .little);
        d.pos += 4;
        return v;
    }

    pub fn consumeFixed64(d: *Decoder) Error!u64 {
        if (d.pos + 8 > d.buf.len) return Error.Truncated;
        const v = std.mem.readInt(u64, d.buf[d.pos..][0..8], .little);
        d.pos += 8;
        return v;
    }

    /// Parses a length-prefixed bytes value, returning a subslice of the
    /// decoder buffer (ConsumeBytes).
    pub fn consumeBytes(d: *Decoder) Error![]const u8 {
        const m = try d.consumeVarint();
        if (m > d.buf.len - d.pos) return Error.Truncated;
        const v = d.buf[d.pos..][0..m];
        d.pos += m;
        return v;
    }

    /// Parses a varint-encoded tag (ConsumeTag).
    pub fn consumeTag(d: *Decoder) Error!struct { num: Number, typ: Type } {
        const v = try d.consumeVarint();
        const num = decodeTagNum(v);
        const typ = decodeTagType(v);
        if (num < min_valid_number) return Error.FieldNumber;
        return .{ .num = num, .typ = typ };
    }

    /// Parses a whole field record (ConsumeField): tag plus value.
    pub fn consumeField(d: *Decoder) Error!Field {
        const start = d.pos;
        const tag = try d.consumeTag();
        try d.consumeFieldValueD(tag.num, tag.typ, default_recursion_limit);
        return .{ .num = tag.num, .typ = tag.typ, .n = d.pos - start };
    }

    /// Parses a field value for an already-parsed tag (ConsumeFieldValue).
    pub fn consumeFieldValue(d: *Decoder, num: Number, typ: Type) Error!usize {
        const start = d.pos;
        try d.consumeFieldValueD(num, typ, default_recursion_limit);
        return d.pos - start;
    }

    /// Skips an unknown field: identical to consumeFieldValue.
    pub fn skipField(d: *Decoder, num: Number, typ: Type) Error!usize {
        return d.consumeFieldValue(num, typ);
    }

    /// Parses a group value (ConsumeGroup): returns the payload without the
    /// end marker; the total length including the marker is available from
    /// the position advance.
    pub fn consumeGroup(d: *Decoder, num: Number) Error![]const u8 {
        const start = d.pos;
        try d.consumeFieldValueD(num, .start_group, default_recursion_limit);
        // Truncate the end marker, handling denormalized varints the same way
        // as protowire.ConsumeGroup: trailing bytes whose low 7 bits are zero
        // cannot be part of the end marker varint.
        var payload_end = d.pos;
        while (payload_end > start and d.buf[payload_end - 1] & 0x7f == 0) {
            payload_end -= 1;
        }
        payload_end -= sizeTag(num);
        return d.buf[start..payload_end];
    }

    fn consumeFieldValueD(d: *Decoder, num: Number, typ: Type, depth: i32) Error!void {
        switch (typ) {
            .varint => _ = try d.consumeVarint(),
            .fixed32 => _ = try d.consumeFixed32(),
            .fixed64 => _ = try d.consumeFixed64(),
            .bytes => _ = try d.consumeBytes(),
            .start_group => {
                if (depth < 0) return Error.RecursionDepth;
                while (true) {
                    const tag = try d.consumeTag();
                    if (tag.typ == .end_group) {
                        if (num != tag.num) return Error.EndGroup;
                        return;
                    }
                    try d.consumeFieldValueD(tag.num, tag.typ, depth - 1);
                }
            },
            .end_group => return Error.EndGroup,
            _ => return Error.Reserved,
        }
    }
};

/// Encoded size of a varint, 1..=10 (SizeVarint).
pub fn sizeVarint(v_in: u64) usize {
    // Same arithmetic as protowire: 1 + (bits.Len64(v)-1)/7 expressed via
    // leading zeros, with v|=1 to keep it defined for 0.
    const v = v_in | 1;
    const lz: u7 = @clz(v);
    const log2value: u64 = @as(u64, lz) ^ 63;
    return @intCast((log2value * 9 + (64 + 9)) / 64);
}

pub fn sizeTag(num: Number) usize {
    return sizeVarint(encodeTag(num, .varint)); // wire type has no effect on size
}

pub fn sizeFixed32() usize {
    return 4;
}

pub fn sizeFixed64() usize {
    return 8;
}

pub fn sizeBytes(n: usize) usize {
    return sizeVarint(n) + n;
}

pub fn sizeGroup(num: Number, n: usize) usize {
    return n + sizeTag(num);
}

/// Decodes the field number from a unified tag; returns -1 on overflow of
/// int32 (DecodeTag).
pub fn decodeTagNum(x: u64) Number {
    if (x >> 3 > std.math.maxInt(i32)) return -1;
    return @intCast(x >> 3);
}

/// Decodes the wire type from a unified tag (DecodeTag).
pub fn decodeTagType(x: u64) Type {
    // x & 7 may name a reserved type (6, 7); the decoder reports Reserved
    // when such a field is consumed, matching protowire.
    return @enumFromInt(@as(u8, @truncate(x & 7)));
}

/// Encodes a field number and wire type into the unified tag (EncodeTag).
pub fn encodeTag(num: Number, typ: Type) u64 {
    return (@as(u64, @intCast(num)) << 3) | @intFromEnum(typ);
}

/// DecodeZigZag: {…, 5, 3, 1, 0, 2, 4, 6, …} → {…, -3, -2, -1, 0, +1, +2, +3, …}.
pub fn decodeZigZag(x: u64) i64 {
    const casted: i64 = @bitCast(x);
    return @as(i64, @bitCast(x >> 1)) ^ (casted << 63) >> 63;
}

/// EncodeZigZag: {…, -3, -2, -1, 0, +1, +2, +3, …} → {…, 5, 3, 1, 0, 2, 4, 6, …}.
pub fn encodeZigZag(x: i64) u64 {
    const shifted: u64 = @bitCast(x << 1);
    const sign: u64 = @bitCast(x >> 63);
    return shifted ^ sign;
}

/// DecodeBool: nonzero means true.
pub fn decodeBool(x: u64) bool {
    return x != 0;
}

/// EncodeBool: false → 0, true → 1.
pub fn encodeBool(x: bool) u64 {
    return if (x) 1 else 0;
}

test "compile" {
    _ = std.testing.refAllDecls(@This());
}
