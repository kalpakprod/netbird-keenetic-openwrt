//! Tests for the protobuf wire port (src/proto/wire.zig).
//!
//! Byte vectors in the go_vector_* tests were produced by
//! google.golang.org/protobuf/encoding/protowire (v1.36.11, vendored upstream)
//! via ~/.cache/netbird-zig-context/gen/vectors.go.

const std = @import("std");
const testing = std.testing;
const wire = @import("wire.zig");

// --- Go vectors: varint -----------------------------------------------------

test "go vector: varint canonical encodings" {
    const cases = [_]struct { v: u64, want: []const u8 }{
        .{ .v = 0, .want = "\x00" },
        .{ .v = 1, .want = "\x01" },
        .{ .v = 127, .want = "\x7f" },
        .{ .v = 128, .want = "\x80\x01" },
        .{ .v = 129, .want = "\x81\x01" },
        .{ .v = 300, .want = "\xac\x02" },
        .{ .v = 16383, .want = "\xff\x7f" },
        .{ .v = 16384, .want = "\x80\x80\x01" },
        .{ .v = (1 << 32) - 1, .want = "\xff\xff\xff\xff\x0f" },
        .{ .v = 1 << 32, .want = "\x80\x80\x80\x80\x10" },
        .{ .v = (1 << 57) - 1, .want = "\xff\xff\xff\xff\xff\xff\xff\xff\x01" },
        .{ .v = 1 << 57, .want = "\x80\x80\x80\x80\x80\x80\x80\x80\x02" },
        .{ .v = 1 << 63, .want = "\x80\x80\x80\x80\x80\x80\x80\x80\x80\x01" },
        .{ .v = std.math.maxInt(u64), .want = "\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01" },
    };
    for (cases) |c| {
        var buf: [16]u8 = undefined;
        var e = wire.Encoder.init(&buf);
        try e.appendVarint(c.v);
        try testing.expectEqualStrings(c.want, e.bytes());
        try testing.expectEqual(c.want.len, wire.sizeVarint(c.v));
    }
}

test "go vector: negative int32 sign-extended to 10 bytes" {
    const cases = [_]struct { v: i64, want: []const u8 }{
        .{ .v = -1, .want = "\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01" },
        .{ .v = -2, .want = "\xfe\xff\xff\xff\xff\xff\xff\xff\xff\x01" },
        .{ .v = -128, .want = "\x80\xff\xff\xff\xff\xff\xff\xff\xff\x01" },
        .{ .v = -2147483648, .want = "\x80\x80\x80\x80\xf8\xff\xff\xff\xff\x01" },
    };
    for (cases) |c| {
        var buf: [16]u8 = undefined;
        var e = wire.Encoder.init(&buf);
        try e.appendVarint(@bitCast(c.v));
        try testing.expectEqualStrings(c.want, e.bytes());
    }
}

test "go vector: zigzag via varint" {
    const cases = [_]struct { v: i64, want: []const u8 }{
        .{ .v = 0, .want = "\x00" },
        .{ .v = -1, .want = "\x01" },
        .{ .v = 1, .want = "\x02" },
        .{ .v = -2, .want = "\x03" },
        .{ .v = 2, .want = "\x04" },
        .{ .v = -63, .want = "\x7d" },
        .{ .v = -64, .want = "\x7f" },
        .{ .v = 63, .want = "\x7e" },
        .{ .v = 64, .want = "\x80\x01" },
        .{ .v = (1 << 63) - 1, .want = "\xfe\xff\xff\xff\xff\xff\xff\xff\xff\x01" },
        .{ .v = -(1 << 63), .want = "\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01" },
    };
    for (cases) |c| {
        try testing.expectEqual(c.v, wire.decodeZigZag(wire.encodeZigZag(c.v)));
        var buf: [16]u8 = undefined;
        var e = wire.Encoder.init(&buf);
        try e.appendVarint(wire.encodeZigZag(c.v));
        try testing.expectEqualStrings(c.want, e.bytes());
    }
}

// --- Go vectors: tags -------------------------------------------------------

test "go vector: tags for every wire type and boundary numbers" {
    const cases = [_]struct { num: wire.Number, typ: wire.Type, want: []const u8 }{
        .{ .num = 1, .typ = .varint, .want = "\x08" },
        .{ .num = 2, .typ = .fixed64, .want = "\x11" },
        .{ .num = 3, .typ = .bytes, .want = "\x1a" },
        .{ .num = 4, .typ = .start_group, .want = "\x23" },
        .{ .num = 5, .typ = .fixed32, .want = "\x2d" },
        .{ .num = 6, .typ = .end_group, .want = "\x34" },
        .{ .num = 150, .typ = .varint, .want = "\xb0\x09" },
        .{ .num = 19000, .typ = .varint, .want = "\xc0\xa3\x09" },
        .{ .num = 19999, .typ = .varint, .want = "\xf8\xe1\x09" },
        .{ .num = 20000, .typ = .varint, .want = "\x80\xe2\x09" },
        .{ .num = 536870911, .typ = .bytes, .want = "\xfa\xff\xff\xff\x0f" },
    };
    for (cases) |c| {
        var buf: [8]u8 = undefined;
        var e = wire.Encoder.init(&buf);
        try e.appendTag(c.num, c.typ);
        try testing.expectEqualStrings(c.want, e.bytes());
        try testing.expectEqual(c.want.len, wire.sizeTag(c.num));

        var d = wire.Decoder.init(c.want);
        const tag = try d.consumeTag();
        try testing.expectEqual(c.num, tag.num);
        try testing.expectEqual(c.typ, tag.typ);
        try testing.expect(d.done());
    }
}

// --- Go vectors: fixed and length-delimited ----------------------------------

test "go vector: fixed32/fixed64 little-endian" {
    var buf: [8]u8 = undefined;
    var e = wire.Encoder.init(&buf);
    try e.appendFixed32(1);
    try testing.expectEqualStrings("\x01\x00\x00\x00", e.bytes());
    var e2 = wire.Encoder.init(&buf);
    try e2.appendFixed32(0xdeadbeef);
    try testing.expectEqualStrings("\xef\xbe\xad\xde", e2.bytes());
    var e3 = wire.Encoder.init(&buf);
    try e3.appendFixed64(1);
    try testing.expectEqualStrings("\x01\x00\x00\x00\x00\x00\x00\x00", e3.bytes());
    var e4 = wire.Encoder.init(&buf);
    try e4.appendFixed64(0x0123456789abcdef);
    try testing.expectEqualStrings("\xef\xcd\xab\x89\x67\x45\x23\x01", e4.bytes());
}

test "go vector: length-delimited bytes" {
    const cases = [_]struct { v: []const u8, want: []const u8 }{
        .{ .v = "testing", .want = "\x07testing" },
        .{ .v = "", .want = "\x00" },
        .{ .v = "hello world", .want = "\x0bhello world" },
    };
    for (cases) |c| {
        var buf: [32]u8 = undefined;
        var e = wire.Encoder.init(&buf);
        try e.appendBytes(c.v);
        try testing.expectEqualStrings(c.want, e.bytes());
        try testing.expectEqual(c.want.len, wire.sizeBytes(c.v.len));

        var d = wire.Decoder.init(c.want);
        try testing.expectEqualStrings(c.v, try d.consumeBytes());
        try testing.expect(d.done());
    }
}

test "go vector: classic field-1 varint 150 message" {
    var buf: [8]u8 = undefined;
    var e = wire.Encoder.init(&buf);
    try e.appendField(1, .{ .varint = 150 });
    try testing.expectEqualStrings("\x08\x96\x01", e.bytes());

    var d = wire.Decoder.init("\x08\x96\x01");
    const f = try d.consumeField();
    try testing.expectEqual(@as(wire.Number, 1), f.num);
    try testing.expectEqual(wire.Type.varint, f.typ);
    try testing.expectEqual(@as(usize, 3), f.n);
    try testing.expect(d.done());
}

// --- Go vectors: groups ------------------------------------------------------

test "go vector: group round-trip and consumeGroup payload" {
    const msg = "\x1b\x08\x2a\x15\x07\x00\x00\x00\x1c"; // group3 vector
    var buf: [16]u8 = undefined;
    var e = wire.Encoder.init(&buf);
    try e.appendField(3, .{ .start_group = "\x08\x2a\x15\x07\x00\x00\x00" });
    try testing.expectEqualStrings(msg, e.bytes());

    var d = wire.Decoder.init(msg);
    const f = try d.consumeField();
    try testing.expectEqual(@as(wire.Number, 3), f.num);
    try testing.expectEqual(wire.Type.start_group, f.typ);
    try testing.expectEqual(msg.len, f.n);
    try testing.expect(d.done());

    var d2 = wire.Decoder.init(msg);
    _ = try d2.consumeTag(); // Go ConsumeGroup expects the start tag consumed
    const payload = try d2.consumeGroup(3);
    try testing.expectEqualStrings("\x08\x2a\x15\x07\x00\x00\x00", payload);
    try testing.expect(d2.done());
}

test "go vector: nested groups" {
    const msg = "\x23\x2b\x08\x01\x2c\x24"; // nested_groups vector
    var buf: [16]u8 = undefined;
    var e = wire.Encoder.init(&buf);
    try e.appendField(4, .{ .start_group = "\x2b\x08\x01\x2c" });
    try testing.expectEqualStrings(msg, e.bytes());

    var d = wire.Decoder.init(msg);
    const f = try d.consumeField();
    try testing.expectEqual(@as(wire.Number, 4), f.num);
    try testing.expectEqual(msg.len, f.n);
}

// --- Unknown field skipping --------------------------------------------------

test "go vector: skip unknown fields lands on known field" {
    // f1 varint 300 | f6 fixed64 | f7 group { f1 varint 9 } | f8 bytes "tail"
    const msg = "\x08\xac\x02\x31\x11\x11\x11\x11\x11\x11\x11\x11\x3b\x08\x09\x3c\x42\x04tail";
    var d = wire.Decoder.init(msg);

    var f = try d.consumeField();
    try testing.expectEqual(@as(wire.Number, 1), f.num);
    try testing.expectEqual(@as(usize, 3), f.n);

    f = try d.consumeField(); // unknown fixed64
    try testing.expectEqual(@as(wire.Number, 6), f.num);
    try testing.expectEqual(wire.Type.fixed64, f.typ);
    try testing.expectEqual(@as(usize, 9), f.n);

    f = try d.consumeField(); // unknown group
    try testing.expectEqual(@as(wire.Number, 7), f.num);
    try testing.expectEqual(wire.Type.start_group, f.typ);
    try testing.expectEqual(@as(usize, 4), f.n);

    f = try d.consumeField(); // unknown bytes
    try testing.expectEqual(@as(wire.Number, 8), f.num);
    try testing.expectEqual(wire.Type.bytes, f.typ);
    try testing.expectEqual(@as(usize, 6), f.n);

    try testing.expect(d.done());
}

// --- Error conditions (ParseError codes) -------------------------------------

test "truncated inputs report Truncated" {
    var d1 = wire.Decoder.init("");
    try testing.expectError(wire.Error.Truncated, d1.consumeVarint());

    var d2 = wire.Decoder.init("\x08");
    try testing.expectError(wire.Error.Truncated, d2.consumeField());

    var d3 = wire.Decoder.init("\x80");
    try testing.expectError(wire.Error.Truncated, d3.consumeVarint());

    var d4 = wire.Decoder.init("\x2d\x01\x02"); // fixed32 needs 4 bytes
    try testing.expectError(wire.Error.Truncated, d4.consumeFixed32());

    var d5 = wire.Decoder.init("\x01\x02\x03\x04\x05\x06\x07"); // fixed64 needs 8
    try testing.expectError(wire.Error.Truncated, d5.consumeFixed64());

    var d6 = wire.Decoder.init("\x0a\x05ab"); // len 5, only 2 bytes
    try testing.expectError(wire.Error.Truncated, d6.consumeBytes());

    var d7 = wire.Decoder.init("\x23\x08\x01"); // unterminated group
    try testing.expectError(wire.Error.Truncated, d7.consumeField());
}

test "varint overflow: 10th byte >= 2 reports Overflow" {
    var d1 = wire.Decoder.init("\x80\x80\x80\x80\x80\x80\x80\x80\x80\x02");
    try testing.expectError(wire.Error.Overflow, d1.consumeVarint());
    var d2 = wire.Decoder.init("\x80\x80\x80\x80\x80\x80\x80\x80\x80\x81");
    try testing.expectError(wire.Error.Overflow, d2.consumeVarint());
}

test "denormalized varint (10 bytes, 10th byte 0) is accepted" {
    var d = wire.Decoder.init("\x80\x80\x80\x80\x80\x80\x80\x80\x80\x00");
    try testing.expectEqual(@as(u64, 0), try d.consumeVarint());
    try testing.expect(d.done());
}

test "field number 0 and tag overflow report FieldNumber" {
    var d1 = wire.Decoder.init("\x00");
    try testing.expectError(wire.Error.FieldNumber, d1.consumeTag());

    // tag varint overflows int32 field number: -1 < MinValidNumber
    var d2 = wire.Decoder.init("\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01");
    try testing.expectError(wire.Error.FieldNumber, d2.consumeTag());
}

test "reserved wire types 6 and 7 report Reserved" {
    var d1 = wire.Decoder.init("\x36\x01"); // num 6, type 6
    try testing.expectError(wire.Error.Reserved, d1.consumeField());
    var d2 = wire.Decoder.init("\x37\x01"); // num 6, type 7
    try testing.expectError(wire.Error.Reserved, d2.consumeField());
}

test "mismatched end group marker reports EndGroup" {
    var d1 = wire.Decoder.init("\x1b\x24"); // start f3, end f4
    try testing.expectError(wire.Error.EndGroup, d1.consumeField());
    var d2 = wire.Decoder.init("\x24"); // bare end group
    try testing.expectError(wire.Error.EndGroup, d2.consumeField());
}

test "group recursion limit matches protowire" {
    // Field 3 start group tag is 0x1b, end group is 0x1c (see group3 vector).
    // 10001 nested groups (field 3) parse fine, 10002 exceed the limit.
    inline for (.{ 10001, 10002 }) |levels| {
        var buf: [2 * levels + 2]u8 = undefined;
        for (0..levels) |i| {
            buf[i] = 0x1b;
            buf[levels + i] = 0x1c;
        }
        var d = wire.Decoder.init(buf[0 .. 2 * levels]);
        if (levels == 10001) {
            const f = try d.consumeField();
            try testing.expectEqual(@as(usize, 2 * levels), f.n);
        } else {
            try testing.expectError(wire.Error.RecursionDepth, d.consumeField());
        }
    }
}

// --- Round-trips ---------------------------------------------------------------

test "round-trip sweep of varint values" {
    const specials = [_]u64{ 0, 1, 127, 128, 300, 1 << 20, (1 << 28) - 1, 1 << 28, (1 << 35) - 1, 1 << 35, 1 << 42, 1 << 49, 1 << 56, (1 << 63) - 1, 1 << 63, std.math.maxInt(u64) };
    var buf: [10]u8 = undefined;
    var v: u64 = 0;
    while (v < 2000) : (v += 1) {
        try roundTripVarint(&buf, v);
    }
    for (specials) |x| {
        try roundTripVarint(&buf, x);
    }
}

fn roundTripVarint(buf: []u8, v: u64) !void {
    var e = wire.Encoder.init(buf);
    try e.appendVarint(v);
    try testing.expectEqual(wire.sizeVarint(v), e.bytes().len);
    var d = wire.Decoder.init(e.bytes());
    try testing.expectEqual(v, try d.consumeVarint());
    try testing.expect(d.done());
}

test "round-trip of every wire type via appendField/consumeTag+consume" {
    var buf: [64]u8 = undefined;

    var e = wire.Encoder.init(&buf);
    try e.appendField(1, .{ .varint = 300 });
    try e.appendField(2, .{ .fixed64 = 0x0123456789abcdef });
    try e.appendField(3, .{ .bytes = "netbird" });
    try e.appendField(4, .{ .start_group = "\x08\x01" });
    try e.appendField(5, .{ .fixed32 = 0xdeadbeef });
    var d = wire.Decoder.init(e.bytes());

    var tag = try d.consumeTag();
    try testing.expectEqual(@as(wire.Number, 1), tag.num);
    try testing.expectEqual(wire.Type.varint, tag.typ);
    try testing.expectEqual(@as(u64, 300), try d.consumeVarint());

    tag = try d.consumeTag();
    try testing.expectEqual(@as(wire.Number, 2), tag.num);
    try testing.expectEqual(wire.Type.fixed64, tag.typ);
    try testing.expectEqual(@as(u64, 0x0123456789abcdef), try d.consumeFixed64());

    tag = try d.consumeTag();
    try testing.expectEqual(@as(wire.Number, 3), tag.num);
    try testing.expectEqual(wire.Type.bytes, tag.typ);
    try testing.expectEqualStrings("netbird", try d.consumeBytes());

    tag = try d.consumeTag();
    try testing.expectEqual(@as(wire.Number, 4), tag.num);
    try testing.expectEqual(wire.Type.start_group, tag.typ);
    try testing.expectEqualStrings("\x08\x01", try d.consumeGroup(4));

    tag = try d.consumeTag();
    try testing.expectEqual(@as(wire.Number, 5), tag.num);
    try testing.expectEqual(wire.Type.fixed32, tag.typ);
    try testing.expectEqual(@as(u32, 0xdeadbeef), try d.consumeFixed32());

    try testing.expect(d.done());
}

// --- Sizes --------------------------------------------------------------------

test "size functions agree with encoded lengths" {
    var buf: [16]u8 = undefined;
    var v: u64 = 0;
    while (v < 3000) : (v += 1) {
        var e = wire.Encoder.init(&buf);
        try e.appendVarint(v);
        try testing.expectEqual(e.bytes().len, wire.sizeVarint(v));
    }
    try testing.expectEqual(@as(usize, 4), wire.sizeFixed32());
    try testing.expectEqual(@as(usize, 8), wire.sizeFixed64());
    try testing.expectEqual(@as(usize, 8), wire.sizeBytes("testing".len)); // 1 len byte + 7
    // SizeGroup counts payload + end tag only (like Go): 7 + sizeTag(3)=1 → 8;
    // the full group3 field is start tag (1) + 8 = 9 bytes.
    try testing.expectEqual(@as(usize, 8), wire.sizeGroup(3, 7));
}

// --- Encoder capacity ----------------------------------------------------------

test "encoder without room reports NoSpaceLeft" {
    var small: [2]u8 = undefined;
    var e = wire.Encoder.init(&small);
    _ = try e.appendVarint(300); // exactly 2 bytes fit
    try testing.expectError(wire.Error.NoSpaceLeft, e.appendVarint(1));
    var e2 = wire.Encoder.init(small[0..1]);
    try testing.expectError(wire.Error.NoSpaceLeft, e2.appendVarint(300));
    var three: [3]u8 = undefined;
    var e3 = wire.Encoder.init(&three);
    try testing.expectError(wire.Error.NoSpaceLeft, e3.appendBytes("abcd"));
}

// --- Bool helpers ----------------------------------------------------------------

test "bool encode/decode" {
    try testing.expectEqual(@as(u64, 0), wire.encodeBool(false));
    try testing.expectEqual(@as(u64, 1), wire.encodeBool(true));
    try testing.expect(!wire.decodeBool(0));
    try testing.expect(wire.decodeBool(1));
    try testing.expect(wire.decodeBool(2)); // nonzero means true
}

test "zigzag edges: min/max int64" {
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), wire.encodeZigZag(-(1 << 63)));
    try testing.expectEqual(@as(i64, -(1 << 63)), wire.decodeZigZag(std.math.maxInt(u64)));
    try testing.expectEqual(@as(u64, std.math.maxInt(u64) - 1), wire.encodeZigZag((1 << 63) - 1));
    try testing.expectEqual(@as(i64, (1 << 63) - 1), wire.decodeZigZag(std.math.maxInt(u64) - 1));
}
