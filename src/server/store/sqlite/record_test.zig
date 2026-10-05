// Port of netbird management/server/store (v0.80.0), AGPL-3.0
const std = @import("std");
const r = @import("record.zig");
const a = std.testing.allocator;
fn unhex(s: []const u8) ![]u8 {
    const b = try a.alloc(u8, s.len / 2);
    errdefer a.free(b);
    _ = try std.fmt.hexToBytes(b, s);
    return b;
}
test "Go SQLite raw records decode typed values and encode byte exact" {
    var lines = std.mem.splitScalar(u8, @embedFile("testdata/record/go-vectors.tsv"), '\n');
    var count: usize = 0;
    while (lines.next()) |line| {
        if (line.len == 0 or line[0] == '#') continue;
        var cols = std.mem.splitScalar(u8, line, '\t');
        const bytes = try unhex(cols.next().?);
        defer a.free(bytes);
        const kind = cols.next().?;
        const expected = cols.next().?;
        var value: r.Value = undefined;
        var owned: ?[]u8 = null;
        defer if (owned) |b| a.free(b);
        if (std.mem.eql(u8, kind, "null")) value = .null else if (std.mem.eql(u8, kind, "int")) {
            value = .{ .integer = try std.fmt.parseInt(i64, expected, 10) };
        } else if (std.mem.eql(u8, kind, "real")) {
            value = .{ .real = @bitCast(try std.fmt.parseInt(u64, expected, 16)) };
        } else {
            owned = try unhex(expected);
            value = if (std.mem.eql(u8, kind, "text")) .{ .text = owned.? } else .{ .blob = owned.? };
        }
        const decoded = try r.decode(a, bytes);
        defer a.free(decoded); // byte slices borrow the input, only the value array is owned.
        try std.testing.expectEqual(@as(usize, 1), decoded.len);
        try equal(value, decoded[0]);
        const encoded = try r.encode(a, &.{value});
        defer a.free(encoded);
        try std.testing.expectEqualSlices(u8, bytes, encoded);
        count += 1;
    }
    try std.testing.expectEqual(@as(usize, 35), count);
}
fn equal(x: r.Value, y: r.Value) !void {
    try std.testing.expectEqual(std.meta.activeTag(x), std.meta.activeTag(y));
    switch (x) {
        .null => {},
        .integer => |v| try std.testing.expectEqual(v, y.integer),
        .real => |v| try std.testing.expectEqual(@as(u64, @bitCast(v)), @as(u64, @bitCast(y.real))),
        .text => |v| try std.testing.expectEqualSlices(u8, v, y.text),
        .blob => |v| try std.testing.expectEqualSlices(u8, v, y.blob),
    }
}
test "varint known SQLite encodings and random minimal widths" {
    const cases = [_]struct { v: u64, hex: []const u8 }{
        .{ .v = 0, .hex = "00" },                                  .{ .v = 127, .hex = "7f" },                                  .{ .v = 128, .hex = "8100" },
        .{ .v = 16383, .hex = "ff7f" },                            .{ .v = 16384, .hex = "818000" },                            .{ .v = 0x00ffffffffffffff, .hex = "ffffffffffffff7f" },
        .{ .v = 0x0100000000000000, .hex = "80c080808080808000" }, .{ .v = std.math.maxInt(u64), .hex = "ffffffffffffffffff" },
    };
    for (cases) |c| {
        var buf: [9]u8 = undefined;
        const n = try r.putVarint(&buf, c.v);
        const b = try unhex(c.hex);
        defer a.free(b);
        try std.testing.expectEqualSlices(u8, b, buf[0..n]);
        const got = try r.getVarint(b);
        try std.testing.expectEqual(c.v, got.value);
        try std.testing.expectEqual(b.len, got.len);
    }
    var rng = std.Random.DefaultPrng.init(0x5199);
    for (0..10000) |_| {
        const v = rng.random().int(u64);
        var buf: [9]u8 = undefined;
        const n = try r.putVarint(&buf, v);
        const got = try r.getVarint(buf[0..n]);
        try std.testing.expectEqual(v, got.value);
        try std.testing.expectEqual(n, got.len);
        var bits = v;
        var want: usize = 1;
        while (bits > 127 and want < 9) : (want += 1) bits >>= 7;
        try std.testing.expectEqual(want, n);
        const iv: i64 = @bitCast(v);
        const t = try r.serialTypeFor(.{ .integer = iv });
        const size = try r.sizeOf(t);
        const widths = [_]usize{ 1, 2, 3, 4, 6, 8 };
        var expected: usize = 8;
        if (iv == 0 or iv == 1) expected = 0 else for (widths) |w| {
            const limit: i128 = @as(i128, 1) << @intCast(w * 8 - 1);
            if (iv >= -limit and iv < limit) {
                expected = w;
                break;
            }
        }
        try std.testing.expectEqual(expected, size);
    }
}
test "multi column header fixed point and round trip" {
    const values = try a.alloc(r.Value, 200);
    defer a.free(values);
    for (values, 0..) |*v, i| v.* = switch (i % 5) {
        0 => .null,
        1 => .{ .integer = -123456789 },
        2 => .{ .real = -0.5 },
        3 => .{ .text = "世界" },
        else => .{ .blob = "\x00\xff" },
    };
    const bytes = try r.encode(a, values);
    defer a.free(bytes);
    const header = try r.getVarint(bytes);
    try std.testing.expectEqual(@as(u64, 202), header.value);
    const got = try r.decode(a, bytes);
    defer a.free(got);
    try std.testing.expectEqual(values.len, got.len);
    for (values, got) |x, y| try equal(x, y);
    for (0..bytes.len) |n| try std.testing.expectError(error.Truncated, r.decode(a, bytes[0..n]));
}
test "corrupt headers reserved types and bounded writes" {
    for ([_][]const u8{ &.{0}, &.{ 1, 0 }, &.{ 2, 10 }, &.{ 2, 11 }, &.{ 2, 0, 99 }, &.{ 2, 255, 0 } }) |b| {
        try std.testing.expectError(error.Malformed, r.decode(a, b));
    }
    try std.testing.expectError(error.Truncated, r.getVarint(&.{128}));
    var tiny: [1]u8 = undefined;
    try std.testing.expectError(error.Truncated, r.putVarint(&tiny, 128));
    try std.testing.expectError(error.Malformed, r.sizeOf(10));
    try std.testing.expectError(error.Malformed, r.sizeOf(11));
}
test "allocation failures release encoder and decoder allocations" {
    try std.testing.checkAllAllocationFailures(a, allocationCase, .{});
}
fn allocationCase(allocator: std.mem.Allocator) !void {
    const bytes = try r.encode(allocator, &.{ .{ .text = "abc" }, .{ .integer = -999 } });
    defer allocator.free(bytes);
    const values = try r.decode(allocator, bytes);
    defer allocator.free(values);
}
