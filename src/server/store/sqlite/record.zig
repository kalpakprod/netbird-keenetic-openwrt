// Port of netbird management/server/store (v0.80.0), AGPL-3.0
// SQLite record format v2. No column affinity is applied at this layer.
const std = @import("std");
pub const Value = union(enum) { null, integer: i64, real: f64, text: []const u8, blob: []const u8 };
pub const Error = error{ Truncated, Malformed, TooLarge };
pub const Varint = struct { value: u64, len: usize };
pub fn getVarint(bytes: []const u8) Error!Varint {
    var v: u64 = 0;
    for (0..8) |i| {
        if (i >= bytes.len) return error.Truncated;
        v = (v << 7) | (bytes[i] & 127);
        if (bytes[i] < 128) return .{ .value = v, .len = i + 1 };
    }
    if (bytes.len < 9) return error.Truncated;
    return .{ .value = (v << 8) | bytes[8], .len = 9 };
}
fn varintSize(v: u64) usize {
    if (v > 0x00ffffffffffffff) return 9;
    var n: usize = 1;
    var x = v;
    while (x > 127) : (n += 1) x >>= 7;
    return n;
}
/// Does not modify the buffer if it is too short.
pub fn putVarint(bytes: []u8, v: u64) Error!usize {
    const n = varintSize(v);
    if (bytes.len < n) return error.Truncated;
    var x = v;
    var i = n;
    if (n == 9) {
        bytes[8] = @truncate(x);
        x >>= 8;
        i = 8;
    }
    while (i > 0) {
        i -= 1;
        bytes[i] = @as(u8, @truncate(x & 127)) | (if (i + 1 < n) @as(u8, 128) else 0);
        x >>= 7;
    }
    return n;
}
pub fn serialTypeFor(value: Value) Error!u64 {
    return switch (value) {
        .null => 0,
        .real => 7,
        .integer => |v| blk: {
            if (v == 0) break :blk 8;
            if (v == 1) break :blk 9;
            const widths = [_]u7{ 8, 16, 24, 32, 48, 64 };
            for (widths, 1..) |bits, t| {
                const limit = @as(i128, 1) << (bits - 1);
                if (v >= -limit and v < limit) break :blk @intCast(t);
            }
            unreachable;
        },
        .text => |b| try sizedType(b.len, 13),
        .blob => |b| try sizedType(b.len, 12),
    };
}
fn sizedType(n: usize, base: u64) Error!u64 {
    if (n > (std.math.maxInt(u64) - base) / 2) return error.TooLarge;
    return @as(u64, n) * 2 + base;
}
pub fn sizeOf(t: u64) Error!usize {
    const n: u64 = switch (t) {
        0, 8, 9 => 0,
        1 => 1,
        2 => 2,
        3 => 3,
        4 => 4,
        5 => 6,
        6, 7 => 8,
        10, 11 => return error.Malformed,
        else => (t - 12) / 2,
    };
    return std.math.cast(usize, n) orelse error.TooLarge;
}
fn add(x: usize, y: usize) Error!usize {
    return std.math.add(usize, x, y) catch error.TooLarge;
}
/// Caller owns returned bytes. REAL stays REAL, including signed zero. SQLite's
/// SQL affinity processing belongs above this codec, not in serialTypeFor.
pub fn encode(allocator: std.mem.Allocator, values: []const Value) ![]u8 {
    var types_size: usize = 0;
    var body_size: usize = 0;
    for (values) |v| {
        const t = try serialTypeFor(v);
        types_size = try add(types_size, varintSize(t));
        body_size = try add(body_size, try sizeOf(t));
    }
    var header_size = try add(types_size, 1);
    while (true) {
        const next = try add(types_size, varintSize(@intCast(header_size)));
        if (next == header_size) break;
        header_size = next;
    }
    const bytes = try allocator.alloc(u8, try add(header_size, body_size));
    errdefer allocator.free(bytes);
    var h = try putVarint(bytes, @intCast(header_size));
    var b = header_size;
    for (values) |v| {
        const t = try serialTypeFor(v);
        h += try putVarint(bytes[h..header_size], t);
        const size = try sizeOf(t);
        switch (v) {
            .null => {},
            .integer, .real => {
                var bits: u64 = switch (v) {
                    .integer => |i| @bitCast(i),
                    .real => |f| @bitCast(f),
                    else => unreachable,
                };
                var j = size;
                while (j > 0) {
                    j -= 1;
                    bytes[b + j] = @truncate(bits);
                    bits >>= 8;
                }
            },
            .text, .blob => {
                const data = switch (v) {
                    .text => |s| s,
                    .blob => |s| s,
                    else => unreachable,
                };
                @memcpy(bytes[b..][0..size], data);
            },
        }
        b += size;
    }
    return bytes;
}
/// Caller owns only the returned Value array. TEXT/BLOB slices borrow bytes.
/// Accepts non-canonical varints as SQLite does, but rejects reserved serial
/// types, incomplete headers/bodies, and trailing bytes outside the record.
pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) ![]Value {
    const first = try getVarint(bytes);
    const header = std.math.cast(usize, first.value) orelse return error.TooLarge;
    if (header < first.len) return error.Malformed;
    if (header > bytes.len) return error.Truncated;
    var h = first.len;
    var count: usize = 0;
    var body: usize = 0;
    while (h < header) {
        const t = getVarint(bytes[h..header]) catch return error.Malformed;
        h += t.len;
        body = try add(body, try sizeOf(t.value));
        count += 1;
    }
    if (body > bytes.len - header) return error.Truncated;
    if (body < bytes.len - header) return error.Malformed;
    const values = try allocator.alloc(Value, count);
    errdefer allocator.free(values);
    h = first.len;
    var b = header;
    for (values) |*v| {
        const t = try getVarint(bytes[h..header]);
        h += t.len;
        const size = try sizeOf(t.value);
        const data = bytes[b..][0..size];
        v.* = switch (t.value) {
            0 => .null,
            8 => .{ .integer = 0 },
            9 => .{ .integer = 1 },
            1...7 => blk: {
                var bits: u64 = 0;
                for (data) |byte| bits = (bits << 8) | byte;
                if (t.value == 7) break :blk .{ .real = @bitCast(bits) };
                if (size < 8 and data[0] & 128 != 0) bits |= std.math.maxInt(u64) ^ (@as(u64, 1) << @as(u6, @intCast(size * 8))) - 1;
                break :blk .{ .integer = @bitCast(bits) };
            },
            10, 11 => unreachable,
            else => if (t.value & 1 == 0) .{ .blob = data } else .{ .text = data },
        };
        b += size;
    }
    return values;
}
