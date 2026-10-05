//! Tests for the Zig code generator: parse a representative proto subset,
//! generate, and assert the emitted shapes (types, wire tags, packed loops,
//! oneof unions, map entries, deinit structure).

const std = @import("std");
const ast = @import("ast.zig");
const parser = @import("parser.zig");
const gen = @import("gen.zig");

const sample =
    \\syntax = "proto3";
    \\package testpkg;
    \\import "google/protobuf/timestamp.proto";
    \\option go_package = "/proto";
    \\message Inner {
    \\  sint64 delta = 1;
    \\  fixed32 checksum = 2;
    \\}
    \\message Sample {
    \\  enum Kind { NONE = 0; BASIC = 1; }
    \\  Kind kind = 1;
    \\  string name = 2;
    \\  repeated uint32 ports = 3;
    \\  repeated string labels = 4;
    \\  Inner inner = 5;
    \\  optional int32 retries = 6;
    \\  map<string, Inner> items = 7;
    \\  oneof choice {
    \\    uint32 number = 8;
    \\    Inner detail = 9;
    \\  }
    \\  google.protobuf.Timestamp stamp = 10;
    \\  message Nested {
    \\    bool flag = 1;
    \\  }
    \\  Nested nested = 11;
    \\  int64 big = 12;
    \\}
;

fn genSample(arena: *std.heap.ArenaAllocator) ![]const u8 {
    var p = try parser.Parser.init(arena.allocator(), sample);
    const file = try p.parse();
    return gen.generate(arena.allocator(), &file, "test/sample.proto");
}

fn expectContains(out: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, out, needle) == null) {
        std.debug.print("missing: {s}\n--- output ---\n{s}\n", .{ needle, out });
        return error.MissingOutput;
    }
}

test "generate emits struct fields and types" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const out = try genSample(&arena);
    try expectContains(out, "pub const Sample = struct {");
    try expectContains(out, "kind: Sample.Kind = @enumFromInt(0),");
    try expectContains(out, "name: []const u8 = \"\",");
    try expectContains(out, "ports: []u32 = &.{}");
    try expectContains(out, "labels: [][]const u8 = &.{}");
    try expectContains(out, "inner: ?Inner = null,");
    try expectContains(out, "retries: ?i32 = null,");
    try expectContains(out, "stamp: ?Timestamp = null,");
    try expectContains(out, "pub const Timestamp = struct {");
    try expectContains(out, "seconds: i64 = 0,");
    try expectContains(out, "pub const Kind = enum(i32) {");
    try expectContains(out, "BASIC = 1,");
    try expectContains(out, "_,");
    try expectContains(out, "pub const Nested = struct {");
    try expectContains(out, "nested: ?Sample.Nested = null,");
}

test "generate emits oneof union and map entry" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const out = try genSample(&arena);
    try expectContains(out, "pub const choice_union = union(enum) {");
    try expectContains(out, "number: u32,");
    try expectContains(out, "detail: Inner,");
    try expectContains(out, "choice: ?choice_union = null,");
    try expectContains(out, "pub const items_Entry = struct {");
    try expectContains(out, "key: []const u8 = \"\",");
    try expectContains(out, "value: Inner = .{}");
    try expectContains(out, "items: []items_Entry = &.{}");
}

test "generate emits wire semantics" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const out = try genSample(&arena);
    // field-number ascending order: 1 before 2 before 3 ...
    try expectContains(out, "wire.sizeTag(1)");
    try expectContains(out, "wire.sizeTag(12)");
    // sint64 zigzag
    try expectContains(out, "wire.encodeZigZag(m.delta)");
    try expectContains(out, "wire.decodeZigZag(v)");
    // fixed32
    try expectContains(out, "if ((m.checksum != 0)) n += wire.sizeTag(2) + 4;");
    try expectContains(out, "e.appendFixed32(m.checksum)");
    // packed repeated scalar
    try expectContains(out, "var payload: usize = 0;");
    try expectContains(out, "n += wire.sizeTag(3) + wire.sizeVarint(payload) + payload;");
    // packed and unpacked decode arms for ports
    try expectContains(out, "var pd = wire.Decoder.init(pb);");
    try expectContains(out, "3 => switch (tag.typ) {");
    // int32 sign extension (proto3 optional captures as v)
    try expectContains(out, "if (m.retries) |v| n += wire.sizeTag(6) + wire.sizeVarint(@as(u64, @bitCast(@as(i64, v))));");
    // message nesting encode
    try expectContains(out, "try c.encode(e.buf[e.len..][0..sz]);");
    // depth guard
    try expectContains(out, "if (depth == 0) return error.RecursionDepth;");
    // recursion default
    try expectContains(out, "pub const default_recursion_depth: u32 = 10000;");
    // deinit structure
    try expectContains(out, "pub fn deinit(m: *@This(), a: std.mem.Allocator) void {");
    try expectContains(out, "for (m.items) |*en| {");
}

test "generate header carries license by path" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var p = try parser.Parser.init(arena.allocator(), sample);
    const file = try p.parse();
    const agpl = try gen.generate(arena.allocator(), &file, "shared/signal/proto/signalexchange.proto");
    try expectContains(agpl, "AGPL-3.0");
    const bsd = try gen.generate(arena.allocator(), &file, "client/proto/daemon.proto");
    try expectContains(bsd, "BSD-3-Clause");
}

// Compile and execute the actual generated codec, rather than asserting text.
// The parent zig test is admitted by swarm-heavy.sh. Its compiler child runs
// synchronously under that same admission and closes the inherited gate fd.
fn runGenerated(schema: []const u8, checks: []const u8) !void {
    if (@import("builtin").target.cpu.arch != .x86_64) return;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var p = try parser.Parser.init(a, schema);
    const file = try p.parse();
    const source = try gen.generate(a, &file, "shared/signal/proto/signalexchange.proto");
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const wire = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, "src/proto/wire.zig", a, .unlimited);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "wire.zig", .data = wire });
    var codecs = try tmp.dir.createDirPathOpen(std.testing.io, "gen", .{});
    defer codecs.close(std.testing.io);
    try codecs.writeFile(std.testing.io, .{ .sub_path = "codec.zig", .data = source });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "runtime.zig", .data = checks });
    var path_buf: [4096]u8 = undefined;
    const n = try tmp.dir.realPath(std.testing.io, &path_buf);
    const result = try std.process.run(a, std.testing.io, .{
        .argv = &.{ "sh", "-c", "exec 9>&-; exec zig test runtime.zig" },
        .cwd = .{ .path = path_buf[0..n] },
    });
    std.debug.print("generated runtime:\n{s}{s}", .{ result.stdout, result.stderr });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
}


test "generated unknown fields preserve raw bytes" {
    try runGenerated(
        "syntax = \"proto3\"; message Mode { bool direct = 1; } message Empty {}",
        \\const std = @import("std");
        \\const c = @import("gen/codec.zig");
        \\test "unknown and wrong wire type round trip" {
        \\    const input = [_]u8{16,1};
        \\    var m = try c.Mode.decode(std.testing.allocator,&input);
        \\    defer m.deinit(std.testing.allocator);
        \\    try std.testing.expectEqual(@as(usize,2),m.size());
        \\    var out: [2]u8 = undefined;
        \\    try m.encode(&out);
        \\    try std.testing.expectEqualSlices(u8,&input,&out);
        \\    const wrong = [_]u8{10,1,42,27,32,1,28};
        \\    var w = try c.Mode.decode(std.testing.allocator,&wrong);
        \\    defer w.deinit(std.testing.allocator);
        \\    var wb: [7]u8 = undefined;
        \\    try w.encode(&wb);
        \\    try std.testing.expectEqualSlices(u8,&wrong,&wb);
        \\    var empty = try c.Empty.decode(std.testing.allocator,&input);
        \\    defer empty.deinit(std.testing.allocator);
        \\    try std.testing.expectEqual(@as(usize,2),empty.size());
        \\    try empty.encode(&out);
        \\    try std.testing.expectEqualSlices(u8,&input,&out);
        \\}
    );
}
