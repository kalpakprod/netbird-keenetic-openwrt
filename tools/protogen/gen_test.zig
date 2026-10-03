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
