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

test "generated signal packed features wire length" {
    try runGenerated(
        "syntax = \"proto3\"; message Body { repeated uint32 features = 1; }",
        \\const std = @import("std");
        \\const codec = @import("gen/codec.zig");
        \\test "features [1,2,3] exact packed bytes" {
        \\    var values = [_]u32{1,2,3};
        \\    const m = codec.Body{ .features = &values };
        \\    try std.testing.expectEqual(@as(usize, 5), m.size());
        \\    var buf: [5]u8 = undefined;
        \\    try m.encode(&buf);
        \\    try std.testing.expectEqualSlices(u8, &.{0x0a,3,1,2,3}, &buf);
        \\    var decoded = try codec.Body.decode(std.testing.allocator, &buf);
        \\    defer decoded.deinit(std.testing.allocator);
        \\    try std.testing.expectEqualSlices(u32, &values, decoded.features);
        \\}
    );
}

test "generated single case oneof executes" {
    try runGenerated(
        "syntax = \"proto3\"; message JobResponse { oneof result { bool accepted = 1; } }",
        \\const std = @import("std");
        \\const codec = @import("gen/codec.zig");
        \\test "single arm size encode decode" {
        \\    const m = codec.JobResponse{ .result = .{ .accepted = true } };
        \\    try std.testing.expectEqual(@as(usize, 2), m.size());
        \\    var buf: [2]u8 = undefined;
        \\    try m.encode(&buf);
        \\    try std.testing.expectEqualSlices(u8, &.{8,1}, &buf);
        \\    var decoded = try codec.JobResponse.decode(std.testing.allocator, &buf);
        \\    defer decoded.deinit(std.testing.allocator);
        \\    try std.testing.expect(decoded.result.?.accepted);
        \\}
    );
}

test "duplicate singular submessages merge" {
    try runGenerated(
        "syntax = \"proto3\"; message Mode { optional bool direct = 1; optional bool other = 2; } message Body { Mode mode = 5; }",
        \\const std = @import("std");
        \\const codec = @import("gen/codec.zig");
        \\test "empty occurrence preserves previous fields and explicit defaults overwrite" {
        \\    var m = try codec.Body.decode(std.testing.allocator, &.{0x2a,2,8,1,0x2a,0});
        \\    defer m.deinit(std.testing.allocator);
        \\    try std.testing.expectEqual(@as(?bool, true), m.mode.?.direct);
        \\    var n = try codec.Body.decode(std.testing.allocator, &.{0x2a,2,8,1,0x2a,4,8,0,16,1});
        \\    defer n.deinit(std.testing.allocator);
        \\    try std.testing.expectEqual(@as(?bool, false), n.mode.?.direct);
        \\    try std.testing.expectEqual(@as(?bool, true), n.mode.?.other);
        \\}
    );
}

test "duplicate strings and failed decode release ownership" {
    try runGenerated(
        "syntax = \"proto3\"; message Message { string key = 1; bytes body = 2; repeated string names = 3; repeated bytes blobs = 4; }",
        \\const std = @import("std");
        \\const codec = @import("gen/codec.zig");
        \\test "duplicate singular strings last wins without leaks" {
        \\    var m = try codec.Message.decode(std.testing.allocator, &.{10,1,97,10,1,98,18,1,97,18,1,98});
        \\    defer m.deinit(std.testing.allocator);
        \\    try std.testing.expectEqualStrings("b", m.key);
        \\    try std.testing.expectEqualStrings("b", m.body);
        \\}
        \\test "truncated decode frees singular and repeated allocations" {
        \\    try std.testing.expectError(error.Truncated, codec.Message.decode(std.testing.allocator, &.{10,1,97,26,1,98,34,1,99,18,3,1}));
        \\}
        \\test "allocation failures release pending elements" {
        \\    try std.testing.checkAllAllocationFailures(std.testing.allocator, decode, .{});
        \\}
        \\fn decode(a: std.mem.Allocator) !void {
        \\    var m = try codec.Message.decode(a, &.{10,1,97,10,1,98,26,1,97,26,1,98,34,1,99});
        \\    defer m.deinit(a);
        \\}
    );
}

test "generated SSHAuth map last wins and deterministic order" {
    try runGenerated(
        "syntax = \"proto3\"; message MachineUserIndexes { uint32 index = 1; } message SSHAuth { map<string, MachineUserIndexes> machine_users = 3; }",
        \\const std = @import("std");
        \\const c = @import("gen/codec.zig");
        \\test "duplicate key replaces owned message and sorts constructed entries" {
        \\    const input = [_]u8{26,7,10,1,'b',18,2,8,1,26,7,10,1,'b',18,2,8,2};
        \\    var m = try c.SSHAuth.decode(std.testing.allocator, &input);
        \\    defer m.deinit(std.testing.allocator);
        \\    try std.testing.expectEqual(@as(usize,1),m.machine_users.len);
        \\    try std.testing.expectEqual(@as(u32,2),m.machine_users[0].value.index);
        \\    var entries = [_]c.SSHAuth.machine_users_Entry{.{.key="b",.value=.{.index=2}},.{.key="a",.value=.{.index=1}}};
        \\    const constructed = c.SSHAuth{.machine_users=&entries};
        \\    var out: [18]u8 = undefined;
        \\    try constructed.encode(&out);
        \\    try std.testing.expectEqualSlices(u8,&.{26,7,10,1,'a',18,2,8,1,26,7,10,1,'b',18,2,8,2},&out);
        \\    try std.testing.expectEqualStrings("b",entries[0].key);
        \\}
    );
}

test "headers normalize upstream origins and pinned license" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var p = try parser.Parser.init(arena.allocator(), sample);
    const file = try p.parse();
    const paths = [_][]const u8{
        "upstream/netbird/management/proto/job.proto",
        "/home/user/.cache/release/upstream-v080/signal/proto/job.proto",
        "upstream-v080/relay/proto/job.proto",
        "combined/proto/job.proto",
        "upstream/netbird/shared/management/proto/management.proto",
        "/cache/upstream-v080/shared/signal/proto/signalexchange.proto",
    };
    const origins = [_][]const u8{ "management/proto/job.proto", "signal/proto/job.proto", "relay/proto/job.proto", "combined/proto/job.proto", "shared/management/proto/management.proto", "shared/signal/proto/signalexchange.proto" };
    for (paths, origins) |path, origin| {
        const out = try gen.generate(arena.allocator(), &file, path);
        const expected = try std.fmt.allocPrint(arena.allocator(), "Port of netbird {s} (v0.80.0), AGPL-3.0", .{origin});
        try expectContains(out, expected);
        try std.testing.expect(std.mem.indexOf(u8, out, "upstream") == null);
        try std.testing.expect(std.mem.indexOf(u8, out, "/home/") == null);
    }
    const bsd = try gen.generate(arena.allocator(), &file, "/cache/upstream-v080/client/proto/daemon.proto");
    try expectContains(bsd, "Port of netbird client/proto/daemon.proto (v0.80.0), BSD-3-Clause");
    try std.testing.expect(std.mem.indexOf(u8, bsd, "/cache/") == null);
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

test "review 144 canonical unknown tag" {
    try runGenerated("syntax = \"proto3\"; message Empty {}",
        \\const std = @import("std");
        \\const c = @import("gen/codec.zig");
        \\test "minimal tag preserves nonminimal value" {
        \\    var m = try c.Empty.decode(std.testing.allocator, &.{0x90,0,0x81,0});
        \\    defer m.deinit(std.testing.allocator);
        \\    try std.testing.expectEqualSlices(u8, &.{0x10,0x81,0}, m.unknown_fields);
        \\    try std.testing.expectEqual(@as(usize,3), m.size());
        \\}
    );
}

test "review 144 unknown storage OOM releases decoded fields" {
    try runGenerated("syntax = \"proto3\"; message Message { string key = 1; repeated string names = 2; }",
        \\const std = @import("std");
        \\const c = @import("gen/codec.zig");
        \\test "append and owned slice failures" {
        \\    for ([_]usize{1,2}) |index| {
        \\        var a = std.testing.FailingAllocator.init(std.testing.allocator, .{.fail_index=index,.resize_fail_index=0});
        \\        try std.testing.expectError(error.OutOfMemory,c.Message.decode(a.allocator(), &.{10,1,97,24,1}));
        \\        try std.testing.expectEqual(a.allocated_bytes,a.freed_bytes);
        \\    }
        \\}
    );
}

test "review 144 repeated child append owns pending child" {
    try runGenerated("syntax = \"proto3\"; message Child {} message Parent { repeated Child children = 2; }",
        \\const std = @import("std");
        \\const c = @import("gen/codec.zig");
        \\test "child append OOM" {
        \\    var a = std.testing.FailingAllocator.init(std.testing.allocator, .{.fail_index=1});
        \\    try std.testing.expectError(error.OutOfMemory,c.Parent.decode(a.allocator(), &.{18,2,16,1}));
        \\    try std.testing.expectEqual(a.allocated_bytes,a.freed_bytes);
        \\}
    );
}

test "review 144 replaced oneof releases unknown child" {
    try runGenerated("syntax = \"proto3\"; message Child {} message Parent { oneof result { bool accepted = 4; Child detail = 5; } }",
        \\const std = @import("std");
        \\const c = @import("gen/codec.zig");
        \\test "message to scalar replacement" {
        \\    var m = try c.Parent.decode(std.testing.allocator, &.{42,2,16,1,32,1});
        \\    defer m.deinit(std.testing.allocator);
        \\    try std.testing.expect(m.result.?.accepted);
        \\}
    );
}

test "review 187 pending map entry owns unknown bytes" {
    try runGenerated("syntax = \"proto3\"; message Child {} message Parent { map<string, Child> items = 3; string later = 6; }",
        \\const std = @import("std");
        \\const c = @import("gen/codec.zig");
        \\test "append OOM releases child unknown bytes" {
        \\    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 1 });
        \\    try std.testing.expectError(error.OutOfMemory, c.Parent.decode(failing.allocator(), &.{26,4,18,2,16,1}));
        \\    try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
        \\}
    );
}
