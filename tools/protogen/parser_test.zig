//! Tests for the proto3-subset parser against realistic snippets of the
//! upstream NetBird .proto files.

const std = @import("std");
const ast = @import("ast.zig");
const parser = @import("parser.zig");

test "parse signal message subset" {
    const src =
        \\syntax = "proto3";
        \\package signalexchange;
        \\service SignalExchange {
        \\  rpc Send(EncryptedMessage) returns (EncryptedMessage) {}
        \\}
        \\message EncryptedMessage {
        \\  string key = 2;
        \\  string remoteKey = 3;
        \\  bytes body = 4;
        \\}
        \\message Body {
        \\  enum Type { OFFER = 0; ANSWER = 1; }
        \\  Type type = 1;
        \\  string payload = 2;
        \\  uint32 wgListenPort = 3;
        \\  repeated uint32 featuresSupported = 6;
        \\  optional string relayServerAddress = 8;
        \\  reserved 9;
        \\  optional bytes sessionId = 10;
        \\}
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var p = try parser.Parser.init(arena.allocator(), src);
    const f = try p.parse();
    try std.testing.expectEqualStrings("proto3", f.syntax);
    try std.testing.expectEqualStrings("signalexchange", f.package);
    try std.testing.expectEqual(@as(usize, 2), f.messages.len);
    const body = f.messages[1];
    try std.testing.expectEqualStrings("Body", body.name);
    try std.testing.expectEqual(@as(usize, 6), body.fields.len);
    try std.testing.expectEqual(ast.Label.optional, body.fields[4].label);
    try std.testing.expectEqual(@as(i32, 8), body.fields[4].number);
    try std.testing.expectEqual(@as(usize, 1), body.enums.len);
    try std.testing.expectEqualStrings("Type", body.enums[0].name);
    try std.testing.expectEqual(@as(usize, 2), body.enums[0].values.len);
}

test "parse oneof map nested reserved ranges and options" {
    const src =
        \\syntax = "proto3";
        \\package management;
        \\option go_package = "/proto";
        \\import "google/protobuf/timestamp.proto";
        \\message SSHAuth {
        \\  map<string, MachineUserIndexes> machine_users = 3;
        \\}
        \\message PortInfo {
        \\  oneof portSelection {
        \\    uint32 port = 1;
        \\    Range range = 2;
        \\  }
        \\  message Range {
        \\    uint32 start = 1;
        \\    uint32 end = 2;
        \\  }
        \\}
        \\message FirewallRule {
        \\  string PeerIP = 1 [deprecated = true];
        \\  repeated bytes sourcePrefixes = 9;
        \\  reserved 26 to 50;
        \\}
        \\message Envelope {
        \\  oneof payload {
        \\    Full full = 1;
        \\    Delta delta = 2;
        \\  }
        \\  google.protobuf.Timestamp stamp = 7;
        \\  .management.Deep deep = 8;
        \\}
        \\enum Signed {
        \\  ZERO = 0;
        \\  MINUS = -1;
        \\}
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var p = try parser.Parser.init(arena.allocator(), src);
    const f = try p.parse();
    try std.testing.expectEqualStrings("management", f.package);
    const ssh = f.messages[0];
    try std.testing.expectEqual(@as(usize, 1), ssh.maps.len);
    try std.testing.expectEqual(ast.Scalar.string, ssh.maps[0].key);
    try std.testing.expectEqualStrings("MachineUserIndexes", ssh.maps[0].value.named);
    const port = f.messages[1];
    try std.testing.expectEqual(@as(usize, 1), port.oneofs.len);
    try std.testing.expectEqual(@as(usize, 2), port.oneofs[0].fields.len);
    try std.testing.expectEqual(@as(usize, 1), port.messages.len);
    const fw = f.messages[2];
    try std.testing.expectEqualStrings("deprecated", fw.fields[0].options[0].name);
    try std.testing.expectEqualStrings("true", fw.fields[0].options[0].value);
    try std.testing.expectEqual(@as(i32, 26), fw.reserved[0].start);
    try std.testing.expectEqual(@as(i32, 50), fw.reserved[0].end);
    const env = f.messages[3];
    try std.testing.expectEqualStrings("google.protobuf.Timestamp", env.fields[0].typ.named);
    try std.testing.expectEqualStrings(".management.Deep", env.fields[1].typ.named);
    const signed = f.enums[0];
    try std.testing.expectEqual(@as(i32, 0), signed.values[0].number);
    try std.testing.expectEqual(@as(i32, -1), signed.values[1].number);
}

test "parse errors" {
    const cases = [_]struct { src: []const u8, want: parser.Error }{
        .{ .src = "syntax = \"proto2\";", .want = parser.Error.Syntax },
        .{ .src = "syntax = \"proto3\"; message A { string a = 1; string b = 1; }", .want = parser.Error.DuplicateFieldNumber },
        .{ .src = "syntax = \"proto3\"; message A { reserved 3; string a = 3; }", .want = parser.Error.ReservedConflict },
        .{ .src = "syntax = \"proto3\"; message A { map<float, string> m = 1; }", .want = parser.Error.BadMapKey },
        .{ .src = "syntax = \"proto3\"; message A { required string a = 1; }", .want = parser.Error.RequiredLabel },
        .{ .src = "syntax = \"proto3\"; message A { string a = 19001; }", .want = parser.Error.BadNumber },
        .{ .src = "syntax = \"proto3\"; enum E { A = 1; }", .want = parser.Error.EnumZeroMissing },
        .{ .src = "syntax = \"proto3\"; enum E { A = 0; B = 0; }", .want = parser.Error.DuplicateEnumValue },
        .{ .src = "syntax = \"proto3\"; message A { string a = 1", .want = parser.Error.UnexpectedEof },
    };
    for (cases) |c| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        var p = parser.Parser.init(arena.allocator(), c.src) catch continue;
        const got = p.parse();
        try std.testing.expectError(c.want, got);
    }
}
