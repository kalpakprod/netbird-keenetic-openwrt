// Pure gRPC value-helper tests (std-only via format.zig).
// Live tests against a Go grpc server live in src/net/grpc_live_test.zig:
// build.zig discovery gives each suite no named imports, so the suite that
// needs both grpc/ and h2/ sits at their common dir with relative imports.

const std = @import("std");
const format = @import("format.zig");

test "grpc timeout formats largest integral unit" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("5S", format.formatTimeout(5 * std.time.ns_per_s, &buf));
    try std.testing.expectEqualStrings("50m", format.formatTimeout(50 * std.time.ns_per_ms, &buf));
    try std.testing.expectEqualStrings("2H", format.formatTimeout(2 * 3600 * std.time.ns_per_s, &buf));
    try std.testing.expectEqualStrings("1500n", format.formatTimeout(1500, &buf));
    try std.testing.expectEqualStrings("3u", format.formatTimeout(3000, &buf));
}

test "grpc message percent-decodes" {
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("no such thing", try format.decodeMessage("no%20such%20thing", &buf));
    try std.testing.expectEqualStrings("ok", try format.decodeMessage("ok", &buf));
    try std.testing.expectError(format.Error.GrpcProtocol, format.decodeMessage("bad%2", &buf));
}
