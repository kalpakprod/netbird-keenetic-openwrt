// Pure gRPC value-helper tests (std-only via format.zig).
// Live tests against a Go grpc server live in src/net/grpc_live_test.zig:
// build.zig discovery gives each suite no named imports, so the suite that
// needs both grpc/ and h2/ sits at their common dir with relative imports.

const std = @import("std");
const format = @import("format.zig");

test "grpc timeout matches Go EncodeDuration" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("5000000u", format.formatTimeout(5 * std.time.ns_per_s, &buf));
    try std.testing.expectEqualStrings("50000000n", format.formatTimeout(50 * std.time.ns_per_ms, &buf));
    try std.testing.expectEqualStrings("7200000m", format.formatTimeout(2 * 3600 * std.time.ns_per_s, &buf));
    try std.testing.expectEqualStrings("1500n", format.formatTimeout(1500, &buf));
    try std.testing.expectEqualStrings("3000n", format.formatTimeout(3000, &buf));
}

test "grpc timeout bounds values to eight digits" {
    var buf: [32]u8 = undefined;
    // Eight-digit cap with upward rounding (Go maxTimeoutValue=99999999).
    try std.testing.expectEqualStrings("99999999n", format.formatTimeout(99999999, &buf));
    try std.testing.expectEqualStrings("100000u", format.formatTimeout(100000000, &buf));
    try std.testing.expectEqualStrings("100001u", format.formatTimeout(100000001, &buf));
    // Threshold crossings micro/milli/sec/minute.
    try std.testing.expectEqualStrings("99999999u", format.formatTimeout(99999999 * std.time.ns_per_us, &buf));
    try std.testing.expectEqualStrings("100000m", format.formatTimeout(100000000 * std.time.ns_per_us, &buf));
    try std.testing.expectEqualStrings("99999999m", format.formatTimeout(99999999 * std.time.ns_per_ms, &buf));
    try std.testing.expectEqualStrings("100000S", format.formatTimeout(100000000 * std.time.ns_per_ms, &buf));
    try std.testing.expectEqualStrings("99999999S", format.formatTimeout(99999999 * std.time.ns_per_s, &buf));
    try std.testing.expectEqualStrings("1666667M", format.formatTimeout(100000000 * std.time.ns_per_s, &buf));
    try std.testing.expectEqualStrings("99999999M", format.formatTimeout(99999999 * 60 * std.time.ns_per_s, &buf));
    try std.testing.expectEqualStrings("1666667H", format.formatTimeout(100000000 * 60 * std.time.ns_per_s, &buf));
    // Nonpositive saturates to 0n; max i64 formats without overflow.
    try std.testing.expectEqualStrings("0n", format.formatTimeout(0, &buf));
    try std.testing.expectEqualStrings("0n", format.formatTimeout(-1, &buf));
    try std.testing.expectEqualStrings("0n", format.formatTimeout(std.math.minInt(i64), &buf));
    try std.testing.expectEqualStrings("2562048H", format.formatTimeout(std.math.maxInt(i64), &buf));
}

test "grpc message percent-decodes" {
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("no such thing", try format.decodeMessage("no%20such%20thing", &buf));
    try std.testing.expectEqualStrings("ok", try format.decodeMessage("ok", &buf));
    try std.testing.expectError(format.Error.GrpcProtocol, format.decodeMessage("bad%2", &buf));
}
