// Port of netbird shared/relay/client/dialer/ws/ws.go (v0.80.0), BSD-3-Clause
const std = @import("std");
const url = @import("url.zig");

test "prepareURL matches Go oracle" {
    const cases = [_]struct { input: []const u8, want: ?[]const u8 }{
        .{ .input = "rel://host", .want = "ws://host/relay" },                                       .{ .input = "rels://host:443", .want = "wss://host:443/relay" },
        .{ .input = "rel://host:1234/old", .want = "ws://host:1234/relay" },                         .{ .input = "rels://host/path?q=1#frag", .want = "wss://host/relay?q=1#frag" },
        .{ .input = "rel://user:pass@host:9/x?q=1#f", .want = "ws://user:pass@host:9/relay?q=1#f" }, .{ .input = "rel://[::1]:443", .want = "ws://[::1]:443/relay" },
        .{ .input = "rel://", .want = null },                                                        .{ .input = "rel:///x", .want = null },
        .{ .input = "http://host", .want = null },                                                   .{ .input = "wss://host", .want = null },
        .{ .input = "", .want = null },                                                              .{ .input = "host", .want = null },
        .{ .input = "REL://HOST", .want = "ws://HOST/relay" },                                       .{ .input = "rel://host?x=1#f", .want = "ws://host/relay?x=1#f" },
    };
    for (cases) |case| {
        var out: [256]u8 = undefined;
        if (case.want) |want| try std.testing.expectEqualStrings(want, try url.prepareUrl(case.input, &out)) else try std.testing.expectError(if (std.mem.startsWith(u8, case.input, "rel://")) error.MissingHost else error.UnsupportedScheme, url.prepareUrl(case.input, &out));
    }
}

test "NoSpace leaves output untouched" {
    var out: [8]u8 = @splat('X');
    try std.testing.expectError(error.NoSpace, url.prepareUrl("rel://host", &out));
    try std.testing.expectEqualSlices(u8, &(@as([8]u8, @splat('X'))), &out);
}

test "bad scheme is rejected" {
    var out: [64]u8 = undefined;
    try std.testing.expectError(error.UnsupportedScheme, url.prepareUrl("relays://host", &out));
    try std.testing.expectError(error.UnsupportedScheme, url.prepareUrl("host", &out));
}

test "invalid URL leaves output untouched" {
    var out: [128]u8 = @splat('X');
    for ([_][]const u8{ "rel://[::1", "rel://host:abc", "rel://host/%zz", "rel://ho st", "rel://host\n" }) |input| {
        try std.testing.expectError(error.BadUrl, url.prepareUrl(input, &out));
        try std.testing.expectEqualSlices(u8, &(@as([128]u8, @splat('X'))), &out);
    }
}

test "exact capacity and path replacement" {
    var out: [15]u8 = undefined;
    try std.testing.expectEqualStrings("ws://host/relay", try url.prepareUrl("rel://host/a/long/path", &out));
}
