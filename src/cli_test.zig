// M8 CLI parser tests: public parse/usage only. No network, no engine.

const std = @import("std");
const cli = @import("cli.zig");

test "no args shows help" {
    var o = try cli.parse(std.testing.allocator, &.{"netbird"});
    defer o.deinit();
    try std.testing.expectEqual(cli.Command.help, o.command);
    try std.testing.expect(o.config == null);
    try std.testing.expect(o.setup_key == null);
    try std.testing.expect(o.management_url == null);
    try std.testing.expect(!o.foreground);
    try std.testing.expect(!o.json);

    var o2 = try cli.parse(std.testing.allocator, &.{});
    defer o2.deinit();
    try std.testing.expectEqual(cli.Command.help, o2.command);
}

test "help command" {
    var o = try cli.parse(std.testing.allocator, &.{ "netbird", "help" });
    defer o.deinit();
    try std.testing.expectEqual(cli.Command.help, o.command);
}

test "help flag overrides command" {
    var o = try cli.parse(std.testing.allocator, &.{ "netbird", "up", "--help" });
    defer o.deinit();
    try std.testing.expectEqual(cli.Command.help, o.command);
}

test "version" {
    var o = try cli.parse(std.testing.allocator, &.{ "netbird", "version" });
    defer o.deinit();
    try std.testing.expectEqual(cli.Command.version, o.command);
}

test "status with flags before command" {
    var o = try cli.parse(std.testing.allocator, &.{ "netbird", "--json", "status" });
    defer o.deinit();
    try std.testing.expectEqual(cli.Command.status, o.command);
    try std.testing.expect(o.json);
}

test "login with setup key" {
    var o = try cli.parse(std.testing.allocator, &.{ "netbird", "login", "--setup-key", "KEY123" });
    defer o.deinit();
    try std.testing.expectEqual(cli.Command.login, o.command);
    try std.testing.expectEqualStrings("KEY123", o.setup_key.?);
}

test "up foreground with mixed short and long flags" {
    var o = try cli.parse(std.testing.allocator, &.{
        "netbird",          "up",            "-F",
        "--management-url", "https://m:443", "-c",
        "/tmp/cfg",
    });
    defer o.deinit();
    try std.testing.expectEqual(cli.Command.up, o.command);
    try std.testing.expect(o.foreground);
    try std.testing.expectEqualStrings("https://m:443", o.management_url.?);
    try std.testing.expectEqualStrings("/tmp/cfg", o.config.?);
}

test "down bare" {
    var o = try cli.parse(std.testing.allocator, &.{ "netbird", "down" });
    defer o.deinit();
    try std.testing.expectEqual(cli.Command.down, o.command);
}

test "unknown command" {
    try std.testing.expectError(
        cli.Error.UnknownCommand,
        cli.parse(std.testing.allocator, &.{ "netbird", "frobnicate" }),
    );
}

test "unknown flag" {
    try std.testing.expectError(
        cli.Error.UnknownFlag,
        cli.parse(std.testing.allocator, &.{ "netbird", "up", "--frobnicate" }),
    );
    // equals form is not a supported flag shape
    try std.testing.expectError(
        cli.Error.UnknownFlag,
        cli.parse(std.testing.allocator, &.{ "netbird", "up", "--config=/tmp/x" }),
    );
}

test "missing value" {
    try std.testing.expectError(
        cli.Error.MissingValue,
        cli.parse(std.testing.allocator, &.{ "netbird", "up", "--config" }),
    );
}

test "empty value" {
    try std.testing.expectError(
        cli.Error.EmptyValue,
        cli.parse(std.testing.allocator, &.{ "netbird", "--config", "" }),
    );
}

test "duplicate setup key" {
    try std.testing.expectError(
        cli.Error.DuplicateSetupKey,
        cli.parse(std.testing.allocator, &.{ "netbird", "login", "--setup-key", "A", "--setup-key", "B" }),
    );
}

test "positional extra" {
    try std.testing.expectError(
        cli.Error.UnexpectedPositional,
        cli.parse(std.testing.allocator, &.{ "netbird", "version", "x" }),
    );
}

test "values are owned copies" {
    var key = [_]u8{ 'K', '1' };
    var cfg = [_]u8{ 'c', '1' };
    var url = [_]u8{ 'u', '1' };
    const argv = [_][]const u8{
        "netbird",          "up",
        "--setup-key",      key[0..],
        "--config",         cfg[0..],
        "--management-url", url[0..],
    };
    var o = try cli.parse(std.testing.allocator, &argv);
    defer o.deinit();
    @memset(&key, 'X');
    @memset(&cfg, 'Y');
    @memset(&url, 'Z');
    try std.testing.expectEqualStrings("K1", o.setup_key.?);
    try std.testing.expectEqualStrings("c1", o.config.?);
    try std.testing.expectEqualStrings("u1", o.management_url.?);
}

test "usage output names commands and flags" {
    var buf: [2048]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try cli.usage(&w);
    const text = w.buffered();
    for ([_][]const u8{
        "netbird",  "version", "status",      "login",            "up",           "down",
        "--config", "-c",      "--setup-key", "--management-url", "--foreground", "-F",
        "--json",   "--help",
    }) |want| {
        try std.testing.expect(std.mem.indexOf(u8, text, want) != null);
    }
}

test "duplicate config last wins" {
    var o = try cli.parse(std.testing.allocator, &.{ "netbird", "up", "--config", "a", "--config", "b" });
    defer o.deinit();
    try std.testing.expectEqualStrings("b", o.config.?);
}
