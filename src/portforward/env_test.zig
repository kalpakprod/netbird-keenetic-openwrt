// Tests for the env.go port: the ParseBool truth table is the contract.
const std = @import("std");
const env = @import("env.zig");

test "parseBoolGo matches strconv.ParseBool" {
    for ([_][]const u8{ "1", "t", "T", "TRUE", "true", "True" }) |s| {
        try std.testing.expect(env.parseBoolGo(s));
    }
    for ([_][]const u8{ "", "0", "f", "F", "FALSE", "false", "False", "yes", "2", " true" }) |s| {
        try std.testing.expect(!env.parseBoolGo(s));
    }
}
