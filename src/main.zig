//! NetBird client for Keenetic and OpenWrt routers, ported from Go to Zig.
//! Work in progress: see PLAN.md. Ported modules live under src/<module>/.
const std = @import("std");

pub fn main(init: std.process.Init) !void {
    _ = init;
    std.debug.print("netbird-zig: not functional yet, see PLAN.md\n", .{});
}
