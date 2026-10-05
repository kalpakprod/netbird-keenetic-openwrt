//! NetBird client for Keenetic and OpenWrt routers, ported from Go to Zig.
//! M8 foreground executable: parses argv, dispatches offline commands via
//! app.run. Adapted for release v080 (W06-main-dispatch) from the M8 offline
//! draft in wt-m8-main-offline-muse/src/main.zig; behavior unchanged.
//! Production login/up exit NetworkUnavailable until the real
//! service adapter lands (later card); no tunnels are created here.
const std = @import("std");
const app = @import("app.zig");

pub fn main(init: std.process.Init) !void {
    var out_buf: [4096]u8 = undefined;
    var err_buf: [2048]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(init.io, &out_buf);
    var stderr = std.Io.File.stderr().writerStreaming(init.io, &err_buf);

    const argv = collectArgs(init) catch {
        stderr.interface.writeAll("error: out of memory\n") catch {};
        stderr.flush() catch {};
        stdout.flush() catch {};
        std.process.exit(app.exit_config);
    };

    const code = app.run(init.gpa, init.io, argv, &stdout.interface, &stderr.interface, null);
    stdout.flush() catch {};
    stderr.flush() catch {};
    if (code != 0) std.process.exit(code);
}

/// Collect argv (argv[0] first) into arena storage that outlives the
/// dispatcher call. cli.parse copies every value it keeps.
fn collectArgs(init: std.process.Init) std.mem.Allocator.Error![]const []const u8 {
    const alloc = init.arena.allocator();
    var counter = std.process.Args.Iterator.init(init.minimal.args);
    var n: usize = 0;
    while (counter.next() != null) n += 1;
    const argv = try alloc.alloc([]const u8, n);
    var it = std.process.Args.Iterator.init(init.minimal.args);
    var i: usize = 0;
    while (it.next()) |a| : (i += 1) argv[i] = a;
    return argv;
}
