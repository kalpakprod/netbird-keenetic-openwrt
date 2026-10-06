const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "netbird",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    run_cmd.addPassthruArgs();
    b.step("run", "Run the client").dependOn(&run_cmd.step);

    // Every src/**/*_test.zig is its own suite; no hand list to keep in sync.
    // Native: compile and run. Cross (e.g. -Dtarget=aarch64-linux-musl):
    // compile only, so the same set is at least type-checked.
    const test_step = b.step("test", "Run tests");
    const is_native = target.query.isNative();
    const io = b.graph.io;
    var src_dir = b.root.root_dir.handle.openDir(io, "src", .{ .iterate = true }) catch {
        std.debug.print("warning: no src/ directory, no tests discovered\n", .{});
        return;
    };
    defer src_dir.close(io);
    b.dependOnDirectoryContents(b.path("src"));
    discoverTests(b, test_step, target, optimize, src_dir, "src", is_native) catch |err| {
        std.debug.print("test discovery failed: {t}\n", .{err});
    };

    // protogen tests live under tools/ and are not covered by src/ discovery.
    const proto_tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("tools/protogen/main.zig"),
        .target = target,
        .optimize = optimize,
    }) });
    if (is_native) {
        test_step.dependOn(&b.addRunArtifact(proto_tests).step);
    } else {
        test_step.dependOn(&proto_tests.step);
    }
}

fn discoverTests(
    b: *std.Build,
    test_step: *std.Build.Step,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    dir: std.Io.Dir,
    prefix: []const u8,
    is_native: bool,
) !void {
    const io = b.graph.io;
    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        if (entry.kind == .directory) {
            const sub_path = try std.fmt.allocPrint(b.allocator, "{s}/{s}", .{ prefix, entry.name });
            var sub = try dir.openDir(io, entry.name, .{ .iterate = true });
            defer sub.close(io);
            try discoverTests(b, test_step, target, optimize, sub, sub_path, is_native);
        } else if (entry.kind == .file and std.mem.endsWith(u8, entry.name, "_test.zig")) {
            const file_path = try std.fmt.allocPrint(b.allocator, "{s}/{s}", .{ prefix, entry.name });
            const mod = b.createModule(.{
                .root_source_file = b.path(file_path),
                .target = target,
                .optimize = optimize,
            });
            const tests = b.addTest(.{ .root_module = mod });
            if (is_native) {
                test_step.dependOn(&b.addRunArtifact(tests).step);
            } else {
                test_step.dependOn(&tests.step);
            }
        }
    }
}
