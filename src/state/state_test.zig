// Port of netbird client/internal/statemanager (v0.79.0), BSD-3-Clause — tests.
// Golden: testdata/state-golden.txt from gen/statevecs (real json.Marshal +
// util.WriteBytesWithRestrictedPermission path).

const std = @import("std");
const state = @import("state.zig");
const profile = @import("profile.zig");

const tio = std.testing.io;
const golden_txt = @embedFile("testdata/state-golden.txt");

fn goldenJson() []const u8 {
    const nl = std.mem.indexOfScalar(u8, golden_txt, '\n').?;
    return golden_txt[0..nl];
}

fn scratchRoot(allocator: std.mem.Allocator, tag: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "/tmp/nb-state-test-{d}-{s}", .{ std.os.linux.getpid(), tag });
}

fn cleanup(root: []const u8) void {
    std.Io.Dir.cwd().deleteTree(tio, root) catch {};
}

const Sample = struct {
    counter: i64,
    tags: []const []const u8,
    when: []const u8,
};

test "persist matches Go byte-for-byte" {
    const root = try scratchRoot(std.testing.allocator, "persist");
    defer std.testing.allocator.free(root);
    defer cleanup(root);
    const path = try std.fmt.allocPrint(std.testing.allocator, "{s}/sub/state.json", .{root});
    defer std.testing.allocator.free(path);

    var m = state.Manager.init(std.testing.allocator, tio, path);
    defer m.deinit();
    try m.register("sample");
    try m.register("gone");
    // Declaration order matches Go's sorted map keys: counter, tags, when.
    const tags = [_][]const u8{"a"};
    try m.update("sample", .{ .counter = @as(i64, 42), .tags = tags, .when = "then" });
    try m.delete("gone");
    try m.persist();

    const data = try profile.readFileLseek(tio, std.testing.allocator, path);
    defer std.testing.allocator.free(data);
    try std.testing.expectEqualSlices(u8, goldenJson(), data);

    // 0600 like Go
    const st = try std.Io.Dir.cwd().statFile(tio, path, .{});
    try std.testing.expectEqual(@as(u32, 0o600), @as(u32, @intFromEnum(st.permissions)) & 0o777);
}

test "persist is a no-op when clean" {
    const root = try scratchRoot(std.testing.allocator, "clean");
    defer std.testing.allocator.free(root);
    defer cleanup(root);
    const path = try std.fmt.allocPrint(std.testing.allocator, "{s}/state.json", .{root});
    defer std.testing.allocator.free(path);

    var m = state.Manager.init(std.testing.allocator, tio, path);
    defer m.deinit();
    try m.register("sample");
    try m.persist(); // not dirty: no file created
    const data = profile.readFileLseek(tio, std.testing.allocator, path) catch |err| switch (err) {
        profile.FileError.NotFound => null,
        else => return err,
    };
    try std.testing.expect(data == null);
}

test "load and get round trip" {
    const root = try scratchRoot(std.testing.allocator, "roundtrip");
    defer std.testing.allocator.free(root);
    defer cleanup(root);
    const path = try std.fmt.allocPrint(std.testing.allocator, "{s}/state.json", .{root});
    defer std.testing.allocator.free(path);

    {
        var m = state.Manager.init(std.testing.allocator, tio, path);
        defer m.deinit();
        try m.register("sample");
        const tags = [_][]const u8{ "a", "b" };
        try m.update("sample", .{ .counter = @as(i64, 7), .tags = tags, .when = "now" });
        try m.persist();
    }
    {
        var m = state.Manager.init(std.testing.allocator, tio, path);
        defer m.deinit();
        try m.register("sample");
        try m.load("sample");
        var got = (try m.get("sample", Sample)).?;
        defer got.deinit();
        try std.testing.expectEqual(@as(i64, 7), got.value.counter);
        try std.testing.expectEqual(@as(usize, 2), got.value.tags.len);
        try std.testing.expectEqualStrings("now", got.value.when);
    }
}

test "unregistered update is rejected" {
    var m = state.Manager.init(std.testing.allocator, tio, "/tmp/nb-state-test-nope/state.json");
    defer m.deinit();
    try std.testing.expectError(state.Error.StateNotRegistered, m.update("nope", .{}));
    try std.testing.expectError(state.Error.StateNotRegistered, m.delete("nope"));
}

test "oom during update keeps old state and stays usable" {
    var fail = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var m = state.Manager.init(fail.allocator(), tio, "/tmp/nb-state-test-nope-oom/state.json");
    defer m.deinit();
    try m.register("a");
    try m.updateRaw("a", "{\"v\":1}");
    // fail the replacement dupe inside setRaw (delete calls it directly)
    fail.fail_index = fail.alloc_index;
    try std.testing.expectError(error.OutOfMemory, m.delete("a"));
    fail.fail_index = std.math.maxInt(usize);
    // old raw intact
    const V = struct { v: i64 };
    var got = (try m.get("a", V)).?;
    defer got.deinit();
    try std.testing.expectEqual(@as(i64, 1), got.value.v);
    // manager still usable (frees the live raw exactly once)
    try m.updateRaw("a", "{\"v\":3}");
    var got2 = (try m.get("a", V)).?;
    defer got2.deinit();
    try std.testing.expectEqual(@as(i64, 3), got2.value.v);
}

test "oom during dirty mark leaves entry unchanged and clean" {
    const root = try scratchRoot(std.testing.allocator, "oomdirty");
    defer std.testing.allocator.free(root);
    defer cleanup(root);
    const path = try std.fmt.allocPrint(std.testing.allocator, "{s}/state.json", .{root});
    defer std.testing.allocator.free(path);

    var fail = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var m = state.Manager.init(fail.allocator(), tio, path);
    defer m.deinit();
    try m.register("a");
    try m.updateRaw("a", "{\"v\":1}");
    try m.persist();
    // fail the dirty-key dupe: replacement ok, markDirty errors
    // (delete calls setRaw directly, so indices stay deterministic)
    fail.fail_index = fail.alloc_index + 1;
    try std.testing.expectError(error.OutOfMemory, m.delete("a"));
    fail.fail_index = std.math.maxInt(usize);
    // entry unchanged ...
    const V = struct { v: i64 };
    var got = (try m.get("a", V)).?;
    defer got.deinit();
    try std.testing.expectEqual(@as(i64, 1), got.value.v);
    // ... and not dirty: persist rewrites nothing
    try m.persist();
    const data = try profile.readFileLseek(tio, std.testing.allocator, path);
    defer std.testing.allocator.free(data);
    try std.testing.expectEqualSlices(u8, "{\"a\":{\"v\":1}}", data);
}

test "deleteByName needs the name in the file" {
    const root = try scratchRoot(std.testing.allocator, "delbyname");
    defer std.testing.allocator.free(root);
    defer cleanup(root);
    const path = try std.fmt.allocPrint(std.testing.allocator, "{s}/state.json", .{root});
    defer std.testing.allocator.free(path);

    var m = state.Manager.init(std.testing.allocator, tio, path);
    defer m.deinit();
    try m.register("sample");
    const tags = [_][]const u8{"a"};
    try m.update("sample", .{ .counter = @as(i64, 1), .tags = tags, .when = "x" });
    try m.persist();
    // missing file section -> StateNotFound (no registration needed)
    try std.testing.expectError(state.Error.StateNotFound, m.deleteByName("absent"));
    // present -> null + dirty, key survives persist like Go
    try m.deleteByName("sample");
    try std.testing.expect((try m.get("sample", Sample)) == null);
    try m.persist();
    const data = try profile.readFileLseek(tio, std.testing.allocator, path);
    defer std.testing.allocator.free(data);
    try std.testing.expectEqualSlices(u8, "{\"sample\":null}", data);
}

test "deleteAll counts file states" {
    const root = try scratchRoot(std.testing.allocator, "delall");
    defer std.testing.allocator.free(root);
    defer cleanup(root);
    const path = try std.fmt.allocPrint(std.testing.allocator, "{s}/state.json", .{root});
    defer std.testing.allocator.free(path);

    var m = state.Manager.init(std.testing.allocator, tio, path);
    defer m.deinit();
    try std.testing.expectEqual(@as(usize, 0), try m.deleteAll()); // missing file
    try m.register("a");
    try m.register("b");
    try m.update("a", .{ .x = @as(i64, 1) });
    try m.update("b", .{ .y = @as(i64, 2) });
    try m.persist();
    try std.testing.expectEqual(@as(usize, 2), try m.deleteAll());
    try m.persist();
    const data = try profile.readFileLseek(tio, std.testing.allocator, path);
    defer std.testing.allocator.free(data);
    try std.testing.expectEqualSlices(u8, "{\"a\":null,\"b\":null}", data);
}

test "savedNames skips nulls" {
    const root = try scratchRoot(std.testing.allocator, "names");
    defer std.testing.allocator.free(root);
    defer cleanup(root);
    const path = try std.fmt.allocPrint(std.testing.allocator, "{s}/state.json", .{root});
    defer std.testing.allocator.free(path);

    var m = state.Manager.init(std.testing.allocator, tio, path);
    defer m.deinit();
    const empty = try m.savedNames();
    try std.testing.expectEqual(@as(usize, 0), empty.len);
    try m.register("sample");
    try m.register("gone");
    const tags = [_][]const u8{"a"};
    try m.update("sample", .{ .counter = @as(i64, 42), .tags = tags, .when = "then" });
    try m.delete("gone");
    try m.persist();
    const names = try m.savedNames();
    defer m.freeNames(names);
    try std.testing.expectEqual(@as(usize, 1), names.len);
    try std.testing.expectEqualStrings("sample", names[0]);
}

test "corrupt file is renamed aside" {
    const root = try scratchRoot(std.testing.allocator, "corrupt");
    defer std.testing.allocator.free(root);
    defer cleanup(root);
    const path = try std.fmt.allocPrint(std.testing.allocator, "{s}/state.json", .{root});
    defer std.testing.allocator.free(path);

    var m = state.Manager.init(std.testing.allocator, tio, path);
    defer m.deinit();
    try m.register("sample");
    const tags = [_][]const u8{"a"};
    try m.update("sample", .{ .counter = @as(i64, 1), .tags = tags, .when = "x" });
    try m.persist();
    // corrupt the file
    {
        var f = try std.Io.Dir.openFileAbsolute(tio, path, .{ .mode = .write_only });
        defer f.close(tio);
        try f.writePositionalAll(tio, "{oops", 0);
    }
    try std.testing.expect(try m.backupIfCorrupt());
    // original gone, backup exists with the corrupt content
    const gone = profile.readFileLseek(tio, std.testing.allocator, path) catch |err| switch (err) {
        profile.FileError.NotFound => null,
        else => return err,
    };
    try std.testing.expect(gone == null);
    var dir = try std.Io.Dir.openDirAbsolute(tio, root, .{ .iterate = true });
    defer dir.close(tio);
    var it = dir.iterate();
    var found_backup = false;
    while (try it.next(tio)) |entry| {
        if (std.mem.startsWith(u8, entry.name, "state.json.corrupted.")) found_backup = true;
    }
    try std.testing.expect(found_backup);
    // valid file: no backup
    try m.persist(); // still dirty from update -> rewrites valid file
    try std.testing.expect(!try m.backupIfCorrupt());
}

fn wipeCounter(s: *Sample) anyerror!void {
    s.counter = 0;
}

fn failCleanup(_: *Sample) anyerror!void {
    return error.Boom;
}

test "cleanupByName deletes on success, preserves on error" {
    const root = try scratchRoot(std.testing.allocator, "cleanup");
    defer std.testing.allocator.free(root);
    defer cleanup(root);
    const path = try std.fmt.allocPrint(std.testing.allocator, "{s}/state.json", .{root});
    defer std.testing.allocator.free(path);

    var m = state.Manager.init(std.testing.allocator, tio, path);
    defer m.deinit();
    try m.register("sample");
    const tags = [_][]const u8{"a"};
    try m.update("sample", .{ .counter = @as(i64, 9), .tags = tags, .when = "x" });
    try m.persist();
    // error path preserves the value
    try std.testing.expectError(state.Error.CleanupFailed, m.cleanupByName("sample", Sample, failCleanup));
    var kept = (try m.get("sample", Sample)).?;
    defer kept.deinit();
    try std.testing.expectEqual(@as(i64, 9), kept.value.counter);
    // success path deletes
    try m.cleanupByName("sample", Sample, wipeCounter);
    try std.testing.expect((try m.get("sample", Sample)) == null);
    // unregistered name rejected
    try std.testing.expectError(
        state.Error.StateNotRegistered,
        m.cleanupByName("nope", Sample, wipeCounter),
    );
}
