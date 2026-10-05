// Port of netbird management/server/store (v0.80.0), AGPL-3.0 — tests.
// Vectors: gen/sqlite-fixtures/ref-small.db, created by the pinned upstream
// Go driver stack (gorm sqlite v1.5.7 + mattn go-sqlite3 v1.14.42) via
// gen/sqlite-fixtures/goref. The fixture is cache-local reference only;
// tests embed its observed header values, never the database itself.
// What this proves: the VFS reads a real Go-created SQLite file (magic,
// 4096-byte pages, 4 pages, rollback-journal v1, UTF-8), persists
// page writes across close/reopen, rejects malformed/truncated input, and
// serializes an independent locking process (flock holder) via timeout.
// What it does NOT prove: SQL, b-tree, pager, WAL, transactions.

const std = @import("std");
const builtin = @import("builtin");
const file = @import("file.zig");

const tio = std.testing.io;

// Observed header of the Go-created reference database
// (gen/sqlite-fixtures/ref-small.db, 16384 bytes):
// magic ok, page size 4096, write/read version 1, reserved 0,
// declared pages 4, encoding UTF-8 (1), schema format 4.
const ref_page_size: u32 = 4096;
const ref_page_count: u32 = 4;

fn scratchRoot(allocator: std.mem.Allocator) ![]u8 {
    const root = try std.fmt.allocPrint(allocator, "/tmp/nb-sqlite-file-test-{d}", .{std.os.linux.getpid()});
    std.Io.Dir.createDirAbsolute(tio, root, @enumFromInt(0o750)) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    return root;
}

fn cleanup(root: []const u8) void {
    std.Io.Dir.cwd().deleteTree(tio, root) catch {};
}

test "header parses real Go-created database" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    const root = try scratchRoot(alloc);
    defer alloc.free(root);
    defer cleanup(root);
    const path = try std.fmt.allocPrint(alloc, "{s}/copy.db", .{root});
    defer alloc.free(path);

    // Copy the Go-created reference in through Zig IO.
    {
        const src = std.Io.Dir.openFileAbsolute(tio, "/home/kukuruza/.cache/netbird-zig-context/release-v080-20261005/gen/sqlite-fixtures/ref-small.db", .{ .mode = .read_only }) catch return error.SkipZigTest;
        defer src.close(tio);
        const dst = try std.Io.Dir.createFileAbsolute(tio, path, .{ .read = true, .truncate = true });
        defer dst.close(tio);
        var buf: [8192]u8 = undefined;
        var off: u64 = 0;
        while (true) {
            const n = try src.readPositionalAll(tio, &buf, off);
            if (n == 0) break;
            try dst.writePositionalAll(tio, buf[0..n], off);
            off += n;
        }
        try dst.sync(tio);
    }

    var db = try file.DbFile.openAbsolute(tio, path, .read_write);
    defer db.close();
    const h = try db.readHeader();
    try std.testing.expectEqual(ref_page_size, try h.pageSize());
    try std.testing.expectEqual(@as(u8, 1), h.writeVersion());
    try std.testing.expectEqual(@as(u8, 1), h.readVersion());
    try std.testing.expectEqual(@as(u8, 0), h.reservedPerPage());
    try std.testing.expectEqual(ref_page_count, h.declaredPageCount());
    try std.testing.expectEqual(file.TextEncoding.utf8, try h.textEncoding());
    try std.testing.expectEqual(@as(u32, 4), h.schemaFormat());
    try std.testing.expectEqual(ref_page_count, try db.pageCount(ref_page_size));

    // Every page of the real file reads fully; page 1 starts with the magic.
    const p1 = try alloc.alloc(u8, ref_page_size);
    defer alloc.free(p1);
    try db.readPage(1, ref_page_size, p1);
    try std.testing.expectEqualSlices(u8, file.magic, p1[0..16]);
    const plast = try alloc.alloc(u8, ref_page_size);
    defer alloc.free(plast);
    try db.readPage(ref_page_count, ref_page_size, plast);
}

test "write persists across close and reopen" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    const root = try scratchRoot(alloc);
    defer alloc.free(root);
    defer cleanup(root);
    const path = try std.fmt.allocPrint(alloc, "{s}/w.db", .{root});
    defer alloc.free(path);

    const ps: u32 = 1024;
    try file.createEmpty(tio, alloc, path, ps, 3, .utf8);

    const pattern = try alloc.alloc(u8, ps);
    defer alloc.free(pattern);
    for (pattern, 0..) |*b, i| b.* = @intCast(i & 0xff);
    {
        var db = try file.DbFile.openAbsolute(tio, path, .read_write);
        defer db.close();
        try db.writePage(2, ps, pattern);
        try db.sync();
    }
    {
        var db = try file.DbFile.openAbsolute(tio, path, .read_only);
        defer db.close();
        const back = try alloc.alloc(u8, ps);
        defer alloc.free(back);
        try db.readPage(2, ps, back);
        try std.testing.expectEqualSlices(u8, pattern, back);
    }
}

test "malformed and truncated inputs are rejected" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    const root = try scratchRoot(alloc);
    defer alloc.free(root);
    defer cleanup(root);

    // Not a database at all.
    {
        const path = try std.fmt.allocPrint(alloc, "{s}/junk.db", .{root});
        defer alloc.free(path);
        var f = try std.Io.Dir.createFileAbsolute(tio, path, .{ .read = true });
        defer f.close(tio);
        var junk: [200]u8 = undefined;
        @memset(&junk, 0x7f);
        try f.writePositionalAll(tio, &junk, 0);
        var db = try file.DbFile.openAbsolute(tio, path, .read_write);
        defer db.close();
        try std.testing.expectError(file.Error.NotDatabase, db.readHeader());
    }
    // Truncated header: fewer than 100 bytes.
    {
        const path = try std.fmt.allocPrint(alloc, "{s}/short.db", .{root});
        defer alloc.free(path);
        var f = try std.Io.Dir.createFileAbsolute(tio, path, .{ .read = true });
        defer f.close(tio);
        try f.writePositionalAll(tio, file.magic, 0);
        var db = try file.DbFile.openAbsolute(tio, path, .read_write);
        defer db.close();
        try std.testing.expectError(file.Error.ShortRead, db.readHeader());
    }
    // Bad page size field (non-power-of-two 1000).
    {
        const path = try std.fmt.allocPrint(alloc, "{s}/badps.db", .{root});
        defer alloc.free(path);
        try file.createEmpty(tio, alloc, path, 1024, 2, .utf8);
        var db = try file.DbFile.openAbsolute(tio, path, .read_write);
        defer db.close();
        var p1 = try alloc.alloc(u8, 1024);
        defer alloc.free(p1);
        try db.readPage(1, 1024, p1);
        p1[16] = 0x03;
        p1[17] = 0xe8; // 1000
        try db.writePage(1, 1024, p1);
        try std.testing.expectError(file.Error.InvalidPageSize, db.readHeader());
    }
    // Page out of range and partial tail.
    {
        const path = try std.fmt.allocPrint(alloc, "{s}/tail.db", .{root});
        defer alloc.free(path);
        try file.createEmpty(tio, alloc, path, 512, 2, .utf8);
        var db = try file.DbFile.openAbsolute(tio, path, .read_write);
        defer db.close();
        const pg = try alloc.alloc(u8, 512);
        defer alloc.free(pg);
        try std.testing.expectError(file.Error.PageOutOfRange, db.readPage(0, 512, pg));
        try std.testing.expectError(file.Error.PageOutOfRange, db.readPage(3, 512, pg));
        // Append 100 stray bytes past the page boundary.
        try db.truncate(2 * 512 + 100);
        try std.testing.expectError(file.Error.Corrupt, db.pageCount(512));
    }
}

test "exclusive lock blocks independent process until released" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    const root = try scratchRoot(alloc);
    defer alloc.free(root);
    defer cleanup(root);
    const path = try std.fmt.allocPrint(alloc, "{s}/lock.db", .{root});
    defer alloc.free(path);
    try file.createEmpty(tio, alloc, path, 512, 1, .utf8);

    var db = try file.DbFile.openAbsolute(tio, path, .read_write);
    defer db.close();
    try db.lockWithTimeout(.exclusive, 0);

    // Independent process holds flock -n on the same path: must fail while
    // we hold the lock, and succeed after we release it.
    const hold_args = [_][]const u8{ "flock", "-n", path, "sleep", "30" };
    var holder = try std.process.spawn(tio, .{
        .argv = &hold_args,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    // Give the child a moment to attempt the lock, then check it is waiting.
    std.Io.sleep(tio, .fromMilliseconds(300), .awake) catch {};
    // While we hold exclusive, a second non-blocking flock must fail.
    const probe_args = [_][]const u8{ "flock", "-n", path, "true" };
    var probe1 = try std.process.spawn(tio, .{
        .argv = &probe_args,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    const t1 = try probe1.wait(tio);
    try std.testing.expect(!t1.success());
    // Our own non-blocking attempt from a second fd must also fail.
    var db2 = try file.DbFile.openAbsolute(tio, path, .read_write);
    defer db2.close();
    try std.testing.expect(!(try db2.tryLock(.exclusive)));
    try std.testing.expectError(file.Error.LockBusy, db2.lockWithTimeout(.exclusive, 0));

    db.unlock();
    holder.kill(tio);
    try std.testing.expect(try db2.tryLock(.exclusive));
    db2.unlock();

    var probe2 = try std.process.spawn(tio, .{
        .argv = &probe_args,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    const t2 = try probe2.wait(tio);
    try std.testing.expect(t2.success());
}

test "lock timeout fires against a holder" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    const root = try scratchRoot(alloc);
    defer alloc.free(root);
    defer cleanup(root);
    const path = try std.fmt.allocPrint(alloc, "{s}/timeout.db", .{root});
    defer alloc.free(path);
    try file.createEmpty(tio, alloc, path, 512, 1, .utf8);

    const hold_args = [_][]const u8{ "flock", path, "sleep", "30" };
    var holder = try std.process.spawn(tio, .{
        .argv = &hold_args,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    defer holder.kill(tio);
    std.Io.sleep(tio, .fromMilliseconds(300), .awake) catch {};

    var db = try file.DbFile.openAbsolute(tio, path, .read_write);
    defer db.close();
    try std.testing.expectError(file.Error.LockTimeout, db.lockWithTimeout(.exclusive, 120));
}

test "sync and truncate round trip" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    const root = try scratchRoot(alloc);
    defer alloc.free(root);
    defer cleanup(root);
    const path = try std.fmt.allocPrint(alloc, "{s}/t.db", .{root});
    defer alloc.free(path);
    try file.createEmpty(tio, alloc, path, 512, 2, .utf8);

    var db = try file.DbFile.openAbsolute(tio, path, .read_write);
    defer db.close();
    try db.sync();
    try db.syncDataOnly();
    try db.truncate(512 * 4);
    try std.testing.expectEqual(@as(u32, 4), try db.pageCount(512));
    const pg = try alloc.alloc(u8, 512);
    defer alloc.free(pg);
    @memset(pg, 0xab);
    try db.writePage(4, 512, pg);
    try std.testing.expectEqual(@as(u64, 512 * 4), try db.size());
}

test "missing file reports NotFound" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    try std.testing.expectError(
        file.Error.NotFound,
        file.DbFile.openAbsolute(tio, "/tmp/nb-sqlite-file-test-no-such-dir-9f3/missing.db", .read_only),
    );
}


test "header requires at least 480 usable bytes" {
    var raw: [file.header_len]u8 = undefined;
    @memset(&raw, 0);
    @memcpy(raw[0..16], file.magic);
    raw[18] = 1;
    raw[19] = 1;
    std.mem.writeInt(u32, raw[56..60], 1, .big);
    for ([_]u32{ 512, 1024, 65536 }) |ps| {
        std.mem.writeInt(u16, raw[16..18], if (ps == 65536) 1 else @intCast(ps), .big);
        const max_reserve: u8 = if (ps == 512) 32 else 255;
        for ([_]u8{ 0, max_reserve }) |reserve| {
            raw[20] = reserve;
            const h = try file.Header.parse(&raw);
            try std.testing.expectEqual(ps, try h.pageSize());
            try std.testing.expectEqual(ps - reserve, try h.usableSize());
        }
    }
    std.mem.writeInt(u16, raw[16..18], 512, .big);
    raw[20] = 33;
    try std.testing.expectError(file.Error.Corrupt, file.Header.parse(&raw));
    try std.testing.expectError(file.Error.Corrupt, (file.Header{ .raw = raw }).usableSize());
}
