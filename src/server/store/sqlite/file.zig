// Port of netbird management/server/store (v0.80.0), AGPL-3.0.
// Reference: upstream-v080 management/server/store/sql_store.go (NewSqliteStore),
// docs/sqlite-v080-contract.md sections 2-3.
// Scope: SQLite database file foundation only: 100-byte header decode/encode,
// page-size/page-count geometry, positional page read/write, open/create/close
// ownership, Linux flock shared/exclusive locks with _busy_timeout-compatible
// wait, fsync/fdatasync durability, truncate. No SQL, no b-tree, no pager,
// no WAL, no query engine. Those are follow-up cards (contract section 9).

const std = @import("std");
const linux = std.os.linux;

pub const Error = error{
    NotFound,
    NotDatabase,
    Corrupt,
    ShortRead,
    PageOutOfRange,
    InvalidPageSize,
    UnsupportedVersion,
    UnsupportedEncoding,
    LockBusy,
    LockTimeout,
    LocksUnsupported,
    ReadFailed,
    WriteFailed,
    SyncFailed,
    TruncateFailed,
    OpenFailed,
    CloseFailed,
} || std.mem.Allocator.Error;

/// SQLite magic: every database file starts with these 16 bytes.
pub const magic = "SQLite format 3\x00";

/// Size of the database header at the start of page 1.
pub const header_len = 100;

/// Default lock-wait budget in milliseconds. Mirrors the Go store DSN default
/// `_busy_timeout=30000` injected by NewSqliteStore (sql_store.go:206-208):
/// SQLite waits at most this long on a lock instead of failing immediately.
/// The single-connection Go server never contends with itself; this budget
/// covers a second local process (e.g. a migration helper).
pub const default_busy_timeout_ms = 30_000;

/// Poll interval while waiting on a contended file lock.
pub const lock_poll_ms = 5;

/// Minimum and maximum database page sizes SQLite supports.
pub const min_page_size = 512;
pub const max_page_size = 65536;

/// Text encodings from header offset 56.
pub const TextEncoding = enum(u32) {
    utf8 = 1,
    utf16le = 2,
    utf16be = 3,
};

/// Lock modes offered to future pager/transaction code. Mapped onto
/// flock(2): shared for readers, exclusive for the single writer.
/// SQLite's own rollback-journal protocol uses POSIX byte-range locks;
/// this layer provides whole-file inter-process exclusion with the same
/// shared/exclusive shape, which is all a single-writer store needs.
pub const LockMode = enum {
    shared,
    exclusive,
};

/// Decoded 100-byte SQLite database header.
/// Byte layout per the SQLite file format specification:
/// https://www.sqlite.org/fileformat.html section "The Database Header".
pub const Header = struct {
    /// Raw header bytes; page 1 payload starts at offset 100.
    raw: [header_len]u8,

    pub fn parse(buf: *const [header_len]u8) Error!Header {
        if (!std.mem.eql(u8, buf[0..16], magic)) return Error.NotDatabase;
        const h = Header{ .raw = buf.* };
        // Validate geometry eagerly so callers never divide by garbage.
        _ = try h.pageSize();
        _ = try h.usableSize();
        try h.checkVersions();
        try h.checkEncoding();
        return h;
    }

    fn u16be(self: Header, off: usize) u16 {
        return std.mem.readInt(u16, self.raw[off..][0..2], .big);
    }

    fn u32be(self: Header, off: usize) u32 {
        return std.mem.readInt(u32, self.raw[off..][0..4], .big);
    }

    /// Page size in bytes. Stored value 1 means 65536.
    pub fn pageSize(self: Header) Error!u32 {
        const v = self.u16be(16);
        if (v == 1) return max_page_size;
        if (v < min_page_size or v > max_page_size or (v & (v - 1)) != 0)
            return Error.InvalidPageSize;
        return v;
    }

    /// Write version at offset 18: 1 legacy rollback-journal, 2 WAL.
    /// The Go store uses defaults (rollback-journal, contract section 3),
    /// so version 1 is expected; version 2 parses for forward compatibility
    /// but WAL framing itself is a follow-up card.
    pub fn writeVersion(self: Header) u8 {
        return self.raw[18];
    }

    /// Read version at offset 19. Same domain as the write version.
    pub fn readVersion(self: Header) u8 {
        return self.raw[19];
    }

    fn checkVersions(self: Header) Error!void {
        if (self.writeVersion() == 0 or self.writeVersion() > 2) return Error.UnsupportedVersion;
        if (self.readVersion() == 0 or self.readVersion() > 2) return Error.UnsupportedVersion;
    }

    /// Reserved bytes per page at offset 20. Zero in stock SQLite files;
    /// nonzero shrinks every page payload for extensions.
    pub fn reservedPerPage(self: Header) u8 {
        return self.raw[20];
    }

    /// Text encoding at offset 56: 1 UTF-8, 2 UTF-16LE, 3 UTF-16BE.
    pub fn textEncoding(self: Header) Error!TextEncoding {
        return switch (self.u32be(56)) {
            1 => .utf8,
            2 => .utf16le,
            3 => .utf16be,
            else => Error.UnsupportedEncoding,
        };
    }

    fn checkEncoding(self: Header) Error!void {
        _ = try self.textEncoding();
    }

    /// Schema format at offset 44: 1..4.
    pub fn schemaFormat(self: Header) u32 {
        return self.u32be(44);
    }

    /// File change counter at offset 24.
    pub fn changeCounter(self: Header) u32 {
        return self.u32be(24);
    }

    /// Version-valid-for number at offset 92.
    pub fn versionValidFor(self: Header) u32 {
        return self.u32be(92);
    }

    /// Declared database size in pages at offset 28.
    pub fn declaredPageCount(self: Header) u32 {
        return self.u32be(28);
    }

    /// First freelist trunk page at offset 32 (0 when empty).
    pub fn freelistTrunk(self: Header) u32 {
        return self.u32be(32);
    }

    /// Total freelist pages at offset 36.
    pub fn freelistCount(self: Header) u32 {
        return self.u32be(36);
    }

    /// Schema cookie at offset 40.
    pub fn schemaCookie(self: Header) u32 {
        return self.u32be(40);
    }

    /// Usable payload per page: page size minus reserved bytes.
    pub fn usableSize(self: Header) Error!u32 {
        const page_size = try self.pageSize();
        const usable = page_size - self.reservedPerPage();
        if (usable < 480) return Error.Corrupt;
        return usable;
    }
};

/// File offset of page `page_no` (1-based). Page 1 starts at 0 and carries
/// the 100-byte header; every other page starts at (n-1)*page_size.
pub fn pageOffset(page_no: u32, page_size: u32) Error!u64 {
    if (page_no == 0) return Error.PageOutOfRange;
    return @as(u64, page_no - 1) * page_size;
}

/// An open SQLite database file. Owns the fd; close releases it (and any
/// flock held, since locks die with the descriptor).
pub const DbFile = struct {
    file: std.Io.File,
    io: std.Io,

    /// Open an existing database file. No creation, no truncation.
    pub fn openAbsolute(io: std.Io, path: []const u8, mode: std.Io.Dir.OpenFileOptions.Mode) Error!DbFile {
        const f = std.Io.Dir.openFileAbsolute(io, path, .{ .mode = mode }) catch |err| switch (err) {
            error.FileNotFound => return Error.NotFound,
            else => return Error.OpenFailed,
        };
        return .{ .file = f, .io = io };
    }

    /// Create a database file (or open it): truncate iff `truncate` is set.
    pub fn createAbsolute(io: std.Io, path: []const u8, truncate_existing: bool) Error!DbFile {
        const f = std.Io.Dir.createFileAbsolute(io, path, .{
            .read = true,
            .truncate = truncate_existing,
        }) catch return Error.OpenFailed;
        return .{ .file = f, .io = io };
    }

    pub fn close(self: *DbFile) void {
        self.file.close(self.io);
    }

    /// File size via raw lseek(SEEK_END): no statx, safe on kernel 4.9.
    /// Restores the offset to 0 afterwards.
    pub fn size(self: DbFile) Error!u64 {
        const end = linux.lseek(self.file.handle, 0, linux.SEEK.END);
        if (end > 0xfffffffffffff000) return Error.ReadFailed;
        const back = linux.lseek(self.file.handle, 0, linux.SEEK.SET);
        if (back > 0xfffffffffffff000) return Error.ReadFailed;
        return end;
    }

    /// Page count from the current file size. Errors when the size is not
    /// a whole number of pages (partial tail) or the file is empty.
    pub fn pageCount(self: DbFile, page_size: u32) Error!u32 {
        if (page_size < min_page_size or page_size > max_page_size) return Error.InvalidPageSize;
        const len = try self.size();
        if (len == 0) return Error.Corrupt;
        if (len % page_size != 0) return Error.Corrupt;
        const n = len / page_size;
        if (n > std.math.maxInt(u32)) return Error.Corrupt;
        return @intCast(n);
    }

    /// Read and validate the 100-byte header.
    pub fn readHeader(self: DbFile) Error!Header {
        var buf: [header_len]u8 = undefined;
        const n = self.file.readPositionalAll(self.io, &buf, 0) catch return Error.ReadFailed;
        if (n != header_len) return Error.ShortRead;
        return Header.parse(&buf);
    }

    /// Read full page `page_no` (1-based) into `buf`, which must be exactly
    /// one page. Bounds-checked against the current file size.
    pub fn readPage(self: DbFile, page_no: u32, page_size: u32, buf: []u8) Error!void {
        if (buf.len != page_size) return Error.Corrupt;
        const count = try self.pageCount(page_size);
        if (page_no == 0 or page_no > count) return Error.PageOutOfRange;
        const off = try pageOffset(page_no, page_size);
        const n = self.file.readPositionalAll(self.io, buf, off) catch return Error.ReadFailed;
        if (n != buf.len) return Error.ShortRead;
    }

    /// Write full page `page_no` (1-based) from `buf`. Pages beyond the end
    /// extend the file (used by the future pager for growth); pages before
    /// the end must already exist (no sparse holes).
    pub fn writePage(self: DbFile, page_no: u32, page_size: u32, buf: []const u8) Error!void {
        if (buf.len != page_size) return Error.Corrupt;
        if (page_no == 0) return Error.PageOutOfRange;
        const len = try self.size();
        const off = try pageOffset(page_no, page_size);
        if (off > len) return Error.PageOutOfRange;
        self.file.writePositionalAll(self.io, buf, off) catch return Error.WriteFailed;
    }

    /// Non-blocking lock attempt. Returns true when acquired, false when a
    /// second process holds an incompatible flock.
    pub fn tryLock(self: DbFile, mode: LockMode) Error!bool {
        const op: i32 = switch (mode) {
            .shared => std.posix.LOCK.SH | std.posix.LOCK.NB,
            .exclusive => std.posix.LOCK.EX | std.posix.LOCK.NB,
        };
        while (true) {
            const rc = linux.flock(self.file.handle, op);
            if (rc <= 0xfffffffffffff000) return true;
            const errno = 0xffffffffffffffff - rc + 1;
            if (errno == @intFromEnum(linux.E.INTR)) continue;
            if (errno == @intFromEnum(linux.E.AGAIN)) return false;
            if (errno == @intFromEnum(linux.E.NOLCK)) return Error.LocksUnsupported;
            if (errno == @intFromEnum(linux.E.OPNOTSUPP)) return Error.LocksUnsupported;
            return Error.OpenFailed;
        }
    }

    /// Blocking lock with a busy-timeout budget in milliseconds, mirroring
    /// `_busy_timeout`: polls tryLock every lock_poll_ms until acquired or
    /// the budget expires. budget 0 means a single non-blocking attempt.
    pub fn lockWithTimeout(self: DbFile, mode: LockMode, busy_timeout_ms: u64) Error!void {
        if (try self.tryLock(mode)) return;
        if (busy_timeout_ms == 0) return Error.LockBusy;
        var ts: linux.timespec = undefined;
        if (linux.clock_gettime(linux.CLOCK.MONOTONIC, &ts) != 0) return Error.OpenFailed;
        const start_ms: u64 = @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(@divTrunc(ts.nsec, 1_000_000)));
        while (true) {
            sleepMs(lock_poll_ms);
            if (try self.tryLock(mode)) return;
            if (linux.clock_gettime(linux.CLOCK.MONOTONIC, &ts) != 0) return Error.OpenFailed;
            const now_ms: u64 = @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(@divTrunc(ts.nsec, 1_000_000)));
            if (now_ms -% start_ms >= busy_timeout_ms) return Error.LockTimeout;
        }
    }

    /// Blocking lock with the store default budget (30 s, like _busy_timeout).
    pub fn lock(self: DbFile, mode: LockMode) Error!void {
        return self.lockWithTimeout(mode, default_busy_timeout_ms);
    }

    pub fn unlock(self: DbFile) void {
        _ = linux.flock(self.file.handle, std.posix.LOCK.UN);
    }

    /// Durable sync: fsync flushes data and metadata. Used for commit-grade
    /// durability; fdatasync is the cheaper metadata-skipping variant.
    pub fn sync(self: DbFile) Error!void {
        while (true) {
            const rc = linux.fsync(self.file.handle);
            if (rc <= 0xfffffffffffff000) return;
            const errno = 0xffffffffffffffff - rc + 1;
            if (errno == @intFromEnum(linux.E.INTR)) continue;
            return Error.SyncFailed;
        }
    }

    pub fn syncDataOnly(self: DbFile) Error!void {
        while (true) {
            const rc = linux.fdatasync(self.file.handle);
            if (rc <= 0xfffffffffffff000) return;
            const errno = 0xffffffffffffffff - rc + 1;
            if (errno == @intFromEnum(linux.E.INTR)) continue;
            return Error.SyncFailed;
        }
    }

    /// Truncate or grow the file. Growth zero-fills (kernel guarantee).
    pub fn truncate(self: DbFile, new_len: u64) Error!void {
        if (new_len > std.math.maxInt(i64)) return Error.TruncateFailed;
        while (true) {
            const rc = linux.ftruncate(self.file.handle, @intCast(new_len));
            if (rc <= 0xfffffffffffff000) return;
            const errno = 0xffffffffffffffff - rc + 1;
            if (errno == @intFromEnum(linux.E.INTR)) continue;
            return Error.TruncateFailed;
        }
    }
};

fn sleepMs(ms: u64) void {
    const req = linux.timespec{
        .sec = @intCast(ms / 1000),
        .nsec = @intCast((ms % 1000) * 1_000_000),
    };
    while (true) {
        const rc = linux.nanosleep(&req, null);
        if (rc <= 0xfffffffffffff000) return;
        const errno = 0xffffffffffffffff - rc + 1;
        if (errno != @intFromEnum(linux.E.INTR)) return;
    }
}

/// Write a minimal valid database image: header + `page_count` pages.
/// Page 1 starts with the 100-byte header followed by zeroes; the rest are
/// zero pages. Enough for VFS geometry tests; not a queryable database
/// (b-tree roots are a follow-up card).
pub fn createEmpty(io: std.Io, allocator: std.mem.Allocator, path: []const u8, page_size: u32, page_count: u32, encoding: TextEncoding) Error!void {
    if (page_count == 0) return Error.Corrupt;
    if (page_size < min_page_size or page_size > max_page_size or (page_size & (page_size - 1)) != 0)
        return Error.InvalidPageSize;
    var db = try DbFile.createAbsolute(io, path, true);
    defer db.close();

    var hdr: [header_len]u8 = undefined;
    @memset(&hdr, 0);
    @memcpy(hdr[0..16], magic);
    std.mem.writeInt(u16, hdr[16..18], if (page_size == max_page_size) 1 else @intCast(page_size), .big);
    hdr[18] = 1; // write version: legacy rollback-journal
    hdr[19] = 1; // read version
    std.mem.writeInt(u32, hdr[28..32], page_count, .big); // size in pages
    std.mem.writeInt(u32, hdr[40..44], 1, .big); // schema cookie
    std.mem.writeInt(u32, hdr[44..48], 4, .big); // schema format 4
    std.mem.writeInt(u32, hdr[56..60], @intFromEnum(encoding), .big);
    std.mem.writeInt(u32, hdr[64..68], 0x20000, .big); // sqlite_version_number 3.x placeholder
    var page = try allocator.alloc(u8, page_size);
    defer allocator.free(page);
    @memset(page, 0);
    @memcpy(page[0..header_len], &hdr);
    try db.writePage(1, page_size, page);
    @memset(page[0..header_len], 0);
    var n: u32 = 2;
    while (n <= page_count) : (n += 1) {
        try db.writePage(n, page_size, page);
    }
    try db.sync();
}
