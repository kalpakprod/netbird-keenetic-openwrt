// Port of netbird client/internal/statemanager/manager.go (v0.79.0), BSD-3-Clause.
// Scope: state-file format + load/save semantics compatible with the Go
// manager: compact JSON object with sorted keys, nil states as null,
// atomic replace (temp + rename, 0600), corrupt-file backup on cleanup
// load, raw preservation of unregistered states. Out of scope: the 10s
// periodic-save goroutine (no threads here; the caller drives persist),
// Start/Stop lifecycle, logrus logging. Cleanup callbacks are caller-driven
// (Zig has no reflection): call savedNames + cleanupByName per type.

const std = @import("std");
const profile = @import("profile.zig");

pub const Error = profile.FileError || std.mem.Allocator.Error || error{
    StateNotRegistered,
    StateNotFound,
    CleanupFailed,
    CorruptState,
};

/// In-memory store of one named state: owned raw JSON ("null" when deleted).
const Entry = struct {
    raw: []u8,
    registered: bool,
};

pub const Manager = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    file_path: []const u8,
    entries: std.StringHashMap(Entry),
    dirty: std.StringHashMap(void),

    pub fn init(allocator: std.mem.Allocator, io: std.Io, file_path: []const u8) Manager {
        return .{
            .allocator = allocator,
            .io = io,
            .file_path = file_path,
            .entries = .init(allocator),
            .dirty = .init(allocator),
        };
    }

    pub fn deinit(m: *Manager) void {
        var it = m.entries.iterator();
        while (it.next()) |e| {
            m.allocator.free(e.key_ptr.*);
            m.allocator.free(e.value_ptr.raw);
        }
        m.entries.deinit();
        var dit = m.dirty.iterator();
        while (dit.next()) |e| m.allocator.free(e.key_ptr.*);
        m.dirty.deinit();
    }

    /// RegisterState: registers a name without persisting it.
    pub fn register(m: *Manager, name: []const u8) Error!void {
        if (m.entries.getPtr(name)) |e| {
            e.registered = true;
            return;
        }
        const key = try m.allocator.dupe(u8, name);
        errdefer m.allocator.free(key);
        const raw = try m.allocator.dupe(u8, "null");
        errdefer m.allocator.free(raw);
        try m.entries.put(key, .{ .raw = raw, .registered = true });
    }

    fn markDirty(m: *Manager, name: []const u8) Error!void {
        if (m.dirty.contains(name)) return;
        const key = try m.allocator.dupe(u8, name);
        errdefer m.allocator.free(key);
        try m.dirty.put(key, {});
    }

    fn setRaw(m: *Manager, name: []const u8, raw: []const u8) Error!void {
        const e = m.entries.getPtr(name) orelse return Error.StateNotRegistered;
        m.allocator.free(e.raw);
        e.raw = try m.allocator.dupe(u8, raw);
        try m.markDirty(name);
    }

    /// UpdateState: replaces the state value (compact JSON), marks dirty.
    pub fn update(m: *Manager, name: []const u8, value: anytype) Error!void {
        if (!m.entries.contains(name)) return Error.StateNotRegistered;
        const raw = std.json.Stringify.valueAlloc(m.allocator, value, .{}) catch {
            return profile.FileError.WriteFailed;
        };
        defer m.allocator.free(raw);
        try m.setRaw(name, raw);
    }

    /// Update a state from already-encoded JSON (RawState equivalent).
    pub fn updateRaw(m: *Manager, name: []const u8, raw_json: []const u8) Error!void {
        if (!m.entries.contains(name)) return Error.StateNotRegistered;
        try m.setRaw(name, raw_json);
    }

    /// DeleteState: marks deleted (marshals as null), marks dirty.
    pub fn delete(m: *Manager, name: []const u8) Error!void {
        try m.setRaw(name, "null");
    }

    /// GetState: parses the in-memory value into T (null -> null).
    pub fn get(m: *Manager, name: []const u8, comptime T: type) Error!?std.json.Parsed(T) {
        const e = m.entries.get(name) orelse return Error.StateNotRegistered;
        if (std.mem.eql(u8, e.raw, "null")) return null;
        return std.json.parseFromSlice(T, m.allocator, e.raw, .{
            .ignore_unknown_fields = true,
            .allocate = .alloc_always,
        }) catch {
            return Error.CorruptState;
        };
    }

    /// LoadState: reloads one state from the file into memory.
    pub fn load(m: *Manager, name: []const u8) Error!void {
        const raw_states = try m.loadStateFile(false);
        var states = raw_states orelse return;
        defer states.deinit();
        const raw = states.value.map.get(name) orelse return;
        // loadSingleRawState: "null" decodes to a nil (deleted) state.
        if (raw == .null) {
            if (m.entries.getPtr(name)) |e| {
                m.allocator.free(e.raw);
                e.raw = try m.allocator.dupe(u8, "null");
            }
            return;
        }
        const section = std.json.Stringify.valueAlloc(m.allocator, raw, .{}) catch {
            return Error.CorruptState;
        };
        defer m.allocator.free(section);
        if (m.entries.getPtr(name)) |e| {
            m.allocator.free(e.raw);
            e.raw = try m.allocator.dupe(u8, section);
        }
    }

    /// DeleteStateByName: no registration needed, but the name must exist in
    /// the file.
    pub fn deleteByName(m: *Manager, name: []const u8) Error!void {
        const raw_states = try m.loadStateFile(false);
        var states = raw_states orelse return;
        defer states.deinit();
        if (!states.value.map.contains(name)) return Error.StateNotFound;
        if (m.entries.getPtr(name)) |e| {
            m.allocator.free(e.raw);
            e.raw = try m.allocator.dupe(u8, "null");
        } else {
            const key = try m.allocator.dupe(u8, name);
            errdefer m.allocator.free(key);
            const raw = try m.allocator.dupe(u8, "null");
            errdefer m.allocator.free(raw);
            try m.entries.put(key, .{ .raw = raw, .registered = false });
        }
        try m.markDirty(name);
    }

    /// DeleteAllStates: marks every state in the file deleted; returns count.
    pub fn deleteAll(m: *Manager) Error!usize {
        const raw_states = try m.loadStateFile(false);
        var states = raw_states orelse return 0;
        defer states.deinit();
        var it = states.value.map.iterator();
        while (it.next()) |e| {
            if (m.entries.getPtr(e.key_ptr.*)) |ent| {
                m.allocator.free(ent.raw);
                ent.raw = try m.allocator.dupe(u8, "null");
            } else {
                const key = try m.allocator.dupe(u8, e.key_ptr.*);
                errdefer m.allocator.free(key);
                const raw = try m.allocator.dupe(u8, "null");
                errdefer m.allocator.free(raw);
                try m.entries.put(key, .{ .raw = raw, .registered = false });
            }
            try m.markDirty(e.key_ptr.*);
        }
        return states.value.map.count();
    }

    /// CleanupStateByName: loads the state, runs the caller's cleanup
    /// function on it; on success marks deleted, on error preserves it.
    /// The state must be registered and present in the file.
    pub fn cleanupByName(
        m: *Manager,
        name: []const u8,
        comptime T: type,
        cleanup_fn: *const fn (*T) anyerror!void,
    ) Error!void {
        const ent = m.entries.get(name) orelse return Error.StateNotRegistered;
        if (!ent.registered) return Error.StateNotRegistered;
        const raw_states = try m.loadStateFile(false);
        var states = raw_states orelse return;
        defer states.deinit();
        const raw = states.value.map.get(name) orelse return;
        if (raw == .null) return;
        const section = std.json.Stringify.valueAlloc(m.allocator, raw, .{}) catch {
            return Error.CorruptState;
        };
        defer m.allocator.free(section);
        var parsed = std.json.parseFromSlice(T, m.allocator, section, .{
            .ignore_unknown_fields = true,
            .allocate = .alloc_always,
        }) catch {
            return Error.CorruptState;
        };
        defer parsed.deinit();
        cleanup_fn(&parsed.value) catch {
            // Preserve the state on cleanup error, like Go.
            try m.setRawKeep(name, section);
            return Error.CleanupFailed;
        };
        try m.setRaw(name, "null");
    }

    /// Store a value without dirty-marking (cleanup-error preserve path).
    fn setRawKeep(m: *Manager, name: []const u8, raw: []const u8) Error!void {
        const e = m.entries.getPtr(name) orelse return Error.StateNotRegistered;
        m.allocator.free(e.raw);
        e.raw = try m.allocator.dupe(u8, raw);
    }

    /// GetSavedStateNames: names in the file with non-null values.
    pub fn savedNames(m: *Manager) Error![][]u8 {
        const raw_states = try m.loadStateFile(false);
        var states = raw_states orelse return &.{};
        defer states.deinit();
        var out: std.ArrayList([]u8) = .empty;
        errdefer {
            for (out.items) |n| m.allocator.free(n);
            out.deinit(m.allocator);
        }
        var it = states.value.map.iterator();
        while (it.next()) |e| {
            if (e.value_ptr.* == .null) continue;
            try out.append(m.allocator, try m.allocator.dupe(u8, e.key_ptr.*));
        }
        return out.toOwnedSlice(m.allocator);
    }

    pub fn freeNames(m: *Manager, names: [][]u8) void {
        for (names) |n| m.allocator.free(n);
        m.allocator.free(names);
    }

    /// PersistState: writes the whole map when dirty. Compact JSON with keys
    /// sorted ascending, matching Go's map marshal.
    pub fn persist(m: *Manager) Error!void {
        if (m.dirty.count() == 0) return;
        const keys = try m.allocator.alloc([]const u8, m.entries.count());
        defer m.allocator.free(keys);
        var it = m.entries.iterator();
        var i: usize = 0;
        while (it.next()) |e| : (i += 1) keys[i] = e.key_ptr.*;
        std.mem.sort([]const u8, keys, {}, struct {
            fn less(_: void, a: []const u8, b: []const u8) bool {
                return std.mem.lessThan(u8, a, b);
            }
        }.less);
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(m.allocator);
        try buf.append(m.allocator, '{');
        for (keys, 0..) |k, idx| {
            if (idx > 0) try buf.append(m.allocator, ',');
            const key_json = try std.json.Stringify.valueAlloc(m.allocator, k, .{});
            defer m.allocator.free(key_json);
            try buf.appendSlice(m.allocator, key_json);
            try buf.append(m.allocator, ':');
            try buf.appendSlice(m.allocator, m.entries.get(k).?.raw);
        }
        try buf.append(m.allocator, '}');
        try writeBytesAtomic(m.io, m.file_path, buf.items);
        var dit = m.dirty.iterator();
        while (dit.next()) |e| m.allocator.free(e.key_ptr.*);
        m.dirty.clearRetainingCapacity();
    }

    const RawMap = std.json.ArrayHashMap(std.json.Value);

    /// PerformCleanup's load step: renames a malformed file aside and
    /// returns true; missing or valid files return false.
    pub fn backupIfCorrupt(m: *Manager) Error!bool {
        const maybe = m.loadStateFile(true) catch |err| switch (err) {
            Error.CorruptState => return true,
            else => return err,
        };
        if (maybe) |parsed| {
            var p = parsed;
            p.deinit();
        }
        return false;
    }

    /// loadStateFile: missing file reads as absent (nil); malformed content
    /// is an error, with a backup rename when delete_corrupt is set.
    fn loadStateFile(m: *Manager, delete_corrupt: bool) Error!?std.json.Parsed(RawMap) {
        const data = profile.readFileLseek(m.io, m.allocator, m.file_path) catch |err| switch (err) {
            profile.FileError.NotFound => return null,
            else => return err,
        };
        defer m.allocator.free(data);
        const parsed = std.json.parseFromSlice(RawMap, m.allocator, data, .{
            .allocate = .alloc_always,
        }) catch {
            if (delete_corrupt) m.backupCorrupt();
            return Error.CorruptState;
        };
        return parsed;
    }

    /// handleCorruptedState: renames the file to <path>.corrupted.<unixnano>.
    /// Best-effort like Go (logs and continues there; silent here).
    fn backupCorrupt(m: *Manager) void {
        var tspec: std.os.linux.timespec = .{ .sec = 0, .nsec = 0 };
        _ = std.os.linux.clock_gettime(std.os.linux.CLOCK.REALTIME, &tspec);
        const ts: i128 = @as(i128, tspec.sec) * std.time.ns_per_s + tspec.nsec;
        const backup = std.fmt.allocPrint(m.allocator, "{s}.corrupted.{d}", .{ m.file_path, ts }) catch return;
        defer m.allocator.free(backup);
        std.Io.Dir.renameAbsolute(m.file_path, backup, m.io) catch {};
    }
};

/// Atomic byte write: temp file (0600) in the target dir + rename.
/// Mirrors util.WriteBytesWithRestrictedPermission (MkdirAll 0750, 0600 file).
fn writeBytesAtomic(io: std.Io, path: []const u8, bytes: []const u8) profile.FileError!void {
    const dir = std.fs.path.dirname(path) orelse ".";
    makePathAbsolute(io, dir) catch |err| switch (err) {
        profile.FileError.MkdirFailed => {
            if (!std.mem.eql(u8, dir, ".")) return profile.FileError.MkdirFailed;
        },
        else => return err,
    };
    var tmp_name: [std.fs.max_path_bytes]u8 = undefined;
    const base = std.fs.path.basename(path);
    const pid = std.os.linux.getpid();
    const rand: u32 = @bitCast(std.os.linux.gettid());
    const tmp = std.fmt.bufPrint(&tmp_name, "{s}/.{s}.tmp.{d}.{d}", .{ dir, base, pid, rand }) catch {
        return profile.FileError.WriteFailed;
    };
    {
        const tmp_file = std.Io.Dir.createFileAbsolute(io, tmp, .{
            .truncate = true,
            .permissions = @enumFromInt(0o600),
        }) catch {
            return profile.FileError.WriteFailed;
        };
        defer tmp_file.close(io);
        tmp_file.writePositionalAll(io, bytes, 0) catch {
            std.Io.Dir.deleteFileAbsolute(io, tmp) catch {};
            return profile.FileError.WriteFailed;
        };
    }
    std.Io.Dir.renameAbsolute(tmp, path, io) catch {
        std.Io.Dir.deleteFileAbsolute(io, tmp) catch {};
        return profile.FileError.RenameFailed;
    };
}

fn makePathAbsolute(io: std.Io, path: []const u8) profile.FileError!void {
    var it = std.fs.path.componentIterator(path);
    var cur: [std.fs.max_path_bytes]u8 = undefined;
    var len: usize = 0;
    if (std.fs.path.isAbsolute(path)) {
        cur[0] = '/';
        len = 1;
    }
    while (it.next()) |comp| {
        if (len > 1) {
            cur[len] = '/';
            len += 1;
        }
        if (len + comp.name.len > cur.len) return profile.FileError.MkdirFailed;
        @memcpy(cur[len..][0..comp.name.len], comp.name);
        len += comp.name.len;
        std.Io.Dir.createDirAbsolute(io, cur[0..len], @enumFromInt(0o750)) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return profile.FileError.MkdirFailed,
        };
    }
}
