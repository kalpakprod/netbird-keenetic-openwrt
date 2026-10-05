// Port of netbird client/internal/statemanager/manager.go (v0.80.0), BSD-3-Clause.
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
        const replacement = try m.allocator.dupe(u8, raw);
        errdefer m.allocator.free(replacement);
        try m.markDirty(name);
        m.allocator.free(e.raw);
        e.raw = replacement;
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
    /// Rejects malformed JSON like Go's json.Marshal check, before any
    /// mutation, so the entry, dirty set and file stay untouched. The
    /// original bytes are kept (never re-serialized), and duplicate
    /// member names are accepted like Go json.Valid accepts them.
    pub fn updateRaw(m: *Manager, name: []const u8, raw_json: []const u8) Error!void {
        if (!m.entries.contains(name)) return Error.StateNotRegistered;
        if (!jsonValid(raw_json)) return profile.FileError.InvalidJson;
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
                const replacement = try m.allocator.dupe(u8, "null");
                m.allocator.free(e.raw);
                e.raw = replacement;
            }
            return;
        }
        const section = std.json.Stringify.valueAlloc(m.allocator, raw, .{}) catch {
            return Error.CorruptState;
        };
        defer m.allocator.free(section);
        if (m.entries.getPtr(name)) |e| {
            const replacement = try m.allocator.dupe(u8, section);
            m.allocator.free(e.raw);
            e.raw = replacement;
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
            const replacement = try m.allocator.dupe(u8, "null");
            errdefer m.allocator.free(replacement);
            try m.markDirty(name);
            m.allocator.free(e.raw);
            e.raw = replacement;
            return;
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
                const replacement = try m.allocator.dupe(u8, "null");
                errdefer m.allocator.free(replacement);
                try m.markDirty(e.key_ptr.*);
                m.allocator.free(ent.raw);
                ent.raw = replacement;
                continue;
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
        const replacement = try m.allocator.dupe(u8, raw);
        m.allocator.free(e.raw);
        e.raw = replacement;
    }

    pub fn preserveRaw(m: *Manager, name: []const u8) Error!void {
        if (m.entries.contains(name)) return;
        const data = profile.readFileLseek(m.io, m.allocator, m.file_path) catch |err| switch (err) {
            profile.FileError.NotFound => return,
            else => return err,
        };
        defer m.allocator.free(data);
        const span = try sectionSpan(m.allocator, data, name);
        const found = span orelse return;
        const key = try m.allocator.dupe(u8, name);
        errdefer m.allocator.free(key);
        const owned = try m.allocator.dupe(u8, data[found.start..found.end]);
        errdefer m.allocator.free(owned);
        try m.entries.put(key, .{ .raw = owned, .registered = false });
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
            .duplicate_field_behavior = .use_last,
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

/// Byte span [start, end) of one JSON value inside its document.
const Span = struct { start: usize, end: usize };

const ScanError = error{ InvalidJson, TooDeep };

/// sectionSpan: validate the whole state file (it must be one JSON
/// object, like Go's map unmarshal) and return the original byte span
/// of the named top-level section, or null when absent. The last
/// duplicate wins, matching Go map unmarshal. Malformed documents are
/// CorruptState, like loadStateFile reports them.
fn sectionSpan(allocator: std.mem.Allocator, data: []const u8, name: []const u8) Error!?Span {
    var pos: usize = 0;
    skipWs(data, &pos);
    if (pos >= data.len or data[pos] != '{') return Error.CorruptState;
    pos += 1;
    skipWs(data, &pos);
    var found: ?Span = null;
    if (pos < data.len and data[pos] == '}') {
        pos += 1;
    } else {
        while (true) {
            if (pos >= data.len or data[pos] != '"') return Error.CorruptState;
            const key_start = pos;
            skipString(data, &pos) catch return Error.CorruptState;
            const key_raw = data[key_start..pos];
            skipWs(data, &pos);
            if (pos >= data.len or data[pos] != ':') return Error.CorruptState;
            pos += 1;
            skipWs(data, &pos);
            const val_start = pos;
            skipValue(data, &pos, 0) catch return Error.CorruptState;
            const matches = decodeKeyEquals(allocator, key_raw, name) catch return Error.CorruptState;
            if (matches) found = .{ .start = val_start, .end = pos };
            skipWs(data, &pos);
            if (pos >= data.len) return Error.CorruptState;
            if (data[pos] == ',') {
                pos += 1;
                skipWs(data, &pos);
                continue;
            }
            if (data[pos] == '}') {
                pos += 1;
                break;
            }
            return Error.CorruptState;
        }
    }
    skipWs(data, &pos);
    if (pos != data.len) return Error.CorruptState;
    return found;
}

/// decodeKeyEquals: compare a quoted raw key span against a name the way
/// Go map lookup does — escapes decoded (including \u with surrogate
/// pairing, lone surrogates becoming U+FFFD), then byte-compared.
fn decodeKeyEquals(allocator: std.mem.Allocator, quoted: []const u8, name: []const u8) Error!bool {
    // Fast path: no escapes, direct compare of the inner bytes.
    if (std.mem.indexOfScalar(u8, quoted, '\\') == null) {
        return std.mem.eql(u8, quoted[1 .. quoted.len - 1], name);
    }
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    var i: usize = 1; // skip opening quote; span already validated
    while (i < quoted.len - 1) {
        const c = quoted[i];
        if (c != '\\') {
            try out.append(allocator, c);
            i += 1;
            continue;
        }
        i += 1;
        switch (quoted[i]) {
            '"', '\\', '/' => {
                try out.append(allocator, quoted[i]);
                i += 1;
            },
            'b' => {
                try out.append(allocator, 0x08);
                i += 1;
            },
            'f' => {
                try out.append(allocator, 0x0c);
                i += 1;
            },
            'n' => {
                try out.append(allocator, '\n');
                i += 1;
            },
            'r' => {
                try out.append(allocator, '\r');
                i += 1;
            },
            't' => {
                try out.append(allocator, '\t');
                i += 1;
            },
            'u' => {
                i += 1;
                var cp: u21 = 0;
                for (0..4) |_| {
                    cp = cp * 16 + hexVal(quoted[i]);
                    i += 1;
                }
                // Surrogate pair like Go: high followed by \u low combines,
                // anything else unpaired becomes U+FFFD.
                if (cp >= 0xd800 and cp <= 0xdbff and
                    i + 6 < quoted.len and quoted[i] == '\\' and quoted[i + 1] == 'u')
                {
                    var lo: u21 = 0;
                    for (0..4) |k| lo = lo * 16 + hexVal(quoted[i + 2 + k]);
                    if (lo >= 0xdc00 and lo <= 0xdfff) {
                        cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
                        i += 6;
                    } else {
                        cp = 0xfffd;
                    }
                } else if (cp >= 0xd800 and cp <= 0xdfff) {
                    cp = 0xfffd;
                }
                var utf8: [4]u8 = undefined;
                const n = std.unicode.utf8Encode(cp, &utf8) catch {
                    try out.appendSlice(allocator, "\u{fffd}");
                    continue;
                };
                try out.appendSlice(allocator, utf8[0..n]);
            },
            else => return Error.CorruptState, // unreachable: validated before
        }
    }
    return std.mem.eql(u8, out.items, name);
}

fn hexVal(c: u8) u21 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => 0, // unreachable: validated before
    };
}

/// jsonValid: Go encoding/json Valid equivalent. Strict JSON grammar
/// over one complete value (no trailing data), duplicate member names
/// accepted, zero allocations (an OOM during validation can never
/// misreport valid input as InvalidJson).
fn jsonValid(data: []const u8) bool {
    var pos: usize = 0;
    skipValue(data, &pos, 0) catch return false;
    skipWs(data, &pos);
    return pos == data.len;
}

/// Skip one JSON value; grammar mirrors Go encoding/json (strict
/// numbers, strict escapes, duplicate members accepted, max depth
/// 10000). pos starts past leading ws and ends past the value.
fn skipValue(data: []const u8, pos: *usize, depth: u32) ScanError!void {
    if (depth > 10000) return ScanError.TooDeep;
    skipWs(data, pos);
    if (pos.* >= data.len) return ScanError.InvalidJson;
    switch (data[pos.*]) {
        '{' => {
            pos.* += 1;
            skipWs(data, pos);
            if (pos.* < data.len and data[pos.*] == '}') {
                pos.* += 1;
                return;
            }
            while (true) {
                skipWs(data, pos);
                if (pos.* >= data.len or data[pos.*] != '"') return ScanError.InvalidJson;
                try skipString(data, pos);
                skipWs(data, pos);
                if (pos.* >= data.len or data[pos.*] != ':') return ScanError.InvalidJson;
                pos.* += 1;
                try skipValue(data, pos, depth + 1);
                skipWs(data, pos);
                if (pos.* >= data.len) return ScanError.InvalidJson;
                if (data[pos.*] == ',') {
                    pos.* += 1;
                    continue;
                }
                if (data[pos.*] == '}') {
                    pos.* += 1;
                    return;
                }
                return ScanError.InvalidJson;
            }
        },
        '[' => {
            pos.* += 1;
            skipWs(data, pos);
            if (pos.* < data.len and data[pos.*] == ']') {
                pos.* += 1;
                return;
            }
            while (true) {
                try skipValue(data, pos, depth + 1);
                skipWs(data, pos);
                if (pos.* >= data.len) return ScanError.InvalidJson;
                if (data[pos.*] == ',') {
                    pos.* += 1;
                    continue;
                }
                if (data[pos.*] == ']') {
                    pos.* += 1;
                    return;
                }
                return ScanError.InvalidJson;
            }
        },
        '"' => try skipString(data, pos),
        't' => try skipLiteral(data, pos, "true"),
        'f' => try skipLiteral(data, pos, "false"),
        'n' => try skipLiteral(data, pos, "null"),
        '-', '0'...'9' => try skipNumber(data, pos),
        else => return ScanError.InvalidJson,
    }
}

fn skipWs(data: []const u8, pos: *usize) void {
    while (pos.* < data.len) {
        switch (data[pos.*]) {
            ' ', '\t', '\n', '\r' => pos.* += 1,
            else => return,
        }
    }
}

/// Strings: escapes validated; unescaped bytes below 0x20 rejected.
/// Raw bytes 0x7f and up pass through like Go (no UTF-8 check in Valid).
fn skipString(data: []const u8, pos: *usize) ScanError!void {
    var i = pos.* + 1; // skip opening quote
    while (i < data.len) {
        const c = data[i];
        if (c == '"') {
            pos.* = i + 1;
            return;
        }
        if (c == '\\') {
            i += 1;
            if (i >= data.len) return ScanError.InvalidJson;
            switch (data[i]) {
                '"', '\\', '/', 'b', 'f', 'n', 'r', 't' => i += 1,
                'u' => {
                    i += 1;
                    for (0..4) |_| {
                        if (i >= data.len or !isHexDigit(data[i])) return ScanError.InvalidJson;
                        i += 1;
                    }
                },
                else => return ScanError.InvalidJson,
            }
            continue;
        }
        if (c < 0x20) return ScanError.InvalidJson;
        i += 1;
    }
    return ScanError.InvalidJson;
}

fn skipLiteral(data: []const u8, pos: *usize, word: []const u8) ScanError!void {
    if (pos.* + word.len > data.len) return ScanError.InvalidJson;
    if (!std.mem.eql(u8, data[pos.*..][0..word.len], word)) return ScanError.InvalidJson;
    pos.* += word.len;
}

/// Go number grammar: -?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?
fn skipNumber(data: []const u8, pos: *usize) ScanError!void {
    var i = pos.*;
    if (i < data.len and data[i] == '-') i += 1;
    if (i >= data.len) return ScanError.InvalidJson;
    if (data[i] == '0') {
        i += 1;
    } else if (data[i] >= '1' and data[i] <= '9') {
        while (i < data.len and data[i] >= '0' and data[i] <= '9') i += 1;
    } else {
        return ScanError.InvalidJson;
    }
    if (i < data.len and data[i] == '.') {
        i += 1;
        if (i >= data.len or data[i] < '0' or data[i] > '9') return ScanError.InvalidJson;
        while (i < data.len and data[i] >= '0' and data[i] <= '9') i += 1;
    }
    if (i < data.len and (data[i] == 'e' or data[i] == 'E')) {
        i += 1;
        if (i < data.len and (data[i] == '+' or data[i] == '-')) i += 1;
        if (i >= data.len or data[i] < '0' or data[i] > '9') return ScanError.InvalidJson;
        while (i < data.len and data[i] >= '0' and data[i] <= '9') i += 1;
    }
    pos.* = i;
}

fn isHexDigit(c: u8) bool {
    return (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F');
}

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
            .permissions = @fromBackingInt(@intCast(0o600)),
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
        std.Io.Dir.createDirAbsolute(io, cur[0..len], @fromBackingInt(@intCast(0o750))) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return profile.FileError.MkdirFailed,
        };
    }
}
