// Port of netbird client/internal/profilemanager (v0.79.0), BSD-3-Clause.
// Reference: upstream/netbird/client/internal/profilemanager/config.go,
// profilemanager.go, service.go, state.go, prefs.go, id.go and
// upstream/netbird/util/file.go (atomic JSON write).
// Scope: Config JSON shape + load/save, profile paths, ProfileState email
// file, Prefs namespace store, atomic replace (temp + rename, 0600),
// lseek-based file sizing (no statx). Out of scope: MDM policy, sudo/
// invoking-user resolution, URL migration probes, SSH key generation,
// name sanitization rules beyond storage.

const std = @import("std");

pub const default_management_url = "https://api.netbird.io:443";
pub const default_admin_url = "https://app.netbird.io:443";
pub const default_wg_port = 51820;
pub const default_wg_iface = "wt0";
pub const default_profile_name = "default";

pub const default_config_path_dir_linux = "/var/lib/netbird/";
pub const old_default_config_path_dir_linux = "/etc/netbird/";
pub const default_config_file = "default.json";
pub const old_default_config_file = "config.json";
pub const active_profile_state_file = "active_profile.json";
pub const prefs_file_suffix = ".prefs.json";
pub const state_file_suffix = ".state.json";

/// Test hook mirroring ConfigDirOverride.
pub var config_dir_override: []const u8 = "";

/// User config dir for profile state/email files. Mirrors getConfigDir on
/// Linux: $XDG_CONFIG_HOME/netbird or ~/.config/netbird (no sudo/MDM logic).
/// Takes the process environment map (std.process.Init.environ_map) from
/// the caller: no libc getenv, no /proc scan.
pub fn userConfigDir(allocator: std.mem.Allocator, environ: std.process.Environ.Map) ![]u8 {
    if (config_dir_override.len > 0) {
        return allocator.dupe(u8, config_dir_override);
    }
    if (environ.get("XDG_CONFIG_HOME")) |base| {
        return std.fmt.allocPrint(allocator, "{s}/netbird", .{base});
    }
    const home = environ.get("HOME") orelse return error.EnvironmentVariableNotFound;
    return std.fmt.allocPrint(allocator, "{s}/.config/netbird", .{home});
}

/// net/url.URL JSON shape: Go has no MarshalText on URL, so it marshals as
/// a plain object with these exact fields (verified with Go, see report).
pub const Url = struct {
    Scheme: []const u8 = "",
    Opaque: []const u8 = "",
    User: ?Userinfo = null,
    Host: []const u8 = "",
    Path: []const u8 = "",
    Fragment: []const u8 = "",
    RawQuery: []const u8 = "",
    RawPath: []const u8 = "",
    RawFragment: []const u8 = "",
    ForceQuery: bool = false,
    OmitHost: bool = false,
};

pub const Userinfo = struct {
    username: []const u8,
    password: []const u8,
    passwordSet: bool,
};

/// Mirrors profilemanager.Config field-for-field. No omitempty exists
/// upstream: every field is always present (nil pointer/slice -> null).
pub const Config = struct {
    Name: []const u8 = "",
    PrivateKey: []const u8 = "",
    PreSharedKey: []const u8 = "",
    ManagementURL: ?Url = null,
    AdminURL: ?Url = null,
    WgIface: []const u8 = "",
    WgPort: i64 = 0,
    NetworkMonitor: ?bool = null,
    IFaceBlackList: ?[][]const u8 = null,
    DisableIPv6Discovery: bool = false,
    RosenpassEnabled: bool = false,
    RosenpassPermissive: bool = false,
    ServerSSHAllowed: ?bool = null,
    RemoteJobsAllowed: ?bool = null,
    EnableSSHRoot: ?bool = null,
    EnableSSHSFTP: ?bool = null,
    EnableSSHLocalPortForwarding: ?bool = null,
    EnableSSHRemotePortForwarding: ?bool = null,
    DisableSSHAuth: ?bool = null,
    SSHJWTCacheTTL: ?i64 = null,
    DisableClientRoutes: bool = false,
    DisableServerRoutes: bool = false,
    DisableDNS: bool = false,
    DisableFirewall: bool = false,
    BlockLANAccess: bool = false,
    BlockInbound: bool = false,
    DisableIPv6: bool = false,
    SyncMessageVersion: ?i64 = null,
    DisableNotifications: ?bool = null,
    DNSLabels: ?[][]const u8 = null,
    LocalMetricsEnabled: bool = false,
    LocalMetricsAddress: []const u8 = "",
    SSHKey: []const u8 = "",
    NATExternalIPs: ?[][]const u8 = null,
    CustomDNSAddress: []const u8 = "",
    DisableAutoConnect: bool = false,
    DNSRouteInterval: i64 = 0,
    ClientCertPath: []const u8 = "",
    ClientCertKeyPath: []const u8 = "",
};

pub const ProfileState = struct {
    email: []const u8 = "",
};

pub const FileError = error{
    NotFound,
    ReadFailed,
    WriteFailed,
    RenameFailed,
    MkdirFailed,
    InvalidJson,
    InvalidName,
};

pub const Error = FileError || std.mem.Allocator.Error;

/// File size via raw lseek(SEEK_END): no statx, safe on kernel 4.9.
fn sizeViaLseek(handle: std.Io.File.Handle) FileError!u64 {
    const lseek = std.os.linux.lseek;
    const SEEK = std.os.linux.SEEK;
    const end = lseek(handle, 0, SEEK.END);
    if (end > 0xfffffffffffff000) return FileError.ReadFailed;
    const back = lseek(handle, 0, SEEK.SET);
    if (back > 0xfffffffffffff000) return FileError.ReadFailed;
    return end;
}

/// Read a whole file, sizing with lseek (no statx).
pub fn readFileLseek(io: std.Io, allocator: std.mem.Allocator, path: []const u8) FileError![]u8 {
    const file = std.Io.Dir.openFileAbsolute(io, path, .{ .mode = .read_only }) catch |err| switch (err) {
        error.FileNotFound => return FileError.NotFound,
        else => return FileError.ReadFailed,
    };
    defer file.close(io);
    const size = try sizeViaLseek(file.handle);
    const buf = allocator.alloc(u8, size) catch return FileError.ReadFailed;
    errdefer allocator.free(buf);
    const n = file.readPositionalAll(io, buf, 0) catch return FileError.ReadFailed;
    if (n != buf.len) {
        allocator.free(buf);
        return FileError.ReadFailed;
    }
    return buf;
}

fn makePathAbsolute(io: std.Io, path: []const u8) FileError!void {
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
        if (len + comp.name.len > cur.len) return FileError.MkdirFailed;
        @memcpy(cur[len..][0..comp.name.len], comp.name);
        len += comp.name.len;
        std.Io.Dir.createDirAbsolute(io, cur[0..len], @enumFromInt(0o750)) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return FileError.MkdirFailed,
        };
    }
}

/// Atomic JSON write: temp file (0600) in the target dir + rename.
/// Mirrors util.WriteJson (MarshalIndent 4 spaces, MkdirAll 0750).
pub fn writeJsonAtomic(io: std.Io, allocator: std.mem.Allocator, path: []const u8, value: anytype) FileError!void {
    const dir = std.fs.path.dirname(path) orelse ".";
    makePathAbsolute(io, dir) catch |err| switch (err) {
        FileError.MkdirFailed => {
            // The dir may already exist; makePath tolerates that, so a
            // failure here is real unless it is the degenerate ".".
            if (!std.mem.eql(u8, dir, ".")) return FileError.MkdirFailed;
        },
        else => return err,
    };
    const bytes = std.json.Stringify.valueAlloc(allocator, value, .{ .whitespace = .indent_4 }) catch {
        return FileError.WriteFailed;
    };
    defer allocator.free(bytes);
    var tmp_name: [std.fs.max_path_bytes]u8 = undefined;
    const base = std.fs.path.basename(path);
    const pid = std.os.linux.getpid();
    const rand: u32 = @bitCast(std.os.linux.gettid());
    const tmp = std.fmt.bufPrint(&tmp_name, "{s}/.{s}.tmp.{d}.{d}", .{ dir, base, pid, rand }) catch {
        return FileError.WriteFailed;
    };
    {
        const tmp_file = std.Io.Dir.createFileAbsolute(io, tmp, .{
            .truncate = true,
            .permissions = @enumFromInt(0o600),
        }) catch {
            return FileError.WriteFailed;
        };
        defer tmp_file.close(io);
        tmp_file.writePositionalAll(io, bytes, 0) catch {
            std.Io.Dir.deleteFileAbsolute(io, tmp) catch {};
            return FileError.WriteFailed;
        };
    }
    std.Io.Dir.renameAbsolute(tmp, path, io) catch {
        std.Io.Dir.deleteFileAbsolute(io, tmp) catch {};
        return FileError.RenameFailed;
    };
}

/// Parse config JSON. Unknown fields are ignored like Go's Unmarshal.
/// NOTE: Go matches field names case-insensitively; this port requires
/// exact names (all real writers use them).
pub fn parseConfig(allocator: std.mem.Allocator, data: []const u8) Error!std.json.Parsed(Config) {
    return std.json.parseFromSlice(Config, allocator, data, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch {
        return Error.InvalidJson;
    };
}

/// Structural defaults applied after load, mirroring the createNewConfig +
/// apply() fallback path for missing values (URL/iface/port/bools). Secret
/// generation (SSH key) belongs to later milestones.
pub fn applyDefaults(cfg: *Config) void {
    if (cfg.ManagementURL == null) {
        cfg.ManagementURL = Url{ .Scheme = "https", .Host = "api.netbird.io:443" };
    }
    if (cfg.AdminURL == null) {
        cfg.AdminURL = Url{ .Scheme = "https", .Host = "app.netbird.io:443" };
    }
    if (cfg.WgIface.len == 0) {
        cfg.WgIface = default_wg_iface;
    }
    if (cfg.WgPort == 0) {
        cfg.WgPort = default_wg_port;
    }
    if (cfg.ServerSSHAllowed == null) {
        cfg.ServerSSHAllowed = false;
    }
    if (cfg.RemoteJobsAllowed == null) {
        cfg.RemoteJobsAllowed = false;
    }
}

/// Load config, creating it with defaults when missing (readConfig).
pub fn loadConfig(io: std.Io, allocator: std.mem.Allocator, path: []const u8) Error!std.json.Parsed(Config) {
    const data = readFileLseek(io, allocator, path) catch |err| switch (err) {
        FileError.NotFound => {
            var cfg = Config{};
            applyDefaults(&cfg);
            try writeJsonAtomic(io, allocator, path, cfg);
            const reloaded = try readFileLseek(io, allocator, path);
            defer allocator.free(reloaded);
            return parseConfig(allocator, reloaded);
        },
        else => return err,
    };
    defer allocator.free(data);
    var parsed = try parseConfig(allocator, data);
    applyDefaults(&parsed.value);
    return parsed;
}

/// Save config (WriteOutConfig).
pub fn saveConfig(io: std.Io, allocator: std.mem.Allocator, path: []const u8, cfg: *const Config) FileError!void {
    try writeJsonAtomic(io, allocator, path, cfg);
}

/// ProfileState email file: <dir>/<id>.state.json (Get/SetProfileState).
pub fn profileStatePath(allocator: std.mem.Allocator, dir: []const u8, id: []const u8) Error![]u8 {
    if (!isValidProfileFilenameStem(id)) return Error.InvalidName;
    return std.fmt.allocPrint(allocator, "{s}/{s}{s}", .{ dir, id, state_file_suffix }) catch {
        return Error.InvalidJson;
    };
}

pub fn isValidProfileFilenameStem(id: []const u8) bool {
    if (id.len == 0 or id.len > 64) return false;
    if (std.mem.eql(u8, id, default_profile_name)) return true;
    if (std.mem.indexOfAny(u8, id, "/\\") != null) return false;
    if (std.mem.indexOf(u8, id, "..") != null) return false;
    if (!std.mem.eql(u8, std.fs.path.basename(id), id)) return false;
    for (id) |c| {
        if (c < 0x20 or c == 0x7f) return false;
    }
    return true;
}

/// Prefs namespace store: <dir>/<id>.prefs.json, map namespace -> raw JSON
/// (readPrefsFile/writePrefsFile semantics: missing file reads as empty).
pub const Prefs = struct {
    path: []u8,
    allocator: std.mem.Allocator,
    io: std.Io,

    pub fn init(io: std.Io, allocator: std.mem.Allocator, dir: []const u8, id: []const u8) Error!Prefs {
        if (!isValidProfileFilenameStem(id)) return Error.InvalidName;
        const path = std.fmt.allocPrint(allocator, "{s}/{s}{s}", .{ dir, id, prefs_file_suffix }) catch {
            return Error.InvalidJson;
        };
        return .{ .path = path, .allocator = allocator, .io = io };
    }

    pub fn deinit(p: *Prefs) void {
        p.allocator.free(p.path);
    }

    pub fn get(p: *Prefs, namespace: []const u8, comptime T: type) Error!?std.json.Parsed(T) {
        if (namespace.len == 0) return Error.InvalidName;
        const data = readFileLseek(p.io, p.allocator, p.path) catch |err| switch (err) {
            FileError.NotFound => return null,
            else => return err,
        };
        defer p.allocator.free(data);
        var parsed = std.json.parseFromSlice(std.json.Value, p.allocator, data, .{}) catch {
            return Error.InvalidJson;
        };
        defer parsed.deinit();
        const raw = parsed.value.object.get(namespace) orelse return null;
        const section = std.json.Stringify.valueAlloc(p.allocator, raw, .{}) catch {
            return Error.InvalidJson;
        };
        defer p.allocator.free(section);
        return std.json.parseFromSlice(T, p.allocator, section, .{
            .ignore_unknown_fields = true,
            .allocate = .alloc_always,
        }) catch {
            return Error.InvalidJson;
        };
    }

    pub fn put(p: *Prefs, namespace: []const u8, value: anytype) Error!void {
        if (namespace.len == 0) return Error.InvalidName;
        const Map = std.json.ArrayHashMap(std.json.Value);
        var sections = Map{ .map = .empty };
        defer sections.deinit(p.allocator);
        if (readFileLseek(p.io, p.allocator, p.path)) |data| {
            defer p.allocator.free(data);
            var existing = std.json.parseFromSlice(Map, p.allocator, data, .{}) catch {
                return Error.InvalidJson;
            };
            defer existing.deinit();
            var it = existing.value.map.iterator();
            while (it.next()) |e| {
                sections.map.put(p.allocator, e.key_ptr.*, e.value_ptr.*) catch {
                    return Error.InvalidJson;
                };
            }
            // Fall through with borrowed entries; write before deinit.
            try p.putMerged(namespace, value, &sections);
            return;
        } else |err| switch (err) {
            FileError.NotFound => {},
            else => return err,
        }
        try p.putMerged(namespace, value, &sections);
    }

    fn putMerged(p: *Prefs, namespace: []const u8, value: anytype, sections: anytype) Error!void {
        const val_json = std.json.Stringify.valueAlloc(p.allocator, value, .{}) catch {
            return Error.InvalidJson;
        };
        defer p.allocator.free(val_json);
        var vparsed = std.json.parseFromSlice(std.json.Value, p.allocator, val_json, .{}) catch {
            return Error.InvalidJson;
        };
        defer vparsed.deinit();
        sections.map.put(p.allocator, namespace, vparsed.value) catch return Error.InvalidJson;
        try writeJsonAtomic(p.io, p.allocator, p.path, sections);
    }

    pub fn remove(p: *Prefs, namespace: []const u8) Error!void {
        if (namespace.len == 0) return Error.InvalidName;
        const data = readFileLseek(p.io, p.allocator, p.path) catch |err| switch (err) {
            FileError.NotFound => return,
            else => return err,
        };
        defer p.allocator.free(data);
        var parsed = std.json.parseFromSlice(std.json.Value, p.allocator, data, .{}) catch {
            return Error.InvalidJson;
        };
        defer parsed.deinit();
        if (!parsed.value.object.contains(namespace)) return;
        _ = parsed.value.object.swapRemove(namespace);
        try writeJsonAtomic(p.io, p.allocator, p.path, parsed.value);
    }
};
