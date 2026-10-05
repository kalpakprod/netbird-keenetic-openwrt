// M8 foreground executable: offline command dispatcher (std + cli/engine/profile).
// Adapted for release v080 (W06-main-dispatch) from the M8 offline draft in
// wt-m8-main-offline-muse/src/app.zig; behavior contract unchanged, version
// marker kept per the card contract (0.79.0-zig-dev, Zig dev port, not upstream).
// Real in this slice: help/version/status/down against a local profile
// config. login/up need a service adapter: with an injected Backend (unit
// boundary only) login authenticates via loginFn and up starts via
// Engine.login; without a Backend both exit NetworkUnavailable and create
// no tunnels. No daemon/M9 IPC: down never claims to stop another process.
//
// Precedence (this invocation only, never persisted): --config selects the
// file (default /var/lib/netbird/default.json); the backend always gets
// an effective management URL (override > config > built-in default);
// the setup key is transient
// (passed to loginFn, never written to config, never printed). The override
// is validated before any config file is created; a populated config
// ManagementURL is validated after load. Malformed values are rejected,
// never rewritten. An existing config is never rewritten by this slice;
// loadConfig only creates a missing file.
// Exit codes: 0 ok, 1 usage, 2 config/internal, 3 service/unavailable.

const std = @import("std");
const cli = @import("cli.zig");
const engine = @import("engine.zig");
const profile = @import("state/profile.zig");

pub const version = "0.79.0-zig-dev";

pub const exit_ok: u8 = 0;
pub const exit_usage: u8 = 1;
pub const exit_config: u8 = 2;
pub const exit_service: u8 = 3;

pub const default_config_path = profile.default_config_path_dir_linux ++ profile.default_config_file;

/// Unit service boundary. serviceFn builds a live engine.Service for one
/// command invocation. cfg and management_url are borrowed for the call
/// duration only; management_url is always the effective URL
/// (override > config > built-in default), never null. The setup key is
/// transient (login/up only, never stored or printed). The later real
/// adapter plugs in here with no CLI edits.
pub const Backend = struct {
    ctx: *anyopaque,
    serviceFn: *const fn (
        ctx: *anyopaque,
        cfg: *const profile.Config,
        management_url: []const u8,
        setup_key: ?[]const u8,
    ) engine.Service,
};

pub const ResolveError = error{ CannotResolveConfigPath, OutOfMemory };

/// Absolute config path: absolute input is duped, relative input is joined
/// onto the actual cwd (getcwd syscall, no /proc). loadConfig needs an
/// absolute path (openFileAbsolute/createFileAbsolute).
pub fn resolveConfigPath(alloc: std.mem.Allocator, path: []const u8) ResolveError![]u8 {
    if (std.fs.path.isAbsolute(path)) return alloc.dupe(u8, path);
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const rc = std.os.linux.getcwd(&buf, buf.len);
    if (rc > 0xfffffffffffff000) return ResolveError.CannotResolveConfigPath;
    const end = std.mem.indexOfScalar(u8, &buf, 0) orelse return ResolveError.CannotResolveConfigPath;
    return std.fmt.allocPrint(alloc, "{s}/{s}", .{ buf[0..end], path });
}

fn isValidScheme(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s, 0..) |c, i| {
        const ok = std.ascii.isAlphanumeric(c) or c == '+' or c == '-' or c == '.';
        if (!ok) return false;
        if (i == 0 and !std.ascii.isAlphabetic(c)) return false;
    }
    return true;
}

/// Minimal well-formedness: scheme://host... with a URI scheme start and a
/// non-empty host. Rejects "", "notaurl", "http://", "://h", spaces.
pub fn isValidManagementUrl(s: []const u8) bool {
    for (s) |c| if (c <= 0x20 or c == 0x7f) return false;
    const sep = std.mem.indexOf(u8, s, "://") orelse return false;
    if (!isValidScheme(s[0..sep])) return false;
    const rest = s[sep + 3 ..];
    if (rest.len == 0) return false;
    var host_len: usize = 0;
    for (rest) |c| {
        if (c == '/' or c == '?' or c == '#') break;
        host_len += 1;
    }
    return host_len > 0;
}

/// Same rule for a populated config ManagementURL struct: usable scheme
/// plus non-empty host. A null URL is fine (defaults apply downstream).
pub fn isValidConfigUrl(u: profile.Url) bool {
    if (!isValidScheme(u.Scheme)) return false;
    if (u.Host.len == 0) return false;
    for (u.Host) |c| if (c <= 0x20 or c == 0x7f) return false;
    return true;
}

/// Render a validated config URL as scheme://host + path + query +
/// fragment. User/Opaque/RawPath/ForceQuery/OmitHost never occur in
/// management configs (Go marshals Userinfo as {}) and are not rendered.
fn formatConfigUrl(alloc: std.mem.Allocator, u: profile.Url) std.mem.Allocator.Error![]u8 {
    const qsep: []const u8 = if (u.RawQuery.len > 0) "?" else "";
    const fsep: []const u8 = if (u.Fragment.len > 0) "#" else "";
    return std.fmt.allocPrint(alloc, "{s}://{s}{s}{s}{s}{s}{s}", .{
        u.Scheme, u.Host, u.Path, qsep, u.RawQuery, fsep, u.Fragment,
    });
}

pub fn writeJsonString(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    try w.writeByte('"');
    for (s) |c| switch (c) {
        '"' => try w.writeAll("\\\""),
        '\\' => try w.writeAll("\\\\"),
        '\n' => try w.writeAll("\\n"),
        '\r' => try w.writeAll("\\r"),
        '\t' => try w.writeAll("\\t"),
        0x08 => try w.writeAll("\\b"),
        0x0c => try w.writeAll("\\f"),
        else => {
            if (c < 0x20) {
                const hex = "0123456789abcdef";
                try w.writeAll("\\u00");
                try w.writeByte(hex[c >> 4]);
                try w.writeByte(hex[c & 15]);
            } else {
                try w.writeByte(c);
            }
        },
    };
    try w.writeByte('"');
}

fn writeJsonStatus(w: *std.Io.Writer, state: []const u8, message: []const u8) std.Io.Writer.Error!void {
    try w.writeAll("{\"state\":");
    try writeJsonString(w, state);
    try w.writeAll(",\"message\":");
    try writeJsonString(w, message);
    try w.writeAll("}\n");
}

fn parseErrorText(err: cli.Error) []const u8 {
    return switch (err) {
        error.UnknownCommand => "error: unknown command\n",
        error.UnknownFlag => "error: unknown flag\n",
        error.MissingValue => "error: missing value for flag\n",
        error.EmptyValue => "error: empty value for flag\n",
        error.DuplicateSetupKey => "error: duplicate setup key\n",
        error.UnexpectedPositional => "error: unexpected argument\n",
        error.OutOfMemory => "error: out of memory\n",
    };
}

/// Run one command. Owns nothing after return; backend borrows only during
/// the call. help/version touch neither config nor network nor backend.
/// status/down never touch the network; login/up without a backend exit
/// NetworkUnavailable. --json affects status/down only.
pub fn run(
    alloc: std.mem.Allocator,
    io: std.Io,
    argv: []const []const u8,
    stdout: *std.Io.Writer,
    stderr: *std.Io.Writer,
    backend: ?Backend,
) u8 {
    var opts = cli.parse(alloc, argv) catch |err| {
        stderr.writeAll(parseErrorText(err)) catch {};
        return if (err == error.OutOfMemory) exit_config else exit_usage;
    };
    defer opts.deinit();

    if (opts.command == .help) {
        cli.usage(stdout) catch {};
        return exit_ok;
    }
    if (opts.command == .version) {
        stdout.print("netbird {s}\n", .{version}) catch {};
        return exit_ok;
    }

    if (opts.management_url) |u| {
        if (!isValidManagementUrl(u)) {
            stderr.writeAll("error: malformed management URL\n") catch {};
            return exit_usage;
        }
    }

    const raw_path: []const u8 = opts.config orelse default_config_path;
    const abs_path = resolveConfigPath(alloc, raw_path) catch |err| {
        stderr.writeAll(if (err == error.OutOfMemory)
            "error: out of memory\n"
        else
            "error: cannot resolve config path\n") catch {};
        return exit_config;
    };
    defer alloc.free(abs_path);

    var parsed = profile.loadConfig(io, alloc, abs_path) catch |err| {
        switch (err) {
            error.InvalidJson => stderr.print("error: corrupt config: {s}\n", .{abs_path}) catch {},
            error.OutOfMemory => stderr.writeAll("error: out of memory\n") catch {},
            else => stderr.print("error: cannot load config {s} (use --config PATH)\n", .{abs_path}) catch {},
        }
        return exit_config;
    };
    defer parsed.deinit();

    if (parsed.value.ManagementURL) |mu| {
        if (!isValidConfigUrl(mu)) {
            stderr.print("error: malformed management URL in config: {s}\n", .{abs_path}) catch {};
            return exit_config;
        }
    }

    // Effective management URL: override > config > built-in default.
    // Borrowed by the backend for the call; nothing is persisted.
    var owned_mgmt: ?[]u8 = null;
    defer {
        if (owned_mgmt) |m| alloc.free(m);
    }
    const mgmt: []const u8 = mgmt: {
        if (opts.management_url) |u| break :mgmt u;
        const mu = parsed.value.ManagementURL orelse break :mgmt profile.default_management_url;
        owned_mgmt = formatConfigUrl(alloc, mu) catch {
            stderr.writeAll("error: out of memory\n") catch {};
            return exit_config;
        };
        break :mgmt owned_mgmt.?;
    };
    return switch (opts.command) {
        .status => cmdStatus(&opts, &parsed.value, stdout),
        .down => cmdDown(alloc, &opts, &parsed.value, mgmt, stdout, stderr, backend),
        .login => cmdLogin(&opts, &parsed.value, mgmt, stdout, stderr, backend),
        .up => cmdUp(alloc, &opts, &parsed.value, mgmt, stdout, stderr, backend),
        .help, .version => unreachable,
    };
}

fn cmdStatus(opts: *const cli.Options, cfg: *const profile.Config, stdout: *std.Io.Writer) u8 {
    // No identity -> needs_login. A stored private key alone never means
    // connected/authenticated: without a daemon to query we report stopped.
    const st: engine.State = if (cfg.PrivateKey.len == 0) .needs_login else .stopped;
    const msg: []const u8 = if (cfg.PrivateKey.len == 0)
        "setup key required"
    else
        "not running (standalone offline status; no daemon queried)";
    if (opts.json) {
        writeJsonStatus(stdout, st.name(), msg) catch {};
    } else {
        const status = engine.Status{ .state = st, .message = msg };
        status.format(stdout) catch {};
    }
    return exit_ok;
}

fn cmdDown(
    alloc: std.mem.Allocator,
    opts: *const cli.Options,
    cfg: *const profile.Config,
    mgmt: []const u8,
    stdout: *std.Io.Writer,
    stderr: *std.Io.Writer,
    backend: ?Backend,
) u8 {
    // Offline down: no network, config preserved, idempotent. With a unit
    // backend the Engine still runs down() so live resources (if any) are
    // cleaned at most once; from idle that is a quiet no-op. Never claims
    // to stop another process: M9 IPC does not exist yet.
    if (backend) |b| {
        var eng = engine.Engine.init(alloc, b.serviceFn(b.ctx, cfg, mgmt, null)) catch {
            stderr.writeAll("down: out of memory\n") catch {};
            return exit_config;
        };
        defer eng.deinit();
        eng.down() catch {};
    }
    const msg = "no foreground service running (offline; config preserved)";
    if (opts.json) {
        writeJsonStatus(stdout, engine.State.stopped.name(), msg) catch {};
    } else {
        stdout.print("down: {s}\n", .{msg}) catch {};
    }
    return exit_ok;
}

fn cmdLogin(
    opts: *const cli.Options,
    cfg: *const profile.Config,
    mgmt: []const u8,
    stdout: *std.Io.Writer,
    stderr: *std.Io.Writer,
    backend: ?Backend,
) u8 {
    const key = opts.setup_key orelse {
        stderr.writeAll("login: setup key required\n") catch {};
        return exit_usage;
    };
    const b = backend orelse {
        stderr.writeAll("login: NetworkUnavailable: no service adapter in this offline slice; no tunnels created\n") catch {};
        return exit_service;
    };
    // Unit path only: authenticate via loginFn, never start. The key is
    // borrowed for this call, never stored, never printed.
    const svc = b.serviceFn(b.ctx, cfg, mgmt, key);
    svc.loginFn(svc.ctx, key) catch |err| {
        switch (err) {
            error.AuthFailed => stderr.writeAll("login: authentication failed\n") catch {},
            error.Network => stderr.writeAll("login: network error\n") catch {},
            error.OutOfMemory => stderr.writeAll("login: out of memory\n") catch {},
        }
        return if (err == error.OutOfMemory) exit_config else exit_service;
    };
    stdout.writeAll("login: authenticated (no tunnel started in this offline slice)\n") catch {};
    return exit_ok;
}

fn cmdUp(
    alloc: std.mem.Allocator,
    opts: *const cli.Options,
    cfg: *const profile.Config,
    mgmt: []const u8,
    stdout: *std.Io.Writer,
    stderr: *std.Io.Writer,
    backend: ?Backend,
) u8 {
    const key = opts.setup_key orelse {
        stderr.writeAll("up: setup key required (no persisted authentication in this slice)\n") catch {};
        return exit_usage;
    };
    const b = backend orelse {
        stderr.writeAll("up: NetworkUnavailable: no service adapter in this offline slice; no tunnels created\n") catch {};
        return exit_service;
    };
    // Unit path only: each invocation starts unauthenticated (no daemon or
    // session store yet), so up authenticates then starts through
    // Engine.login; all transitions stay in the Engine. -F is accepted but
    // there is no foreground supervisor until the real adapter lands.
    var eng = engine.Engine.init(alloc, b.serviceFn(b.ctx, cfg, mgmt, key)) catch {
        stderr.writeAll("up: out of memory\n") catch {};
        return exit_config;
    };
    defer eng.deinit();
    // LIFO: down runs before deinit on every return after start, so a
    // started service is released exactly once; from error/idle states
    // down is a quiet no-op and never re-stops a rolled-back start.
    defer eng.down() catch {};
    eng.login(key) catch |err| {
        switch (err) {
            error.MissingSetupKey => stderr.writeAll("up: setup key required\n") catch {},
            error.AuthFailed => stderr.writeAll("up: authentication failed\n") catch {},
            error.Network => stderr.writeAll("up: network error\n") catch {},
            error.StartFailed => stderr.writeAll("up: start failed\n") catch {},
            error.OutOfMemory => stderr.writeAll("up: out of memory\n") catch {},
        }
        return switch (err) {
            error.MissingSetupKey => exit_usage,
            error.OutOfMemory => exit_config,
            else => exit_service,
        };
    };
    stdout.writeAll("up: connected (injected unit service only; no real network)\n") catch {};
    return exit_ok;
}
