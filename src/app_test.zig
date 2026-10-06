// M8 offline dispatcher tests: public app.run only, plus pure helpers.
// Adapted for release v080 (W06-main-dispatch) from the M8 offline draft in
// wt-m8-main-offline-muse/src/app_test.zig; cases unchanged.
// Config files live under pid-namespaced /tmp scratch dirs; the real
// /var/lib and /etc paths are never touched. No network, no daemon.

const std = @import("std");
const app = @import("app.zig");
const engine = @import("engine.zig");
const profile = @import("state/profile.zig");

const tio = std.testing.io;

fn scratchRoot(alloc: std.mem.Allocator) ![]u8 {
    return std.fmt.allocPrint(alloc, "/tmp/nb-app-test-{d}", .{std.os.linux.getpid()});
}

fn cleanup(root: []const u8) void {
    std.Io.Dir.cwd().deleteTree(tio, root) catch {};
}

const Fake = struct {
    service_calls: usize = 0,
    login_calls: usize = 0,
    start_calls: usize = 0,
    stop_calls: usize = 0,
    seen_wg_port: i64 = 0,
    seen_private_len: usize = 0,
    seen_mgmt_len: usize = 0,
    seen_key_none: bool = true,
    seen_key_len: usize = 0,
    mgmt_buf: [256]u8 = undefined,
    key_buf: [256]u8 = undefined,
    login_err: ?engine.Service.AuthError = null,
    start_err: ?engine.Service.StartError = null,

    fn backend(f: *Fake) app.Backend {
        return .{ .ctx = f, .serviceFn = serviceFn };
    }

    fn serviceFn(
        ctx: *anyopaque,
        cfg: *const profile.Config,
        mgmt: []const u8,
        key: ?[]const u8,
    ) engine.Service {
        const f: *Fake = @ptrCast(@alignCast(ctx));
        f.service_calls += 1;
        f.seen_wg_port = cfg.WgPort;
        f.seen_private_len = cfg.PrivateKey.len;
        f.seen_mgmt_len = @min(mgmt.len, f.mgmt_buf.len);
        @memcpy(f.mgmt_buf[0..f.seen_mgmt_len], mgmt[0..f.seen_mgmt_len]);
        if (key) |k| {
            f.seen_key_none = false;
            f.seen_key_len = @min(k.len, f.key_buf.len);
            @memcpy(f.key_buf[0..f.seen_key_len], k[0..f.seen_key_len]);
        } else {
            f.seen_key_none = true;
            f.seen_key_len = 0;
        }
        return .{ .ctx = ctx, .loginFn = loginFn, .startFn = startFn, .stopFn = stopFn };
    }

    fn seenMgmt(f: *const Fake) []const u8 {
        return f.mgmt_buf[0..f.seen_mgmt_len];
    }

    fn seenKey(f: *const Fake) ?[]const u8 {
        return if (f.seen_key_none) null else f.key_buf[0..f.seen_key_len];
    }

    fn loginFn(ctx: *anyopaque, key: []const u8) engine.Service.AuthError!void {
        const f: *Fake = @ptrCast(@alignCast(ctx));
        f.login_calls += 1;
        _ = key;
        if (f.login_err) |e| return e;
    }

    fn startFn(ctx: *anyopaque) engine.Service.StartError!void {
        const f: *Fake = @ptrCast(@alignCast(ctx));
        f.start_calls += 1;
        if (f.start_err) |e| return e;
    }

    fn stopFn(ctx: *anyopaque) void {
        const f: *Fake = @ptrCast(@alignCast(ctx));
        f.stop_calls += 1;
    }
};

fn runOz(
    argv: []const []const u8,
    out: *std.Io.Writer,
    err: *std.Io.Writer,
    be: ?app.Backend,
) u8 {
    return app.run(std.testing.allocator, tio, argv, out, err, be);
}

test "help and no args exit zero without backend config or network" {
    var fake = Fake{};
    for ([_][]const []const u8{ &.{ "netbird", "help" }, &.{"netbird"} }) |argv| {
        var ob: [4096]u8 = undefined;
        var eb: [1024]u8 = undefined;
        var out = std.Io.Writer.fixed(&ob);
        var err = std.Io.Writer.fixed(&eb);
        try std.testing.expectEqual(@as(u8, 0), runOz(argv, &out, &err, fake.backend()));
        try std.testing.expect(std.mem.indexOf(u8, out.buffered(), "usage:") != null);
        try std.testing.expectEqual(@as(usize, 0), err.buffered().len);
    }
    try std.testing.expectEqual(@as(usize, 0), fake.service_calls);
}

test "version prints zig dev version and creates no config" {
    const root = try scratchRoot(std.testing.allocator);
    defer std.testing.allocator.free(root);
    cleanup(root);
    defer cleanup(root);
    const path = try std.fmt.allocPrint(std.testing.allocator, "{s}/nope/config.json", .{root});
    defer std.testing.allocator.free(path);

    var fake = Fake{};
    var ob: [1024]u8 = undefined;
    var eb: [1024]u8 = undefined;
    var out = std.Io.Writer.fixed(&ob);
    var err = std.Io.Writer.fixed(&eb);
    const argv = [_][]const u8{ "netbird", "version", "-c", path };
    try std.testing.expectEqual(@as(u8, 0), runOz(&argv, &out, &err, fake.backend()));
    try std.testing.expect(std.mem.indexOf(u8, out.buffered(), "0.79.0-zig-dev") != null);
    try std.testing.expectEqual(@as(usize, 0), err.buffered().len);
    try std.testing.expectEqual(@as(usize, 0), fake.service_calls);
    try std.testing.expectError(profile.FileError.NotFound, profile.readFileLseek(tio, std.testing.allocator, path));
}

test "unknown command exits nonzero with stderr only" {
    var ob: [1024]u8 = undefined;
    var eb: [1024]u8 = undefined;
    var out = std.Io.Writer.fixed(&ob);
    var err = std.Io.Writer.fixed(&eb);
    const argv = [_][]const u8{ "netbird", "frobnicate" };
    try std.testing.expectEqual(app.exit_usage, runOz(&argv, &out, &err, null));
    try std.testing.expectEqual(@as(usize, 0), out.buffered().len);
    try std.testing.expect(std.mem.indexOf(u8, err.buffered(), "unknown command") != null);
}

test "missing unknown and duplicate flags exit nonzero" {
    const cases = [_][]const []const u8{
        &.{ "netbird", "up", "--config" },
        &.{ "netbird", "up", "--frobnicate" },
        &.{ "netbird", "login", "--setup-key", "A", "--setup-key", "B" },
        &.{ "netbird", "version", "extra" },
    };
    for (cases) |argv| {
        var ob: [1024]u8 = undefined;
        var eb: [1024]u8 = undefined;
        var out = std.Io.Writer.fixed(&ob);
        var err = std.Io.Writer.fixed(&eb);
        try std.testing.expectEqual(app.exit_usage, runOz(argv, &out, &err, null));
        try std.testing.expectEqual(@as(usize, 0), out.buffered().len);
        try std.testing.expect(err.buffered().len > 0);
    }
}

test "status creates 0600 config then reports stopped once identity exists" {
    const root = try scratchRoot(std.testing.allocator);
    defer std.testing.allocator.free(root);
    cleanup(root);
    defer cleanup(root);
    const path = try std.fmt.allocPrint(std.testing.allocator, "{s}/sub/config.json", .{root});
    defer std.testing.allocator.free(path);

    const argv = [_][]const u8{ "netbird", "status", "-c", path };
    var ob: [4096]u8 = undefined;
    var eb: [1024]u8 = undefined;
    var out = std.Io.Writer.fixed(&ob);
    var err = std.Io.Writer.fixed(&eb);
    try std.testing.expectEqual(@as(u8, 0), runOz(&argv, &out, &err, null));
    try std.testing.expect(std.mem.indexOf(u8, out.buffered(), "needs_login") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.buffered(), "connected") == null);
    try std.testing.expectEqual(@as(usize, 0), err.buffered().len);

    const st = try std.Io.Dir.cwd().statFile(tio, path, .{});
    try std.testing.expectEqual(@as(u32, 0o600), @as(u32, @backingInt(st.permissions)) & 0o777);

    // Store an identity: a private key alone must report stopped, never connected.
    {
        var parsed = try profile.loadConfig(tio, std.testing.allocator, path);
        defer parsed.deinit();
        parsed.value.PrivateKey = "cHJpdi1rZXktZmFrZS1mb3ItdGVzdA";
        try profile.saveConfig(tio, std.testing.allocator, path, &parsed.value);
    }
    var ob2: [4096]u8 = undefined;
    var eb2: [1024]u8 = undefined;
    var out2 = std.Io.Writer.fixed(&ob2);
    var err2 = std.Io.Writer.fixed(&eb2);
    try std.testing.expectEqual(@as(u8, 0), runOz(&argv, &out2, &err2, null));
    try std.testing.expect(std.mem.indexOf(u8, out2.buffered(), "stopped") != null);
    try std.testing.expect(std.mem.indexOf(u8, out2.buffered(), "not running") != null);
    try std.testing.expect(std.mem.indexOf(u8, out2.buffered(), "connected") == null);
}

test "status json is a stable machine-parseable object" {
    const root = try scratchRoot(std.testing.allocator);
    defer std.testing.allocator.free(root);
    cleanup(root);
    defer cleanup(root);
    const path = try std.fmt.allocPrint(std.testing.allocator, "{s}/j.json", .{root});
    defer std.testing.allocator.free(path);

    const argv = [_][]const u8{ "netbird", "status", "--json", "-c", path };
    var ob: [4096]u8 = undefined;
    var eb: [1024]u8 = undefined;
    var out = std.Io.Writer.fixed(&ob);
    var err = std.Io.Writer.fixed(&eb);
    try std.testing.expectEqual(@as(u8, 0), runOz(&argv, &out, &err, null));
    try std.testing.expectEqual(@as(usize, 0), err.buffered().len);

    const SJ = struct { state: []const u8, message: []const u8 };
    var p = try std.json.parseFromSlice(SJ, std.testing.allocator, out.buffered(), .{});
    defer p.deinit();
    try std.testing.expectEqualStrings("needs_login", p.value.state);
    try std.testing.expect(p.value.message.len > 0);
    try std.testing.expect(std.mem.indexOf(u8, out.buffered(), "PrivateKey") == null);

    // With identity the JSON state is stopped, still parseable.
    {
        var parsed = try profile.loadConfig(tio, std.testing.allocator, path);
        defer parsed.deinit();
        parsed.value.PrivateKey = "a2V5";
        try profile.saveConfig(tio, std.testing.allocator, path, &parsed.value);
    }
    var ob2: [4096]u8 = undefined;
    var eb2: [1024]u8 = undefined;
    var out2 = std.Io.Writer.fixed(&ob2);
    var err2 = std.Io.Writer.fixed(&eb2);
    try std.testing.expectEqual(@as(u8, 0), runOz(&argv, &out2, &err2, null));
    var p2 = try std.json.parseFromSlice(SJ, std.testing.allocator, out2.buffered(), .{});
    defer p2.deinit();
    try std.testing.expectEqualStrings("stopped", p2.value.state);
}

test "json string escaping covers quotes backslash and controls" {
    var buf: [256]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try app.writeJsonString(&w, "a\"b\\c\n\x01\t\x08\x0c\r");
    try std.testing.expectEqualStrings("\"a\\\"b\\\\c\\n\\u0001\\t\\b\\f\\r\"", w.buffered());
}

test "repeated offline down preserves config and never logs in or starts" {
    const root = try scratchRoot(std.testing.allocator);
    defer std.testing.allocator.free(root);
    cleanup(root);
    defer cleanup(root);
    const path = try std.fmt.allocPrint(std.testing.allocator, "{s}/d.json", .{root});
    defer std.testing.allocator.free(path);
    {
        var parsed = try profile.loadConfig(tio, std.testing.allocator, path);
        defer parsed.deinit();
        parsed.value.PrivateKey = "ZG93bi1pZGVudGl0eQ";
        parsed.value.WgPort = 52111;
        try profile.saveConfig(tio, std.testing.allocator, path, &parsed.value);
    }
    const before = try profile.readFileLseek(tio, std.testing.allocator, path);
    defer std.testing.allocator.free(before);

    var fake = Fake{};
    const argv = [_][]const u8{ "netbird", "down", "-c", path };
    const argv_key = [_][]const u8{ "netbird", "down", "-c", path, "--setup-key", "IGNORED" };
    for ([_][]const []const u8{ &argv, &argv_key }) |a| {
        var ob: [4096]u8 = undefined;
        var eb: [1024]u8 = undefined;
        var out = std.Io.Writer.fixed(&ob);
        var err = std.Io.Writer.fixed(&eb);
        try std.testing.expectEqual(@as(u8, 0), runOz(a, &out, &err, fake.backend()));
        try std.testing.expect(std.mem.indexOf(u8, out.buffered(), "no foreground service running") != null);
        try std.testing.expect(std.mem.indexOf(u8, out.buffered(), "remote") == null);
        try std.testing.expectEqual(@as(usize, 0), err.buffered().len);
    }
    try std.testing.expectEqual(@as(usize, 0), fake.login_calls);
    try std.testing.expectEqual(@as(usize, 0), fake.start_calls);
    try std.testing.expect(fake.seenKey() == null);

    const after = try profile.readFileLseek(tio, std.testing.allocator, path);
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);

    // --json down is the same stable object shape.
    var ob3: [4096]u8 = undefined;
    var eb3: [1024]u8 = undefined;
    var out3 = std.Io.Writer.fixed(&ob3);
    var err3 = std.Io.Writer.fixed(&eb3);
    const argv_json = [_][]const u8{ "netbird", "down", "--json", "-c", path };
    try std.testing.expectEqual(@as(u8, 0), runOz(&argv_json, &out3, &err3, null));
    const SJ = struct { state: []const u8, message: []const u8 };
    var p = try std.json.parseFromSlice(SJ, std.testing.allocator, out3.buffered(), .{});
    defer p.deinit();
    try std.testing.expectEqualStrings("stopped", p.value.state);
}

test "login authenticates only and never starts or leaks the key" {
    const root = try scratchRoot(std.testing.allocator);
    defer std.testing.allocator.free(root);
    cleanup(root);
    defer cleanup(root);
    const path = try std.fmt.allocPrint(std.testing.allocator, "{s}/l.json", .{root});
    defer std.testing.allocator.free(path);

    var fake = Fake{};
    var ob: [4096]u8 = undefined;
    var eb: [1024]u8 = undefined;
    var out = std.Io.Writer.fixed(&ob);
    var err = std.Io.Writer.fixed(&eb);
    const argv = [_][]const u8{ "netbird", "login", "-c", path, "--setup-key", "UNITKEY-1" };
    try std.testing.expectEqual(@as(u8, 0), runOz(&argv, &out, &err, fake.backend()));
    try std.testing.expectEqual(@as(usize, 1), fake.login_calls);
    try std.testing.expectEqual(@as(usize, 0), fake.start_calls);
    try std.testing.expectEqual(@as(usize, 0), fake.stop_calls);
    try std.testing.expect(std.mem.indexOf(u8, out.buffered(), "authenticated") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.buffered(), "connected") == null);
    try std.testing.expect(std.mem.indexOf(u8, out.buffered(), "UNITKEY-1") == null);
    try std.testing.expect(std.mem.indexOf(u8, err.buffered(), "UNITKEY-1") == null);
    const data = try profile.readFileLseek(tio, std.testing.allocator, path);
    defer std.testing.allocator.free(data);
    try std.testing.expect(std.mem.indexOf(u8, data, "UNITKEY-1") == null);
}

test "injected auth failure exits nonzero with no secret and no start" {
    const root = try scratchRoot(std.testing.allocator);
    defer std.testing.allocator.free(root);
    cleanup(root);
    defer cleanup(root);
    const path = try std.fmt.allocPrint(std.testing.allocator, "{s}/lf.json", .{root});
    defer std.testing.allocator.free(path);

    var fake = Fake{ .login_err = error.AuthFailed };
    var ob: [4096]u8 = undefined;
    var eb: [1024]u8 = undefined;
    var out = std.Io.Writer.fixed(&ob);
    var err = std.Io.Writer.fixed(&eb);
    const argv = [_][]const u8{ "netbird", "login", "-c", path, "--setup-key", "BADKEY-2" };
    try std.testing.expectEqual(app.exit_service, runOz(&argv, &out, &err, fake.backend()));
    try std.testing.expectEqual(@as(usize, 0), out.buffered().len);
    try std.testing.expect(std.mem.indexOf(u8, err.buffered(), "authentication failed") != null);
    try std.testing.expect(std.mem.indexOf(u8, err.buffered(), "BADKEY-2") == null);
    try std.testing.expectEqual(@as(usize, 1), fake.login_calls);
    try std.testing.expectEqual(@as(usize, 0), fake.start_calls);
    try std.testing.expectEqual(@as(usize, 0), fake.stop_calls);
}

test "up invokes start and reports the unit boundary honestly" {
    const root = try scratchRoot(std.testing.allocator);
    defer std.testing.allocator.free(root);
    cleanup(root);
    defer cleanup(root);
    const path = try std.fmt.allocPrint(std.testing.allocator, "{s}/u.json", .{root});
    defer std.testing.allocator.free(path);

    var fake = Fake{};
    var ob: [4096]u8 = undefined;
    var eb: [1024]u8 = undefined;
    var out = std.Io.Writer.fixed(&ob);
    var err = std.Io.Writer.fixed(&eb);
    const argv = [_][]const u8{ "netbird", "up", "-F", "-c", path, "--setup-key", "UPKEY-3" };
    try std.testing.expectEqual(@as(u8, 0), runOz(&argv, &out, &err, fake.backend()));
    try std.testing.expectEqual(@as(usize, 1), fake.login_calls);
    try std.testing.expectEqual(@as(usize, 1), fake.start_calls);
    // One-shot unit up releases the started service before returning.
    try std.testing.expectEqual(@as(usize, 1), fake.stop_calls);
    try std.testing.expect(std.mem.indexOf(u8, out.buffered(), "connected") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.buffered(), "no real network") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.buffered(), "UPKEY-3") == null);
    const data = try profile.readFileLseek(tio, std.testing.allocator, path);
    defer std.testing.allocator.free(data);
    try std.testing.expect(std.mem.indexOf(u8, data, "UPKEY-3") == null);
}

test "injected start failure rolls back with exactly one stop" {
    const root = try scratchRoot(std.testing.allocator);
    defer std.testing.allocator.free(root);
    cleanup(root);
    defer cleanup(root);
    const path = try std.fmt.allocPrint(std.testing.allocator, "{s}/uf.json", .{root});
    defer std.testing.allocator.free(path);

    var fake = Fake{ .start_err = error.StartFailed };
    var ob: [4096]u8 = undefined;
    var eb: [1024]u8 = undefined;
    var out = std.Io.Writer.fixed(&ob);
    var err = std.Io.Writer.fixed(&eb);
    const argv = [_][]const u8{ "netbird", "up", "-c", path, "--setup-key", "UPKEY-4" };
    try std.testing.expectEqual(app.exit_service, runOz(&argv, &out, &err, fake.backend()));
    try std.testing.expectEqual(@as(usize, 0), out.buffered().len);
    try std.testing.expect(std.mem.indexOf(u8, err.buffered(), "start failed") != null);
    try std.testing.expect(std.mem.indexOf(u8, err.buffered(), "UPKEY-4") == null);
    try std.testing.expectEqual(@as(usize, 1), fake.login_calls);
    try std.testing.expectEqual(@as(usize, 1), fake.start_calls);
    try std.testing.expectEqual(@as(usize, 1), fake.stop_calls);
}

test "production login and up exit NetworkUnavailable with no tunnels" {
    const root = try scratchRoot(std.testing.allocator);
    defer std.testing.allocator.free(root);
    cleanup(root);
    defer cleanup(root);
    const path = try std.fmt.allocPrint(std.testing.allocator, "{s}/p.json", .{root});
    defer std.testing.allocator.free(path);

    const logv = [_][]const u8{ "netbird", "login", "-c", path, "--setup-key", "SYNTH-5" };
    var ob: [4096]u8 = undefined;
    var eb: [4096]u8 = undefined;
    var out = std.Io.Writer.fixed(&ob);
    var err = std.Io.Writer.fixed(&eb);
    try std.testing.expectEqual(app.exit_service, runOz(&logv, &out, &err, null));
    try std.testing.expect(std.mem.indexOf(u8, err.buffered(), "Unavailable") != null);
    try std.testing.expect(std.mem.indexOf(u8, err.buffered(), "no tunnels created") != null);
    try std.testing.expect(std.mem.indexOf(u8, err.buffered(), "SYNTH-5") == null);
    try std.testing.expectEqual(@as(usize, 0), out.buffered().len);

    const upv = [_][]const u8{ "netbird", "up", "-c", path, "--setup-key", "SYNTH-6" };
    var ob2: [4096]u8 = undefined;
    var eb2: [4096]u8 = undefined;
    var out2 = std.Io.Writer.fixed(&ob2);
    var err2 = std.Io.Writer.fixed(&eb2);
    try std.testing.expectEqual(app.exit_service, runOz(&upv, &out2, &err2, null));
    try std.testing.expect(std.mem.indexOf(u8, err2.buffered(), "Unavailable") != null);
    try std.testing.expect(std.mem.indexOf(u8, err2.buffered(), "SYNTH-6") == null);

    // Missing key is a usage error even without a backend.
    const nokey = [_][]const u8{ "netbird", "login", "-c", path };
    var ob3: [1024]u8 = undefined;
    var eb3: [1024]u8 = undefined;
    var out3 = std.Io.Writer.fixed(&ob3);
    var err3 = std.Io.Writer.fixed(&eb3);
    try std.testing.expectEqual(app.exit_usage, runOz(&nokey, &out3, &err3, null));
    try std.testing.expect(std.mem.indexOf(u8, err3.buffered(), "setup key required") != null);
}

test "corrupt config is rejected and never overwritten" {
    const root = try scratchRoot(std.testing.allocator);
    defer std.testing.allocator.free(root);
    cleanup(root);
    defer cleanup(root);
    const path = try std.fmt.allocPrint(std.testing.allocator, "{s}/c.json", .{root});
    defer std.testing.allocator.free(path);
    // Create dirs first through a real command, then corrupt the file.
    {
        var ob0: [1024]u8 = undefined;
        var eb0: [1024]u8 = undefined;
        var out0 = std.Io.Writer.fixed(&ob0);
        var err0 = std.Io.Writer.fixed(&eb0);
        const mk = [_][]const u8{ "netbird", "status", "-c", path };
        try std.testing.expectEqual(@as(u8, 0), runOz(&mk, &out0, &err0, null));
    }
    {
        const f = try std.Io.Dir.createFileAbsolute(tio, path, .{ .truncate = true });
        defer f.close(tio);
        try f.writePositionalAll(tio, "{oops not json", 0);
    }
    const argv = [_][]const u8{ "netbird", "status", "-c", path };
    var ob: [1024]u8 = undefined;
    var eb: [4096]u8 = undefined;
    var out = std.Io.Writer.fixed(&ob);
    var err = std.Io.Writer.fixed(&eb);
    try std.testing.expectEqual(app.exit_config, runOz(&argv, &out, &err, null));
    try std.testing.expect(std.mem.indexOf(u8, err.buffered(), "corrupt") != null);
    const data = try profile.readFileLseek(tio, std.testing.allocator, path);
    defer std.testing.allocator.free(data);
    try std.testing.expectEqualStrings("{oops not json", data);

    // Config errors precede the production unavailable exit.
    const logv = [_][]const u8{ "netbird", "login", "-c", path, "--setup-key", "K" };
    var ob2: [1024]u8 = undefined;
    var eb2: [4096]u8 = undefined;
    var out2 = std.Io.Writer.fixed(&ob2);
    var err2 = std.Io.Writer.fixed(&eb2);
    try std.testing.expectEqual(app.exit_config, runOz(&logv, &out2, &err2, null));
}

test "malformed management url is rejected before config creation" {
    const root = try scratchRoot(std.testing.allocator);
    defer std.testing.allocator.free(root);
    cleanup(root);
    defer cleanup(root);
    const path = try std.fmt.allocPrint(std.testing.allocator, "{s}/absent/m.json", .{root});
    defer std.testing.allocator.free(path);

    const argv = [_][]const u8{ "netbird", "status", "-c", path, "--management-url", "::::" };
    var ob: [1024]u8 = undefined;
    var eb: [1024]u8 = undefined;
    var out = std.Io.Writer.fixed(&ob);
    var err = std.Io.Writer.fixed(&eb);
    try std.testing.expectEqual(app.exit_usage, runOz(&argv, &out, &err, null));
    try std.testing.expect(std.mem.indexOf(u8, err.buffered(), "malformed") != null);
    try std.testing.expectError(profile.FileError.NotFound, profile.readFileLseek(tio, std.testing.allocator, path));

    for ([_][]const u8{ "https://api.netbird.io:443", "http://localhost:8080", "https://h:443/p?q=1#f" }) |u| {
        try std.testing.expect(app.isValidManagementUrl(u));
    }
    for ([_][]const u8{ "", "notaurl", "http://", "://host", "http:///p", "1http://h", "http://ho st", "http://h:1 2" }) |u| {
        try std.testing.expect(!app.isValidManagementUrl(u));
    }
}

test "malformed management url in config is rejected without rewriting" {
    const root = try scratchRoot(std.testing.allocator);
    defer std.testing.allocator.free(root);
    cleanup(root);
    defer cleanup(root);
    const path = try std.fmt.allocPrint(std.testing.allocator, "{s}/mu.json", .{root});
    defer std.testing.allocator.free(path);

    const bad = [_]profile.Url{
        .{ .Scheme = "https", .Host = "" },
        .{ .Scheme = "9bad", .Host = "h:443" },
    };
    for (bad) |mu| {
        {
            var parsed = try profile.loadConfig(tio, std.testing.allocator, path);
            defer parsed.deinit();
            parsed.value.ManagementURL = mu;
            try profile.saveConfig(tio, std.testing.allocator, path, &parsed.value);
        }
        const before = try profile.readFileLseek(tio, std.testing.allocator, path);
        defer std.testing.allocator.free(before);
        const argv = [_][]const u8{ "netbird", "status", "-c", path };
        var ob: [1024]u8 = undefined;
        var eb: [4096]u8 = undefined;
        var out = std.Io.Writer.fixed(&ob);
        var err = std.Io.Writer.fixed(&eb);
        try std.testing.expectEqual(app.exit_config, runOz(&argv, &out, &err, null));
        try std.testing.expect(std.mem.indexOf(u8, err.buffered(), "malformed") != null);
        const after = try profile.readFileLseek(tio, std.testing.allocator, path);
        defer std.testing.allocator.free(after);
        try std.testing.expectEqualSlices(u8, before, after);
    }

    // A well-formed custom URL in config is accepted.
    {
        var parsed = try profile.loadConfig(tio, std.testing.allocator, path);
        defer parsed.deinit();
        parsed.value.ManagementURL = .{ .Scheme = "https", .Host = "custom:8443" };
        try profile.saveConfig(tio, std.testing.allocator, path, &parsed.value);
    }
    const argv = [_][]const u8{ "netbird", "status", "-c", path };
    var ob: [4096]u8 = undefined;
    var eb: [1024]u8 = undefined;
    var out = std.Io.Writer.fixed(&ob);
    var err = std.Io.Writer.fixed(&eb);
    try std.testing.expectEqual(@as(u8, 0), runOz(&argv, &out, &err, null));
}

test "backend receives override config url and key" {
    const root = try scratchRoot(std.testing.allocator);
    defer std.testing.allocator.free(root);
    cleanup(root);
    defer cleanup(root);
    const path = try std.fmt.allocPrint(std.testing.allocator, "{s}/b.json", .{root});
    defer std.testing.allocator.free(path);
    {
        var parsed = try profile.loadConfig(tio, std.testing.allocator, path);
        defer parsed.deinit();
        parsed.value.WgPort = 52999;
        try profile.saveConfig(tio, std.testing.allocator, path, &parsed.value);
    }

    var fake = Fake{};
    var ob: [4096]u8 = undefined;
    var eb: [1024]u8 = undefined;
    var out = std.Io.Writer.fixed(&ob);
    var err = std.Io.Writer.fixed(&eb);
    const argv = [_][]const u8{
        "netbird",          "up",                  "-c",          path,
        "--management-url", "https://custom:1234", "--setup-key", "K9",
    };
    try std.testing.expectEqual(@as(u8, 0), runOz(&argv, &out, &err, fake.backend()));
    try std.testing.expectEqual(@as(i64, 52999), fake.seen_wg_port);
    try std.testing.expectEqualStrings("https://custom:1234", fake.seenMgmt());
    try std.testing.expectEqualStrings("K9", fake.seenKey().?);

    // Without the flag the backend gets the effective config URL (here the
    // stored default), never null.
    var fake2 = Fake{};
    var ob2: [4096]u8 = undefined;
    var eb2: [1024]u8 = undefined;
    var out2 = std.Io.Writer.fixed(&ob2);
    var err2 = std.Io.Writer.fixed(&eb2);
    const argv2 = [_][]const u8{ "netbird", "login", "-c", path, "--setup-key", "K10" };
    try std.testing.expectEqual(@as(u8, 0), runOz(&argv2, &out2, &err2, fake2.backend()));
    try std.testing.expectEqualStrings("https://api.netbird.io:443", fake2.seenMgmt());
    try std.testing.expectEqualStrings("K10", fake2.seenKey().?);
    try std.testing.expectEqual(@as(i64, 52999), fake2.seen_wg_port);

    // A custom config URL (with path, query, fragment) renders through.
    {
        var parsed = try profile.loadConfig(tio, std.testing.allocator, path);
        defer parsed.deinit();
        parsed.value.ManagementURL = .{
            .Scheme = "https",
            .Host = "cfg:8443",
            .Path = "/m",
            .RawQuery = "x=1",
            .Fragment = "f",
        };
        try profile.saveConfig(tio, std.testing.allocator, path, &parsed.value);
    }
    var fake3 = Fake{};
    var ob3: [4096]u8 = undefined;
    var eb3: [1024]u8 = undefined;
    var out3 = std.Io.Writer.fixed(&ob3);
    var err3 = std.Io.Writer.fixed(&eb3);
    try std.testing.expectEqual(@as(u8, 0), runOz(&argv2, &out3, &err3, fake3.backend()));
    try std.testing.expectEqualStrings("https://cfg:8443/m?x=1#f", fake3.seenMgmt());
}

test "relative config path resolves against the actual cwd" {
    var linkbuf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try std.Io.Dir.readLinkAbsolute(tio, "/proc/self/cwd", &linkbuf);
    const expected = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/rel-sub/x.json",
        .{linkbuf[0..n]},
    );
    defer std.testing.allocator.free(expected);
    const got = try app.resolveConfigPath(std.testing.allocator, "rel-sub/x.json");
    defer std.testing.allocator.free(got);
    try std.testing.expectEqualStrings(expected, got);

    const abs = try app.resolveConfigPath(std.testing.allocator, "/tmp/x.json");
    defer std.testing.allocator.free(abs);
    try std.testing.expectEqualStrings("/tmp/x.json", abs);
}

test "default config path matches profile constants" {
    try std.testing.expectEqualStrings("/var/lib/netbird/default.json", app.default_config_path);
}

fn runUsagePath(alloc: std.mem.Allocator) u8 {
    var ob: [1024]u8 = undefined;
    var eb: [1024]u8 = undefined;
    var out = std.Io.Writer.fixed(&ob);
    var err = std.Io.Writer.fixed(&eb);
    const argv = [_][]const u8{ "netbird", "status", "--management-url", "::::" };
    return app.run(alloc, tio, &argv, &out, &err, null);
}

test "allocation failures on the usage path leak nothing" {
    // Malformed URL exits usage; any allocation failure exits config. Both
    // must free what they own: every failing run must balance bytes.
    const total = blk: {
        var fa = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        try std.testing.expectEqual(app.exit_usage, runUsagePath(fa.allocator()));
        break :blk fa.alloc_index;
    };
    for (0..total + 1) |i| {
        var fa = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = i });
        const code = runUsagePath(fa.allocator());
        try std.testing.expect(code == app.exit_usage or code == app.exit_config);
        try std.testing.expectEqual(fa.allocated_bytes, fa.freed_bytes);
    }
}
