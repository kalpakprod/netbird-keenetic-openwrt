// Port of netbird client/internal/profilemanager (v0.79.0), BSD-3-Clause — tests.
// Golden files: testdata/config-golden.json (every field set) and
// testdata/config-nils.json (zero Config) from gen/statevecs, which uses
// the real url.URL/domain.List/WriteJson shapes.

const std = @import("std");
const profile = @import("profile.zig");

const golden = @embedFile("testdata/config-golden.json");
const nils = @embedFile("testdata/config-nils.json");

const tio = std.testing.io;

/// Absolute scratch root unique to this process. Cleaned by each test.
fn scratchRoot(allocator: std.mem.Allocator) ![]u8 {
    return std.fmt.allocPrint(allocator, "/tmp/nb-state-test-{d}", .{std.os.linux.getpid()});
}

fn cleanup(root: []const u8) void {
    std.Io.Dir.cwd().deleteTree(tio, root) catch {};
}

test "parse golden config from Go" {
    var parsed = try profile.parseConfig(std.testing.allocator, golden);
    defer parsed.deinit();
    const c = parsed.value;
    try std.testing.expectEqualStrings("test-profile", c.Name);
    try std.testing.expectEqualStrings("utun101", c.WgIface);
    try std.testing.expectEqual(@as(i64, 51820), c.WgPort);
    try std.testing.expectEqualStrings("https", c.ManagementURL.?.Scheme);
    try std.testing.expectEqualStrings("api.netbird.io:443", c.ManagementURL.?.Host);
    try std.testing.expectEqualStrings("app.netbird.io:443", c.AdminURL.?.Host);
    try std.testing.expect(c.ManagementURL.?.User == null);
    try std.testing.expectEqual(true, c.NetworkMonitor.?);
    try std.testing.expectEqual(@as(usize, 2), c.IFaceBlackList.?.len);
    try std.testing.expectEqual(@as(i64, 3600), c.SSHJWTCacheTTL.?);
    try std.testing.expectEqual(@as(i64, 7), c.SyncMessageVersion.?);
    try std.testing.expectEqual(@as(usize, 2), c.DNSLabels.?.len);
    try std.testing.expectEqualStrings("label-a", c.DNSLabels.?[0]);
    try std.testing.expectEqual(@as(i64, 30000000000), c.DNSRouteInterval);
    try std.testing.expectEqualStrings("12.34.56.78/eth0", c.NATExternalIPs.?[0]);
    try std.testing.expect(c.BlockInbound);
    try std.testing.expect(!c.RemoteJobsAllowed.?);
}

test "parse nils config from Go" {
    var parsed = try profile.parseConfig(std.testing.allocator, nils);
    defer parsed.deinit();
    const c = parsed.value;
    try std.testing.expect(c.ManagementURL == null);
    try std.testing.expect(c.IFaceBlackList == null);
    try std.testing.expect(c.NetworkMonitor == null);
    try std.testing.expectEqualStrings("", c.Name);
    try std.testing.expectEqual(@as(i64, 0), c.WgPort);
}

test "save matches Go byte-for-byte" {
    var parsed = try profile.parseConfig(std.testing.allocator, golden);
    defer parsed.deinit();
    const out = try std.json.Stringify.valueAlloc(std.testing.allocator, parsed.value, .{ .whitespace = .indent_4 });
    defer std.testing.allocator.free(out);
    try std.testing.expectEqualSlices(u8, golden, out);

    var parsed_nils = try profile.parseConfig(std.testing.allocator, nils);
    defer parsed_nils.deinit();
    const out_nils = try std.json.Stringify.valueAlloc(std.testing.allocator, parsed_nils.value, .{ .whitespace = .indent_4 });
    defer std.testing.allocator.free(out_nils);
    try std.testing.expectEqualSlices(u8, nils, out_nils);
}

test "unknown fields ignored like Go" {
    const with_unknown =
        \\{"Name": "x", "NoSuchField": {"a": [1,2]}, "WgPort": 1, "Another": null}
    ;
    var parsed = try profile.parseConfig(std.testing.allocator, with_unknown);
    defer parsed.deinit();
    try std.testing.expectEqualStrings("x", parsed.value.Name);
    try std.testing.expectEqual(@as(i64, 1), parsed.value.WgPort);
}

test "parseConfig folds field names like Go" {
    const mixed =
        \\{"name": "lower", "wgport": 51821, "managementurl": {"scheme": "https", "host": "h:443"},
        \\ "serversshallowed": true, "ifaceblacklist": ["a", "b"]}
    ;
    var parsed = try profile.parseConfig(std.testing.allocator, mixed);
    defer parsed.deinit();
    const c = parsed.value;
    try std.testing.expectEqualStrings("lower", c.Name);
    try std.testing.expectEqual(@as(i64, 51821), c.WgPort);
    try std.testing.expectEqualStrings("https", c.ManagementURL.?.Scheme);
    try std.testing.expectEqualStrings("h:443", c.ManagementURL.?.Host);
    try std.testing.expectEqual(true, c.ServerSSHAllowed.?);
    try std.testing.expectEqual(@as(usize, 2), c.IFaceBlackList.?.len);
    // duplicates resolve last-wins like Go, regardless of exact/folded
    const dup1 = "{\"name\": \"folded\", \"Name\": \"exact\"}";
    var p1 = try profile.parseConfig(std.testing.allocator, dup1);
    defer p1.deinit();
    try std.testing.expectEqualStrings("exact", p1.value.Name);
    const dup2 = "{\"Name\": \"exact\", \"name\": \"folded\"}";
    var p2 = try profile.parseConfig(std.testing.allocator, dup2);
    defer p2.deinit();
    try std.testing.expectEqualStrings("folded", p2.value.Name);
}

test "defaults fill missing values" {
    var cfg = profile.Config{};
    profile.applyDefaults(&cfg);
    try std.testing.expectEqualStrings("https", cfg.ManagementURL.?.Scheme);
    try std.testing.expectEqualStrings("api.netbird.io:443", cfg.ManagementURL.?.Host);
    try std.testing.expectEqualStrings("app.netbird.io:443", cfg.AdminURL.?.Host);
    try std.testing.expectEqualStrings("wt0", cfg.WgIface);
    try std.testing.expectEqual(@as(i64, 51820), cfg.WgPort);
    try std.testing.expectEqual(false, cfg.ServerSSHAllowed.?);
    try std.testing.expectEqual(false, cfg.RemoteJobsAllowed.?);
}

test "load creates missing config with defaults" {
    const root = try scratchRoot(std.testing.allocator);
    defer std.testing.allocator.free(root);
    defer cleanup(root);
    const path = try std.fmt.allocPrint(std.testing.allocator, "{s}/sub/dir/config.json", .{root});
    defer std.testing.allocator.free(path);

    var parsed = try profile.loadConfig(tio, std.testing.allocator, path);
    defer parsed.deinit();
    try std.testing.expectEqualStrings("wt0", parsed.value.WgIface);
    try std.testing.expectEqualStrings("https", parsed.value.ManagementURL.?.Scheme);
    // file now exists with 0600
    const st = try std.Io.Dir.cwd().statFile(tio, path, .{});
    try std.testing.expectEqual(@as(u32, 0o600), @as(u32, @intFromEnum(st.permissions)) & 0o777);
    // second load reads it back identically
    var parsed2 = try profile.loadConfig(tio, std.testing.allocator, path);
    defer parsed2.deinit();
    try std.testing.expectEqualStrings(parsed.value.WgIface, parsed2.value.WgIface);
}

test "save round trip through files" {
    const root = try scratchRoot(std.testing.allocator);
    defer std.testing.allocator.free(root);
    defer cleanup(root);
    const path = try std.fmt.allocPrint(std.testing.allocator, "{s}/config.json", .{root});
    defer std.testing.allocator.free(path);

    var parsed = try profile.parseConfig(std.testing.allocator, golden);
    defer parsed.deinit();
    try profile.saveConfig(tio, std.testing.allocator, path, &parsed.value);
    const data = try profile.readFileLseek(tio, std.testing.allocator, path);
    defer std.testing.allocator.free(data);
    try std.testing.expectEqualSlices(u8, golden, data);
}

test "profile state path validation" {
    const ok = try profile.profileStatePath(std.testing.allocator, "/cfg", "default");
    defer std.testing.allocator.free(ok);
    try std.testing.expectEqualStrings("/cfg/default.state.json", ok);
    try std.testing.expectError(profile.Error.InvalidName, profile.profileStatePath(std.testing.allocator, "/cfg", "../evil"));
    try std.testing.expectError(profile.Error.InvalidName, profile.profileStatePath(std.testing.allocator, "/cfg", "a/b"));
    try std.testing.expectError(profile.Error.InvalidName, profile.profileStatePath(std.testing.allocator, "/cfg", ""));
}

test "profile stem matches Go IsValidProfileFilenameStem" {
    const ok = [_][]const u8{ "default", "abc", "ABC-xyz_019", "é", "Профиль", "under_score", "with-dash" };
    for (ok) |s| {
        try std.testing.expect(profile.isValidProfileFilenameStem(s));
    }
    const bad = [_][]const u8{
        "",          "a:b", "a b",  "a.b",   "a/b", "a\\b", "..", "../evil",
        "a\tb",      "a\n", "\xff", "a\xff",
        "a😀",
        "trailing ",
    };
    for (bad) |s| {
        try std.testing.expect(!profile.isValidProfileFilenameStem(s));
    }
    // 64 ok, 65 rejected (Go counts bytes)
    const stem64 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const stem65 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    try std.testing.expect(profile.isValidProfileFilenameStem(stem64));
    try std.testing.expect(!profile.isValidProfileFilenameStem(stem65));
}

test "prefs put get remove" {
    const dir = try scratchRoot(std.testing.allocator);
    defer std.testing.allocator.free(dir);
    defer cleanup(dir);

    var prefs = try profile.Prefs.init(tio, std.testing.allocator, dir, "default");
    defer prefs.deinit();
    // missing file reads as absent
    try std.testing.expect(try prefs.get("ui", struct { theme: []const u8 }) == null);

    try prefs.put("ui", .{ .theme = "dark", .zoom = @as(i64, 120) });
    var got = (try prefs.get("ui", struct { theme: []const u8, zoom: i64 })).?;
    defer got.deinit();
    try std.testing.expectEqualStrings("dark", got.value.theme);
    try std.testing.expectEqual(@as(i64, 120), got.value.zoom);

    // second namespace coexists
    try prefs.put("net", .{ .mtu = @as(i64, 1280) });
    var got2 = (try prefs.get("net", struct { mtu: i64 })).?;
    defer got2.deinit();
    try std.testing.expectEqual(@as(i64, 1280), got2.value.mtu);
    var got1b = (try prefs.get("ui", struct { theme: []const u8, zoom: i64 })).?;
    defer got1b.deinit();
    try std.testing.expectEqualStrings("dark", got1b.value.theme);

    try prefs.remove("ui", );
    try std.testing.expect(try prefs.get("ui", struct { theme: []const u8 }) == null);
    // removing twice is fine
    try prefs.remove("ui");
}

test "userConfigDir reads the environment" {
    // override path (no env needed)
    profile.config_dir_override = "/tmp/nb-override";
    const over = try profile.userConfigDir(std.testing.allocator);
    defer std.testing.allocator.free(over);
    try std.testing.expectEqualStrings("/tmp/nb-override", over);
    profile.config_dir_override = "";
    // env path: HOME is set for tests, result ends in /netbird
    const dir = try profile.userConfigDir(std.testing.allocator);
    defer std.testing.allocator.free(dir);
    try std.testing.expect(std.mem.endsWith(u8, dir, "/netbird"));
}
