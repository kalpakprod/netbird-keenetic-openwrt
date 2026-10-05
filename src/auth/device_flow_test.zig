// Behavioral tests for the device authorization flow port.
// Public API plus a real localhost HTTP wire adapter: request bytes and
// JSON responses travel over loopback TCP, so the tested protocol is not
// replaced by fake success callbacks. No sleeps; a controlled clock drives
// time semantics. No WireGuard/Engine startup.

const std = @import("std");
const df = @import("device_flow.zig");

const tio = std.testing.io;
const alloc = std.testing.allocator;

// ---------------------------------------------------------------------------
// Scripted in-memory transport (unit-level polling scenarios).
// ---------------------------------------------------------------------------

const Scripted = struct {
    statuses: []const u16,
    bodies: []const []const u8,
    at: usize = 0,
    last_body: ?[]u8 = null,
    fail_transport: bool = false,

    fn postFn(ctx: *anyopaque, a: std.mem.Allocator, _: []const u8, body: []const u8) df.Transport.TransportError!df.Transport.Response {
        const s: *Scripted = @ptrCast(@alignCast(ctx));
        if (s.fail_transport) return error.Transport;
        if (s.last_body) |b| a.free(b);
        s.last_body = a.dupe(u8, body) catch return error.OutOfMemory;
        const i = @min(s.at, s.statuses.len - 1);
        s.at += 1;
        const owned = a.dupe(u8, s.bodies[i]) catch return error.OutOfMemory;
        return .{ .status = s.statuses[i], .body = owned };
    }

    fn transport(s: *Scripted) df.Transport {
        return .{ .ctx = s, .postFn = postFn };
    }

    fn deinit(s: *Scripted, a: std.mem.Allocator) void {
        if (s.last_body) |b| a.free(b);
    }
};

const ManualClock = struct {
    now: i64 = 1000,

    fn nowFn(ctx: *anyopaque) i64 {
        const c: *ManualClock = @ptrCast(@alignCast(ctx));
        return c.now;
    }

    fn clock(c: *ManualClock) df.Clock {
        return .{ .ctx = c, .nowFn = nowFn };
    }
};

fn testConfig() df.DeviceAuthProviderConfig {
    return .{
        .client_id = "test-client",
        .audience = "test-aud",
        .scope = "openid",
        .token_endpoint = "http://127.0.0.1/token",
        .device_auth_endpoint = "http://127.0.0.1/device",
    };
}

/// Craft an unsigned JWT with the given claims JSON payload.
fn craftJwt(a: std.mem.Allocator, claims_json: []const u8) ![]u8 {
    const enc = std.base64.url_safe_no_pad.Encoder;
    const hdr = "eyJhbGciOiJub25lIn0"; // {"alg":"none"}
    const out_len = enc.calcSize(claims_json.len);
    var payload: [512]u8 = undefined;
    if (out_len > payload.len) return error.OutOfMemory;
    const enc_slice = enc.encode(payload[0..out_len], claims_json);
    return std.fmt.allocPrint(a, "{s}.{s}.sig", .{ hdr, enc_slice });
}

fn tokenBody(a: std.mem.Allocator, jwt: []const u8) ![]u8 {
    return std.fmt.allocPrint(a, "{{\"access_token\":\"{s}\"}}", .{jwt});
}

// ---------------------------------------------------------------------------
// Config validation.
// ---------------------------------------------------------------------------

test "config rejects empty audience client endpoints" {
    var bad = testConfig();
    bad.audience = "";
    try std.testing.expectError(df.Error.InvalidConfig, df.validateDeviceAuthConfig(&bad));
    bad = testConfig();
    bad.client_id = "";
    try std.testing.expectError(df.Error.InvalidConfig, df.validateDeviceAuthConfig(&bad));
    bad = testConfig();
    bad.token_endpoint = "";
    try std.testing.expectError(df.Error.InvalidConfig, df.validateDeviceAuthConfig(&bad));
    bad = testConfig();
    bad.device_auth_endpoint = "";
    try std.testing.expectError(df.Error.InvalidConfig, df.validateDeviceAuthConfig(&bad));
    try df.validateDeviceAuthConfig(&testConfig());
}

// ---------------------------------------------------------------------------
// Device-code request/response over scripted transport.
// ---------------------------------------------------------------------------

test "device code request body encodes form and parses response" {
    var s = Scripted{
        .statuses = &.{200},
        .bodies = &.{"{\"device_code\":\"dc1\",\"user_code\":\"uc1\",\"verification_uri\":\"https://idp/activate\",\"expires_in\":600,\"interval\":5}"},
    };
    defer s.deinit(alloc);
    var tr = s.transport();
    const cfg = testConfig();
    var info = try df.requestAuthInfo(alloc, &cfg, &tr);
    defer info.deinit(alloc);
    try std.testing.expectEqualStrings("dc1", info.device_code);
    try std.testing.expectEqualStrings("uc1", info.user_code);
    // verification_uri_complete falls back to verification_uri.
    try std.testing.expectEqualStrings("https://idp/activate", info.verification_uri_complete);
    try std.testing.expectEqual(@as(i64, 600), info.expires_in);
    try std.testing.expectEqual(@as(i64, 5), info.interval);
    // Wire body carries the expected form fields.
    try std.testing.expect(std.mem.indexOf(u8, s.last_body.?, "client_id=test-client") != null);
    try std.testing.expect(std.mem.indexOf(u8, s.last_body.?, "audience=test-aud") != null);
    try std.testing.expect(std.mem.indexOf(u8, s.last_body.?, "scope=openid") != null);
}

test "device code wrong response status is BadStatus" {
    var s = Scripted{
        .statuses = &.{400},
        .bodies = &.{"{\"error\":\"invalid_client\"}"},
    };
    defer s.deinit(alloc);
    var tr = s.transport();
    const cfg = testConfig();
    try std.testing.expectError(df.Error.BadStatus, df.requestAuthInfo(alloc, &cfg, &tr));
}

test "device code malformed json is BadJson" {
    var s = Scripted{
        .statuses = &.{200},
        .bodies = &.{"not json {"},
    };
    defer s.deinit(alloc);
    var tr = s.transport();
    const cfg = testConfig();
    try std.testing.expectError(df.Error.BadJson, df.requestAuthInfo(alloc, &cfg, &tr));
}

test "device code transport failure surfaces" {
    var s = Scripted{ .statuses = &.{200}, .bodies = &.{"{}"}, .fail_transport = true };
    defer s.deinit(alloc);
    var tr = s.transport();
    const cfg = testConfig();
    try std.testing.expectError(df.Error.Transport, df.requestAuthInfo(alloc, &cfg, &tr));
}

test "login hint appended to verification uris" {
    var s = Scripted{
        .statuses = &.{200},
        .bodies = &.{"{\"device_code\":\"d\",\"verification_uri\":\"https://idp/a\",\"verification_uri_complete\":\"https://idp/a?x=1\",\"expires_in\":60,\"interval\":5}"},
    };
    defer s.deinit(alloc);
    var tr = s.transport();
    var cfg = testConfig();
    cfg.login_hint = "user@example.com";
    var info = try df.requestAuthInfo(alloc, &cfg, &tr);
    defer info.deinit(alloc);
    try std.testing.expect(std.mem.indexOf(u8, info.verification_uri_complete, "login_hint=") != null);
    try std.testing.expect(std.mem.indexOf(u8, info.verification_uri, "login_hint=") != null);
}

test "login hint mutates query replacing existing key and keeping fragment" {
    const enc = "user%40example.com";
    // Appends to an existing query.
    const got1 = try df.appendLoginHint(alloc, "https://idp/a?x=1", "user@example.com");
    defer alloc.free(got1);
    try std.testing.expectEqualStrings("https://idp/a?login_hint=" ++ enc ++ "&x=1", got1);
    // Fragment stays out of the query.
    const got2 = try df.appendLoginHint(alloc, "https://idp/a?x=1#frag", "user@example.com");
    defer alloc.free(got2);
    try std.testing.expectEqualStrings("https://idp/a?login_hint=" ++ enc ++ "&x=1" ++ "#frag", got2);
    // Fragment-only URI gets a query before the fragment.
    const got3 = try df.appendLoginHint(alloc, "https://idp/a#frag", "user@example.com");
    defer alloc.free(got3);
    try std.testing.expectEqualStrings("https://idp/a?login_hint=" ++ enc ++ "#frag", got3);
    // Prior login_hint is replaced, duplicates collapse (Go Query().Set).
    const got4 = try df.appendLoginHint(alloc, "https://idp/a?login_hint=old&x=1&login_hint=old2", "user@example.com");
    defer alloc.free(got4);
    try std.testing.expectEqualStrings("https://idp/a?login_hint=" ++ enc ++ "&x=1", got4);
    // Hint value is percent-encoded.
    const got5 = try df.appendLoginHint(alloc, "https://idp/a", "john doe+1");
    defer alloc.free(got5);
    try std.testing.expectEqualStrings("https://idp/a?login_hint=john+doe%2B1", got5);
    // Empty hint leaves the URI unchanged.
    const got6 = try df.appendLoginHint(alloc, "https://idp/a?x=1#frag", "");
    defer alloc.free(got6);
    try std.testing.expectEqualStrings("https://idp/a?x=1#frag", got6);
}

test "login hint replaces percent decoded query key" {
    const got = try df.appendLoginHint(alloc, "https://example.test/verify?login%5Fhint=old#frag", "new");
    defer alloc.free(got);
    try std.testing.expectEqualStrings("https://example.test/verify?login_hint=new#frag", got);
}

test "login hint preserves empty query key with Go query encoding" {
    const got = try df.appendLoginHint(alloc, "https://example.test/verify?=keep", "new");
    defer alloc.free(got);
    try std.testing.expectEqualStrings("https://example.test/verify?=keep&login_hint=new", got);
    const normalized = try df.appendLoginHint(alloc, "https://example.test/verify?z=%2f&=a+b&z=second&bare&bad=%GG&semi=x;y&&login%5fhint=old", "new");
    defer alloc.free(normalized);
    try std.testing.expectEqualStrings("https://example.test/verify?=a+b&bare=&login_hint=new&z=%2F&z=second", normalized);
}

// ---------------------------------------------------------------------------
// Token polling: success, pending, slow_down, fatal, expiry, cancellation.
// ---------------------------------------------------------------------------

fn waitSetup() df.AuthFlowInfo {
    return .{
        .device_code = "devcode",
        .user_code = "",
        .verification_uri = "",
        .verification_uri_complete = "",
        .expires_in = 60,
        .interval = 5,
    };
}

test "token poll success validates audience and shapes body" {
    const jwt = try craftJwt(alloc, "{\"aud\":\"test-aud\"}");
    defer alloc.free(jwt);
    const body = try tokenBody(alloc, jwt);
    defer alloc.free(body);
    var s = Scripted{ .statuses = &.{200}, .bodies = &.{body} };
    defer s.deinit(alloc);
    var tr = s.transport();
    var mc = ManualClock{};
    const clk = mc.clock();
    const cfg = testConfig();
    var info = waitSetup();
    const tick = struct {
        fn f(_: i64) void {}
    }.f;
    var tok = try df.waitToken(alloc, &cfg, &tr, &clk, null, &info, tick, 4);
    defer tok.deinit(alloc);
    try std.testing.expectEqualStrings(jwt, tok.access_token);
    try std.testing.expect(std.mem.indexOf(u8, s.last_body.?, "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code") != null or
        std.mem.indexOf(u8, s.last_body.?, "device_code=devcode") != null);
}

test "token poll rejects wrong audience" {
    const jwt = try craftJwt(alloc, "{\"aud\":\"someone-else\"}");
    defer alloc.free(jwt);
    const body = try tokenBody(alloc, jwt);
    defer alloc.free(body);
    var s = Scripted{ .statuses = &.{200}, .bodies = &.{body} };
    defer s.deinit(alloc);
    var tr = s.transport();
    var mc = ManualClock{};
    const clk = mc.clock();
    const cfg = testConfig();
    var info = waitSetup();
    try std.testing.expectError(df.Error.InvalidToken, df.waitToken(alloc, &cfg, &tr, &clk, null, &info, null, 4));
}

test "token poll rejects malformed jwt" {
    const body = "{\"access_token\":\"not.a.jwt.at.all.x\"}";
    var s = Scripted{ .statuses = &.{200}, .bodies = &.{body} };
    defer s.deinit(alloc);
    var tr = s.transport();
    var mc = ManualClock{};
    const clk = mc.clock();
    const cfg = testConfig();
    var info = waitSetup();
    try std.testing.expectError(df.Error.InvalidToken, df.waitToken(alloc, &cfg, &tr, &clk, null, &info, null, 4));
}

test "token pollpending then success" {
    const jwt = try craftJwt(alloc, "{\"aud\":\"test-aud\"}");
    defer alloc.free(jwt);
    const ok_body = try tokenBody(alloc, jwt);
    defer alloc.free(ok_body);
    var s = Scripted{
        .statuses = &.{ 200, 200, 200 },
        .bodies = &.{ "{\"error\":\"authorization_pending\"}", "{\"error\":\"authorization_pending\"}", ok_body },
    };
    defer s.deinit(alloc);
    var tr = s.transport();
    var mc = ManualClock{};
    const clk = mc.clock();
    const cfg = testConfig();
    var info = waitSetup();
    var tok = try df.waitToken(alloc, &cfg, &tr, &clk, null, &info, null, 5);
    defer tok.deinit(alloc);
    try std.testing.expectEqualStrings(jwt, tok.access_token);
    try std.testing.expectEqual(@as(usize, 3), s.at);
}

test "slow_down stretches polling interval" {
    const jwt = try craftJwt(alloc, "{\"aud\":\"test-aud\"}");
    defer alloc.free(jwt);
    const ok_body = try tokenBody(alloc, jwt);
    defer alloc.free(ok_body);
    var s = Scripted{
        .statuses = &.{ 200, 200 },
        .bodies = &.{ "{\"error\":\"slow_down\"}", ok_body },
    };
    defer s.deinit(alloc);
    var tr = s.transport();
    var mc = ManualClock{};
    const clk = mc.clock();
    const cfg = testConfig();
    var info = waitSetup();
    const Seen = struct {
        var intervals: [4]i64 = undefined;
        var n: usize = 0;
        fn f(iv: i64) void {
            if (n < intervals.len) {
                intervals[n] = iv;
                n += 1;
            }
        }
    };
    Seen.n = 0;
    var tok = try df.waitToken(alloc, &cfg, &tr, &clk, null, &info, Seen.f, 4);
    defer tok.deinit(alloc);
    try std.testing.expectEqual(@as(usize, 2), Seen.n);
    try std.testing.expectEqual(@as(i64, 5), Seen.intervals[0]);
    try std.testing.expectEqual(@as(i64, 5 + df.slow_down_backoff_s), Seen.intervals[1]);
}

test "token poll fatal idp error" {
    var s = Scripted{
        .statuses = &.{200},
        .bodies = &.{"{\"error\":\"access_denied\",\"error_description\":\"user said no\"}"},
    };
    defer s.deinit(alloc);
    var tr = s.transport();
    var mc = ManualClock{};
    const clk = mc.clock();
    const cfg = testConfig();
    var info = waitSetup();
    try std.testing.expectError(df.Error.Protocol, df.waitToken(alloc, &cfg, &tr, &clk, null, &info, null, 4));
}

test "token poll server 5xx is protocol error" {
    var s = Scripted{ .statuses = &.{503}, .bodies = &.{"overloaded"} };
    defer s.deinit(alloc);
    var tr = s.transport();
    var mc = ManualClock{};
    const clk = mc.clock();
    const cfg = testConfig();
    var info = waitSetup();
    try std.testing.expectError(df.Error.Protocol, df.pollTokenOnce(alloc, &cfg, &tr, &info));
    // waitToken maps the same 5xx path to protocol error.
    try std.testing.expectError(df.Error.Protocol, df.waitToken(alloc, &cfg, &tr, &clk, null, &info, null, 2));
}

test "token poll expiry from controlled clock" {
    const jwt = try craftJwt(alloc, "{\"aud\":\"test-aud\"}");
    defer alloc.free(jwt);
    const body = try tokenBody(alloc, jwt);
    defer alloc.free(body);
    var s = Scripted{
        .statuses = &.{200},
        .bodies = &.{"{\"error\":\"authorization_pending\"}"},
    };
    defer s.deinit(alloc);
    var tr = s.transport();
    var mc = ManualClock{ .now = 1000 };
    const clk = mc.clock();
    _ = mc.now;
    const cfg = testConfig();
    var info = waitSetup(); // expires_in 60 -> deadline start+60
    info.expires_in = 0; // deadline == start: already expired, zero polls
    try std.testing.expectError(df.Error.Expired, df.waitToken(alloc, &cfg, &tr, &clk, null, &info, null, 4));
    try std.testing.expectEqual(@as(usize, 0), s.at);
}

test "token poll max polls exhausted is expiry" {
    var s = Scripted{
        .statuses = &.{200},
        .bodies = &.{"{\"error\":\"authorization_pending\"}"},
    };
    defer s.deinit(alloc);
    var tr = s.transport();
    var mc = ManualClock{};
    const clk = mc.clock();
    const cfg = testConfig();
    var info = waitSetup();
    try std.testing.expectError(df.Error.Expired, df.waitToken(alloc, &cfg, &tr, &clk, null, &info, null, 2));
    try std.testing.expectEqual(@as(usize, 2), s.at);
}

test "token poll cancellation preempts wait" {
    var s = Scripted{
        .statuses = &.{200},
        .bodies = &.{"{\"error\":\"authorization_pending\"}"},
    };
    defer s.deinit(alloc);
    var tr = s.transport();
    var mc = ManualClock{};
    const clk = mc.clock();
    const cfg = testConfig();
    var info = waitSetup();
    var cancel = df.Cancel{};
    cancel.cancel();
    try std.testing.expectError(df.Error.Canceled, df.waitToken(alloc, &cfg, &tr, &clk, &cancel, &info, null, 4));
    try std.testing.expectEqual(@as(usize, 0), s.at);
}

// ---------------------------------------------------------------------------
// Audience and email helpers.
// ---------------------------------------------------------------------------

test "audience accepts string and array forms" {
    const good_str = try craftJwt(alloc, "{\"aud\":\"test-aud\"}");
    defer alloc.free(good_str);
    try df.validateTokenAudience(alloc, good_str, "test-aud");
    const good_arr = try craftJwt(alloc, "{\"aud\":[\"other\",\"test-aud\"]}");
    defer alloc.free(good_arr);
    try df.validateTokenAudience(alloc, good_arr, "test-aud");
    const bad = try craftJwt(alloc, "{\"aud\":\"other\"}");
    defer alloc.free(bad);
    try std.testing.expectError(df.Error.InvalidToken, df.validateTokenAudience(alloc, bad, "test-aud"));
    const no_aud = try craftJwt(alloc, "{\"sub\":\"123\"}");
    defer alloc.free(no_aud);
    try std.testing.expectError(df.Error.InvalidToken, df.validateTokenAudience(alloc, no_aud, "test-aud"));
    try std.testing.expectError(df.Error.InvalidToken, df.validateTokenAudience(alloc, "", "test-aud"));
    try std.testing.expectError(df.Error.InvalidToken, df.validateTokenAudience(alloc, "flat", "test-aud"));
}

test "audience accepts normal jwt claims around aud" {
    // Normal payload: numeric exp/iat/nbf, nested objects/arrays, bool,
    // null and unknown claims next to aud (review of PR #117).
    const rich = try craftJwt(alloc, "{\"iss\":\"https://idp\",\"sub\":\"u1\",\"aud\":\"test-aud\",\"exp\":1759680000,\"iat\":1759676400,\"nbf\":1759676400,\"custom\":{\"k\":[1,2,{\"deep\":true}]},\"flag\":true,\"empty\":null}");
    defer alloc.free(rich);
    try df.validateTokenAudience(alloc, rich, "test-aud");
    try std.testing.expectError(df.Error.InvalidToken, df.validateTokenAudience(alloc, rich, "other"));

    const arr_numeric = try craftJwt(alloc, "{\"aud\":[\"x\",\"test-aud\"],\"exp\":1759680000,\"iat\":1759676400}");
    defer alloc.free(arr_numeric);
    try df.validateTokenAudience(alloc, arr_numeric, "test-aud");

    // Non-string aud, malformed JSON and non-object payload still rejected.
    const aud_num = try craftJwt(alloc, "{\"aud\":123,\"exp\":1759680000}");
    defer alloc.free(aud_num);
    try std.testing.expectError(df.Error.InvalidToken, df.validateTokenAudience(alloc, aud_num, "test-aud"));
    const aud_obj = try craftJwt(alloc, "{\"aud\":{\"a\":\"test-aud\"}}");
    defer alloc.free(aud_obj);
    try std.testing.expectError(df.Error.InvalidToken, df.validateTokenAudience(alloc, aud_obj, "test-aud"));
    const aud_null = try craftJwt(alloc, "{\"aud\":null}");
    defer alloc.free(aud_null);
    try std.testing.expectError(df.Error.InvalidToken, df.validateTokenAudience(alloc, aud_null, "test-aud"));
    const broken = try craftJwt(alloc, "{\"aud\":\"test-aud\"");
    defer alloc.free(broken);
    try std.testing.expectError(df.Error.InvalidToken, df.validateTokenAudience(alloc, broken, "test-aud"));
    const not_object = try craftJwt(alloc, "[1,2,3]");
    defer alloc.free(not_object);
    try std.testing.expectError(df.Error.InvalidToken, df.validateTokenAudience(alloc, not_object, "test-aud"));
}

test "email parsed from id token with name fallback" {
    const with_email = try craftJwt(alloc, "{\"email\":\"user@example.com\"}");
    defer alloc.free(with_email);
    const email = try df.parseEmailFromIDToken(alloc, with_email);
    defer alloc.free(email);
    try std.testing.expectEqualStrings("user@example.com", email);
    const with_name = try craftJwt(alloc, "{\"name\":\"Display Name\"}");
    defer alloc.free(with_name);
    const name = try df.parseEmailFromIDToken(alloc, with_name);
    defer alloc.free(name);
    try std.testing.expectEqualStrings("Display Name", name);
    const bare = try craftJwt(alloc, "{\"sub\":\"123\"}");
    defer alloc.free(bare);
    try std.testing.expectError(df.Error.InvalidToken, df.parseEmailFromIDToken(alloc, bare));
}

// ---------------------------------------------------------------------------
// PendingFlow session handle.
// ---------------------------------------------------------------------------

test "pending flow set get expiry cancel clear" {
    var mc = ManualClock{ .now = 5000 };
    const clk = mc.clock();
    var p = df.PendingFlow{};
    try std.testing.expect(!p.isPending());
    try std.testing.expect((try p.get(alloc)) == null);

    const info = df.AuthFlowInfo{
        .device_code = try alloc.dupe(u8, "dc-9"),
        .user_code = try alloc.dupe(u8, "uc-9"),
        .verification_uri = try alloc.dupe(u8, "https://idp/x"),
        .verification_uri_complete = try alloc.dupe(u8, "https://idp/x?c=1"),
        .expires_in = 300,
        .interval = 5,
    };
    p.set(alloc, &clk, info); // ownership moves into p
    try std.testing.expect(p.isPending());
    try std.testing.expectEqual(@as(i64, 5300), p.expiresAt());

    var got = (try p.get(alloc)).?;
    defer got.deinit(alloc);
    try std.testing.expectEqualStrings("dc-9", got.device_code);

    // Wait-cancel preemption mirrors server.go CancelWait/SetWaitCancel.
    p.setWaitActive();
    try std.testing.expect(!p.waitCanceled());
    p.cancelWait();
    try std.testing.expect(p.waitCanceled());

    p.clear(alloc);
    try std.testing.expect(!p.isPending());
    try std.testing.expect((try p.get(alloc)) == null);
    // Cancel on empty flow is safe.
    p.cancelWait();
}

test "pending flow repeated set replaces owned info" {
    var mc = ManualClock{ .now = 1000 };
    const clk = mc.clock();
    var p = df.PendingFlow{};

    const first = df.AuthFlowInfo{
        .device_code = try alloc.dupe(u8, "dc-1"),
        .user_code = try alloc.dupe(u8, "uc-1"),
        .verification_uri = try alloc.dupe(u8, "https://idp/one"),
        .verification_uri_complete = try alloc.dupe(u8, "https://idp/one?c=1"),
        .expires_in = 100,
        .interval = 5,
    };
    p.set(alloc, &clk, first);
    const second = df.AuthFlowInfo{
        .device_code = try alloc.dupe(u8, "dc-2"),
        .user_code = try alloc.dupe(u8, "uc-2"),
        .verification_uri = try alloc.dupe(u8, "https://idp/two"),
        .verification_uri_complete = try alloc.dupe(u8, "https://idp/two?c=2"),
        .expires_in = 200,
        .interval = 7,
    };
    p.set(alloc, &clk, second); // must release the first flow, not leak it
    var got = (try p.get(alloc)).?;
    defer got.deinit(alloc);
    try std.testing.expectEqualStrings("dc-2", got.device_code);
    try std.testing.expectEqualStrings("uc-2", got.user_code);
    try std.testing.expectEqual(@as(i64, 1200), p.expiresAt());
    p.clear(alloc);
    try std.testing.expect((try p.get(alloc)) == null);
}

test "pending flow get oom leaves no partial copy" {
    var mc = ManualClock{ .now = 1000 };
    const clk = mc.clock();
    var p = df.PendingFlow{};
    const info = df.AuthFlowInfo{
        .device_code = try alloc.dupe(u8, "dc-oom"),
        .user_code = try alloc.dupe(u8, "uc-oom"),
        .verification_uri = try alloc.dupe(u8, "https://idp/oom"),
        .verification_uri_complete = try alloc.dupe(u8, "https://idp/oom?c=1"),
        .expires_in = 60,
        .interval = 5,
    };
    p.set(alloc, &clk, info);
    defer p.clear(alloc);
    // Third string allocation fails; the two staged strings must be freed.
    var failing = std.testing.FailingAllocator.init(alloc, .{ .fail_index = 2 });
    try std.testing.expectError(df.Error.OutOfMemory, p.get(failing.allocator()));
}

// ---------------------------------------------------------------------------
// Real localhost HTTP wire adapter.
// ---------------------------------------------------------------------------

const SockTx = struct {
    port: u16,

    fn postFn(ctx: *anyopaque, a: std.mem.Allocator, path: []const u8, body: []const u8) df.Transport.TransportError!df.Transport.Response {
        const s: *SockTx = @ptrCast(@alignCast(ctx));
        var caddr = std.Io.net.IpAddress{ .ip4 = .loopback(s.port) };
        var cli = caddr.connect(tio, .{ .mode = .stream }) catch return error.Transport;
        defer cli.close(tio);
        var wbuf: [2048]u8 = undefined;
        var w = cli.writer(tio, &wbuf);
        w.interface.print(
            "POST {s} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n",
            .{ path, body.len },
        ) catch return error.Transport;
        w.interface.writeAll(body) catch return error.Transport;
        w.interface.flush() catch return error.Transport;
        var rbuf: [4096]u8 = undefined;
        var r = cli.reader(tio, &rbuf);
        var raw: std.ArrayList(u8) = .empty;
        defer raw.deinit(a);
        var chunk: [1024]u8 = undefined;
        while (true) {
            const n = r.interface.readSliceShort(&chunk) catch return error.Transport;
            if (n == 0) break;
            raw.appendSlice(a, chunk[0..n]) catch return error.OutOfMemory;
        }
        const sep = std.mem.indexOf(u8, raw.items, "\r\n\r\n") orelse return error.Transport;
        const head = raw.items[0..sep];
        var lines = std.mem.splitScalar(u8, head, '\n');
        const status_line = std.mem.trimEnd(u8, lines.first(), "\r");
        var sp = std.mem.splitScalar(u8, status_line, ' ');
        _ = sp.first(); // HTTP/1.1
        const code_str = sp.next() orelse return error.Transport;
        const code = std.fmt.parseInt(u16, code_str, 10) catch return error.Transport;
        const payload = raw.items[sep + 4 ..];
        const owned = a.dupe(u8, payload) catch return error.OutOfMemory;
        return .{ .status = code, .body = owned };
    }

    fn transport(s: *SockTx) df.Transport {
        return .{ .ctx = s, .postFn = postFn };
    }
};

const WireServer = struct {
    srv: *std.Io.net.Server,
    statuses: []const u16,
    bodies: []const []const u8,
    methods: [8][]u8 = undefined,
    paths: [8][]u8 = undefined,
    req_bodies: [8][]u8 = undefined,
    count: usize = 0,
    failed: bool = false,

    fn reason(code: u16) []const u8 {
        return switch (code) {
            200 => "OK",
            400 => "Bad Request",
            500 => "Internal Server Error",
            else => "Error",
        };
    }

    fn run(s: *WireServer) void {
        var n: usize = 0;
        while (n < s.statuses.len) : (n += 1) {
            var c: std.Io.net.Stream = s.srv.accept(tio) catch {
                s.failed = true;
                return;
            };
            defer c.close(tio);
            var rbuf: [4096]u8 = undefined;
            var r = c.reader(tio, &rbuf);
            const req_line = (r.interface.takeDelimiter('\n') catch null) orelse {
                s.failed = true;
                return;
            };
            const trimmed = std.mem.trimEnd(u8, req_line, "\r");
            var parts = std.mem.splitScalar(u8, trimmed, ' ');
            const method = std.testing.allocator.dupe(u8, parts.first()) catch {
                s.failed = true;
                return;
            };
            const path = std.testing.allocator.dupe(u8, parts.next() orelse "/") catch {
                std.testing.allocator.free(method);
                s.failed = true;
                return;
            };
            var content_len: usize = 0;
            while ((r.interface.takeDelimiter('\n') catch null)) |line| {
                const t = std.mem.trimEnd(u8, line, "\r");
                if (t.len == 0) break;
                if (std.mem.startsWith(u8, t, "Content-Length:")) {
                    content_len = std.fmt.parseInt(usize, std.mem.trim(u8, t[15..], " \t"), 10) catch 0;
                }
            }
            var req_body: []u8 = &.{};
            if (content_len > 0) {
                const buf = std.testing.allocator.alloc(u8, content_len) catch {
                    s.failed = true;
                    return;
                };
                r.interface.readSliceAll(buf) catch {
                    std.testing.allocator.free(buf);
                    s.failed = true;
                    return;
                };
                req_body = buf;
            }
            if (s.count < s.methods.len) {
                s.methods[s.count] = method;
                s.paths[s.count] = path;
                s.req_bodies[s.count] = req_body;
                s.count += 1;
            }
            var wbuf: [4096]u8 = undefined;
            var w = c.writer(tio, &wbuf);
            w.interface.print(
                "HTTP/1.1 {d} {s}\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n",
                .{ s.statuses[n], reason(s.statuses[n]), s.bodies[n].len },
            ) catch {
                s.failed = true;
                return;
            };
            w.interface.writeAll(s.bodies[n]) catch {
                s.failed = true;
                return;
            };
            w.interface.flush() catch {
                s.failed = true;
                return;
            };
        }
    }
};

test "wire device code over localhost http" {
    var addr = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var srv = try addr.listen(tio, .{});
    defer srv.deinit(tio);
    const port = srv.socket.address.getPort();
    const device_json = "{\"device_code\":\"wire-dc\",\"user_code\":\"WIRE-1\",\"verification_uri\":\"https://idp/activate\",\"verification_uri_complete\":\"https://idp/activate?c=1\",\"expires_in\":600,\"interval\":5}";
    var ws = WireServer{ .srv = &srv, .statuses = &.{200}, .bodies = &.{device_json} };
    var th = try std.Thread.spawn(.{}, WireServer.run, .{&ws});
    var tx = SockTx{ .port = port };
    var tr = tx.transport();
    var cfg = testConfig();
    cfg.device_auth_endpoint = "/device";
    cfg.token_endpoint = "/token";
    var info = try df.requestAuthInfo(alloc, &cfg, &tr);
    defer info.deinit(alloc);
    th.join();
    try std.testing.expect(!ws.failed);
    try std.testing.expectEqual(@as(usize, 1), ws.count);
    defer {
        for (ws.methods[0..ws.count]) |m| alloc.free(m);
        for (ws.paths[0..ws.count]) |p| alloc.free(p);
        for (ws.req_bodies[0..ws.count]) |b| alloc.free(b);
    }
    try std.testing.expectEqualStrings("wire-dc", info.device_code);
    try std.testing.expectEqualStrings("WIRE-1", info.user_code);
    try std.testing.expectEqualStrings("POST", ws.methods[0]);
    try std.testing.expectEqualStrings("/device", ws.paths[0]);
    try std.testing.expect(std.mem.indexOf(u8, ws.req_bodies[0], "client_id=test-client") != null);
    try std.testing.expect(std.mem.indexOf(u8, ws.req_bodies[0], "audience=test-aud") != null);
    try std.testing.expect(std.mem.indexOf(u8, ws.req_bodies[0], "scope=openid") != null);
}

test "wire token pending then success over localhost http" {
    const jwt = try craftJwt(alloc, "{\"aud\":\"test-aud\"}");
    defer alloc.free(jwt);
    const ok_body = try tokenBody(alloc, jwt);
    defer alloc.free(ok_body);
    var addr = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var srv = try addr.listen(tio, .{});
    defer srv.deinit(tio);
    const port = srv.socket.address.getPort();
    var ws = WireServer{
        .srv = &srv,
        .statuses = &.{ 200, 200 },
        .bodies = &.{ "{\"error\":\"authorization_pending\"}", ok_body },
    };
    var th = try std.Thread.spawn(.{}, WireServer.run, .{&ws});
    var tx = SockTx{ .port = port };
    var tr = tx.transport();
    var cfg = testConfig();
    cfg.device_auth_endpoint = "/device";
    cfg.token_endpoint = "/token";
    var mc = ManualClock{};
    const clk = mc.clock();
    var info = waitSetup();
    var tok = try df.waitToken(alloc, &cfg, &tr, &clk, null, &info, null, 4);
    defer tok.deinit(alloc);
    th.join();
    try std.testing.expect(!ws.failed);
    try std.testing.expectEqual(@as(usize, 2), ws.count);
    defer {
        for (ws.methods[0..ws.count]) |m| alloc.free(m);
        for (ws.paths[0..ws.count]) |p| alloc.free(p);
        for (ws.req_bodies[0..ws.count]) |b| alloc.free(b);
    }
    try std.testing.expectEqualStrings(jwt, tok.access_token);
    for (ws.req_bodies[0..ws.count]) |b| {
        try std.testing.expect(std.mem.indexOf(u8, b, "device_code=devcode") != null);
    }
}

test "wire error status over localhost http is BadStatus" {
    var addr = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var srv = try addr.listen(tio, .{});
    defer srv.deinit(tio);
    const port = srv.socket.address.getPort();
    var ws = WireServer{ .srv = &srv, .statuses = &.{400}, .bodies = &.{"{\"error\":\"invalid_request\"}"} };
    var th = try std.Thread.spawn(.{}, WireServer.run, .{&ws});
    var tx = SockTx{ .port = port };
    var tr = tx.transport();
    var cfg = testConfig();
    cfg.device_auth_endpoint = "/device";
    cfg.token_endpoint = "/token";
    try std.testing.expectError(df.Error.BadStatus, df.requestAuthInfo(alloc, &cfg, &tr));
    th.join();
    try std.testing.expect(!ws.failed);
    defer {
        for (ws.methods[0..ws.count]) |m| alloc.free(m);
        for (ws.paths[0..ws.count]) |p| alloc.free(p);
        for (ws.req_bodies[0..ws.count]) |b| alloc.free(b);
    }
}
