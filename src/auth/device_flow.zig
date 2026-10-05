// Port of netbird client/internal/auth/{device_flow,oauth,pending_flow,util}.go (v0.80.0), BSD-3-Clause.
// Device Authorization (RFC 8628) flow: device-code request, token polling
// with authorization_pending/slow_down handling, client-side JWT audience
// sanity check, email claim extraction, and the PendingFlow session handle
// the daemon holds between Request/Wait RPCs (server/server.go).
// Transport/clock/cancel are injectable boundaries so tests use a fake
// transport plus a controlled clock with no sleeps; real HTTP/TLS production
// adapter is not yet wired (see report).

const std = @import("std");

/// Grant type the IdP token endpoint expects for device-code exchange.
pub const hosted_grant_type = "urn:ietf:params:oauth:grant-type:device_code";

/// How much slow_down stretches the polling interval (device_flow.go).
pub const slow_down_backoff_s: i64 = 3;

/// Provider configuration (DeviceAuthProviderConfig).
pub const DeviceAuthProviderConfig = struct {
    client_id: []const u8 = "",
    client_secret: []const u8 = "",
    domain: []const u8 = "",
    audience: []const u8 = "",
    token_endpoint: []const u8 = "",
    device_auth_endpoint: []const u8 = "",
    scope: []const u8 = "",
    use_id_token: bool = false,
    login_hint: []const u8 = "",
};

/// Device-code authorization info (AuthFlowInfo). Owned strings.
pub const AuthFlowInfo = struct {
    device_code: []const u8 = "",
    user_code: []const u8 = "",
    verification_uri: []const u8 = "",
    verification_uri_complete: []const u8 = "",
    expires_in: i64 = 0,
    interval: i64 = 0,

    pub fn deinit(f: *AuthFlowInfo, alloc: std.mem.Allocator) void {
        alloc.free(f.device_code);
        alloc.free(f.user_code);
        alloc.free(f.verification_uri);
        alloc.free(f.verification_uri_complete);
        f.* = .{};
    }
};

/// Issued token set (TokenInfo). Owned strings. Email is best-effort.
pub const TokenInfo = struct {
    access_token: []const u8 = "",
    refresh_token: []const u8 = "",
    id_token: []const u8 = "",
    token_type: []const u8 = "",
    expires_in: i64 = 0,
    use_id_token: bool = false,
    email: []const u8 = "",

    pub fn deinit(t: *TokenInfo, alloc: std.mem.Allocator) void {
        alloc.free(t.access_token);
        alloc.free(t.refresh_token);
        alloc.free(t.id_token);
        alloc.free(t.token_type);
        alloc.free(t.email);
        t.* = .{};
    }

    /// Token callers must send back (GetTokenToUse).
    pub fn tokenToUse(t: *const TokenInfo) []const u8 {
        if (t.use_id_token) return t.id_token;
        return t.access_token;
    }
};

pub const Error = error{
    InvalidConfig,
    Transport,
    BadStatus,
    BadJson,
    Protocol,
    SlowDown,
    Pending,
    Expired,
    Canceled,
    InvalidToken,
    OutOfMemory,
};

/// Minimal HTTP surface the flow needs. Production wires a real HTTP/TLS
/// client later; tests use fakes or the localhost server adapter.
/// Request/response bodies are small form/JSON payloads.
pub const Transport = struct {
    ctx: *anyopaque,
    postFn: *const fn (
        *anyopaque,
        alloc: std.mem.Allocator,
        endpoint: []const u8,
        body: []const u8,
    ) TransportError!Response,

    pub const Response = struct {
        status: u16,
        body: []u8,

        pub fn deinit(r: *Response, alloc: std.mem.Allocator) void {
            alloc.free(r.body);
            r.* = undefined;
        }
    };

    pub const TransportError = error{ Transport, OutOfMemory };

    pub fn post(
        t: *const Transport,
        alloc: std.mem.Allocator,
        endpoint: []const u8,
        body: []const u8,
    ) TransportError!Response {
        return try t.postFn(t.ctx, alloc, endpoint, body);
    }
};

/// Controllable time source. now_s returns monotonic seconds.
/// Production wires a clock_gettime(CLOCK.MONOTONIC) implementation;
/// tests advance time manually so no sleeps are needed.
pub const Clock = struct {
    ctx: *anyopaque,
    nowFn: *const fn (*anyopaque) i64,

    pub fn now_s(c: *const Clock) i64 {
        return c.nowFn(c.ctx);
    }
};

/// Cooperative cancellation flag polled between polls
/// (mirrors context cancellation in WaitToken).
pub const Cancel = struct {
    flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    pub fn cancel(c: *Cancel) void {
        c.flag.store(true, .release);
    }

    pub fn isCanceled(c: *const Cancel) bool {
        return @constCast(c).flag.load(.acquire);
    }
};

/// Monotonic clock via clock_gettime(CLOCK.MONOTONIC); available since
/// Linux 2.6, safe on the 4.9 router target. Falls back to 0 on error.
pub const SystemClock = struct {
    _anchor: u8 = 0,

    pub fn clock(ctx: *anyopaque) i64 {
        _ = ctx;
        var ts: std.os.linux.timespec = undefined;
        const rc = std.os.linux.clock_gettime(.MONOTONIC, &ts);
        if (std.os.linux.errno(rc) != .SUCCESS) return 0;
        return ts.sec;
    }

    pub fn asClock(s: *SystemClock) Clock {
        return .{ .ctx = @ptrCast(s), .nowFn = clock };
    }
};

/// Validate provider config (validateDeviceAuthConfig). Empty scope is
/// tolerated here: server-side compat defaults it to "openid" (auth.go).
pub fn validateDeviceAuthConfig(cfg: *const DeviceAuthProviderConfig) Error!void {
    if (cfg.audience.len == 0) return Error.InvalidConfig;
    if (cfg.client_id.len == 0) return Error.InvalidConfig;
    if (cfg.token_endpoint.len == 0) return Error.InvalidConfig;
    if (cfg.device_auth_endpoint.len == 0) return Error.InvalidConfig;
    return;
}

/// Append login_hint query parameter (appendLoginHint).
/// Returns owned string; empty uri/hint returns a dupe of uri.
pub fn appendLoginHint(
    alloc: std.mem.Allocator,
    uri: []const u8,
    login_hint: []const u8,
) Error![]u8 {
    if (uri.len == 0 or login_hint.len == 0) {
        return alloc.dupe(u8, uri) catch Error.OutOfMemory;
    }
    const enc_hint = formEncode(alloc, login_hint) catch return Error.OutOfMemory;
    defer alloc.free(enc_hint);
    const sep: u8 = if (std.mem.indexOfScalar(u8, uri, '?') != null) '&' else '?';
    const parts = [_][]const u8{ uri, &[_]u8{sep}, "login_hint=", enc_hint };
    var len: usize = 0;
    for (parts) |p| len += p.len;
    const buf = alloc.alloc(u8, len) catch return Error.OutOfMemory;
    var off: usize = 0;
    for (parts) |p| {
        @memcpy(buf[off .. off + p.len], p);
        off += p.len;
    }
    return buf;
}

/// Percent-encode a form value (application/x-www-form-urlencoded:
/// unreserved + space-as-+ per Go url.Values.Encode used upstream).
fn formEncode(alloc: std.mem.Allocator, s: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);
    const hex = "0123456789ABCDEF";
    for (s) |c| {
        if ((c >= 'A' and c <= 'Z') or (c >= 'a' and c <= 'z') or
            (c >= '0' and c <= '9') or c == '-' or c == '_' or c == '.' or c == '~')
        {
            try out.append(alloc, c);
        } else if (c == ' ') {
            try out.append(alloc, '+');
        } else {
            try out.append(alloc, '%');
            try out.append(alloc, hex[c >> 4]);
            try out.append(alloc, hex[c & 0xF]);
        }
    }
    return try out.toOwnedSlice(alloc);
}

/// Build device-code request body: client_id, audience, scope.
pub fn buildDeviceCodeBody(alloc: std.mem.Allocator, cfg: *const DeviceAuthProviderConfig) Error![]u8 {
    const cid = formEncode(alloc, cfg.client_id) catch return Error.OutOfMemory;
    defer alloc.free(cid);
    const aud = formEncode(alloc, cfg.audience) catch return Error.OutOfMemory;
    defer alloc.free(aud);
    const scope = formEncode(alloc, cfg.scope) catch return Error.OutOfMemory;
    defer alloc.free(scope);
    return std.fmt.allocPrint(
        alloc,
        "client_id={s}&audience={s}&scope={s}",
        .{ cid, aud, scope },
    ) catch Error.OutOfMemory;
}

/// Build token request body: client_id, grant_type, device_code.
pub fn buildTokenBody(
    alloc: std.mem.Allocator,
    cfg: *const DeviceAuthProviderConfig,
    device_code: []const u8,
) Error![]u8 {
    const cid = formEncode(alloc, cfg.client_id) catch return Error.OutOfMemory;
    defer alloc.free(cid);
    const dc = formEncode(alloc, device_code) catch return Error.OutOfMemory;
    defer alloc.free(dc);
    return std.fmt.allocPrint(
        alloc,
        "client_id={s}&grant_type={s}&device_code={s}",
        .{ cid, hosted_grant_type, dc },
    ) catch Error.OutOfMemory;
}

fn jsonString(alloc: std.mem.Allocator, v: std.json.Value) Error![]u8 {
    if (v != .string) return Error.BadJson;
    return alloc.dupe(u8, v.string) catch Error.OutOfMemory;
}

fn jsonInt(v: std.json.Value) i64 {
    return switch (v) {
        .integer => |i| i,
        .float => |f| @intFromFloat(f),
        else => 0,
    };
}

/// Parse device-code response JSON into owned AuthFlowInfo.
/// Applies verification_uri_complete fallback (upstream RequestAuthInfo).
pub fn parseAuthFlowInfo(alloc: std.mem.Allocator, body: []const u8) Error!AuthFlowInfo {
    const parsed = std.json.parseFromSlice(std.json.Value, alloc, body, .{}) catch return Error.BadJson;
    defer parsed.deinit();
    if (parsed.value != .object) return Error.BadJson;
    const obj = parsed.value.object;
    var info: AuthFlowInfo = .{};
    errdefer info.deinit(alloc);
    if (obj.get("device_code")) |v| info.device_code = try jsonString(alloc, v);
    if (obj.get("user_code")) |v| info.user_code = try jsonString(alloc, v);
    if (obj.get("verification_uri")) |v| info.verification_uri = try jsonString(alloc, v);
    if (obj.get("verification_uri_complete")) |v| info.verification_uri_complete = try jsonString(alloc, v);
    if (obj.get("expires_in")) |v| info.expires_in = jsonInt(v);
    if (obj.get("interval")) |v| info.interval = jsonInt(v);
    if (info.verification_uri_complete.len == 0 and info.verification_uri.len != 0) {
        alloc.free(info.verification_uri_complete);
        info.verification_uri_complete = alloc.dupe(u8, info.verification_uri) catch return Error.OutOfMemory;
    }
    return info;
}

/// Token poll outcome: success carries owned TokenInfo, pending/slow_down
/// are explicit states, fatal wraps the IdP error string.
pub const PollOutcome = union(enum) {
    success: TokenInfo,
    pending,
    slow_down,
    fatal: []u8,

    pub fn deinit(o: *PollOutcome, alloc: std.mem.Allocator) void {
        switch (o.*) {
            .success => |*t| t.deinit(alloc),
            .fatal => |e| alloc.free(e),
            .pending, .slow_down => {},
        }
        o.* = undefined;
    }
};

/// Parse one token endpoint response body. status>=500 is a protocol error
/// (upstream returns the raw body as error). error/authorization_pending and
/// error/slow_down map to states; any other error maps to fatal with the
/// description. Success requires audience validation of the token to use.
pub fn parseTokenResponse(
    alloc: std.mem.Allocator,
    status: u16,
    body: []const u8,
    cfg: *const DeviceAuthProviderConfig,
    id_token_hint: []const u8,
) Error!PollOutcome {
    if (status >= 500) return Error.Protocol;
    const parsed = std.json.parseFromSlice(std.json.Value, alloc, body, .{}) catch return Error.BadJson;
    defer parsed.deinit();
    if (parsed.value != .object) return Error.BadJson;
    const obj = parsed.value.object;
    if (obj.get("error")) |ev| {
        if (ev != .string) return Error.BadJson;
        if (std.mem.eql(u8, ev.string, "authorization_pending")) return .pending;
        if (std.mem.eql(u8, ev.string, "slow_down")) return .slow_down;
        var desc: []const u8 = ev.string;
        if (obj.get("error_description")) |dv| {
            if (dv == .string) desc = dv.string;
        }
        const owned = alloc.dupe(u8, desc) catch return Error.OutOfMemory;
        return .{ .fatal = owned };
    }
    var tok: TokenInfo = .{};
    errdefer tok.deinit(alloc);
    if (obj.get("access_token")) |v| tok.access_token = try jsonString(alloc, v);
    if (obj.get("refresh_token")) |v| tok.refresh_token = try jsonString(alloc, v);
    if (obj.get("id_token")) |v| tok.id_token = try jsonString(alloc, v);
    if (obj.get("token_type")) |v| tok.token_type = try jsonString(alloc, v);
    if (obj.get("expires_in")) |v| tok.expires_in = jsonInt(v);
    tok.use_id_token = cfg.use_id_token;
    validateTokenAudience(tok.tokenToUse(), cfg.audience) catch return Error.InvalidToken;
    // Best-effort email like upstream: prefer the id_token claim, ignore failure.
    const id_src = if (tok.id_token.len != 0) tok.id_token else id_token_hint;
    if (id_src.len != 0) {
        if (parseEmailFromIDToken(alloc, id_src)) |email| {
            tok.email = email;
        } else |_| {}
    }
    return .{ .success = tok };
}

/// Request device-code info from the IdP (RequestAuthInfo).
/// Owns all returned strings. Never logs tokens.
pub fn requestAuthInfo(
    alloc: std.mem.Allocator,
    cfg: *const DeviceAuthProviderConfig,
    transport: *const Transport,
) Error!AuthFlowInfo {
    try validateDeviceAuthConfig(cfg);
    const body = try buildDeviceCodeBody(alloc, cfg);
    defer alloc.free(body);
    var resp = transport.post(alloc, cfg.device_auth_endpoint, body) catch return Error.Transport;
    defer resp.deinit(alloc);
    if (resp.status != 200) return Error.BadStatus;
    var info = try parseAuthFlowInfo(alloc, resp.body);
    errdefer info.deinit(alloc);
    if (cfg.login_hint.len != 0) {
        if (info.verification_uri_complete.len != 0) {
            const with_hint = try appendLoginHint(alloc, info.verification_uri_complete, cfg.login_hint);
            alloc.free(info.verification_uri_complete);
            info.verification_uri_complete = with_hint;
        }
        if (info.verification_uri.len != 0) {
            const with_hint = try appendLoginHint(alloc, info.verification_uri, cfg.login_hint);
            alloc.free(info.verification_uri);
            info.verification_uri = with_hint;
        }
    }
    return info;
}

/// Single token poll (requestToken + parse).
pub fn pollTokenOnce(
    alloc: std.mem.Allocator,
    cfg: *const DeviceAuthProviderConfig,
    transport: *const Transport,
    info: *const AuthFlowInfo,
) Error!PollOutcome {
    const body = try buildTokenBody(alloc, cfg, info.device_code);
    defer alloc.free(body);
    var resp = transport.post(alloc, cfg.token_endpoint, body) catch return Error.Transport;
    defer resp.deinit(alloc);
    return try parseTokenResponse(alloc, resp.status, resp.body, cfg, "");
}

/// Wait for user authorization by polling (WaitToken).
/// interval_s starts at info.interval; slow_down adds slow_down_backoff_s.
/// Deadline is info.expires_in seconds after start_s (controlled clock, no
/// sleeps: caller advances the clock; onTick is invoked per poll step so
/// tests and production schedulers can wait or advance time).
pub fn waitToken(
    alloc: std.mem.Allocator,
    cfg: *const DeviceAuthProviderConfig,
    transport: *const Transport,
    clock: *const Clock,
    cancel: ?*const Cancel,
    info: *const AuthFlowInfo,
    onTick: ?*const fn (interval_s: i64) void,
    max_polls: usize,
) Error!TokenInfo {
    const start_s = clock.now_s();
    const deadline_s = start_s + info.expires_in;
    var interval_s: i64 = info.interval;
    if (interval_s <= 0) interval_s = 5;
    var polls: usize = 0;
    while (polls < max_polls) {
        if (cancel != null and cancel.?.isCanceled()) return Error.Canceled;
        if (clock.now_s() >= deadline_s) return Error.Expired;
        if (onTick) |tick| tick(interval_s);
        var outcome = try pollTokenOnce(alloc, cfg, transport, info);
        defer outcome.deinit(alloc);
        switch (outcome) {
            .success => {
                const tok = outcome.success;
                outcome.success = .{};
                return tok;
            },
            .pending => {},
            .slow_down => {
                interval_s += slow_down_backoff_s;
            },
            .fatal => return Error.Protocol,
        }
        polls += 1;
    }
    return Error.Expired;
}

/// Client-side JWT audience sanity check (validateTokenAudience).
/// Signature is NOT verified here; the management server verifies against
/// the IdP JWKS. Only checks well-formedness and aud claim match.
/// aud may be a string or an array of strings.
pub fn validateTokenAudience(token: []const u8, audience: []const u8) Error!void {
    if (token.len == 0) return Error.InvalidToken;
    var dot_count: usize = 0;
    var first_dot: ?usize = null;
    var second_dot: ?usize = null;
    for (token, 0..) |c, i| {
        if (c == '.') {
            dot_count += 1;
            if (first_dot == null) first_dot = i else if (second_dot == null) second_dot = i;
        }
    }
    if (dot_count != 2) return Error.InvalidToken;
    const payload_seg = token[first_dot.? + 1 .. second_dot.?];
    const dec = std.base64.url_safe_no_pad.Decoder;
    const need = dec.calcSizeForSlice(payload_seg) catch return Error.InvalidToken;
    // JWT claims are small; stack cap keeps router memory tight.
    if (need > 16 * 1024) return Error.InvalidToken;
    var buf: [16 * 1024]u8 = undefined;
    const slice = buf[0..need];
    dec.decode(slice, payload_seg) catch return Error.InvalidToken;
    // Lightweight claim scan: find "aud" without a full JSON parser so the
    // check works without allocation. Handles string and string-array forms.
    return checkAudienceClaim(slice, audience);
}

fn skipWs(s: []const u8, i: *usize) void {
    while (i.* < s.len and (s[i.*] == ' ' or s[i.*] == '\t' or s[i.*] == '\n' or s[i.*] == '\r')) : (i.* += 1) {}
}

fn parseJsonString(s: []const u8, i: *usize, out: *std.ArrayList(u8), alloc: std.mem.Allocator) Error!void {
    // s[i] == '"'
    i.* += 1;
    while (i.* < s.len) {
        const c = s[i.*];
        if (c == '"') {
            i.* += 1;
            return;
        }
        if (c == '\\') {
            i.* += 1;
            if (i.* >= s.len) return Error.InvalidToken;
            const e = s[i.*];
            switch (e) {
                '"', '\\', '/' => out.append(alloc, e) catch return Error.OutOfMemory,
                'n' => out.append(alloc, '\n') catch return Error.OutOfMemory,
                't' => out.append(alloc, '\t') catch return Error.OutOfMemory,
                'r' => out.append(alloc, '\r') catch return Error.OutOfMemory,
                'u' => {
                    if (i.* + 4 >= s.len) return Error.InvalidToken;
                    const hex = s[i.* + 1 .. i.* + 5];
                    const cp = std.fmt.parseInt(u21, hex, 16) catch return Error.InvalidToken;
                    var tmp: [4]u8 = undefined;
                    const n = std.unicode.utf8Encode(cp, &tmp) catch return Error.InvalidToken;
                    out.appendSlice(alloc, tmp[0..n]) catch return Error.OutOfMemory;
                    i.* += 4;
                },
                else => return Error.InvalidToken,
            }
            i.* += 1;
        } else {
            out.append(alloc, c) catch return Error.OutOfMemory;
            i.* += 1;
        }
    }
    return Error.InvalidToken;
}

fn checkAudienceClaim(claims: []const u8, audience: []const u8) Error!void {
    // Minimal JSON object scan for top-level "aud": string | [string...].
    var alloc_buf: [512]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&alloc_buf);
    const alloc = fba.allocator();
    var i: usize = 0;
    skipWs(claims, &i);
    if (i >= claims.len or claims[i] != '{') return Error.InvalidToken;
    i += 1;
    var found = false;
    var matched = false;
    while (true) {
        skipWs(claims, &i);
        if (i >= claims.len) return Error.InvalidToken;
        if (claims[i] == '}') break;
        if (claims[i] != '"') return Error.InvalidToken;
        var key: std.ArrayList(u8) = .empty;
        defer key.deinit(alloc);
        try parseJsonString(claims, &i, &key, alloc);
        skipWs(claims, &i);
        if (i >= claims.len or claims[i] != ':') return Error.InvalidToken;
        i += 1;
        skipWs(claims, &i);
        const is_aud = std.mem.eql(u8, key.items, "aud");
        if (i >= claims.len) return Error.InvalidToken;
        if (claims[i] == '"') {
            var val: std.ArrayList(u8) = .empty;
            defer val.deinit(alloc);
            try parseJsonString(claims, &i, &val, alloc);
            if (is_aud) {
                found = true;
                if (std.mem.eql(u8, val.items, audience)) matched = true;
            }
        } else if (claims[i] == '[') {
            i += 1;
            var arr_match = false;
            var first = true;
            while (true) {
                skipWs(claims, &i);
                if (i >= claims.len) return Error.InvalidToken;
                if (claims[i] == ']') {
                    i += 1;
                    break;
                }
                if (!first) {
                    if (claims[i] != ',') return Error.InvalidToken;
                    i += 1;
                    skipWs(claims, &i);
                }
                first = false;
                if (i >= claims.len or claims[i] != '"') return Error.InvalidToken;
                var val: std.ArrayList(u8) = .empty;
                defer val.deinit(alloc);
                try parseJsonString(claims, &i, &val, alloc);
                if (is_aud and std.mem.eql(u8, val.items, audience)) arr_match = true;
            }
            if (is_aud) {
                found = true;
                if (arr_match) matched = true;
            }
        } else {
            return Error.InvalidToken;
        }
        skipWs(claims, &i);
        if (i < claims.len and claims[i] == ',') {
            i += 1;
            continue;
        }
        if (i < claims.len and claims[i] == '}') break;
        if (i >= claims.len) return Error.InvalidToken;
        return Error.InvalidToken;
    }
    if (!found) return Error.InvalidToken;
    if (!matched) return Error.InvalidToken;
}

/// Extract email (or name fallback) claim from an ID token without
/// verifying the signature (parseEmailFromIDToken). Best-effort UX value
/// only; never drives authorization. Returns owned string.
pub fn parseEmailFromIDToken(alloc: std.mem.Allocator, token: []const u8) Error![]u8 {
    const first_dot = std.mem.indexOfScalar(u8, token, '.') orelse return Error.InvalidToken;
    const rest = token[first_dot + 1 ..];
    if (rest.len == 0) return Error.InvalidToken;
    // Payload is the segment up to the next dot (or end for unsigned).
    const payload_seg = if (std.mem.indexOfScalar(u8, rest, '.')) |j| rest[0..j] else rest;
    const dec = std.base64.url_safe_no_pad.Decoder;
    const need = dec.calcSizeForSlice(payload_seg) catch return Error.InvalidToken;
    if (need > 16 * 1024) return Error.InvalidToken;
    var buf: [16 * 1024]u8 = undefined;
    const slice = buf[0..need];
    dec.decode(slice, payload_seg) catch return Error.InvalidToken;
    const parsed = std.json.parseFromSlice(std.json.Value, alloc, slice, .{}) catch return Error.InvalidToken;
    defer parsed.deinit();
    if (parsed.value != .object) return Error.InvalidToken;
    const obj = parsed.value.object;
    if (obj.get("email")) |v| {
        if (v == .string) return alloc.dupe(u8, v.string) catch Error.OutOfMemory;
    }
    if (obj.get("name")) |v| {
        if (v == .string) return alloc.dupe(u8, v.string) catch Error.OutOfMemory;
    }
    return Error.InvalidToken;
}

/// Pending device/PKCE flow handle shared between the RPC that starts it
/// (returns verification URI) and the RPC that waits for completion
/// (pending_flow.go + server.go Request/WaitExtendAuthSession).
/// Single-threaded spinlock guards state; wait-cancel is a cooperative
/// flag the waiter polls, mirroring context.CancelFunc preemption.
pub const PendingFlow = struct {
    lock: std.atomic.Value(u8) = std.atomic.Value(u8).init(0),
    has_flow: bool = false,
    info: AuthFlowInfo = .{},
    expires_at_s: i64 = 0,
    wait_canceled: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    wait_active: bool = false,

    fn acquire(p: *PendingFlow) void {
        while (p.lock.cmpxchgStrong(0, 1, .acquire, .monotonic) != null) {
            std.atomic.spinLoopHint();
        }
    }

    fn release(p: *PendingFlow) void {
        p.lock.store(0, .release);
    }

    /// Store flow info with absolute expiry (Set). Takes ownership of info.
    pub fn set(p: *PendingFlow, clock: *const Clock, info: AuthFlowInfo) void {
        p.acquire();
        defer p.release();
        p.has_flow = true;
        p.info = info;
        p.expires_at_s = clock.now_s() + info.expires_in;
        p.wait_active = false;
        p.wait_canceled.store(false, .release);
    }

    /// Copy out stored info for the waiter (Get). Returns false when empty.
    /// Caller owns the returned copy.
    pub fn get(p: *PendingFlow, alloc: std.mem.Allocator) Error!?AuthFlowInfo {
        p.acquire();
        defer p.release();
        if (!p.has_flow) return null;
        return AuthFlowInfo{
            .device_code = alloc.dupe(u8, p.info.device_code) catch return Error.OutOfMemory,
            .user_code = alloc.dupe(u8, p.info.user_code) catch return Error.OutOfMemory,
            .verification_uri = alloc.dupe(u8, p.info.verification_uri) catch return Error.OutOfMemory,
            .verification_uri_complete = alloc.dupe(u8, p.info.verification_uri_complete) catch return Error.OutOfMemory,
            .expires_in = p.info.expires_in,
            .interval = p.info.interval,
        };
    }

    pub fn expiresAt(p: *PendingFlow) i64 {
        p.acquire();
        defer p.release();
        return p.expires_at_s;
    }

    pub fn isPending(p: *PendingFlow) bool {
        p.acquire();
        defer p.release();
        return p.has_flow;
    }

    /// Mark a wait in progress (SetWaitCancel).
    pub fn setWaitActive(p: *PendingFlow) void {
        p.acquire();
        defer p.release();
        p.wait_active = true;
        p.wait_canceled.store(false, .release);
    }

    /// Preempt the in-progress wait (CancelWait). Safe with no waiter.
    pub fn cancelWait(p: *PendingFlow) void {
        p.wait_canceled.store(true, .release);
    }

    pub fn waitCanceled(p: *PendingFlow) bool {
        return p.wait_canceled.load(.acquire);
    }

    /// Drop stored flow (Clear). Does not invoke cancellation; call
    /// cancelWait first when the waiter must stop.
    pub fn clear(p: *PendingFlow, alloc: std.mem.Allocator) void {
        p.acquire();
        defer p.release();
        if (p.has_flow) p.info.deinit(alloc);
        p.has_flow = false;
        p.info = .{};
        p.expires_at_s = 0;
        p.wait_active = false;
        p.wait_canceled.store(false, .release);
    }
};
