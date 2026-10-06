// Port of netbird shared/management/client/grpc.go (v0.79.0), BSD-3-Clause.
// ManagementService client: GetServerKey, Login/Register (NaCl-boxed bodies),
// Sync stream. Covers only what step 3 needs: no retry/backoff, no conn-state
// listeners, no Job/Expose/AuthSession RPCs (engine layers add those).
// Bodies are boxed with the server key from GetServerKey exactly like
// encryption.EncryptMessage/DecryptMessage (marshal then box.Seal/Open).

const std = @import("std");
const h2 = @import("../net/h2/conn.zig");
const grpc = @import("../net/grpc/client.zig");
const messages = @import("messages.zig");
const wgbox = @import("wgbox.zig");

pub const Error = grpc.Error || messages.Error || wgbox.Error || error{MgmtStatus};

/// Upstream ConnectTimeout (grpc.go) for Login; GetServerKey uses 5s.
pub const login_timeout_ns: i64 = 10 * std.time.ns_per_s;
pub const server_key_timeout_ns: i64 = 5 * std.time.ns_per_s;

pub const Client = struct {
    conn: *h2.Conn,
    alloc: std.mem.Allocator,
    authority: []const u8,
    io: std.Io,
    key: wgbox.Key,
    server_key: ?wgbox.Key = null,
    last_status_code: u32 = 0,
    last_status_msg: std.ArrayList(u8) = .empty,

    pub fn deinit(c: *Client) void {
        c.last_status_msg.deinit(c.alloc);
    }

    fn setStatus(c: *Client, code: u32, msg: []const u8) Error!void {
        c.last_status_code = code;
        c.last_status_msg.clearRetainingCapacity();
        try c.last_status_msg.appendSlice(c.alloc, msg);
    }

    /// GetServerKey: unary Empty -> server WireGuard public key (cached).
    pub fn getServerKey(c: *Client) Error!wgbox.Key {
        try c.setStatus(0, "");
        const req = try messages.Empty.encode(c.alloc);
        defer c.alloc.free(req);
        var res = try grpc.unary(
            c.conn,
            c.alloc,
            "/management.ManagementService/GetServerKey",
            c.authority,
            server_key_timeout_ns,
            req,
            c.io,
        );
        defer res.deinit(c.alloc);
        if (res.status != 0) {
            try c.setStatus(res.status, res.message);
            return Error.MgmtStatus;
        }
        const body = res.body orelse return Error.GrpcProtocol;
        var sk = try messages.ServerKeyResponse.decode(c.alloc, body);
        defer sk.deinit(c.alloc);
        const key = try wgbox.parseKey(sk.key);
        c.server_key = key;
        return key;
    }

    fn encryptEnvelope(
        c: *Client,
        server_key: wgbox.Key,
        plain: []const u8,
    ) Error![]u8 {
        const my_pub = wgbox.publicKey(c.key);
        const my_pub_str = try wgbox.allocString(c.alloc, my_pub);
        defer c.alloc.free(my_pub_str);
        const body = try wgbox.encrypt(c.alloc, plain, server_key, c.key, c.io);
        defer c.alloc.free(body);
        const env = messages.EncryptedMessage{ .wg_pub_key = my_pub_str, .body = body };
        return try env.encode(c.alloc);
    }

    fn decryptBody(c: *Client, server_key: wgbox.Key, env_bytes: []const u8) Error![]u8 {
        var env = try messages.EncryptedMessage.decode(c.alloc, env_bytes);
        defer env.deinit(c.alloc);
        return try wgbox.decrypt(c.alloc, env.body, server_key, c.key);
    }

    fn loginRequest(
        c: *Client,
        req: *const messages.LoginRequest,
    ) Error!messages.LoginResponse {
        try c.setStatus(0, "");
        const server_key = try c.getServerKey();
        const plain = try req.encode(c.alloc);
        defer c.alloc.free(plain);
        const body = try c.encryptEnvelope(server_key, plain);
        defer c.alloc.free(body);
        var res = try grpc.unary(
            c.conn,
            c.alloc,
            "/management.ManagementService/Login",
            c.authority,
            login_timeout_ns,
            body,
            c.io,
        );
        defer res.deinit(c.alloc);
        if (res.status != 0) {
            try c.setStatus(res.status, res.message);
            return Error.MgmtStatus;
        }
        const resp_body = res.body orelse return Error.GrpcProtocol;
        const dec = try c.decryptBody(server_key, resp_body);
        defer c.alloc.free(dec);
        return try messages.LoginResponse.decode(c.alloc, dec);
    }

    /// Register: Login with a setup key (and optional JWT).
    pub fn register(
        c: *Client,
        setup_key: []const u8,
        jwt_token: []const u8,
        meta: messages.PeerSystemMeta,
        ssh_pub_key: []const u8,
        dns_labels: []const []const u8,
    ) Error!messages.LoginResponse {
        const my_pub = wgbox.publicKey(c.key);
        const my_pub_str = try wgbox.allocString(c.alloc, my_pub);
        defer c.alloc.free(my_pub_str);
        // Upstream sends the base64 STRING as PeerKeys.wgPubKey bytes.
        const keys = messages.PeerKeys{ .ssh_pub_key = ssh_pub_key, .wg_pub_key = my_pub_str };
        const req = messages.LoginRequest{
            .setup_key = setup_key,
            .meta = meta,
            .jwt_token = jwt_token,
            .peer_keys = keys,
            .dns_labels = dns_labels,
        };
        return try c.loginRequest(&req);
    }

    /// Login without a setup key.
    pub fn login(
        c: *Client,
        meta: messages.PeerSystemMeta,
        ssh_pub_key: []const u8,
        dns_labels: []const []const u8,
    ) Error!messages.LoginResponse {
        const my_pub = wgbox.publicKey(c.key);
        const my_pub_str = try wgbox.allocString(c.alloc, my_pub);
        defer c.alloc.free(my_pub_str);
        const keys = messages.PeerKeys{ .ssh_pub_key = ssh_pub_key, .wg_pub_key = my_pub_str };
        const req = messages.LoginRequest{
            .meta = meta,
            .peer_keys = keys,
            .dns_labels = dns_labels,
        };
        return try c.loginRequest(&req);
    }

    /// Sync: open the update stream (SyncRequest is boxed like Login).
    pub fn sync(c: *Client, meta: messages.PeerSystemMeta) Error!SyncStream {
        try c.setStatus(0, "");
        const server_key = if (c.server_key) |k| k else try c.getServerKey();
        const req = messages.SyncRequest{ .meta = meta };
        const plain = try req.encode(c.alloc);
        defer c.alloc.free(plain);
        const body = try c.encryptEnvelope(server_key, plain);
        defer c.alloc.free(body);
        var call = try grpc.startCall(
            c.conn,
            c.alloc,
            "/management.ManagementService/Sync",
            c.authority,
            null,
            c.io,
        );
        errdefer call.deinit();
        try grpc.sendMessage(&call, body, true);
        return .{
            .call = call,
            .alloc = c.alloc,
            .server_key = server_key,
            .my_priv = c.key,
        };
    }
};

/// One Sync stream; next() decrypts + decodes each update.
/// Terminal status: null with stream.statusCode() == 0 on clean EOF,
/// error.MgmtStatus (code/message on the stream) otherwise.
pub const SyncStream = struct {
    call: grpc.Call,
    alloc: std.mem.Allocator,
    server_key: wgbox.Key,
    my_priv: wgbox.Key,
    last_status_code: u32 = 0,
    last_status_msg: std.ArrayList(u8) = .empty,

    pub fn deinit(s: *SyncStream) void {
        s.call.deinit();
        s.last_status_msg.deinit(s.alloc);
    }

    pub fn next(s: *SyncStream) Error!?messages.SyncResponse {
        const msg = try grpc.recvMessage(&s.call) orelse {
            const code = s.call.status() orelse 0;
            s.last_status_code = code;
            if (code != 0) {
                s.last_status_msg.clearRetainingCapacity();
                try s.last_status_msg.appendSlice(s.alloc, s.call.statusMessage());
                return Error.MgmtStatus;
            }
            return null;
        };
        // msg is borrowed from the call's rx buffer (freed by call.deinit);
        // decode/decrypt dupe everything they keep.
        var env = try messages.EncryptedMessage.decode(s.alloc, msg);
        defer env.deinit(s.alloc);
        const dec = try wgbox.decrypt(s.alloc, env.body, s.server_key, s.my_priv);
        defer s.alloc.free(dec);
        return try messages.SyncResponse.decode(s.alloc, dec);
    }
};
