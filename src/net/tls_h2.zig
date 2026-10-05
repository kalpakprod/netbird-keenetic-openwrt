// Port of netbird client/internal (v0.80.0), BSD-3-Clause
// TLS-to-H2/gRPC transport adapter.
// Owns a TLS client connection over a TCP stream and exposes it as the
// byte transport for src/net/h2 Conn and src/net/grpc calls. Enforces the
// required h2 ALPN, closes exactly once including partial failure,
// preserves CA/hostname verification, and surfaces transport failures
// (never maps a TLS error into a fake successful EOF).

const std = @import("std");
const tls_client = @import("tls/client.zig");
const h2 = @import("h2/conn.zig");

/// Trust root for the TLS handshake. test_pem pins one CA from memory
/// (the per-run helper CA, real verification, no /etc/ssl on the router).
/// self_signed accepts a valid self-signed leaf for the expected host.
/// bundle reuses a caller-owned system bundle with its own lock.
pub const Ca = union(enum) {
    test_pem: []const u8,
    self_signed,
    bundle: struct {
        gpa: std.mem.Allocator,
        io: std.Io,
        lock: *std.Io.RwLock,
        bundle: *std.crypto.Certificate.Bundle,
    },
};

pub const Options = struct {
    host: []const u8,
    ca: Ca,
    io: std.Io,
    alloc: std.mem.Allocator,
};

/// Failure of connect() before any byte is usable by gRPC: transport/TLS
/// setup errors (incl. certificate and ALPN rejection) vs H2 handshake
/// errors after TLS is up.
pub const ConnectError = error{
    OutOfMemory,
    AlpnRejected,
    TlsFailed,
    HandshakeFailed,
    ConnectFailed,
};

/// Runtime transport failures after connect(). Closed is a clean close;
/// Reset is a TLS alert/record failure or a torn-down TCP path surfaced
/// through the H2 transport callbacks (never a fake successful EOF).
pub const TransportError = error{
    Closed,
    Reset,
};

fn mapConnectErr(err: anyerror) ConnectError {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.AlpnRejected => error.AlpnRejected,
        error.ConnectionRefused,
        error.NetworkUnreachable,
        error.HostUnreachable,
        error.Timeout,
        error.AddressUnavailable,
        error.AddressFamilyUnsupported,
        error.SystemResources,
        error.ConnectionPending,
        error.ConnectionResetByPeer,
        error.OptionUnsupported,
        error.ProcessFdQuotaExceeded,
        error.SystemFdQuotaExceeded,
        error.ProtocolUnsupportedBySystem,
        error.ProtocolUnsupportedByAddressFamily,
        error.SocketModeUnsupported,
        error.AccessDenied,
        error.WouldBlock,
        error.NetworkDown,
        => error.ConnectFailed,
        else => error.TlsFailed,
    };
}

/// Owned TLS-to-H2 client connection. Exactly one close(): after connect()
/// succeeds the caller must call close() once; after connect() fails
/// nothing is owned. close() is idempotent: a second call is a no-op so
/// deferred cleanup after a partial call path cannot double-close.
pub const Conn = struct {
    stream: std.Io.net.Stream,
    io: std.Io,
    alloc: std.mem.Allocator,
    rx_sock_buf: [tls_client.min_buffer_len]u8,
    tx_sock_buf: [tls_client.min_buffer_len]u8,
    sock_rdr: std.Io.net.Stream.Reader,
    sock_wtr: std.Io.net.Stream.Writer,
    tls_read_buf: [tls_client.min_buffer_len]u8,
    tls_write_buf: [tls_client.min_buffer_len]u8,
    entropy: [tls_client.Options.entropy_len]u8,
    tls: tls_client,
    ca_bundle: std.crypto.Certificate.Bundle,
    ca_lock: std.Io.RwLock,
    ca_from_pem: bool,
    h2_conn: h2.Conn,
    tctx: TlsCtx,
    closed: bool,
    tls_initialized: bool,

    const TlsCtx = struct {
        conn: *Conn,

        fn readFn(ctx: *anyopaque, buf: []u8) h2.Transport.ReadError!usize {
            const t: *TlsCtx = @ptrCast(@alignCast(ctx));
            const c = t.conn;
            if (c.closed) return error.Closed;
            c.tls.reader.readSliceAll(buf) catch {
                // Any TLS failure (alert, bad record, truncation) or a
                // torn-down TCP path is a Reset: the H2/grpc layers must
                // see a transport failure, never a clean EOF with data
                // silently missing. A genuine close_notify shutdown
                // surfaces as EndOfStream here and maps to Closed.
                if (c.tls.eof()) return error.Closed;
                return error.Reset;
            };
            return buf.len;
        }

        fn writeFn(ctx: *anyopaque, buf: []const u8) h2.Transport.WriteError!void {
            const t: *TlsCtx = @ptrCast(@alignCast(ctx));
            const c = t.conn;
            if (c.closed) return error.Closed;
            c.tls.writer.writeAll(buf) catch return error.Reset;
            c.tls.writer.flush() catch return error.Reset;
            c.sock_wtr.interface.flush() catch return error.Reset;
        }
    };

    /// Connect to addr over TCP, run the TLS handshake with h2 ALPN and
    /// CA/hostname verification, enforce ALPN h2, then run the H2
    /// handshake. Any failure before return tears down everything opened
    /// so far and owns nothing.
    pub fn connect(
        alloc: std.mem.Allocator,
        addr: *std.Io.net.IpAddress,
        opt: Options,
    ) ConnectError!*Conn {
        const self: *Conn = alloc.create(Conn) catch return error.OutOfMemory;
        errdefer self.deinit(alloc);
        self.* = .{
            .stream = undefined,
            .io = opt.io,
            .alloc = alloc,
            .rx_sock_buf = undefined,
            .tx_sock_buf = undefined,
            .sock_rdr = undefined,
            .sock_wtr = undefined,
            .tls_read_buf = undefined,
            .tls_write_buf = undefined,
            .entropy = undefined,
            .tls = undefined,
            .ca_bundle = .empty,
            .ca_lock = .init,
            .ca_from_pem = false,
            .h2_conn = undefined,
            .tctx = undefined,
            .closed = true,
            .tls_initialized = false,
        };
        self.stream = addr.connect(opt.io, .{ .mode = .stream }) catch {
            return error.ConnectFailed;
        };
        self.closed = false;

        self.sock_rdr = std.Io.net.Stream.Reader.init(self.stream, opt.io, &self.rx_sock_buf);
        self.sock_wtr = self.stream.writer(opt.io, &self.tx_sock_buf);

        opt.io.randomSecure(&self.entropy) catch {
            opt.io.random(&self.entropy);
        };

        self.tlsHandshake(opt) catch |err| {
            if (err == error.AlpnRejected) return error.AlpnRejected;
            return mapConnectErr(err);
        };

        self.tctx = .{ .conn = self };
        self.h2_conn = h2.Conn.init(.{
            .ctx = @ptrCast(&self.tctx),
            .readFn = TlsCtx.readFn,
            .writeFn = TlsCtx.writeFn,
        });
        self.h2_conn.handshake() catch {
            return error.HandshakeFailed;
        };
        return self;
    }

    fn tlsHandshake(self: *Conn, opt: Options) !void {
        switch (opt.ca) {
            .self_signed => {
                self.tls = try tls_client.init(
                    &self.sock_rdr.interface,
                    &self.sock_wtr.interface,
                    .{
                        .host = .{ .explicit = opt.host },
                        .ca = .self_signed,
                        .write_buffer = &self.tls_write_buf,
                        .read_buffer = &self.tls_read_buf,
                        .entropy = &self.entropy,
                        .realtime_now = std.Io.Clock.real.now(opt.io),
                    },
                    &.{"h2"},
                );
            },
            .test_pem => |pem_bytes| {
                self.ca_from_pem = true;
                loadPemForTest(&self.ca_bundle, self.alloc, opt.io, pem_bytes) catch |err| {
                    if (err == error.OutOfMemory) return err;
                    return error.TlsCertificateNotVerified;
                };
                self.tls = try tls_client.init(
                    &self.sock_rdr.interface,
                    &self.sock_wtr.interface,
                    .{
                        .host = .{ .explicit = opt.host },
                        .ca = .{ .bundle = .{
                            .gpa = self.alloc,
                            .io = opt.io,
                            .lock = &self.ca_lock,
                            .bundle = &self.ca_bundle,
                        } },
                        .write_buffer = &self.tls_write_buf,
                        .read_buffer = &self.tls_read_buf,
                        .entropy = &self.entropy,
                        .realtime_now = std.Io.Clock.real.now(opt.io),
                    },
                    &.{"h2"},
                );
            },
            .bundle => |b| {
                self.tls = try tls_client.init(
                    &self.sock_rdr.interface,
                    &self.sock_wtr.interface,
                    .{
                        .host = .{ .explicit = opt.host },
                        .ca = .{ .bundle = .{
                            .gpa = b.gpa,
                            .io = b.io,
                            .lock = b.lock,
                            .bundle = b.bundle,
                        } },
                        .write_buffer = &self.tls_write_buf,
                        .read_buffer = &self.tls_read_buf,
                        .entropy = &self.entropy,
                        .realtime_now = std.Io.Clock.real.now(opt.io),
                    },
                    &.{"h2"},
                );
            },
        }
        self.tls_initialized = true;
        // The handshake flights buffer through the socket writer: push
        // them now (same contract as tls_test.zig: init flushes the TLS
        // output, the caller flushes the transport).
        try self.sock_wtr.interface.flush();
        const got = self.tls.negotiatedAlpn();
        if (got == null or !std.mem.eql(u8, got.?, "h2")) return error.AlpnRejected;
    }

    /// Idempotent teardown: best-effort TLS close_notify, then TCP close.
    /// Safe to call twice (deferred cleanup after an explicit close).
    pub fn close(self: *Conn) void {
        if (self.closed) return;
        self.closed = true;
        if (self.tls_initialized) {
            self.tls.end() catch {};
            self.sock_wtr.interface.flush() catch {};
        }
        self.stream.close(self.io);
    }

    pub fn deinit(self: *Conn, alloc: std.mem.Allocator) void {
        self.close();
        if (self.ca_from_pem) self.ca_bundle.deinit(self.alloc);
        alloc.destroy(self);
    }

    /// The H2 connection multiplexed over this TLS session. Valid until
    /// close().
    pub fn h2Conn(self: *Conn) *h2.Conn {
        return &self.h2_conn;
    }

    /// Cancel one open stream with RST_STREAM CANCEL (client-initiated
    /// abort, e.g. dropping a server stream early).
    pub fn cancelStream(self: *Conn, stream_id: u32) TransportError!void {
        if (self.closed) return error.Closed;
        self.h2_conn.resetStream(stream_id, .cancel) catch |err| switch (err) {
            error.Closed => return error.Closed,
            else => return error.Reset,
        };
    }
};

const base64 = std.base64.standard.decoderWithIgnore(" \t\r\n");

/// Parse PEM/DER CA bytes into a bundle without touching the filesystem
/// (pure memory, so no statx and no File API). Mirrors
/// Bundle.addCertsFromFile's PEM loop over an in-memory slice. Only the
/// helper-CA path uses this; production uses .bundle (system CA).
fn loadPemForTest(
    bundle: *std.crypto.Certificate.Bundle,
    alloc: std.mem.Allocator,
    io: std.Io,
    pem_bytes: []const u8,
) !void {
    const now_sec = std.Io.Timestamp.now(io, .real).toSeconds();
    if (std.mem.indexOf(u8, pem_bytes, "-----BEGIN") == null) {
        // Raw DER fallback (single certificate).
        const start: u32 = @intCast(bundle.bytes.items.len);
        try bundle.bytes.appendSlice(alloc, pem_bytes);
        errdefer bundle.bytes.items.len = start;
        try bundle.parseCert(alloc, start, now_sec);
        return;
    }
    const begin_marker = "-----BEGIN CERTIFICATE-----";
    const end_marker = "-----END CERTIFICATE-----";
    var start_index: usize = 0;
    var found = false;
    while (std.mem.findPos(u8, pem_bytes, start_index, begin_marker)) |begin_start| {
        const cert_start = begin_start + begin_marker.len;
        const cert_end = std.mem.findPos(u8, pem_bytes, cert_start, end_marker) orelse
            return error.MissingEndCertificateMarker;
        start_index = cert_end + end_marker.len;
        const encoded = std.mem.trim(u8, pem_bytes[cert_start..cert_end], " \t\r\n");
        const upper = base64.calcSizeUpperBound(encoded.len);
        const decoded_start: u32 = @intCast(bundle.bytes.items.len);
        try bundle.bytes.ensureUnusedCapacity(alloc, upper);
        const dest = bundle.bytes.allocatedSlice()[decoded_start..][0..upper];
        const n = try base64.decode(dest, encoded);
        bundle.bytes.items.len = decoded_start + n;
        errdefer bundle.bytes.items.len = decoded_start;
        try bundle.parseCert(alloc, decoded_start, now_sec);
        found = true;
    }
    if (!found) return error.MissingEndCertificateMarker;
}
