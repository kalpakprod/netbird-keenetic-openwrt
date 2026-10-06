// Port of netbird client/internal/connect.go and engine.go (v0.80.0), BSD-3-Clause
// Real engine.Service adapter: management login + signal/management
// connection lifecycle over the Dial seam. Replaces the production
// NetworkUnavailable path (app: "no service adapter") once wired into
// main. Mirrors upstream connect.go loginToManagement (line 734) and
// connectToSignal (line 715) plus engine.go Start ordering: login stores
// state only after an actual LoginResponse, the signal client dials the
// endpoint from that response (connect.go:389), the WG runtime binds
// next, and the management Sync stream opens last (engine.go:544+
// creates the interface before receiveManagementEvents). Start succeeds
// only with all of them live; every failure path releases what was
// acquired, exactly once, LIFO.
//
// Binding points for cards that own the missing pieces:
// - Transport: `Dial` is the seam. This file ships the plaintext dial
//   (numeric ip:port, no DNS, no TLS). The TLS dial (ALPN h2, host/CA
//   verification, TLS-sized buffers) is the tls adapter card's binding;
//   until it lands, `plain_dial` is the only transport and production
//   endpoints (DNS names, TLS) fail fast with error.DialFailed.
// - Data plane: `WgBinding` is the WG runtime seam. Unbound means the
//   required data-plane resources do not exist, so start fails — never a
//   success mock. Real types land with the WG runtime card.
// - Sync stream pumping (network maps -> peers) is the connect-state
//   card; this adapter holds the stream open as a resource.

const std = @import("std");
const engine = @import("engine.zig");
const profile = @import("state/profile.zig");
const h2 = @import("net/h2/conn.zig");
const mgmt = @import("mgmt/client.zig");
const mgmt_messages = @import("mgmt/messages.zig");
const wgbox = @import("mgmt/wgbox.zig");
const signal = @import("signal/client.zig");

/// Transport seam: open one byte transport for an endpoint and run any
/// transport-level handshake (TLS: full handshake with ALPN h2). Returns
/// an h2 Transport plus its release fn; buffers are allocated with
/// `alloc` and freed by closeFn. The adapter adds the h2 handshake.
pub const Dial = struct {
    ctx: *anyopaque,
    dialFn: *const fn (ctx: *anyopaque, endpoint: []const u8, alloc: std.mem.Allocator, io: std.Io) DialError!DialResult,
};

pub const DialResult = struct {
    /// Passed to closeFn; the transport's own ctx already points here.
    ctx: *anyopaque,
    transport: h2.Transport,
    closeFn: *const fn (ctx: *anyopaque) void,
};

pub const DialError = error{ DialFailed, OutOfMemory };

/// Plaintext transport: TCP to a numeric ip:port endpoint. Local test
/// slice transport; production endpoints need DNS + TLS (separate dial).
pub const plain_dial = Dial{ .ctx = undefined, .dialFn = plainDialFn };

// Proven buffer size for the plaintext h2 tests (mgmt_test.zig Live).
// A TLS dial sizes its own buffers >= tls min_buffer_len.
const plain_buffer_len = 16384;

const TcpState = struct {
    alloc: std.mem.Allocator,
    io: std.Io,
    stream: std.Io.net.Stream,
    rx_buf: []u8,
    tx_buf: []u8,
    rdr: std.Io.net.Stream.Reader,
    wtr: std.Io.net.Stream.Writer,
    tctx: TransportCtx,

    const TransportCtx = struct {
        reader: *std.Io.Reader,
        writer: *std.Io.Writer,
    };

    fn readFn(ctx: *anyopaque, buf: []u8) h2.Transport.ReadError!usize {
        const st: *TcpState = @ptrCast(@alignCast(ctx));
        st.tctx.reader.readSliceAll(buf) catch return error.Closed;
        return buf.len;
    }

    fn writeFn(ctx: *anyopaque, buf: []const u8) h2.Transport.WriteError!void {
        const st: *TcpState = @ptrCast(@alignCast(ctx));
        st.tctx.writer.writeAll(buf) catch return error.Closed;
        st.tctx.writer.flush() catch return error.Closed;
    }

    fn closeFn(ctx: *anyopaque) void {
        const st: *TcpState = @ptrCast(@alignCast(ctx));
        st.stream.close(st.io);
        st.alloc.free(st.rx_buf);
        st.alloc.free(st.tx_buf);
        st.alloc.destroy(st);
    }
};

fn plainDialFn(_: *anyopaque, endpoint: []const u8, alloc: std.mem.Allocator, io: std.Io) DialError!DialResult {
    // Numeric "ip:port" only: hostname resolution is part of the later
    // production dial. A DNS name here (e.g. a real signal URI from the
    // login response) fails fast instead of dialing anything unexpected.
    const colon = std.mem.lastIndexOfScalar(u8, endpoint, ':') orelse return error.DialFailed;
    const port = std.fmt.parseInt(u16, endpoint[colon + 1 ..], 10) catch return error.DialFailed;
    const addr = std.Io.net.IpAddress.parse(endpoint[0..colon], port) catch return error.DialFailed;

    const st = try alloc.create(TcpState);
    errdefer alloc.destroy(st);
    st.stream = addr.connect(io, .{ .mode = .stream }) catch return error.DialFailed;
    errdefer st.stream.close(io);
    st.alloc = alloc;
    st.io = io;
    st.rx_buf = try alloc.alloc(u8, plain_buffer_len);
    errdefer alloc.free(st.rx_buf);
    st.tx_buf = try alloc.alloc(u8, plain_buffer_len);
    errdefer alloc.free(st.tx_buf);
    st.rdr = std.Io.net.Stream.Reader.init(st.stream, io, st.rx_buf);
    st.wtr = st.stream.writer(io, st.tx_buf);
    st.tctx = .{ .reader = &st.rdr.interface, .writer = &st.wtr.interface };
    return .{
        .ctx = st,
        .transport = .{ .ctx = st, .readFn = TcpState.readFn, .writeFn = TcpState.writeFn },
        .closeFn = TcpState.closeFn,
    };
}

/// WG runtime binding point. The adapter calls startFn once per start,
/// after the signal stream is registered, and stopFn once per release
/// (LIFO with the connections). Real runtime types land with the WG
/// runtime card; until then tests bind a stub and the CLI path stays
/// failed-by-design (no data plane, no success).
pub const WgBinding = struct {
    ctx: *anyopaque,
    startFn: *const fn (ctx: *anyopaque, view: View) WgError!void,
    stopFn: *const fn (ctx: *anyopaque) void,

    /// What the adapter hands the runtime today: the peer identity from
    /// the actual management login response.
    pub const View = struct {
        peer_address: []const u8,
    };

    pub const WgError = error{ WgFailed, OutOfMemory };
};

/// Authenticated state, stored only after a real management LoginResponse.
/// Survives stop (down() keeps authentication so a later up() reconnects
/// without a new login, like the Engine contract); freed in deinit.
pub const AuthState = struct {
    /// NetBird address of the registered peer; empty when the response
    /// omitted peer_config.
    peer_address: []u8,
    /// Signal endpoint from the response (netbird_config.signal.uri).
    signal_uri: []u8,
};

/// One service adapter instance. Address-stable while started (live
/// h2 Clients borrow the Conn fields); keep it inside heap-allocated
/// ServiceContext storage. Drive it through engine.Engine: login -> up,
/// down, up, ...; deinit at shutdown.
pub const Adapter = struct {
    alloc: std.mem.Allocator,
    io: std.Io,
    dial: Dial,
    /// Configuration/identity inputs, borrowed: the creator keeps them
    /// valid for the adapter's lifetime (system info is gathered once).
    config: Config,
    /// Effective management endpoint of the current Backend call
    /// (borrowed until the returned service is stopped and no longer used).
    mgmt_url: []const u8 = "",
    auth: ?AuthState = null,

    // Live resources; null once released. Created signal -> wg -> mgmt.
    sig_transport: ?DialResult = null,
    sig_conn: ?h2.Conn = null,
    sig_client: ?signal.Client = null,
    sig_stream: ?signal.Stream = null,
    wg: ?WgBinding = null,
    wg_started: bool = false,
    mgmt_transport: ?DialResult = null,
    mgmt_conn: ?h2.Conn = null,
    mgmt_client: ?mgmt.Client = null,
    sync: ?mgmt.SyncStream = null,

    pub const Config = struct {
        wg_priv: wgbox.Key,
        meta: mgmt_messages.PeerSystemMeta = .{},
        ssh_pub_key: []const u8 = "",
        dns_labels: []const []const u8 = &.{},
        /// Overrides the signal endpoint from the login response (local
        /// tests point this at the fake signal server).
        signal_uri: ?[]const u8 = null,
    };

    /// Release every live resource, LIFO, exactly once. Safe from any
    /// state: after a failed start (the Engine's rollback stop), after a
    /// clean stop, or from a fresh adapter.
    pub fn release(a: *Adapter) void {
        if (a.sync) |*s| {
            s.deinit();
            a.sync = null;
        }
        if (a.mgmt_client) |*c| {
            c.deinit();
            a.mgmt_client = null;
        }
        a.mgmt_conn = null;
        if (a.mgmt_transport) |t| {
            t.closeFn(t.ctx);
            a.mgmt_transport = null;
        }
        if (a.wg_started) {
            const wg = a.wg.?;
            wg.stopFn(wg.ctx);
            a.wg_started = false;
        }
        if (a.sig_stream) |*s| {
            s.deinit();
            a.sig_stream = null;
        }
        if (a.sig_client) |*c| {
            c.deinit();
            a.sig_client = null;
        }
        a.sig_conn = null;
        if (a.sig_transport) |t| {
            t.closeFn(t.ctx);
            a.sig_transport = null;
        }
    }

    pub fn deinit(a: *Adapter) void {
        a.release();
        if (a.auth) |old| {
            a.alloc.free(old.signal_uri);
            a.alloc.free(old.peer_address);
            a.auth = null;
        }
    }

    fn connectEndpoint(a: *Adapter, endpoint: []const u8, slot: *?h2.Conn) DialError!DialResult {
        var res = try a.dial.dialFn(a.dial.ctx, endpoint, a.alloc, a.io);
        errdefer res.closeFn(res.ctx);
        slot.* = h2.Conn.init(res.transport);
        errdefer slot.* = null;
        slot.*.?.handshake() catch return error.DialFailed;
        return res;
    }

    /// Stage 1: signal connection + registered ConnectStream.
    fn startSignal(a: *Adapter, uri: []const u8) engine.Service.StartError!void {
        const res = a.connectEndpoint(uri, &a.sig_conn) catch |err| return startFromDial(err);
        a.sig_transport = res;
        a.sig_client = .{
            .conn = &a.sig_conn.?,
            .alloc = a.alloc,
            .authority = uri,
            .io = a.io,
            .key = a.config.wg_priv,
        };
        a.sig_stream = a.sig_client.?.connectStream() catch |err| {
            return if (err == error.OutOfMemory) error.OutOfMemory else error.StartFailed;
        };
    }

    /// Stage 3: management connection + Sync stream, held open (pumping
    /// network maps is the connect-state card's work).
    fn startMgmt(a: *Adapter) engine.Service.StartError!void {
        const res = a.connectEndpoint(a.mgmt_url, &a.mgmt_conn) catch |err| return startFromDial(err);
        a.mgmt_transport = res;
        a.mgmt_client = .{
            .conn = &a.mgmt_conn.?,
            .alloc = a.alloc,
            .authority = a.mgmt_url,
            .io = a.io,
            .key = a.config.wg_priv,
        };
        a.sync = a.mgmt_client.?.sync(a.config.meta) catch |err| {
            return if (err == error.OutOfMemory) error.OutOfMemory else error.StartFailed;
        };
    }

    fn setAuth(a: *Adapter, uri: []const u8, addr: []const u8) std.mem.Allocator.Error!void {
        const u = try a.alloc.dupe(u8, uri);
        errdefer a.alloc.free(u);
        const p = try a.alloc.dupe(u8, addr);
        errdefer a.alloc.free(p);
        if (a.auth) |old| {
            a.alloc.free(old.signal_uri);
            a.alloc.free(old.peer_address);
        }
        a.auth = .{ .signal_uri = u, .peer_address = p };
    }
};

fn startFromDial(err: DialError) engine.Service.StartError {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.DialFailed => error.StartFailed,
    };
}

fn adapterLogin(ctx: *anyopaque, setup_key: []const u8) engine.Service.AuthError!void {
    const a: *Adapter = @ptrCast(@alignCast(ctx));
    // One transient connection for the auth exchange; released on every
    // path. The setup key is only borrowed by register, never stored.
    var res = a.dial.dialFn(a.dial.ctx, a.mgmt_url, a.alloc, a.io) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.DialFailed => return error.Network,
    };
    // Transient auth connection: closed on every path, success included.
    defer res.closeFn(res.ctx);
    var conn = h2.Conn.init(res.transport);
    conn.handshake() catch return error.Network;
    var client = mgmt.Client{
        .conn = &conn,
        .alloc = a.alloc,
        .authority = a.mgmt_url,
        .io = a.io,
        .key = a.config.wg_priv,
    };
    defer client.deinit();
    var resp = client.register(
        setup_key,
        "",
        a.config.meta,
        a.config.ssh_pub_key,
        a.config.dns_labels,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        // The server answered and refused (e.g. bad setup key).
        error.MgmtStatus => return error.AuthFailed,
        // Deadline, protocol, decode or decrypt failure.
        else => return error.Network,
    };
    defer resp.deinit(a.alloc);
    // Authenticated state only after an actual management response with a
    // usable configuration; nothing is stored on earlier failures.
    const nb = resp.netbird_config orelse return error.AuthFailed;
    const sig = nb.signal orelse return error.AuthFailed;
    const addr: []const u8 = if (resp.peer_config) |pc| pc.address else "";
    a.setAuth(sig.uri, addr) catch return error.OutOfMemory;
}

fn adapterStart(ctx: *anyopaque) engine.Service.StartError!void {
    const a: *Adapter = @ptrCast(@alignCast(ctx));
    // StartError has no AlreadyStarted case. Release the previous
    // generation before replacement so live fields are never overwritten.
    a.release();
    // Without a login response there is no signal endpoint and no
    // registration: the start failed (the Engine only calls start after
    // an authenticated login or up).
    const auth = a.auth orelse return error.StartFailed;
    // Upstream order: signal client from the login response config
    // (connect.go:389), WG interface up (engine.go), management Sync
    // stream last (engine.go receiveManagementEvents).
    const uri = a.config.signal_uri orelse auth.signal_uri;
    a.startSignal(uri) catch |err| {
        a.release();
        return err;
    };
    const wg = a.wg orelse {
        // Data plane missing (WG runtime not bound): release what the
        // start acquired; success is never claimed.
        a.release();
        return error.StartFailed;
    };
    wg.startFn(wg.ctx, .{ .peer_address = auth.peer_address }) catch |err| {
        a.release();
        return if (err == error.OutOfMemory) error.OutOfMemory else error.StartFailed;
    };
    a.wg_started = true;
    a.startMgmt() catch |err| {
        a.release();
        return err;
    };
}

fn adapterStop(ctx: *anyopaque) void {
    const a: *Adapter = @ptrCast(@alignCast(ctx));
    a.release();
}

/// Long-lived backend state for the real adapter: one per process (the
/// app.Backend ctx). Holds the adapter by value at a stable heap address.
pub const ServiceContext = struct {
    alloc: std.mem.Allocator,
    io: std.Io,
    dial: Dial,
    /// Borrowed configuration/identity inputs (see Adapter.Config).
    config: Adapter.Config,
    adapter: Adapter,

    pub fn create(
        alloc: std.mem.Allocator,
        io: std.Io,
        config: Adapter.Config,
        dial: Dial,
    ) std.mem.Allocator.Error!*ServiceContext {
        const sc = try alloc.create(ServiceContext);
        errdefer alloc.destroy(sc);
        sc.* = .{
            .alloc = alloc,
            .io = io,
            .dial = dial,
            .config = config,
            .adapter = undefined,
        };
        sc.adapter = .{ .alloc = alloc, .io = io, .dial = dial, .config = config };
        return sc;
    }

    pub fn destroy(sc: *ServiceContext) void {
        sc.adapter.deinit();
        sc.alloc.destroy(sc);
    }

    /// app.Backend binding for one non-reentrant invocation. The creator
    /// supplies identity/meta through Adapter.Config, not profile.Config.
    /// cfg is deliberately unused: profile-to-runtime conversion belongs
    /// to the caller. management_url must remain valid until this returned
    /// service is stopped and no longer used. This context cannot outlive
    /// the invocation's URL storage or serve concurrent invocations.
    /// setup_key is deliberately not retained or used here. Only loginFn
    /// consumes the Engine's transient key borrow.
    pub fn serviceFn(
        ctx: *anyopaque,
        cfg: *const profile.Config,
        management_url: []const u8,
        setup_key: ?[]const u8,
    ) engine.Service {
        _ = cfg;
        _ = setup_key;
        const sc: *ServiceContext = @ptrCast(@alignCast(ctx));
        sc.adapter.mgmt_url = management_url;
        return .{
            .ctx = &sc.adapter,
            .loginFn = adapterLogin,
            .startFn = adapterStart,
            .stopFn = adapterStop,
        };
    }
};
