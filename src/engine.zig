// M8 foreground engine: transport-independent lifecycle state machine.
// Services inject through the Service boundary; real Management/Signal/TUN
// wiring is a later card. No network I/O here.

const std = @import("std");

pub const State = enum {
    idle,
    needs_login,
    starting,
    connected,
    stopped,
    @"error",

    pub fn name(s: State) []const u8 {
        return switch (s) {
            .idle => "idle",
            .needs_login => "needs_login",
            .starting => "starting",
            .connected => "connected",
            .stopped => "stopped",
            .@"error" => "error",
        };
    }
};

/// Point-in-time view. `message` borrows engine storage: valid until the
/// next Engine call or deinit.
pub const Status = struct {
    state: State,
    message: []const u8,

    pub fn format(st: Status, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.print("state: {s}\nmessage: {s}\n", .{ st.state.name(), st.message });
    }
};

/// Injectable service boundary (repo Transport-style vtable). The setup key
/// is passed transiently to loginFn and never stored by the Engine.
pub const Service = struct {
    ctx: *anyopaque,
    loginFn: *const fn (*anyopaque, []const u8) AuthError!void,
    startFn: *const fn (*anyopaque) StartError!void,
    stopFn: *const fn (*anyopaque) void,

    pub const AuthError = error{ AuthFailed, Network, OutOfMemory };
    pub const StartError = error{ StartFailed, OutOfMemory };
};

pub const LoginError = error{ MissingSetupKey, AuthFailed, Network, StartFailed, OutOfMemory };
pub const UpError = error{ NotAuthenticated, StartFailed, OutOfMemory };

pub const Engine = struct {
    alloc: std.mem.Allocator,
    service: Service,
    state: State = .idle,
    authenticated: bool = false,
    message: []u8 = undefined,

    pub fn init(alloc: std.mem.Allocator, service: Service) std.mem.Allocator.Error!Engine {
        return .{
            .alloc = alloc,
            .service = service,
            .message = try alloc.dupe(u8, State.idle.name()),
        };
    }

    pub fn deinit(e: *Engine) void {
        e.alloc.free(e.message);
        e.* = undefined;
    }

    pub fn status(e: *const Engine) Status {
        return .{ .state = e.state, .message = e.message };
    }

    /// Replace state and message; on OutOfMemory the previous state is kept.
    fn transition(e: *Engine, s: State, msg: []const u8) std.mem.Allocator.Error!void {
        const n = try e.alloc.dupe(u8, msg);
        e.alloc.free(e.message);
        e.message = n;
        e.state = s;
    }

    fn startChain(e: *Engine) Service.StartError!void {
        try e.transition(.starting, State.starting.name());
        e.service.startFn(e.service.ctx) catch |err| {
            try e.transition(.@"error", "start failed");
            return err;
        };
        try e.transition(.connected, State.connected.name());
    }

    /// Authenticate with a setup key, then start. The key is passed to the
    /// service transiently and never stored. Empty key -> needs_login; any
    /// service failure -> error with a stable key-free message. A failed
    /// attempt leaves `authenticated` unchanged; call again to retry.
    pub fn login(e: *Engine, setup_key: []const u8) LoginError!void {
        if (setup_key.len == 0) {
            try e.transition(.needs_login, "setup key required");
            return error.MissingSetupKey;
        }
        e.service.loginFn(e.service.ctx, setup_key) catch |err| {
            try e.transition(.@"error", "login failed");
            return err;
        };
        e.authenticated = true;
        try e.startChain();
    }

    /// Start when already authenticated (e.g. reconnect after down).
    /// Unauthenticated -> needs_login. When already .connected the live
    /// service is left alone: up returns without a second start (idempotent).
    pub fn up(e: *Engine) UpError!void {
        if (!e.authenticated) {
            try e.transition(.needs_login, "not authenticated");
            return error.NotAuthenticated;
        }
        if (e.state == .connected) return;
        try e.startChain();
    }

    /// Ensure stopped. Idempotent from any state; the service stop runs
    /// only when leaving a live (connected/starting) state, so repeated
    /// downs never re-invoke it. State is stopped on return even when the
    /// message copy fails with OutOfMemory.
    pub fn down(e: *Engine) std.mem.Allocator.Error!void {
        const live = e.state == .connected or e.state == .starting;
        if (live) e.service.stopFn(e.service.ctx);
        e.state = .stopped;
        const n = try e.alloc.dupe(u8, State.stopped.name());
        e.alloc.free(e.message);
        e.message = n;
    }
};
