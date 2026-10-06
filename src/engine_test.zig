// M8 engine tests: public lifecycle API with an allocation-free fake
// service. No network, no WireGuard/TUN.

const std = @import("std");
const engine = @import("engine.zig");

const Fake = struct {
    login_calls: usize = 0,
    start_calls: usize = 0,
    stop_calls: usize = 0,
    live: usize = 0,
    key_buf: [128]u8 = undefined,
    key_len: usize = 0,
    login_err: ?engine.Service.AuthError = null,
    start_err: ?engine.Service.StartError = null,

    fn service(f: *Fake) engine.Service {
        return .{ .ctx = f, .loginFn = loginFn, .startFn = startFn, .stopFn = stopFn };
    }

    fn loginFn(ctx: *anyopaque, key: []const u8) engine.Service.AuthError!void {
        const f: *Fake = @ptrCast(@alignCast(ctx));
        f.login_calls += 1;
        f.key_len = @min(key.len, f.key_buf.len);
        @memcpy(f.key_buf[0..f.key_len], key[0..f.key_len]);
        if (f.login_err) |e| return e;
    }

    fn startFn(ctx: *anyopaque) engine.Service.StartError!void {
        const f: *Fake = @ptrCast(@alignCast(ctx));
        f.start_calls += 1;
        f.live += 1;
        if (f.start_err) |e| return e;
    }

    fn stopFn(ctx: *anyopaque) void {
        const f: *Fake = @ptrCast(@alignCast(ctx));
        f.stop_calls += 1;
        if (f.live > 0) f.live -= 1;
    }
};

test "initial state idle" {
    var fake = Fake{};
    var e = try engine.Engine.init(std.testing.allocator, fake.service());
    defer e.deinit();
    const st = e.status();
    try std.testing.expectEqual(engine.State.idle, st.state);
    try std.testing.expectEqualStrings("idle", st.message);
}

test "login success reaches connected" {
    var fake = Fake{};
    var e = try engine.Engine.init(std.testing.allocator, fake.service());
    defer e.deinit();
    try e.login("KEY-1");
    const st = e.status();
    try std.testing.expectEqual(engine.State.connected, st.state);
    try std.testing.expectEqualStrings("connected", st.message);
    try std.testing.expectEqual(@as(usize, 1), fake.login_calls);
    try std.testing.expectEqual(@as(usize, 1), fake.start_calls);
    try std.testing.expectEqualStrings("KEY-1", fake.key_buf[0..fake.key_len]);
}

test "login without setup key needs login" {
    var fake = Fake{};
    var e = try engine.Engine.init(std.testing.allocator, fake.service());
    defer e.deinit();
    try std.testing.expectError(engine.LoginError.MissingSetupKey, e.login(""));
    const st = e.status();
    try std.testing.expectEqual(engine.State.needs_login, st.state);
    try std.testing.expectEqualStrings("setup key required", st.message);
    try std.testing.expectEqual(@as(usize, 0), fake.login_calls);
    try std.testing.expectEqual(@as(usize, 0), fake.start_calls);
}

test "login auth failure reports error" {
    var fake = Fake{ .login_err = error.AuthFailed };
    var e = try engine.Engine.init(std.testing.allocator, fake.service());
    defer e.deinit();
    try std.testing.expectError(engine.LoginError.AuthFailed, e.login("BAD"));
    const st = e.status();
    try std.testing.expectEqual(engine.State.@"error", st.state);
    try std.testing.expectEqualStrings("login failed", st.message);
    try std.testing.expectEqual(@as(usize, 0), fake.start_calls);
}

test "login network failure reports error" {
    var fake = Fake{ .login_err = error.Network };
    var e = try engine.Engine.init(std.testing.allocator, fake.service());
    defer e.deinit();
    try std.testing.expectError(engine.LoginError.Network, e.login("K"));
    try std.testing.expectEqual(engine.State.@"error", e.status().state);
}

test "start failure reports error with stable message" {
    var fake = Fake{ .start_err = error.StartFailed };
    var e = try engine.Engine.init(std.testing.allocator, fake.service());
    defer e.deinit();
    try std.testing.expectError(engine.LoginError.StartFailed, e.login("K"));
    const st = e.status();
    try std.testing.expectEqual(engine.State.@"error", st.state);
    try std.testing.expectEqualStrings("start failed", st.message);
    try std.testing.expectEqualStrings("start failed", e.status().message);
}

test "up without auth needs login" {
    var fake = Fake{};
    var e = try engine.Engine.init(std.testing.allocator, fake.service());
    defer e.deinit();
    try std.testing.expectError(engine.UpError.NotAuthenticated, e.up());
    const st = e.status();
    try std.testing.expectEqual(engine.State.needs_login, st.state);
    try std.testing.expectEqualStrings("not authenticated", st.message);
    try std.testing.expectEqual(@as(usize, 0), fake.login_calls);
    try std.testing.expectEqual(@as(usize, 0), fake.start_calls);
}

test "up after successful login does not start a second live service" {
    var fake = Fake{};
    var e = try engine.Engine.init(std.testing.allocator, fake.service());
    defer e.deinit();
    try e.login("LOCAL_SYNTHETIC_KEY");
    try std.testing.expectEqual(engine.State.connected, e.status().state);
    try e.up();
    try std.testing.expectEqual(engine.State.connected, e.status().state);
    try std.testing.expectEqual(@as(usize, 1), fake.login_calls);
    try std.testing.expectEqual(@as(usize, 1), fake.start_calls);
    try std.testing.expectEqual(@as(usize, 0), fake.stop_calls);
}

test "up after down reconnects without new login" {
    var fake = Fake{};
    var e = try engine.Engine.init(std.testing.allocator, fake.service());
    defer e.deinit();
    try e.login("K");
    try e.down();
    try std.testing.expectEqual(engine.State.stopped, e.status().state);
    try e.up();
    try std.testing.expectEqual(engine.State.connected, e.status().state);
    try std.testing.expectEqual(@as(usize, 1), fake.login_calls);
    try std.testing.expectEqual(@as(usize, 2), fake.start_calls);
    try std.testing.expectEqual(@as(usize, 1), fake.stop_calls);
}

test "down from idle is quiet" {
    var fake = Fake{};
    var e = try engine.Engine.init(std.testing.allocator, fake.service());
    defer e.deinit();
    try e.down();
    try e.down();
    try e.down();
    try std.testing.expectEqual(engine.State.stopped, e.status().state);
    try std.testing.expectEqualStrings("stopped", e.status().message);
    try std.testing.expectEqual(@as(usize, 0), fake.stop_calls);
}

test "down from connected stops once then stable" {
    var fake = Fake{};
    var e = try engine.Engine.init(std.testing.allocator, fake.service());
    defer e.deinit();
    try e.login("K");
    try e.down();
    try e.down();
    try e.down();
    try std.testing.expectEqual(engine.State.stopped, e.status().state);
    try std.testing.expectEqual(@as(usize, 1), fake.stop_calls);
}

test "retry after error" {
    var fake = Fake{ .start_err = error.StartFailed };
    var e = try engine.Engine.init(std.testing.allocator, fake.service());
    defer e.deinit();
    try std.testing.expectError(engine.LoginError.StartFailed, e.login("K"));
    try std.testing.expectEqual(engine.State.@"error", e.status().state);
    fake.start_err = null;
    try e.login("K");
    try std.testing.expectEqual(engine.State.connected, e.status().state);
}

test "setup key never surfaces in status" {
    var key = [_]u8{ 'S', 'E', 'C', 'R', 'E', 'T' };
    var fake = Fake{};
    var e = try engine.Engine.init(std.testing.allocator, fake.service());
    defer e.deinit();
    try e.login(key[0..]);
    @memset(&key, 'X');
    const st = e.status();
    try std.testing.expect(std.mem.indexOf(u8, st.message, "SECRET") == null);
    try std.testing.expectEqualStrings("connected", st.message);
    try std.testing.expectEqualStrings("SECRET", fake.key_buf[0..fake.key_len]);
}

test "down after failed start does not stop again" {
    var fake = Fake{ .start_err = error.StartFailed };
    var e = try engine.Engine.init(std.testing.allocator, fake.service());
    defer e.deinit();
    try std.testing.expectError(engine.LoginError.StartFailed, e.login("K"));
    // Rollback already stopped once and released the partial resource.
    try std.testing.expectEqual(@as(usize, 1), fake.stop_calls);
    try std.testing.expectEqual(@as(usize, 0), fake.live);
    try e.down();
    try std.testing.expectEqual(engine.State.stopped, e.status().state);
    try std.testing.expectEqual(@as(usize, 1), fake.stop_calls);
    try std.testing.expectEqual(@as(usize, 0), fake.live);
}

test "relogin while connected reuses the live chain" {
    var fake = Fake{};
    var e = try engine.Engine.init(std.testing.allocator, fake.service());
    defer e.deinit();
    try e.login("K1");
    try e.login("K2");
    try std.testing.expectEqual(engine.State.connected, e.status().state);
    try std.testing.expectEqual(@as(usize, 1), fake.login_calls);
    try std.testing.expectEqual(@as(usize, 1), fake.start_calls);
    try std.testing.expectEqualStrings("K1", fake.key_buf[0..fake.key_len]);
}

test "status formatting names state and message" {
    var fake = Fake{};
    var e = try engine.Engine.init(std.testing.allocator, fake.service());
    defer e.deinit();
    try e.login("K");
    var buf: [256]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try e.status().format(&w);
    const text = w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, text, "connected") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "state:") != null);
    try std.testing.expectEqualStrings("error", engine.State.@"error".name());
    try std.testing.expectEqualStrings("needs_login", engine.State.needs_login.name());
}

fn oomFlow(alloc: std.mem.Allocator) !void {
    var fake = Fake{};
    var e = try engine.Engine.init(alloc, fake.service());
    defer e.deinit();
    try e.login("K");
    try e.down();
}

test "allocator failures leave no debris" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, oomFlow, .{});
}

test "failed start rolls back live resources exactly once" {
    var fake = Fake{ .start_err = error.StartFailed };
    var e = try engine.Engine.init(std.testing.allocator, fake.service());
    defer e.deinit();
    try std.testing.expectError(engine.LoginError.StartFailed, e.login("K"));
    try std.testing.expectEqual(@as(usize, 0), fake.live);
    try std.testing.expectEqual(@as(usize, 1), fake.stop_calls);
    try e.down();
    try e.down();
    try std.testing.expectEqual(engine.State.stopped, e.status().state);
    try std.testing.expectEqual(@as(usize, 0), fake.live);
    try std.testing.expectEqual(@as(usize, 1), fake.stop_calls);
}

test "every allocation failure still releases live resources" {
    const total = blk: {
        var fa = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        var fake = Fake{};
        var e = try engine.Engine.init(fa.allocator(), fake.service());
        defer e.deinit();
        try e.login("K");
        try e.down();
        break :blk fa.alloc_index;
    };
    for (0..total + 1) |i| {
        var fa = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = i });
        var fake = Fake{};
        {
            var e = engine.Engine.init(fa.allocator(), fake.service()) catch |err| {
                try std.testing.expectEqual(error.OutOfMemory, err);
                try std.testing.expectEqual(@as(usize, 0), fake.live);
                try std.testing.expectEqual(fa.allocated_bytes, fa.freed_bytes);
                continue;
            };
            defer e.deinit();
            e.login("K") catch |err| {
                try std.testing.expectEqual(error.OutOfMemory, err);
            };
            e.down() catch |err| {
                try std.testing.expectEqual(error.OutOfMemory, err);
            };
            try std.testing.expectEqual(@as(usize, 0), fake.live);
        }
        try std.testing.expectEqual(fa.allocated_bytes, fa.freed_bytes);
    }
}

test "failed start keeps service error when status allocation fails" {
    const total = blk: {
        var fa = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        var fake = Fake{ .start_err = error.StartFailed };
        var e = try engine.Engine.init(fa.allocator(), fake.service());
        defer e.deinit();
        try std.testing.expectError(engine.LoginError.StartFailed, e.login("K"));
        try e.down();
        break :blk fa.alloc_index;
    };
    var saw_preserved = false;
    for (0..total + 1) |i| {
        var fa = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = i });
        var fake = Fake{ .start_err = error.StartFailed };
        {
            var e = engine.Engine.init(fa.allocator(), fake.service()) catch |err| {
                try std.testing.expectEqual(error.OutOfMemory, err);
                try std.testing.expectEqual(@as(usize, 0), fake.live);
                try std.testing.expectEqual(fa.allocated_bytes, fa.freed_bytes);
                continue;
            };
            defer e.deinit();
            e.login("K") catch |err| {
                try std.testing.expect(err == error.OutOfMemory or err == error.StartFailed);
                if (fa.has_induced_failure and err == error.StartFailed) saw_preserved = true;
            };
            e.down() catch |err| {
                try std.testing.expectEqual(error.OutOfMemory, err);
            };
            try std.testing.expectEqual(@as(usize, 0), fake.live);
        }
        try std.testing.expectEqual(fa.allocated_bytes, fa.freed_bytes);
    }
    try std.testing.expect(saw_preserved);
}

fn expectBalance(fake: *const Fake, live: usize) !void {
    try std.testing.expectEqual(live, fake.live);
    try std.testing.expect(fake.stop_calls <= fake.start_calls);
    try std.testing.expectEqual(fake.start_calls - fake.stop_calls, fake.live);
}

test "successful relogin then down balances live services" {
    var fake = Fake{};
    var e = try engine.Engine.init(std.testing.allocator, fake.service());
    defer e.deinit();
    try e.login("K1");
    try e.login("K2");
    try expectBalance(&fake, 1);
    try e.down();
    try expectBalance(&fake, 0);
    try e.down();
    try expectBalance(&fake, 0);
}

test "connected relogin bypasses auth rejection and down balances live services" {
    var fake = Fake{};
    var e = try engine.Engine.init(std.testing.allocator, fake.service());
    defer e.deinit();
    try e.login("K1");
    fake.login_err = error.AuthFailed;
    try e.login("BAD");
    try expectBalance(&fake, 1);
    try e.down();
    try std.testing.expectError(error.AuthFailed, e.login("BAD"));
    try e.down();
    try expectBalance(&fake, 0);
    try e.down();
    try expectBalance(&fake, 0);
}

test "relogin after down second start OutOfMemory balances live services" {
    var fake = Fake{};
    var e = try engine.Engine.init(std.testing.allocator, fake.service());
    defer e.deinit();
    try e.login("K1");
    try e.down();
    fake.start_err = error.OutOfMemory;
    try std.testing.expectError(error.OutOfMemory, e.login("K2"));
    try expectBalance(&fake, 0);
    try e.down();
    try expectBalance(&fake, 0);
    try e.down();
    try expectBalance(&fake, 0);
}

test "missing key relogin then down balances live services" {
    var fake = Fake{};
    var e = try engine.Engine.init(std.testing.allocator, fake.service());
    defer e.deinit();
    try e.login("K1");
    try e.login("");
    try expectBalance(&fake, 1);
    try e.down();
    try expectBalance(&fake, 0);
    try e.down();
    try expectBalance(&fake, 0);
    try std.testing.expectEqual(@as(usize, 1), fake.login_calls);
}
