// Port of netbird client/internal/ipcauth tests (v0.80.0), BSD-3-Clause —
// tests. Covers the Unix surface of identity.go/privileged.go/self_unix.go
// and real SO_PEERCRED acquisition over a local unix socket (listen/accept/
// connect on the loopback namespace only). Runs as the current user; no test
// changes uid, users or permissions, so no namespace isolation is needed.

const std = @import("std");
const ipcauth = @import("ipcauth.zig");

const Identity = ipcauth.Identity;
const tio = std.testing.io;

test {
    // The first-capture concurrency tests live in ipcauth.zig next to the
    // private state they stage; this pulls them into this test run.
    _ = @import("ipcauth.zig");
}

test "same user compares accounts only" {
    const cases = [_]struct { a: Identity, b: Identity, want: bool }{
        // Same uid.
        .{ .a = .{ .uid = 1000, .gid = 1000 }, .b = .{ .uid = 1000, .gid = 1000 }, .want = true },
        // Same uid, different gid and pid still the same user.
        .{ .a = .{ .uid = 1000, .gid = 1000, .pid = 11 }, .b = .{ .uid = 1000, .gid = 27, .pid = 22 }, .want = true },
        .{ .a = .{ .uid = 1000 }, .b = .{ .uid = 1001 }, .want = false },
    };
    for (cases) |c| {
        try std.testing.expectEqual(c.want, c.a.sameUser(c.b));
        try std.testing.expectEqual(c.want, c.b.sameUser(c.a)); // symmetric
    }
}

test "privilege is uid 0 on linux" {
    const root = Identity{ .uid = 0, .gid = 0 };
    try std.testing.expect(root.isPrivileged());
    const user = Identity{ .uid = 1000, .gid = 1000 };
    try std.testing.expect(!user.isPrivileged());
}

// The self rule is the one place privilege is granted to something other than
// the platform administrator, so its guards matter: it must apply only when
// the daemon is itself unprivileged, and only to a caller with the daemon's
// identity. The Windows rows of the upstream table have no meaning here.
test "daemon self rule: who may act with the daemon's authority" {
    const self_unprivileged = Identity{ .uid = 1000 };
    const self_root = Identity{ .uid = 0 };
    // Root is privileged whatever the daemon runs as.
    try std.testing.expect(ipcauth.isPrivilegedCallerWith(self_unprivileged, Identity{ .uid = 0 }));
    // An unprivileged daemon delegates to its own user (rootless container)...
    try std.testing.expect(ipcauth.isPrivilegedCallerWith(self_unprivileged, Identity{ .uid = 1000 }));
    // ...and to nobody else.
    try std.testing.expect(!ipcauth.isPrivilegedCallerWith(self_unprivileged, Identity{ .uid = 1001 }));
    // A root daemon delegates to nobody: on a normal install sharing its
    // identity is already covered by being root; nothing else may match.
    try std.testing.expect(!ipcauth.isPrivilegedCallerWith(self_root, Identity{ .uid = 1000 }));
}

// The real process must never accidentally delegate: a test binary running as
// a normal user is unprivileged, so it may match itself, but nothing else.
test "this process may act as itself, an unrelated identity never" {
    const self = ipcauth.currentProcessIdentity();
    try std.testing.expect(ipcauth.isPrivilegedCaller(self));

    const other = Identity{ .uid = self.uid + 1 };
    try std.testing.expect(!ipcauth.isPrivilegedCaller(other));
}

test "mayDelegate excludes a privileged daemon" {
    try std.testing.expect(ipcauth.mayDelegate(Identity{ .uid = 1000 }));
    try std.testing.expect(!ipcauth.mayDelegate(Identity{ .uid = 0 }));
}

test "selfDelegatesTo names the daemon's own user when unprivileged" {
    if (std.os.linux.geteuid() == 0) return error.SkipZigTest;
    const delegated = ipcauth.selfDelegatesTo() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(std.os.linux.geteuid(), delegated.uid);
}

test "currentProcessIdentity reports euid/egid and no pid, as upstream" {
    const self = ipcauth.currentProcessIdentity();
    try std.testing.expectEqual(std.os.linux.geteuid(), self.uid);
    try std.testing.expectEqual(std.os.linux.getegid(), self.gid);
    try std.testing.expectEqual(@as(i32, 0), self.pid);
}

test "error info and actor wording match upstream" {
    try std.testing.expectEqualStrings("PRIVILEGE_REQUIRED", ipcauth.error_reason_privilege_required);
    try std.testing.expectEqualStrings("daemon.netbird.io", ipcauth.error_domain);
    try std.testing.expectEqualStrings("summary", ipcauth.error_meta_summary);
    try std.testing.expectEqualStrings("command", ipcauth.error_meta_command);
    try std.testing.expectEqualStrings("root", ipcauth.privilegedActor());
    try std.testing.expectEqualStrings("root", ipcauth.privilegedActorKey());
}

test "elevated command wording matches upstream" {
    const alloc = std.testing.allocator;
    const up = try ipcauth.elevatedCommand(alloc, "netbird up --flag");
    defer alloc.free(up);
    try std.testing.expectEqualStrings("sudo netbird up --flag", up);

    const both = try ipcauth.upCommand(alloc, "--flag");
    defer alloc.free(both);
    // ";" so the line pastes into PowerShell 5.1, which rejects "&&".
    try std.testing.expectEqualStrings("sudo netbird down; sudo netbird up --flag", both);
}

test "identity renders as uid/gid for audit logs" {
    var buf: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try (Identity{ .uid = 1000, .gid = 100 }).format(&w);
    try std.testing.expectEqualStrings("uid=1000 gid=100", w.buffered());
}

// The connecting process is this test process, so the kernel must report
// exactly this process's uid/gid/pid: evidence of real acquisition, not a
// filled-in struct. Socket lives in /tmp under a pid-unique name; nothing
// outside the test's own files is touched.
test "peerIdentity reads kernel credentials of a connected unix socket" {
    var path_buf: [64]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "/tmp/nb-ipcauth-test-{d}.sock", .{std.os.linux.getpid()});
    std.Io.Dir.deleteFileAbsolute(tio, path) catch {}; // stale socket from an earlier run
    defer std.Io.Dir.deleteFileAbsolute(tio, path) catch {};

    var ua = try std.Io.net.UnixAddress.init(path);
    var srv = try ua.listen(tio, .{});
    defer srv.deinit(tio);

    // Nothing connected yet, so there is no peer: kernel 4.9 reports no
    // process (pid 0), which peerIdentity refuses, while newer kernels report
    // the socket creator's own credentials. Upstream only ever calls this on
    // accepted connections, so either way nothing here may name a third
    // party: it must error or describe this very process (the creator).
    if (ipcauth.peerIdentity(srv.socket.handle)) |listening_id| {
        try std.testing.expectEqual(std.os.linux.geteuid(), listening_id.uid);
    } else |_| {}

    var client = try ua.connect(tio);
    defer client.close(tio);
    var conn = try srv.accept(tio);
    defer conn.close(tio);

    const id = try ipcauth.peerIdentity(conn.socket.handle);
    try std.testing.expectEqual(std.os.linux.geteuid(), id.uid);
    try std.testing.expectEqual(std.os.linux.getegid(), id.gid);
    try std.testing.expectEqual(@as(i32, @intCast(std.os.linux.getpid())), id.pid);
    // The daemon would treat this caller as itself.
    try std.testing.expect(ipcauth.currentProcessIdentity().sameUser(id));
}

// Failed/malformed socket handling: any fd without a connected unix peer must
// error, never fabricate an identity. A TCP socket is upstream's "connection
// is not a unix socket" case; a regular file is not a socket at all.
test "peerIdentity fails closed without a unix peer" {
    var tcp: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var tsrv = try tcp.listen(tio, .{});
    defer tsrv.deinit(tio);
    try std.testing.expectError(error.NoPeerCredentials, ipcauth.peerIdentity(tsrv.socket.handle));

    var file = try std.Io.Dir.openFileAbsolute(tio, "/dev/null", .{ .mode = .read_only });
    defer file.close(tio);
    try std.testing.expectError(error.NoPeerCredentials, ipcauth.peerIdentity(file.handle));
}
