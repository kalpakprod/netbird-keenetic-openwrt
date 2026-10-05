// Test-only helper: serialize the fw integration suites that share the
// single netns iptables state (zig build runs test binaries concurrently).
// flock(2) over a lock file; raw syscalls only.
const std = @import("std");
const linux = std.os.linux;

pub const lock_ex: i32 = 2; // LOCK_EX, stable flock.h UAPI
pub const lock_un: i32 = 8; // LOCK_UN

pub const Lock = struct {
    fd: linux.fd_t,

    pub fn acquire(path: [*:0]const u8) !Lock {
        const fd_usize = linux.open(path, .{ .ACCMODE = .RDWR, .CREAT = true, .CLOEXEC = true }, 0o644);
        if (fd_usize > 0xfffffffffffff000) return error.LockOpenFailed;
        const fd: linux.fd_t = @intCast(fd_usize);
        errdefer _ = linux.close(fd);
        const rc = linux.flock(fd, lock_ex);
        if (rc > 0xfffffffffffff000) return error.LockFailed;
        return .{ .fd = fd };
    }

    pub fn release(l: *Lock) void {
        _ = linux.flock(l.fd, lock_un);
        _ = linux.close(l.fd);
        l.fd = -1;
    }
};

pub const lock_path: [*:0]const u8 = "/tmp/netbird-fw-test.lock";
