// Blocking mutex for the DNS resolver paths. Zig 0.17's std.atomic.Mutex
// only offers tryLock; these critical sections are short and low-contention
// (query path vs. netmap update), so a spin with Thread.yield is the direct
// solution without pulling the std.Io futex runtime in.

const std = @import("std");

pub const Mutex = struct {
    inner: std.atomic.Mutex = .unlocked,

    pub fn lock(m: *Mutex) void {
        while (!m.inner.tryLock()) {
            std.Thread.yield() catch {};
        }
    }

    pub fn unlock(m: *Mutex) void {
        m.inner.unlock();
    }
};
