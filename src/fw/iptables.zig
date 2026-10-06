// iptables binary runner. Same role as github.com/coreos/go-iptables with
// NewWithProtocol + Timeout(0): every call appends a bare "--wait" and
// Exists/DeleteIfExists/AppendUnique/InsertUnique are built on "-C".
// 1.4.21 constraints (checked against the iptables-1.4.21 release sources):
//   - bare "--wait" only (it takes no seconds argument before 1.6.0);
//   - "-C" exists (since 1.4.11);
//   - "-S [chain]" takes no rulenum (so ChainExists uses "-S <chain>",
//     not go-iptables' "-S <chain> 1").
// The binary path is configurable (router: /opt/sbin/iptables; v6: ip6tables).
const std = @import("std");

pub const Error = std.process.RunError || error{
    IptablesFailed,
    SpecTooLong,
};

pub const Runner = struct {
    /// Binary path, caller-owned ("iptables", "/opt/sbin/iptables", ...).
    path: []const u8,
    alloc: std.mem.Allocator,
    io: std.Io,
    /// stderr of the most recent failed run, owned. Freed on the next
    /// run and on deinit.
    last_stderr: ?[]u8 = null,

    pub fn deinit(r: *Runner) void {
        if (r.last_stderr) |s| {
            r.alloc.free(s);
            r.last_stderr = null;
        }
    }

    fn forgetStderr(r: *Runner) void {
        if (r.last_stderr) |s| {
            r.alloc.free(s);
            r.last_stderr = null;
        }
    }

    /// Full argv (without the binary path). Appends "--wait" like go-iptables.
    fn argvOf(r: *const Runner, buf: [][]const u8, args: []const []const u8) Error![][]const u8 {
        if (args.len + 2 > buf.len) return Error.SpecTooLong;
        buf[0] = r.path;
        @memcpy(buf[1 .. 1 + args.len], args);
        buf[1 + args.len] = "--wait";
        return buf[0 .. 2 + args.len];
    }

    /// Run and require exit 0. On failure keeps stderr in last_stderr.
    pub fn run(r: *Runner, args: []const []const u8) Error!void {
        const code = try r.runCode(args);
        if (code != 0) return Error.IptablesFailed;
    }

    /// Run and return the exit code. Non-exit terms (signal) are an error.
    /// On nonzero exit keeps stderr in last_stderr.
    pub fn runCode(r: *Runner, args: []const []const u8) Error!u8 {
        var buf: [72][]const u8 = undefined;
        const argv = try r.argvOf(&buf, args);
        const res = try std.process.run(r.alloc, r.io, .{ .argv = argv });
        defer r.alloc.free(res.stdout);
        defer r.alloc.free(res.stderr);
        r.forgetStderr();
        const code: u8 = switch (res.term) {
            .exited => |c| c,
            else => return Error.IptablesFailed,
        };
        if (code != 0) {
            r.last_stderr = r.alloc.dupe(u8, res.stderr) catch null;
        }
        return code;
    }

    /// Run and capture stdout (owned, caller frees). Requires exit 0.
    pub fn runCapture(r: *Runner, args: []const []const u8) Error![]u8 {
        var buf: [72][]const u8 = undefined;
        const argv = try r.argvOf(&buf, args);
        const res = try std.process.run(r.alloc, r.io, .{ .argv = argv });
        defer r.alloc.free(res.stderr);
        errdefer r.alloc.free(res.stdout);
        r.forgetStderr();
        const ok = switch (res.term) {
            .exited => |c| c == 0,
            else => false,
        };
        if (!ok) {
            r.last_stderr = r.alloc.dupe(u8, res.stderr) catch null;
            return Error.IptablesFailed;
        }
        return res.stdout;
    }

    fn fullArgs(
        buf: [][]const u8,
        head: []const []const u8,
        spec: []const []const u8,
    ) []const []const u8 {
        @memcpy(buf[0..head.len], head);
        @memcpy(buf[head.len .. head.len + spec.len], spec);
        return buf[0 .. head.len + spec.len];
    }

    /// "-C": true when the exact rule exists. Exit 1 means "no";
    /// any other nonzero exit is an error (same as go-iptables Exists).
    pub fn exists(r: *Runner, table: []const u8, chain: []const u8, spec: []const []const u8) Error!bool {
        var head: [4][]const u8 = .{ "-t", table, "-C", chain };
        var buf: [68][]const u8 = undefined;
        const code = try r.runCode(fullArgs(&buf, &head, spec));
        return switch (code) {
            0 => true,
            1 => false,
            else => Error.IptablesFailed,
        };
    }

    pub fn insert(r: *Runner, table: []const u8, chain: []const u8, pos: u32, spec: []const []const u8) Error!void {
        var pos_buf: [12]u8 = undefined;
        const pos_text = std.fmt.bufPrint(&pos_buf, "{d}", .{pos}) catch unreachable;
        var head: [5][]const u8 = .{ "-t", table, "-I", chain, pos_text };
        var buf: [68][]const u8 = undefined;
        try r.run(fullArgs(&buf, &head, spec));
    }

    pub fn append(r: *Runner, table: []const u8, chain: []const u8, spec: []const []const u8) Error!void {
        var head: [4][]const u8 = .{ "-t", table, "-A", chain };
        var buf: [68][]const u8 = undefined;
        try r.run(fullArgs(&buf, &head, spec));
    }

    pub fn delete(r: *Runner, table: []const u8, chain: []const u8, spec: []const []const u8) Error!void {
        var head: [4][]const u8 = .{ "-t", table, "-D", chain };
        var buf: [68][]const u8 = undefined;
        try r.run(fullArgs(&buf, &head, spec));
    }

    pub fn insertUnique(r: *Runner, table: []const u8, chain: []const u8, pos: u32, spec: []const []const u8) Error!void {
        if (!try r.exists(table, chain, spec)) try r.insert(table, chain, pos, spec);
    }

    pub fn appendUnique(r: *Runner, table: []const u8, chain: []const u8, spec: []const []const u8) Error!void {
        if (!try r.exists(table, chain, spec)) try r.append(table, chain, spec);
    }

    pub fn deleteIfExists(r: *Runner, table: []const u8, chain: []const u8, spec: []const []const u8) Error!void {
        if (try r.exists(table, chain, spec)) try r.delete(table, chain, spec);
    }

    /// "-N". Fails when the chain already exists (caller clears stale first).
    pub fn newChain(r: *Runner, table: []const u8, chain: []const u8) Error!void {
        const args: [4][]const u8 = .{ "-t", table, "-N", chain };
        try r.run(&args);
    }

    pub fn flushChain(r: *Runner, table: []const u8, chain: []const u8) Error!void {
        const args: [4][]const u8 = .{ "-t", table, "-F", chain };
        try r.run(&args);
    }

    pub fn deleteChain(r: *Runner, table: []const u8, chain: []const u8) Error!void {
        const args: [4][]const u8 = .{ "-t", table, "-X", chain };
        try r.run(&args);
    }

    pub fn clearAndDeleteChain(r: *Runner, table: []const u8, chain: []const u8) Error!void {
        if (!try r.chainExists(table, chain)) return;
        try r.flushChain(table, chain);
        try r.deleteChain(table, chain);
    }

    /// "-S <chain>" (no rulenum: 1.4.21 has no "-S chain rulenum").
    /// Exit 0 = exists, 1 = missing, anything else is an error.
    pub fn chainExists(r: *Runner, table: []const u8, chain: []const u8) Error!bool {
        const args: [4][]const u8 = .{ "-t", table, "-S", chain };
        const code = try r.runCode(&args);
        return switch (code) {
            0 => true,
            1 => false,
            else => Error.IptablesFailed,
        };
    }

    /// "-S <chain>" listing, owned. Used only by tests/debug, not by Manager.
    pub fn list(r: *Runner, table: []const u8, chain: []const u8) Error![]u8 {
        const args: [4][]const u8 = .{ "-t", table, "-S", chain };
        return r.runCapture(&args);
    }
};
