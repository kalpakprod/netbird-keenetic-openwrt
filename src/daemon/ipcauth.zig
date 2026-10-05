// Port of netbird client/internal/ipcauth (v0.80.0), BSD-3-Clause.
// Sources: identity.go, privileged.go, creds_unix.go, peercred_linux.go,
// self_unix.go (Unix/Linux part). Not in this port: the gRPC transport and
// context wrappers (AuthInfo, IdentityFromContext, forward.go's
// CallerIdentity/forwarded-identity metadata), the Windows named-pipe
// identity (SID/Groups/Elevated fields and their rules), and ownedfile*.go —
// separate concerns with no Linux-only consumer in this card. Consumers must
// fail closed whenever identity acquisition returns an error.
//
// Peer credential acquisition is a raw socket syscall (no libc); the SO_*
// and SOL_* constants come from std and resolve per target, arm64 included.

const std = @import("std");

/// Kernel-authenticated identity of a local IPC caller (upstream Identity).
/// The zero value is not a valid identity: consumers must only use one
/// obtained with a successful peerIdentity/currentProcessIdentity call.
pub const Identity = struct {
    /// Caller's Unix user id (upstream UID).
    uid: u32 = 0,
    /// Caller's primary group id (upstream GID).
    gid: u32 = 0,
    /// Caller's process id where the platform reports it (SO_PEERCRED), and 0
    /// where it does not. It identifies the daemon's own process dialling
    /// itself, and is never used to grant anything (upstream PID).
    pid: i32 = 0,

    /// Whether the caller is the platform's administrative principal, which
    /// is what the daemon requires for changes that cross the user-to-root
    /// boundary. On Linux that is uid 0 (upstream IsPrivileged, Unix branch).
    pub fn isPrivileged(i: Identity) bool {
        return i.uid == 0;
    }

    /// Whether two identities are the same local principal (upstream
    /// SameUser): only the account is compared. The zero Identity carries
    /// uid 0, so callers must establish that both identities are real before
    /// the answer means anything.
    pub fn sameUser(i: Identity, other: Identity) bool {
        return i.uid == other.uid;
    }

    /// Renders the identity for audit logs and denial messages (upstream
    /// String, Unix branch).
    pub fn format(i: Identity, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.print("uid={d} gid={d}", .{ i.uid, i.gid });
    }
};

// Detail the daemon attaches to a PermissionDenied it raises for an operation
// that requires root (upstream ErrorInfo constants). Clients match on Reason
// and Domain rather than on the message text, and render the summary and
// command themselves so the user gets guidance instead of a gRPC error dump.
pub const error_reason_privilege_required = "PRIVILEGE_REQUIRED";
pub const error_domain = "daemon.netbird.io";
pub const error_meta_summary = "summary";
pub const error_meta_command = "command";

// This process's identity, captured once because it cannot change (upstream
// captures in package init, before any concurrency). selfMayDelegate
// additionally requires this process to be unprivileged: see mayDelegate. On
// Linux reading it cannot fail (upstream self_unix.go returns no error), so
// there is no selfKnown flag; the parameterized
// isPrivilegedCallerWith/isDaemonSelfWith keep the decision testable.
//
// One-time publication across the daemon's IPC workers: self_state is the
// initializer protocol. The winner of the idle->capturing CAS is the only
// writer of self_id/self_may_delegate, and its release store of .ready is
// the publication; every other caller's acquire load of .ready (the fast
// path, or after waiting out a capture in progress) is what makes the pair
// visible to that caller's later plain reads. No caller ever sees a
// half-published identity, the capture (two id syscalls over constant state)
// runs exactly once, and the steady path costs one acquire load with no
// syscall.
const CaptureState = enum(u32) { idle, capturing, ready };

var self_id: Identity = .{};
var self_may_delegate = false;
var self_state = std.atomic.Value(CaptureState).init(.idle);

fn ensureSelfCaptured() void {
    if (self_state.load(.acquire) == .ready) return;

    if (self_state.cmpxchgStrong(.idle, .capturing, .acquire, .monotonic) == null) {
        // This thread owns the one-time capture and its publication.
        selfCaptureTestPoint();
        const id = currentProcessIdentity();
        self_id = id;
        self_may_delegate = mayDelegate(id);
        self_state.store(.ready, .release);
        return;
    }

    // Another thread holds the capture: wait out its publication rather than
    // capture on our own; the acquire loads re-publish the pair here.
    while (self_state.load(.acquire) != .ready) {
        if (self_capture_test_gate) |gate| gate.waiter_seen.store(true, .release);
        std.Thread.yield() catch {};
        std.atomic.spinLoopHint();
    }
}

// Test support for the first-capture concurrency tests at the bottom of this
// file: while a test has registered a gate here, the capturing thread
// announces itself on `entered` and pauses until `open` (so the test can
// stage a concurrent first call against a held capture), `wins` counts the
// threads that won the capture, and `waiter_seen` marks a caller that met
// the capture in progress. Production leaves the gate null and pays a null
// check on paths that run once per process (or only inside the first-capture
// window).
const SelfCaptureGate = struct {
    entered: std.atomic.Value(bool) = .init(false),
    open: std.atomic.Value(bool) = .init(true),
    wins: std.atomic.Value(u32) = .init(0),
    waiter_seen: std.atomic.Value(bool) = .init(false),
};
var self_capture_test_gate: ?*SelfCaptureGate = null;

fn selfCaptureTestPoint() void {
    const gate = self_capture_test_gate orelse return;
    _ = gate.wins.fetchAdd(1, .monotonic);
    gate.entered.store(true, .release);
    while (!gate.open.load(.acquire)) {
        std.Thread.yield() catch {};
        std.atomic.spinLoopHint();
    }
}

/// Whether a daemon running as `id` may extend its authority to callers
/// sharing its identity (upstream mayDelegate). Root never delegates: sharing
/// its identity does not mean sharing its power, and a rootless daemon's
/// caller can already rewrite the config files it reads and replace the
/// binary it runs. Upstream also excludes the Windows shared service
/// accounts, whose SID is held by unrelated services; they have no Linux
/// meaning.
pub fn mayDelegate(id: Identity) bool {
    return !id.isPrivileged();
}

/// Whether an identity is the given self identity (upstream IsDaemonSelf):
/// the JSON gateway runs inside the daemon and re-dials it locally, so this
/// is what distinguishes the gateway from any other caller, whatever user the
/// daemon runs as.
pub fn isDaemonSelfWith(self: Identity, id: Identity) bool {
    return id.uid == self.uid;
}

/// The daemon's own privilege rule against explicitly given self state
/// (upstream IsPrivilegedCaller): beyond root it accepts a caller running as
/// the daemon's own identity when the daemon is itself unprivileged. That
/// keeps a rootless container working, where there is no uid 0 at all. This
/// is the daemon's own rule and cannot be evaluated by a client, which does
/// not know what the daemon runs as.
pub fn isPrivilegedCallerWith(self: Identity, caller: Identity) bool {
    if (caller.isPrivileged()) return true;
    return mayDelegate(self) and isDaemonSelfWith(self, caller);
}

/// Whether an identity is this very process (upstream IsDaemonSelf).
pub fn isDaemonSelf(id: Identity) bool {
    ensureSelfCaptured();
    return isDaemonSelfWith(self_id, id);
}

/// Whether an identity may make the changes the daemon restricts to the
/// platform administrator (upstream IsPrivilegedCaller).
pub fn isPrivilegedCaller(id: Identity) bool {
    ensureSelfCaptured();
    return isPrivilegedCallerWith(self_id, id);
}

/// The identity this process delegates its authority to, and whether it
/// delegates at all: only an unprivileged daemon does (upstream
/// SelfDelegatesTo). It exists so a refusal can name who may actually perform
/// the operation, because on such a host root is neither required nor
/// necessarily available.
pub fn selfDelegatesTo() ?Identity {
    ensureSelfCaptured();
    if (!self_may_delegate) return null;
    return self_id;
}

/// This process's identity as the daemon would see it if this process
/// connected to the local IPC (upstream CurrentProcessIdentity). It lets a
/// client decide up front whether a privileged operation can succeed, without
/// a round-trip and without duplicating the rules. The pid is not reported,
/// exactly as upstream.
pub fn currentProcessIdentity() Identity {
    return .{
        .uid = std.os.linux.geteuid(),
        .gid = std.os.linux.getegid(),
        .pid = 0,
    };
}

/// Names the principal a privileged operation requires, for use in messages
/// shown to the user (upstream PrivilegedActor; Linux is always root).
pub fn privilegedActor() []const u8 {
    return "root";
}

/// The value PrivilegedActorKey returns for Linux (upstream ActorKeyRoot).
pub const actor_key_root = "root";

/// Identifies the required principal without wording it, for a client that
/// writes its own message in the user's language (upstream
/// PrivilegedActorKey). The words privilegedActor returns are English, and a
/// translated sentence cannot borrow them.
pub fn privilegedActorKey() []const u8 {
    return actor_key_root;
}

/// Renders a command so that running it grants the privileges the operation
/// needs (upstream ElevatedCommand). Caller owns the returned memory.
pub fn elevatedCommand(alloc: std.mem.Allocator, command: []const u8) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(alloc, "sudo {s}", .{command});
}

/// Renders an elevated `netbird up` with the given flags, preceded by a
/// `down` (upstream UpCommand). The down is what makes the command work on a
/// connected client: `netbird up` prints "Already connected" and returns
/// without applying any config flag. ";" rather than "&&" so the line can be
/// pasted into any of the shells a user might have, including PowerShell 5.1,
/// which rejects "&&". Caller owns the returned memory.
pub fn upCommand(alloc: std.mem.Allocator, flags: []const u8) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(alloc, "sudo netbird down; sudo netbird up {s}", .{flags});
}

/// Kernel struct ucred, as SO_PEERCRED reports it.
const Ucred = extern struct {
    pid: i32,
    uid: u32,
    gid: u32,
};

pub const PeerIdentityError = error{
    /// The kernel could not report peer credentials for this fd: it is not a
    /// connected unix stream socket (or one end of a socketpair), or no peer
    /// was recorded (e.g. a listening socket nothing connected to). Consumers
    /// must fail closed on this.
    NoPeerCredentials,
    /// The kernel returned a credential of unexpected size: a failed read,
    /// refused rather than treated as an identity.
    MalformedCredentials,
};

/// Reads the kernel-authenticated identity of the process on the other end of
/// a connected unix socket via SO_PEERCRED (upstream PeerIdentity,
/// peercred_linux.go; upstream ConnIdentity folds into it). The credentials
/// are recorded by the kernel at connect() time and cannot be changed for the
/// life of the connection, so they are not spoofable by the caller. The uid
/// comes only from the kernel, never from anything the client sent.
pub fn peerIdentity(fd: std.posix.fd_t) PeerIdentityError!Identity {
    var cred: Ucred = .{ .pid = 0, .uid = 0, .gid = 0 };
    var len: std.posix.socklen_t = @sizeOf(Ucred);
    const rc = std.os.linux.getsockopt(
        fd,
        std.os.linux.SOL.SOCKET,
        std.os.linux.SO.PEERCRED,
        @ptrCast(&cred),
        &len,
    );
    if (rc != 0) return error.NoPeerCredentials;
    if (len != @sizeOf(Ucred)) return error.MalformedCredentials;
    // A credential with no process behind it (a socket without a connected
    // peer reports zeros) must not be surfaced: uid 0 would read as root.
    if (cred.pid == 0) return error.NoPeerCredentials;
    return .{ .uid = cred.uid, .gid = cred.gid, .pid = cred.pid };
}

// ---------------------------------------------------------------------------
// First-capture concurrency tests. They stage the private initializer
// protocol under simultaneous first calls, which the public surface alone
// cannot observe, so they live here for that access; ipcauth_test.zig pulls
// them into its run.
// ---------------------------------------------------------------------------

test "first capture under simultaneous first calls publishes exactly once" {
    if (std.os.linux.geteuid() == 0) return error.SkipZigTest;

    var gate: SelfCaptureGate = .{};
    self_capture_test_gate = &gate;
    self_state.store(.idle, .monotonic);
    self_id = .{};
    self_may_delegate = false;
    defer self_capture_test_gate = null;

    const Caller = struct {
        start: *std.atomic.Value(bool),
        verdict: bool = false,
        fn run(c: *@This()) void {
            while (!c.start.load(.acquire)) {
                std.Thread.yield() catch {};
            }
            c.verdict = isPrivilegedCaller(Identity{ .uid = 9999 });
        }
    };
    var start = std.atomic.Value(bool).init(false);
    var callers: [8]Caller = undefined;
    var threads: [8]std.Thread = undefined;
    var spawned: usize = 0;
    var joined = false;
    defer {
        start.store(true, .release);
        if (!joined) {
            for (threads[0..spawned]) |t| t.join();
        }
    }
    for (&callers, &threads) |*caller, *t| {
        caller.* = .{ .start = &start };
        t.* = std.Thread.spawn(.{}, Caller.run, .{caller}) catch return error.SkipZigTest;
        spawned += 1;
    }
    // Release the whole group at once, so the first calls overlap.
    start.store(true, .release);
    for (threads[0..spawned]) |t| t.join();
    joined = true;

    // Whatever the interleaving: the capture ran once, every caller's verdict
    // came from that one published pair, and the protocol is at rest.
    try std.testing.expectEqual(@as(u32, 1), gate.wins.load(.monotonic));
    const expected = isPrivilegedCaller(Identity{ .uid = 9999 });
    for (&callers) |*caller| try std.testing.expectEqual(expected, caller.verdict);
    try std.testing.expectEqual(CaptureState.ready, self_state.load(.monotonic));
    try std.testing.expectEqual(std.os.linux.geteuid(), self_id.uid);
}

test "a first call arriving during the capture waits for its publication" {
    if (std.os.linux.geteuid() == 0) return error.SkipZigTest;

    var gate: SelfCaptureGate = .{ .open = .init(false) };
    self_capture_test_gate = &gate;
    self_state.store(.idle, .monotonic);
    self_id = .{};
    self_may_delegate = false;
    defer self_capture_test_gate = null;

    const Call = struct {
        result: ?Identity = null,
        fn run(c: *@This()) void {
            c.result = selfDelegatesTo();
        }
    };
    var capturer: Call = .{};
    var waiter: Call = .{};
    var t1: ?std.Thread = null;
    var t2: ?std.Thread = null;
    var joined = false;
    defer {
        gate.open.store(true, .release);
        if (!joined) {
            if (t1) |t| t.join();
            if (t2) |t| t.join();
        }
    }

    t1 = std.Thread.spawn(.{}, Call.run, .{&capturer}) catch return error.SkipZigTest;

    // Hold the capture until the capturing thread says it is inside, then let
    // a second first call arrive against the held capture.
    var spins: usize = 0;
    while (!gate.entered.load(.acquire)) {
        spins += 1;
        if (spins > 10_000_000) {
            gate.open.store(true, .release);
            t1.?.join();
            joined = true;
            return error.TestUnexpectedResult;
        }
        std.Thread.yield() catch {};
    }

    t2 = std.Thread.spawn(.{}, Call.run, .{&waiter}) catch return error.SkipZigTest;

    // The second caller must meet the held capture and fall into its wait,
    // never capture on its own.
    spins = 0;
    while (!gate.waiter_seen.load(.acquire)) {
        spins += 1;
        if (spins > 10_000_000) break;
        std.Thread.yield() catch {};
    }
    const one_won_while_held = gate.wins.load(.monotonic) == 1;

    gate.open.store(true, .release);
    t1.?.join();
    t2.?.join();
    joined = true;

    try std.testing.expect(gate.waiter_seen.load(.monotonic));
    try std.testing.expect(one_won_while_held);
    try std.testing.expectEqual(@as(u32, 1), gate.wins.load(.monotonic));
    // Both callers read the published pair, never a half-published state.
    const for_caller = capturer.result orelse return error.TestUnexpectedResult;
    const for_waiter = waiter.result orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(std.os.linux.geteuid(), for_caller.uid);
    try std.testing.expectEqual(self_id.uid, for_waiter.uid);
}
