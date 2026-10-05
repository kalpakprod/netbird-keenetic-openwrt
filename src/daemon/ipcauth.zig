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
// captures in package init). selfMayDelegate additionally requires this
// process to be unprivileged: see mayDelegate. On Linux reading it cannot
// fail (upstream self_unix.go returns no error), so there is no selfKnown
// flag; the parameterized isPrivilegedCallerWith/isDaemonSelfWith keep the
// decision testable.
var self_id: Identity = .{};
var self_may_delegate = false;
var self_captured = std.atomic.Value(bool).init(false);

fn ensureSelfCaptured() void {
    if (self_captured.load(.acquire)) return;
    const id = currentProcessIdentity();
    // Concurrent duplicate capture writes the same values (the id is a
    // syscall snapshot of constant state); the release store publishes them.
    self_id = id;
    self_may_delegate = mayDelegate(id);
    self_captured.store(true, .release);
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
