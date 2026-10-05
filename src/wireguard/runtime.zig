// Production Linux runtime adapter: binds the accepted WireGuard Device core
// to a real UDP socket and a real TUN device. Replaces the hand pumps of
// wgtun_test.zig with a reusable start/poll/stop lifecycle for a future
// Engine.Service.
// Single-threaded poll model, matching the Device core (no threads, no TUN
// glue there): poll() drains readable UDP datagrams into Device.receiveDatagram
// and reads TUN packets into Device.sendPacket, then runs Device timers;
// Device callbacks emit encrypted datagrams via the real UDP socket and
// decrypted IP packets via the real TUN. One poll() covers both fds with a
// single poll syscall.
// Raw syscalls only (socket, bind, getsockname, sendto, recvfrom, poll, read,
// write, ioctl, close — all pre-4.9), so this is kernel-4.9 safe.
// IPv4 only: the socket is AF_INET; an Endpoint that is not v4-mapped is
// dropped (router target; wgtun_test skips v6 the same way).
// Reference: upstream wireguard-go device.go send/receive routines (MIT) —
// their goroutine loops collapsed into the caller-driven poll step.
//
// Module boundary: the accepted TUN implementation is src/tun/tun.zig, but
// Zig module roots make ../tun/tun.zig unimportable from src/wireguard/
// ("import of file outside module path"); wgtun_test.zig already carries its
// own attach shim for the same reason. TunDevice below mirrors tun.zig's
// create/read/write/close semantics and constants byte-for-byte (open
// /dev/net/tun, TUNSETIFF IFF_TUN|IFF_NO_PI, SIOCSIFMTU, blocking fd).

const std = @import("std");
const device = @import("device.zig");

const linux = std.os.linux;

/// Raw syscall results encode -errno above this sentinel (same convention as
/// tun.zig).
const max_errno_usize: usize = 0xfffffffffffff000;

fn syscallErrno(n: usize) usize {
    return 0xffffffffffffffff - n + 1;
}

// TUN constants — identical to src/tun/tun.zig (see module boundary note).
const tun_clone_device_path = "/dev/net/tun";
const tunsetiff: u32 = 0x400454ca;
const iff_tun: u16 = 0x0001;
const iff_no_pi: u16 = 0x1000;
const ifnamsiz = 16;

pub const Error = error{
    OutOfMemory,
    CloneMissing,
    OpenFailed,
    NameTooLong,
    IoctlFailed,
    MtuFailed,
    ReadFailed,
    WriteFailed,
    SocketFailed,
    BindFailed,
    GetSockNameFailed,
    PollFailed,
    TunClosed,
    UdpError,
    RecvFailed,
    NotRunning,
    AlreadyRunning,
};

pub const Config = struct {
    /// UDP bind port; 0 lets the kernel pick an ephemeral port.
    bind_port: u16 = 0,
    /// TUN interface name ("wgrt0", or "wgrt%d" for kernel numbering);
    /// null runs UDP-only (no TUN device, decrypted packets dropped by the
    /// Device unless the caller installs its own packet_sink).
    tun_name: ?[]const u8 = null,
    /// TUN MTU when tun_name is set.
    tun_mtu: u16 = 1420,
    /// Tick used by run() between poll steps.
    poll_timeout_ms: i32 = 50,
};

/// Minimal TUN device handle mirroring src/tun/tun.zig's Tun (module
/// boundary note above). Blocking fd: reads happen only after POLLIN.
const TunDevice = struct {
    fd: linux.fd_t,
    name: [ifnamsiz]u8,
    name_len: usize,

    fn ifName(t: *const TunDevice) []const u8 {
        return t.name[0..t.name_len];
    }

    /// CreateTUN: open the clone device, TUNSETIFF, set MTU (tun.zig create).
    /// Name may end in "%d" for kernel numbering (e.g. "tun%d").
    fn create(name: []const u8, mtu: u16) Error!TunDevice {
        if (name.len >= ifnamsiz) return Error.NameTooLong;
        const fd_usize = linux.open(tun_clone_device_path, .{ .ACCMODE = .RDWR, .CLOEXEC = true }, 0);
        if (fd_usize > max_errno_usize) {
            const errno = syscallErrno(fd_usize);
            if (errno == @backingInt(linux.E.NOENT)) return Error.CloneMissing;
            return Error.OpenFailed;
        }
        const fd: linux.fd_t = @intCast(fd_usize);
        errdefer _ = linux.close(fd);
        var ifr: [40]u8 = std.mem.zeroes([40]u8);
        @memcpy(ifr[0..name.len], name);
        std.mem.writeInt(u16, ifr[16..18], iff_tun | iff_no_pi, .little);
        const rc = linux.ioctl(fd, tunsetiff, @intFromPtr(&ifr));
        if (rc > max_errno_usize) return Error.IoctlFailed;
        // kernel may have expanded "%d": read the real name back
        var t = TunDevice{ .fd = fd, .name = undefined, .name_len = 0 };
        const end = std.mem.indexOfScalar(u8, ifr[0..ifnamsiz], 0) orelse ifnamsiz;
        @memcpy(t.name[0..end], ifr[0..end]);
        t.name_len = end;
        try t.setMtu(mtu);
        return t;
    }

    fn close(t: *TunDevice) void {
        _ = linux.close(t.fd);
        t.fd = -1;
    }

    /// Read one IP packet (blocking). Returns the packet length.
    fn read(t: *TunDevice, buf: []u8) Error!usize {
        const n = linux.read(t.fd, buf.ptr, buf.len);
        if (n > max_errno_usize or n == 0) return Error.ReadFailed;
        return n;
    }

    /// Write one IP packet.
    fn write(t: *TunDevice, packet: []const u8) Error!void {
        var off: usize = 0;
        while (off < packet.len) {
            const n = linux.write(t.fd, packet[off..].ptr, packet.len - off);
            if (n > max_errno_usize or n == 0) return Error.WriteFailed;
            off += n;
        }
    }

    fn ifreqSocket() Error!linux.fd_t {
        const s = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
        if (s > max_errno_usize) return Error.SocketFailed;
        return @intCast(s);
    }

    /// setMTU via SIOCSIFMTU (tun.zig setMtu).
    fn setMtu(t: *TunDevice, mtu: u16) Error!void {
        const s = try ifreqSocket();
        defer _ = linux.close(s);
        var ifr: [40]u8 = std.mem.zeroes([40]u8);
        @memcpy(ifr[0..t.name_len], t.ifName());
        std.mem.writeInt(u32, ifr[16..20], mtu, .native);
        const rc = linux.ioctl(s, linux.SIOCSIFMTU, @intFromPtr(&ifr));
        if (rc > max_errno_usize) return Error.MtuFailed;
    }
};

pub const Runtime = struct {
    allocator: std.mem.Allocator,
    dev: *device.Device,
    config: Config,
    sock_fd: linux.fd_t = -1,
    tun: ?TunDevice = null,
    local_port: u16 = 0,
    udp_buf: []u8 = &.{},
    tun_buf: []u8 = &.{},
    running: bool = false,

    /// Prepare an adapter for `dev`. Call start() to open the resources.
    /// While started, the value must stay at its address: the Device
    /// callbacks capture this pointer. stop() clears them, after which the
    /// value may be moved or started again.
    pub fn init(allocator: std.mem.Allocator, dev: *device.Device, config: Config) Runtime {
        return .{ .allocator = allocator, .dev = dev, .config = config };
    }

    /// Open the UDP socket (and the TUN if configured), then install the
    /// Device callbacks. Callbacks go live only once every resource is up,
    /// so the Device never emits into a half-open adapter. On any failure
    /// everything opened so far is closed and the Device is left untouched;
    /// a failed start can be retried.
    pub fn start(r: *Runtime) Error!void {
        if (r.running) return Error.AlreadyRunning;
        errdefer r.stop();

        const fd_usize = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
        if (fd_usize > max_errno_usize) return Error.SocketFailed;
        r.sock_fd = @intCast(fd_usize);
        var sa: linux.sockaddr.in = .{ .port = 0, .addr = 0 }; // INADDR_ANY
        std.mem.writeInt(u16, std.mem.asBytes(&sa.port), r.config.bind_port, .big);
        if (linux.bind(r.sock_fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in)) > max_errno_usize)
            return Error.BindFailed;
        var got: linux.sockaddr.in = std.mem.zeroes(linux.sockaddr.in);
        var slen: linux.socklen_t = @sizeOf(linux.sockaddr.in);
        if (linux.getsockname(r.sock_fd, @ptrCast(&got), &slen) > max_errno_usize)
            return Error.GetSockNameFailed;
        r.local_port = std.mem.readInt(u16, std.mem.asBytes(&got.port), .big);

        if (r.config.tun_name) |name| {
            r.tun = try TunDevice.create(name, r.config.tun_mtu);
        }

        r.udp_buf = try r.allocator.alloc(u8, 65535);
        errdefer {
            r.allocator.free(r.udp_buf);
            r.udp_buf = &.{};
        }
        r.tun_buf = try r.allocator.alloc(u8, 65535);

        r.dev.udp_ctx = @ptrCast(r);
        r.dev.udp_send = udpSend;
        if (r.tun != null) {
            r.dev.sink_ctx = @ptrCast(r);
            r.dev.packet_sink = tunSink;
        }
        r.running = true;
    }

    /// One event-loop step: drain the UDP socket into the Device, read one
    /// TUN packet into the Device, then run Device timers. timeout_ms caps
    /// the wait (poll is level-triggered, so bursts re-fire on later calls).
    pub fn poll(r: *Runtime, timeout_ms: i32) Error!void {
        if (!r.running) return Error.NotRunning;
        var fds: [2]linux.pollfd = undefined;
        var n_fds: usize = 1;
        fds[0] = .{ .fd = r.sock_fd, .events = linux.POLL.IN };
        if (r.tun) |t| {
            fds[1] = .{ .fd = t.fd, .events = linux.POLL.IN };
            n_fds = 2;
        }
        const n = linux.poll(&fds, @intCast(n_fds), timeout_ms);
        if (n > max_errno_usize) {
            if (syscallErrno(n) != @backingInt(linux.E.INTR)) return Error.PollFailed;
            // EINTR: no revents, timers still run below.
        }
        if (fds[0].revents & linux.POLL.NVAL != 0 or
            (n_fds == 2 and fds[1].revents & linux.POLL.NVAL != 0)) return Error.PollFailed;
        if (n_fds == 2 and fds[1].revents & (linux.POLL.ERR | linux.POLL.HUP) != 0)
            return Error.TunClosed;
        // Consume pending UDP errors with SO_ERROR, then return a terminal
        // error even for HUP/ERR with SO_ERROR=0. The owner must stop/restart,
        // never repeatedly treat error-only readiness as a successful tick.
        if (fds[0].revents & (linux.POLL.ERR | linux.POLL.HUP) != 0) {
            var socket_error: i32 = 0;
            var len: linux.socklen_t = @sizeOf(i32);
            _ = linux.getsockopt(r.sock_fd, linux.SOL.SOCKET, linux.SO.ERROR,
                @ptrCast(&socket_error), &len);
            return Error.UdpError;
        }
        if (fds[0].revents & linux.POLL.IN != 0) try r.drainUdp();
        if (n_fds == 2 and fds[1].revents & linux.POLL.IN != 0) try r.readTun();
        r.dev.pollAll(r.nowNs());
    }

    /// Drive poll() until `stop_flag` is set; for one dedicated Engine thread.
    pub fn run(r: *Runtime, stop_flag: *std.atomic.Value(bool)) Error!void {
        while (!stop_flag.load(.acquire)) {
            try r.poll(r.config.poll_timeout_ms);
        }
    }

    /// Close everything and detach from the Device. Idempotent; safe after a
    /// failed (partial) start; callbacks are removed only if they still point
    /// at this adapter.
    pub fn stop(r: *Runtime) void {
        if (r.dev.udp_ctx == @as(?*anyopaque, @ptrCast(r))) {
            r.dev.udp_ctx = null;
            r.dev.udp_send = null;
        }
        if (r.dev.sink_ctx == @as(?*anyopaque, @ptrCast(r))) {
            r.dev.sink_ctx = null;
            r.dev.packet_sink = null;
        }
        if (r.sock_fd >= 0) {
            _ = linux.close(r.sock_fd);
            r.sock_fd = -1;
        }
        if (r.tun) |*t| {
            t.close();
            r.tun = null;
        }
        if (r.udp_buf.len != 0) {
            r.allocator.free(r.udp_buf);
            r.udp_buf = &.{};
        }
        if (r.tun_buf.len != 0) {
            r.allocator.free(r.tun_buf);
            r.tun_buf = &.{};
        }
        r.running = false;
    }

    /// The bound UDP port (0 before start).
    pub fn localPort(r: *const Runtime) u16 {
        return r.local_port;
    }

    /// The TUN interface name, if the adapter created one (for `ip addr` /
    /// `ip link` setup by the owner).
    pub fn tunIfName(r: *const Runtime) ?[]const u8 {
        if (r.tun == null) return null;
        const t: *const TunDevice = &r.tun.?;
        return t.ifName();
    }

    fn nowNs(r: *Runtime) i64 {
        return @intCast(std.Io.Timestamp.now(r.dev.io, .real).nanoseconds);
    }

    /// Recv all queued datagrams (MSG_DONTWAIT), feeding the Device. The
    /// Device may answer synchronously (handshake, keepalive), re-entering
    /// udpSend — safe on a full-duplex socket, single thread.
    fn drainUdp(r: *Runtime) Error!void {
        while (true) {
            var from: linux.sockaddr.in = std.mem.zeroes(linux.sockaddr.in);
            var flen: linux.socklen_t = @sizeOf(linux.sockaddr.in);
            const n = linux.recvfrom(
                r.sock_fd,
                r.udp_buf.ptr,
                r.udp_buf.len,
                linux.MSG.DONTWAIT,
                @ptrCast(&from),
                &flen,
            );
            if (n > max_errno_usize) {
                const errno = syscallErrno(n);
                if (errno == @backingInt(linux.E.AGAIN)) return; // drained
                if (errno == @backingInt(linux.E.INTR)) continue;
                return Error.RecvFailed;
            }
            if (n == 0) continue; // empty datagram: nothing to decrypt
            if (from.family != linux.AF.INET) continue;
            r.dev.receiveDatagram(r.udp_buf[0..n], endpointFromSockaddr(from), r.nowNs());
        }
    }

    /// One TUN packet per POLLIN wakeup. TunDevice.read blocks, which is safe
    /// here: we are the only reader and the kernel said the fd is readable. A
    /// second, would-be-draining read cannot distinguish EAGAIN from a real
    /// failure through the blocking-read error (ReadFailed), so bursts are
    /// served by consecutive poll wakeups instead.
    fn readTun(r: *Runtime) Error!void {
        const t: *TunDevice = &r.tun.?;
        const n = try t.read(r.tun_buf);
        if (n == 0) return;
        r.dev.sendPacket(r.tun_buf[0..n], r.nowNs());
    }

    /// Device -> real UDP. The Device API returns void, so a failed sendto
    /// (ENOBUFS, route lost) drops the datagram, like wireguard-go's send
    /// path; start/poll/stop errors are the ones that propagate.
    fn udpSend(ctx: ?*anyopaque, datagram: []const u8, to: device.Endpoint) void {
        const r: *Runtime = @ptrCast(@alignCast(ctx.?));
        var sa = sockaddrFromEndpoint(to) orelse return; // non-v4 endpoint on v4 socket
        _ = linux.sendto(
            r.sock_fd,
            datagram.ptr,
            datagram.len,
            linux.MSG.DONTWAIT,
            @ptrCast(&sa),
            @sizeOf(linux.sockaddr.in),
        );
    }

    /// Device -> real TUN. Same drop-on-error note as udpSend.
    fn tunSink(ctx: ?*anyopaque, peer: *device.Peer, packet: []const u8) void {
        _ = peer;
        const r: *Runtime = @ptrCast(@alignCast(ctx.?));
        const t: *TunDevice = &r.tun.?;
        t.write(packet) catch {};
    }
};

/// The Device stores IPv4 endpoints as v4-mapped IPv6 (::ffff:a.b.c.d).
/// A non-mapped (real IPv6) endpoint cannot leave the AF_INET socket: null.
fn sockaddrFromEndpoint(e: device.Endpoint) ?linux.sockaddr.in {
    for (e.ip[0..10]) |b| {
        if (b != 0) return null;
    }
    if (e.ip[10] != 0xff or e.ip[11] != 0xff) return null;
    var sa: linux.sockaddr.in = .{ .port = 0, .addr = 0 };
    std.mem.writeInt(u16, std.mem.asBytes(&sa.port), e.port, .big);
    @memcpy(std.mem.asBytes(&sa.addr), e.ip[12..16]);
    return sa;
}

fn endpointFromSockaddr(sa: linux.sockaddr.in) device.Endpoint {
    var ip: [16]u8 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0 };
    @memcpy(ip[12..16], std.mem.asBytes(&sa.addr));
    return .{
        .ip = ip,
        .port = std.mem.readInt(u16, std.mem.asBytes(&sa.port), .big),
    };
}
