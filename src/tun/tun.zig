// Linux TUN device: open /dev/net/tun, TUNSETIFF with IFF_TUN|IFF_NO_PI,
// read/write IP packets, MTU get/set, ifindex lookup. Raw syscalls only
// (open, ioctl, socket, read, write, close — all pre-4.9).
// Reference: upstream wireguard-go tun/tun_linux.go CreateTUN/setMTU and
// netbird client/iface/device/device_usp_unix.go (tun.CreateTUN call).
// No IFF_VNET_HDR (that needs virtio-net header framing, out of scope).

const std = @import("std");
const linux = std.os.linux;

pub const tunsetiff: u32 = 0x400454ca;
pub const iff_tun: u16 = 0x0001;
pub const iff_no_pi: u16 = 0x1000;
pub const ifnamsiz = 16;
pub const clone_device_path = "/dev/net/tun";

pub const Error = error{
    CloneMissing,
    OpenFailed,
    NameTooLong,
    IoctlFailed,
    SocketFailed,
    ReadFailed,
    WriteFailed,
    MtuFailed,
    Timeout,
};

pub const Tun = struct {
    fd: linux.fd_t,
    name: [ifnamsiz]u8,
    name_len: usize,

    pub fn ifName(t: *const Tun) []const u8 {
        return t.name[0..t.name_len];
    }

    /// CreateTUN: open the clone device, TUNSETIFF, set MTU.
    /// Name may end in "%d" for kernel numbering (e.g. "tun%d").
    pub fn create(name: []const u8, mtu: u16) Error!Tun {
        if (name.len >= ifnamsiz) return Error.NameTooLong;
        const fd_usize = linux.open(clone_device_path, .{ .ACCMODE = .RDWR, .CLOEXEC = true }, 0);
        if (fd_usize > 0xfffffffffffff000) {
            const errno = 0xffffffffffffffff - fd_usize + 1;
            if (errno == @intFromEnum(linux.E.NOENT)) return Error.CloneMissing;
            return Error.OpenFailed;
        }
        const fd: linux.fd_t = @intCast(fd_usize);
        errdefer _ = linux.close(fd);
        var ifr: [40]u8 = std.mem.zeroes([40]u8);
        @memcpy(ifr[0..name.len], name);
        std.mem.writeInt(u16, ifr[16..18], iff_tun | iff_no_pi, .little);
        const rc = linux.ioctl(fd, tunsetiff, @intFromPtr(&ifr));
        if (rc > 0xfffffffffffff000) return Error.IoctlFailed;
        // kernel may have expanded "%d": read the real name back
        var tun = Tun{ .fd = fd, .name = undefined, .name_len = 0 };
        const end = std.mem.indexOfScalar(u8, ifr[0..ifnamsiz], 0) orelse ifnamsiz;
        @memcpy(tun.name[0..end], ifr[0..end]);
        tun.name_len = end;
        try tun.setMtu(mtu);
        return tun;
    }

    pub fn close(t: *Tun) void {
        _ = linux.close(t.fd);
        t.fd = -1;
    }

    /// Read one IP packet (blocking). Returns the packet length.
    pub fn read(t: *Tun, buf: []u8) Error!usize {
        const n = linux.read(t.fd, buf.ptr, buf.len);
        if (n > 0xfffffffffffff000 or n == 0) return Error.ReadFailed;
        return n;
    }

    /// Wait until a packet is readable (poll POLLIN, pre-4.9 syscall).
    pub fn waitReadable(t: *Tun, timeout_ms: i32) Error!void {
        var pfd = [_]linux.pollfd{.{ .fd = t.fd, .events = linux.POLL.IN }};
        const n = linux.poll(&pfd, 1, timeout_ms);
        if (n > 0xfffffffffffff000) return Error.ReadFailed;
        if (n == 0) return Error.Timeout;
    }

    /// Write one IP packet.
    pub fn write(t: *Tun, packet: []const u8) Error!void {
        var off: usize = 0;
        while (off < packet.len) {
            const n = linux.write(t.fd, packet[off..].ptr, packet.len - off);
            if (n > 0xfffffffffffff000 or n == 0) return Error.WriteFailed;
            off += n;
        }
    }

    fn ifreqSocket() Error!linux.fd_t {
        const s = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
        if (s > 0xfffffffffffff000) return Error.SocketFailed;
        return @intCast(s);
    }

    /// setMTU via SIOCSIFMTU.
    pub fn setMtu(t: *Tun, mtu: u16) Error!void {
        const s = try ifreqSocket();
        defer _ = linux.close(s);
        var ifr: [40]u8 = std.mem.zeroes([40]u8);
        @memcpy(ifr[0..t.name_len], t.ifName());
        std.mem.writeInt(u32, ifr[16..20], mtu, .native);
        const rc = linux.ioctl(s, linux.SIOCSIFMTU, @intFromPtr(&ifr));
        if (rc > 0xfffffffffffff000) return Error.MtuFailed;
    }

    /// MTU via SIOCGIFMTU.
    pub fn getMtu(t: *Tun) Error!u16 {
        const s = try ifreqSocket();
        defer _ = linux.close(s);
        var ifr: [40]u8 = std.mem.zeroes([40]u8);
        @memcpy(ifr[0..t.name_len], t.ifName());
        const rc = linux.ioctl(s, linux.SIOCGIFMTU, @intFromPtr(&ifr));
        if (rc > 0xfffffffffffff000) return Error.MtuFailed;
        return @intCast(std.mem.readInt(i32, ifr[16..20], .native));
    }

    /// Interface index via SIOCGIFINDEX (needed for rtnetlink calls).
    pub fn ifIndex(t: *Tun) Error!u32 {
        const s = try ifreqSocket();
        defer _ = linux.close(s);
        var ifr: [40]u8 = std.mem.zeroes([40]u8);
        @memcpy(ifr[0..t.name_len], t.ifName());
        const rc = linux.ioctl(s, linux.SIOCGIFINDEX, @intFromPtr(&ifr));
        if (rc > 0xfffffffffffff000) return Error.IoctlFailed;
        return std.mem.readInt(u32, ifr[16..20], .native);
    }
};
