// System CA bundle loading for the vendored TLS client (v0.79.0 port scope).
// Sizes files with lseek (no statx): safe on kernel 4.9, unlike
// std Certificate.Bundle.addCertsFromFilePathAbsolute (File.Reader.getSize).

const std = @import("std");

/// Well-known system bundle paths, first hit wins.
const bundle_paths = [_][]const u8{
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/cert.pem",
};

pub const Error = error{
    NoBundleFound,
    ReadFailed,
} || std.mem.Allocator.Error;

/// File size via raw lseek(SEEK_END): no statx.
fn sizeViaLseek(handle: std.Io.File.Handle) Error!u64 {
    const end = std.os.linux.lseek(handle, 0, std.os.linux.SEEK.END);
    if (end > 0xfffffffffffff000) return Error.ReadFailed;
    const back = std.os.linux.lseek(handle, 0, std.os.linux.SEEK.SET);
    if (back > 0xfffffffffffff000) return Error.ReadFailed;
    return end;
}

/// Load the first readable system bundle into cb. Caller owns cb.
pub fn loadSystem(
    cb: *std.crypto.Certificate.Bundle,
    gpa: std.mem.Allocator,
    io: std.Io,
    now: std.Io.Timestamp,
) Error!void {
    for (bundle_paths) |path| {
        loadFile(cb, gpa, io, now, path) catch continue;
        return;
    }
    return Error.NoBundleFound;
}

fn loadFile(
    cb: *std.crypto.Certificate.Bundle,
    gpa: std.mem.Allocator,
    io: std.Io,
    now: std.Io.Timestamp,
    path: []const u8,
) Error!void {
    var file = std.Io.Dir.openFileAbsolute(io, path, .{ .mode = .read_only }) catch {
        return Error.ReadFailed;
    };
    defer file.close(io);
    const size = try sizeViaLseek(file.handle);
    var buf: [4096]u8 = undefined;
    var reader = std.Io.File.Reader.initSize(file, io, &buf, size);
    cb.addCertsFromFile(gpa, &reader, now.toSeconds()) catch {
        return Error.ReadFailed;
    };
}
