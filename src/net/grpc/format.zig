// Pure gRPC value helpers (grpc-timeout formatting, grpc-message decoding).
// std-only, so the same-dir grpc_test.zig suite stays runnable under
// build.zig discovery (which gives each suite no named imports).

const std = @import("std");

pub const Error = error{
    GrpcProtocol,
    OutOfMemory,
};

/// Format nanoseconds as a grpc-timeout value ("50M", "5S", ...).
pub fn formatTimeout(ns: i64, out: *[32]u8) []u8 {
    const units = [_]struct { div: i64, suf: u8 }{
        .{ .div = 3600 * std.time.ns_per_s, .suf = 'H' },
        .{ .div = 60 * std.time.ns_per_s, .suf = 'M' },
        .{ .div = std.time.ns_per_s, .suf = 'S' },
        .{ .div = std.time.ns_per_ms, .suf = 'm' },
        .{ .div = std.time.ns_per_us, .suf = 'u' },
        .{ .div = 1, .suf = 'n' },
    };
    for (units) |u| {
        if (@rem(ns, u.div) == 0) {
            return std.fmt.bufPrint(out, "{d}{c}", .{ @divTrunc(ns, u.div), u.suf }) catch unreachable;
        }
    }
    unreachable;
}

/// Percent-decode a grpc-message value into out (out must fit the decoded
/// form, which never exceeds src.len).
pub fn decodeMessage(src: []const u8, out: []u8) Error![]u8 {
    var i: usize = 0;
    var o: usize = 0;
    while (i < src.len) {
        if (src[i] == '%') {
            if (i + 2 >= src.len) return Error.GrpcProtocol;
            const hi = std.fmt.charToDigit(src[i + 1], 16) catch return Error.GrpcProtocol;
            const lo = std.fmt.charToDigit(src[i + 2], 16) catch return Error.GrpcProtocol;
            out[o] = hi * 16 + lo;
            o += 1;
            i += 3;
        } else {
            out[o] = src[i];
            o += 1;
            i += 1;
        }
    }
    return out[0..o];
}
