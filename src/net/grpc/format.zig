// Pure gRPC value helpers (grpc-timeout formatting, grpc-message decoding).
// std-only, so the same-dir grpc_test.zig suite stays runnable under
// build.zig discovery (which gives each suite no named imports).

const std = @import("std");

pub const Error = error{
    GrpcProtocol,
    OutOfMemory,
};

/// Format nanoseconds as a grpc-timeout value ("5000000u", "100001u", ...).
/// Matches Go grpc EncodeDuration: the first unit (n, u, m, S, M, H) whose
/// upward-rounded value fits in eight decimal digits; nonpositive is "0n".
pub fn formatTimeout(ns: i64, out: *[32]u8) []u8 {
    if (ns <= 0) {
        return std.fmt.bufPrint(out, "0n", .{}) catch unreachable;
    }
    const max_value: i64 = 99999999;
    const units = [_]struct { div: i64, suf: u8 }{
        .{ .div = 1, .suf = 'n' },
        .{ .div = std.time.ns_per_us, .suf = 'u' },
        .{ .div = std.time.ns_per_ms, .suf = 'm' },
        .{ .div = std.time.ns_per_s, .suf = 'S' },
        .{ .div = 60 * std.time.ns_per_s, .suf = 'M' },
        .{ .div = 3600 * std.time.ns_per_s, .suf = 'H' },
    };
    for (units[0 .. units.len - 1]) |u| {
        const v = divUp(ns, u.div);
        if (v <= max_value) {
            return std.fmt.bufPrint(out, "{d}{c}", .{ v, u.suf }) catch unreachable;
        }
    }
    const h = units[units.len - 1];
    return std.fmt.bufPrint(out, "{d}{c}", .{ divUp(ns, h.div), h.suf }) catch unreachable;
}

/// Upward integer division for positive ns (equivalent to
/// (ns + div - 1) / div, but without overflow): q + 1 can only overflow
/// when q == maxInt64, which needs div == 1 and remainder 0, so no + 1.
fn divUp(ns: i64, div: i64) i64 {
    const q = @divTrunc(ns, div);
    return if (@rem(ns, div) > 0) q + 1 else q;
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
