// Port of netbird shared/relay/client/dialer/ws/ws.go (v0.80.0), BSD-3-Clause

const std = @import("std");

pub const Error = error{ UnsupportedScheme, MissingHost, BadUrl, NoSpace };

/// Rewrites a rel/ rels relay address to the websocket endpoint without allocation.
/// On error, `out` is not modified.
pub fn prepareUrl(address: []const u8, out: []u8) Error![]u8 {
    const colon = std.mem.indexOfScalar(u8, address, ':') orelse return error.UnsupportedScheme;
    if (colon == 0) return error.UnsupportedScheme;
    var scheme: [4]u8 = undefined;
    if (colon > scheme.len) return error.UnsupportedScheme;
    for (address[0..colon], 0..) |c, i| scheme[i] = std.ascii.toLower(c);
    const secure = if (std.mem.eql(u8, scheme[0..colon], "rel")) false else if (std.mem.eql(u8, scheme[0..colon], "rels")) true else return error.UnsupportedScheme;
    const rest = address[colon + 1 ..];
    if (!std.mem.startsWith(u8, rest, "//")) return error.MissingHost;
    const authority_end = std.mem.indexOfAny(u8, rest[2..], "/?#") orelse rest.len - 2;
    const authority = rest[2 .. 2 + authority_end];
    const host_start: usize = if (std.mem.lastIndexOfScalar(u8, authority, '@')) |at| at + 1 else 0;
    if (host_start >= authority.len) return error.MissingHost;
    const host = authority[host_start..];
    if (host.len == 0 or (host[0] == '[' and std.mem.indexOfScalar(u8, host, ']') == null)) return error.BadUrl;
    const suffix = rest[2 + authority_end ..];
    // std.Uri cannot preserve Go's arbitrary numeric ports (including empty
    // and >65535), so retain the authority verbatim rather than reformat it.
    for (address) |c| if (c < 32 or c == 127) return error.BadUrl;
    if (std.mem.indexOfScalar(u8, host, ' ') != null) return error.BadUrl;
    const port_start = if (host[0] == '[') blk: {
        const close = std.mem.indexOfScalar(u8, host, ']') orelse return error.BadUrl;
        if (close + 1 == host.len) break :blk host.len;
        if (host[close + 1] != ':') return error.BadUrl;
        break :blk close + 2;
    } else if (std.mem.lastIndexOfScalar(u8, host, ':')) |pos| pos + 1 else host.len;
    for (host[port_start..]) |c| if (!std.ascii.isDigit(c)) return error.BadUrl;
    // Go validates path escapes even though the path is subsequently replaced.
    var i: usize = 0;
    while (i < address.len) : (i += 1) {
        if (address[i] == '%') {
            if (i + 2 >= address.len or !std.ascii.isHex(address[i + 1]) or !std.ascii.isHex(address[i + 2])) return error.BadUrl;
            i += 2;
        }
    }
    const suffix_start = std.mem.indexOfAny(u8, suffix, "?#") orelse suffix.len;
    var tail = suffix[suffix_start..];
    // Go omits an empty fragment, but retains an empty query (ForceQuery).
    if (std.mem.endsWith(u8, tail, "#")) tail = tail[0 .. tail.len - 1];
    const prefix = if (secure) "wss://" else "ws://";
    const needed = prefix.len + authority.len + 6 + tail.len;
    if (needed > out.len) return error.NoSpace;
    var n: usize = 0;
    @memcpy(out[n..][0..prefix.len], prefix);
    n += prefix.len;
    @memcpy(out[n..][0..authority.len], authority);
    n += authority.len;
    @memcpy(out[n..][0..6], "/relay");
    n += 6;
    @memcpy(out[n..][0..tail.len], tail);
    n += tail.len;
    return out[0..n];
}
