// Port of netbird client/internal/portforward/state.go (v0.79.0), BSD-3-Clause:
// crash-recovery state. Only the JSON encoding and the cleanup order are
// ported; persistence belongs to the (unwritten) state manager.
const std = @import("std");
const discover = @import("discover.zig");

pub const Error = error{
    NoSpace,
    DeleteFailed,
};

pub const name = "port_forward_state";

pub const State = struct {
    internal_port: u16 = 0,
    protocol_buf: [8]u8 = undefined,
    protocol_len: usize = 0,

    pub fn protocol(s: *const State) []const u8 {
        return s.protocol_buf[0..s.protocol_len];
    }

    pub fn setProtocol(s: *State, proto: []const u8) Error!void {
        if (proto.len > s.protocol_buf.len) return Error.NoSpace;
        @memcpy(s.protocol_buf[0..proto.len], proto);
        s.protocol_len = proto.len;
    }

    /// Byte-identical to Go's json.Marshal of State: field order fixed,
    /// omitempty on both fields, no spaces. Protocols are udp/tcp only,
    /// so no escaping can occur.
    pub fn encodeJson(s: *const State, out: []u8) Error![]u8 {
        var len: usize = 0;
        out[0] = '{';
        len = 1;
        if (s.internal_port != 0) {
            const num = std.fmt.bufPrint(out[len..], "\"internal_port\":{d}", .{s.internal_port}) catch return Error.NoSpace;
            len += num.len;
        }
        if (s.protocol_len != 0) {
            if (len > 1) {
                if (len + 1 > out.len) return Error.NoSpace;
                out[len] = ',';
                len += 1;
            }
            const p = std.fmt.bufPrint(out[len..], "\"protocol\":\"{s}\"", .{s.protocol()}) catch return Error.NoSpace;
            len += p.len;
        }
        if (len + 1 > out.len) return Error.NoSpace;
        out[len] = '}';
        len += 1;
        return out[0..len];
    }
};

/// Port of State.Cleanup: re-discover the gateway and delete the mapping.
/// Discovery failure is not an error (the gateway may be gone); only a
/// failed delete on a found gateway is.
pub fn cleanup(internal_port: u16, proto: []const u8, deadline_ms: i64) Error!void {
    if (internal_port == 0) return;
    var gw = discover.discover(deadline_ms) catch return;
    defer gw.close();
    gw.deletePortMapping(proto, internal_port, discover.discovery_timeout_ms) catch return Error.DeleteFailed;
}
