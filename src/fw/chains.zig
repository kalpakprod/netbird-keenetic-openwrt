// Port of netbird client/firewall/iptables/{family,chains}_linux.go chain names
// and static specs (v0.79.0), BSD-3-Clause.
// Table/chain constants plus the static rule specs seeded at setup.
// Builders write into a caller-provided slot buffer and return the slice;
// all args are static strings or the borrowed interface name (no alloc).
const std = @import("std");
const fwmark = @import("fwmark.zig");

pub const table_filter = "filter";
pub const table_nat = "nat";
pub const table_mangle = "mangle";

pub const acl_input = "NETBIRD-ACL-INPUT";
pub const rt_fwd_in = "NETBIRD-RT-FWD-IN";
pub const rt_fwd_out = "NETBIRD-RT-FWD-OUT";
pub const rt_pre = "NETBIRD-RT-PRE";
pub const rt_nat = "NETBIRD-RT-NAT";
pub const rt_rdr = "NETBIRD-RT-RDR";
pub const rt_mss_clamp = "NETBIRD-RT-MSSCLAMP";

pub const input = "INPUT";
pub const output = "OUTPUT";
pub const forward = "FORWARD";
pub const prerouting = "PREROUTING";
pub const postrouting = "POSTROUTING";

/// -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT (getConntrackEstablished).
pub fn established(buf: [][]const u8, iface: []const u8) []const []const u8 {
    buf[0] = "-i";
    buf[1] = iface;
    buf[2] = "-m";
    buf[3] = "conntrack";
    buf[4] = "--ctstate";
    buf[5] = "RELATED,ESTABLISHED";
    buf[6] = "-j";
    buf[7] = "ACCEPT";
    return buf[0..8];
}

/// Established rule without the interface match (for NETBIRD-RT-FWD-*).
pub fn establishedBare(buf: [][]const u8) []const []const u8 {
    buf[0] = "-m";
    buf[1] = "conntrack";
    buf[2] = "--ctstate";
    buf[3] = "RELATED,ESTABLISHED";
    buf[4] = "-j";
    buf[5] = "ACCEPT";
    return buf[0..6];
}

/// jumpRuleSpec: -j <target>.
pub fn jump(buf: [][]const u8, target: []const u8) []const []const u8 {
    buf[0] = "-j";
    buf[1] = target;
    return buf[0..2];
}

pub fn inputDrop(buf: [][]const u8, iface: []const u8) []const []const u8 {
    buf[0] = "-i";
    buf[1] = iface;
    buf[2] = "-j";
    buf[3] = "DROP";
    return buf[0..4];
}

pub fn inputAclJump(buf: [][]const u8, iface: []const u8) []const []const u8 {
    buf[0] = "-i";
    buf[1] = iface;
    buf[2] = "-j";
    buf[3] = acl_input;
    return buf[0..4];
}

pub fn forwardInJump(buf: [][]const u8, iface: []const u8) []const []const u8 {
    buf[0] = "-i";
    buf[1] = iface;
    buf[2] = "-j";
    buf[3] = rt_fwd_in;
    return buf[0..4];
}

pub fn forwardOutJump(buf: [][]const u8, iface: []const u8) []const []const u8 {
    buf[0] = "-o";
    buf[1] = iface;
    buf[2] = "-j";
    buf[3] = rt_fwd_out;
    return buf[0..4];
}

pub fn forwardDrop(buf: [][]const u8, iface: []const u8) []const []const u8 {
    return inputDrop(buf, iface);
}

/// Mangle FORWARD guard: return traffic for accepted flows.
pub fn mangleGuardEst(buf: [][]const u8, iface: []const u8) []const []const u8 {
    buf[0] = "-i";
    buf[1] = iface;
    buf[2] = "-m";
    buf[3] = "conntrack";
    buf[4] = "--ctstate";
    buf[5] = "RELATED,ESTABLISHED";
    buf[6] = "-j";
    buf[7] = "ACCEPT";
    return buf[0..8];
}

/// Mangle FORWARD guard: externally DNATed traffic off the wg interface
/// reaches FORWARD instead of INPUT, bypassing ACL rules. Mangle runs
/// before filter, so the unmarked share is dropped here where a filter
/// ACCEPT above ours cannot override it.
pub fn mangleGuardDnat(buf: [][]const u8, iface: []const u8) []const []const u8 {
    buf[0] = "-i";
    buf[1] = iface;
    buf[2] = "-m";
    buf[3] = "conntrack";
    buf[4] = "--ctstate";
    buf[5] = "DNAT";
    buf[6] = "-m";
    buf[7] = "mark";
    buf[8] = "!";
    buf[9] = "--mark";
    buf[10] = fwmark.redirected_hex;
    buf[11] = "-j";
    buf[12] = "DROP";
    return buf[0..13];
}

/// Optional FORWARD entry at position 2: redirected (marked) traffic
/// is accepted back into the forward path.
pub fn forwardRedirectAccept(buf: [][]const u8) []const []const u8 {
    buf[0] = "-m";
    buf[1] = "mark";
    buf[2] = "--mark";
    buf[3] = fwmark.redirected_hex;
    buf[4] = "-j";
    buf[5] = "ACCEPT";
    return buf[0..6];
}

/// setupDataPlaneMark: inbound NEW connections off the wg interface get
/// the data-plane CONNMARK.
pub fn dataplaneMarkIn(buf: [][]const u8, iface: []const u8) []const []const u8 {
    buf[0] = "-i";
    buf[1] = iface;
    buf[2] = "-m";
    buf[3] = "conntrack";
    buf[4] = "--ctstate";
    buf[5] = "NEW";
    buf[6] = "-j";
    buf[7] = "CONNMARK";
    buf[8] = "--set-mark";
    buf[9] = fwmark.data_plane_in_hex;
    return buf[0..10];
}

pub fn dataplaneMarkOut(buf: [][]const u8, iface: []const u8) []const []const u8 {
    buf[0] = "-o";
    buf[1] = iface;
    buf[2] = "-m";
    buf[3] = "conntrack";
    buf[4] = "--ctstate";
    buf[5] = "NEW";
    buf[6] = "-j";
    buf[7] = "CONNMARK";
    buf[8] = "--set-mark";
    buf[9] = fwmark.data_plane_out_hex;
    return buf[0..10];
}

pub const ipv4_tcp_header_size: u16 = 40;
pub const ipv6_tcp_header_size: u16 = 60;

/// MSS clamp rule for NETBIRD-RT-MSSCLAMP (addMSSClampingRules):
/// -o <iface> -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss <mtu-40/60>.
/// The MSS text is formatted into the caller-provided val buffer.
pub fn mssClamp(
    buf: [][]const u8,
    val: []u8,
    iface: []const u8,
    mtu: u16,
    v6: bool,
) []const []const u8 {
    const overhead = if (v6) ipv6_tcp_header_size else ipv4_tcp_header_size;
    const mss = mtu - overhead;
    const text = std.fmt.bufPrint(val, "{d}", .{mss}) catch unreachable;
    buf[0] = "-o";
    buf[1] = iface;
    buf[2] = "-p";
    buf[3] = "tcp";
    buf[4] = "--tcp-flags";
    buf[5] = "SYN,RST";
    buf[6] = "SYN";
    buf[7] = "-j";
    buf[8] = "TCPMSS";
    buf[9] = "--set-mss";
    buf[10] = text;
    return buf[0..11];
}

/// Static NAT masquerade rules for NETBIRD-RT-NAT (addPostroutingRules).
pub fn natMasqueradeOut(buf: [][]const u8) []const []const u8 {
    buf[0] = "-m";
    buf[1] = "mark";
    buf[2] = "--mark";
    buf[3] = fwmark.masquerade_hex;
    buf[4] = "!";
    buf[5] = "-o";
    buf[6] = "lo";
    buf[7] = "-j";
    buf[8] = "MASQUERADE";
    return buf[0..9];
}

pub fn natMasqueradeReturn(buf: [][]const u8, iface: []const u8) []const []const u8 {
    buf[0] = "-m";
    buf[1] = "mark";
    buf[2] = "--mark";
    buf[3] = fwmark.masquerade_return_hex;
    buf[4] = "-o";
    buf[5] = iface;
    buf[6] = "-j";
    buf[7] = "MASQUERADE";
    return buf[0..8];
}
