// Port of netbird client/net/fwmark.go (v0.79.0), BSD-3-Clause.
// Packet-mark values the firewall rules match and set. Upstream reads the
// range base from NB_FWMARK_BASE; the router port uses the default base
// (no env override) since nothing else claims mark bits on Keenetic.
pub const base: u32 = 0x1bd00;
pub const control_plane: u32 = 0x1bd00;
pub const data_plane_in: u32 = 0x1bd10;
pub const data_plane_out: u32 = 0x1bd11;
pub const redirected: u32 = 0x1bd20;
pub const masquerade: u32 = 0x1bd21;
pub const masquerade_return: u32 = 0x1bd22;

pub const data_plane_lower: u32 = 0x1bd10;
pub const data_plane_upper: u32 = 0x1bdff;

pub fn isDataPlaneMark(mark: u32) bool {
    return mark >= data_plane_lower and mark <= data_plane_upper;
}

// Hex spellings used in iptables specs ("%#x" in Go).
pub const control_plane_hex = "0x1bd00";
pub const data_plane_in_hex = "0x1bd10";
pub const data_plane_out_hex = "0x1bd11";
pub const redirected_hex = "0x1bd20";
pub const masquerade_hex = "0x1bd21";
pub const masquerade_return_hex = "0x1bd22";
