// HPACK decoder regression: fields emitted from the dynamic table must
// stay stable when a later field in the same block evicts and compacts
// the arena (upstream Go strings are immutable; conn fields_buf keeps
// every emitted slice until the next block).

const std = @import("std");
const hpack = @import("hpack.zig");

const Collector = struct {
    names: [8][]const u8 = undefined,
    values: [8][]const u8 = undefined,
    len: usize = 0,

    fn emit(ctx_ptr: ?*anyopaque, hf: hpack.HeaderField) void {
        const self: *Collector = @ptrCast(@alignCast(ctx_ptr.?));
        self.names[self.len] = hf.name;
        self.values[self.len] = hf.value;
        self.len += 1;
    }
};

test "earlier emitted dynamic entry survives later eviction in same block" {
    // Table fits one entry (36) but not two (36+37): the second add
    // evicts and compacts, overwriting arena bytes the first emit aliases.
    var d = hpack.Decoder.init(64);
    // Block 1: table <- (aaa, x) via literal with incremental indexing.
    const setup = [_]u8{ 0x40, 0x03, 'a', 'a', 'a', 0x01, 'x' };
    var c1 = Collector{};
    try d.decodeBlock(&setup, &c1, Collector.emit);
    try std.testing.expectEqual(@as(usize, 1), c1.len);
    // Block 2: indexed (aaa, x), then incremental (bbb, yy) evicting it.
    const block = [_]u8{ 0xbe, 0x40, 0x03, 'b', 'b', 'b', 0x02, 'y', 'y' };
    var c2 = Collector{};
    try d.decodeBlock(&block, &c2, Collector.emit);
    try std.testing.expectEqual(@as(usize, 2), c2.len);
    try std.testing.expectEqualStrings("aaa", c2.names[0]);
    try std.testing.expectEqualStrings("x", c2.values[0]);
    try std.testing.expectEqualStrings("bbb", c2.names[1]);
    try std.testing.expectEqualStrings("yy", c2.values[1]);
}
