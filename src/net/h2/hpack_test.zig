// Port of golang.org/x/net/http2/hpack (BSD-3-Clause) — tests.
// Header-block vectors: RFC 7541 Appendix C hex dumps, each verified by
// decoding with Go x/net/http2/hpack (gen/h2vecs).

const std = @import("std");
const hpack = @import("hpack.zig");

fn hexToBytesAlloc(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, s.len / 2);
    _ = try std.fmt.hexToBytes(out, s);
    return out;
}

const Collector = struct {
    names: [16][]const u8 = undefined,
    values: [16][]const u8 = undefined,
    len: usize = 0,

    fn emitFn(ctx: ?*anyopaque, f: hpack.HeaderField) void {
        const self: *Collector = @ptrCast(@alignCast(ctx.?));
        self.names[self.len] = f.name;
        self.values[self.len] = f.value;
        self.len += 1;
    }

    fn check(self: *Collector, want_names: []const []const u8, want_values: []const []const u8) !void {
        try std.testing.expectEqual(want_names.len, self.len);
        for (want_names, 0..) |w, i| {
            try std.testing.expectEqualStrings(w, self.names[i]);
            try std.testing.expectEqualStrings(want_values[i], self.values[i]);
        }
    }
};

test "C.2 field representations" {
    var d = hpack.Decoder.init(4096);
    var col = Collector{};
    const ctx: ?*anyopaque = @ptrCast(&col);

    // C.2.1 literal with incremental indexing, new name
    const b1 = try hexToBytesAlloc(std.testing.allocator, "400a637573746f6d2d6b65790d637573746f6d2d686561646572");
    defer std.testing.allocator.free(b1);
    try d.decodeBlock(b1, ctx, Collector.emitFn);
    try col.check(
        &[_][]const u8{"custom-key"},
        &[_][]const u8{"custom-header"},
    );

    // C.2.2 literal without indexing, indexed name
    col.len = 0;
    const b2 = try hexToBytesAlloc(std.testing.allocator, "040c2f73616d706c652f70617468");
    defer std.testing.allocator.free(b2);
    try d.decodeBlock(b2, ctx, Collector.emitFn);
    try col.check(&[_][]const u8{":path"}, &[_][]const u8{"/sample/path"});

    // C.2.3 literal never indexed, new name
    col.len = 0;
    const b3 = try hexToBytesAlloc(std.testing.allocator, "100870617373776f726406736563726574");
    defer std.testing.allocator.free(b3);
    try d.decodeBlock(b3, ctx, Collector.emitFn);
    try col.check(&[_][]const u8{"password"}, &[_][]const u8{"secret"});

    // C.2.4 indexed
    col.len = 0;
    const b4 = try hexToBytesAlloc(std.testing.allocator, "82");
    defer std.testing.allocator.free(b4);
    try d.decodeBlock(b4, ctx, Collector.emitFn);
    try col.check(&[_][]const u8{":method"}, &[_][]const u8{"GET"});
}

test "C.3 requests without huffman" {
    var d = hpack.Decoder.init(4096);
    var col = Collector{};
    const ctx: ?*anyopaque = @ptrCast(&col);

    const b1 = try hexToBytesAlloc(std.testing.allocator, "828684410f7777772e6578616d706c652e636f6d");
    defer std.testing.allocator.free(b1);
    try d.decodeBlock(b1, ctx, Collector.emitFn);
    try col.check(
        &[_][]const u8{ ":method", ":scheme", ":path", ":authority" },
        &[_][]const u8{ "GET", "http", "/", "www.example.com" },
    );
    try std.testing.expectEqual(@as(u32, 57), d.dyn_tab.table_size);

    col.len = 0;
    const b2 = try hexToBytesAlloc(std.testing.allocator, "828684be58086e6f2d6361636865");
    defer std.testing.allocator.free(b2);
    try d.decodeBlock(b2, ctx, Collector.emitFn);
    try col.check(
        &[_][]const u8{ ":method", ":scheme", ":path", ":authority", "cache-control" },
        &[_][]const u8{ "GET", "http", "/", "www.example.com", "no-cache" },
    );
    try std.testing.expectEqual(@as(u32, 110), d.dyn_tab.table_size);

    col.len = 0;
    const b3 = try hexToBytesAlloc(std.testing.allocator, "828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565");
    defer std.testing.allocator.free(b3);
    try d.decodeBlock(b3, ctx, Collector.emitFn);
    try col.check(
        &[_][]const u8{ ":method", ":scheme", ":path", ":authority", "custom-key" },
        &[_][]const u8{ "GET", "https", "/index.html", "www.example.com", "custom-value" },
    );
    try std.testing.expectEqual(@as(u32, 164), d.dyn_tab.table_size);
}

test "C.4 requests with huffman" {
    var d = hpack.Decoder.init(4096);
    var col = Collector{};
    const ctx: ?*anyopaque = @ptrCast(&col);

    const b1 = try hexToBytesAlloc(std.testing.allocator, "828684418cf1e3c2e5f23a6ba0ab90f4ff");
    defer std.testing.allocator.free(b1);
    try d.decodeBlock(b1, ctx, Collector.emitFn);
    try col.check(
        &[_][]const u8{ ":method", ":scheme", ":path", ":authority" },
        &[_][]const u8{ "GET", "http", "/", "www.example.com" },
    );

    col.len = 0;
    const b2 = try hexToBytesAlloc(std.testing.allocator, "828684be5886a8eb10649cbf");
    defer std.testing.allocator.free(b2);
    try d.decodeBlock(b2, ctx, Collector.emitFn);
    try col.check(
        &[_][]const u8{ ":method", ":scheme", ":path", ":authority", "cache-control" },
        &[_][]const u8{ "GET", "http", "/", "www.example.com", "no-cache" },
    );

    col.len = 0;
    const b3 = try hexToBytesAlloc(std.testing.allocator, "828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf");
    defer std.testing.allocator.free(b3);
    try d.decodeBlock(b3, ctx, Collector.emitFn);
    try col.check(
        &[_][]const u8{ ":method", ":scheme", ":path", ":authority", "custom-key" },
        &[_][]const u8{ "GET", "https", "/index.html", "www.example.com", "custom-value" },
    );
}

test "C.5 responses without huffman" {
    var d = hpack.Decoder.init(4096);
    var col = Collector{};
    const ctx: ?*anyopaque = @ptrCast(&col);

    const b1 = try hexToBytesAlloc(std.testing.allocator, "4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d706c652e636f6d");
    defer std.testing.allocator.free(b1);
    try d.decodeBlock(b1, ctx, Collector.emitFn);
    try col.check(
        &[_][]const u8{ ":status", "cache-control", "date", "location" },
        &[_][]const u8{ "302", "private", "Mon, 21 Oct 2013 20:13:21 GMT", "https://www.example.com" },
    );

    col.len = 0;
    const b2 = try hexToBytesAlloc(std.testing.allocator, "4803333037c1c0bf");
    defer std.testing.allocator.free(b2);
    try d.decodeBlock(b2, ctx, Collector.emitFn);
    try col.check(
        &[_][]const u8{ ":status", "cache-control", "date", "location" },
        &[_][]const u8{ "307", "private", "Mon, 21 Oct 2013 20:13:21 GMT", "https://www.example.com" },
    );

    col.len = 0;
    const b3 = try hexToBytesAlloc(std.testing.allocator, "88c1611d4d6f6e2c203231204f637420323031332032303a31333a323220474d54c05a04677a69707738666f6f3d4153444a4b48514b425a584f5157454f50495541585157454f49553b206d61782d6167653d333630303b2076657273696f6e3d31");
    defer std.testing.allocator.free(b3);
    try d.decodeBlock(b3, ctx, Collector.emitFn);
    try col.check(
        &[_][]const u8{ ":status", "cache-control", "date", "location", "content-encoding", "set-cookie" },
        &[_][]const u8{ "200", "private", "Mon, 21 Oct 2013 20:13:22 GMT", "https://www.example.com", "gzip", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1" },
    );
}

test "C.6 responses with huffman" {
    var d = hpack.Decoder.init(4096);
    var col = Collector{};
    const ctx: ?*anyopaque = @ptrCast(&col);

    const b1 = try hexToBytesAlloc(std.testing.allocator, "488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3");
    defer std.testing.allocator.free(b1);
    try d.decodeBlock(b1, ctx, Collector.emitFn);
    try col.check(
        &[_][]const u8{ ":status", "cache-control", "date", "location" },
        &[_][]const u8{ "302", "private", "Mon, 21 Oct 2013 20:13:21 GMT", "https://www.example.com" },
    );

    col.len = 0;
    const b2 = try hexToBytesAlloc(std.testing.allocator, "4883640effc1c0bf");
    defer std.testing.allocator.free(b2);
    try d.decodeBlock(b2, ctx, Collector.emitFn);
    try col.check(
        &[_][]const u8{ ":status", "cache-control", "date", "location" },
        &[_][]const u8{ "307", "private", "Mon, 21 Oct 2013 20:13:21 GMT", "https://www.example.com" },
    );

    col.len = 0;
    const b3 = try hexToBytesAlloc(std.testing.allocator, "88c16196d07abe941054d444a8200595040b8166e084a62d1bffc05a839bd9ab77ad94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007");
    defer std.testing.allocator.free(b3);
    try d.decodeBlock(b3, ctx, Collector.emitFn);
    try col.check(
        &[_][]const u8{ ":status", "cache-control", "date", "location", "content-encoding", "set-cookie" },
        &[_][]const u8{ "200", "private", "Mon, 21 Oct 2013 20:13:22 GMT", "https://www.example.com", "gzip", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1" },
    );
}

test "encoder matches Go byte-for-byte" {
    // Go Encoder outputs from gen/h2vecs (deterministic: huffman when
    // shorter, newest-name index, index everything non-sensitive).
    var e = hpack.Encoder.init();
    var out: [256]u8 = undefined;

    var n: usize = 0;
    n += try e.writeField(out[n..], .{ .name = ":method", .value = "GET" });
    n += try e.writeField(out[n..], .{ .name = ":scheme", .value = "http" });
    n += try e.writeField(out[n..], .{ .name = ":path", .value = "/" });
    n += try e.writeField(out[n..], .{ .name = ":authority", .value = "www.example.com" });
    const want1 = try hexToBytesAlloc(std.testing.allocator, "828684418cf1e3c2e5f23a6ba0ab90f4ff");
    defer std.testing.allocator.free(want1);
    try std.testing.expectEqualSlices(u8, want1, out[0..n]);

    n = 0;
    n += try e.writeField(out[n..], .{ .name = ":method", .value = "GET" });
    n += try e.writeField(out[n..], .{ .name = ":scheme", .value = "http" });
    n += try e.writeField(out[n..], .{ .name = ":path", .value = "/" });
    n += try e.writeField(out[n..], .{ .name = ":authority", .value = "www.example.com" });
    n += try e.writeField(out[n..], .{ .name = "cache-control", .value = "no-cache" });
    const want2 = try hexToBytesAlloc(std.testing.allocator, "828684be5886a8eb10649cbf");
    defer std.testing.allocator.free(want2);
    try std.testing.expectEqualSlices(u8, want2, out[0..n]);
}

test "encoder response matches Go byte-for-byte" {
    var e = hpack.Encoder.init();
    var out: [256]u8 = undefined;
    var n: usize = 0;
    n += try e.writeField(out[n..], .{ .name = ":status", .value = "302" });
    n += try e.writeField(out[n..], .{ .name = "cache-control", .value = "private" });
    n += try e.writeField(out[n..], .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" });
    n += try e.writeField(out[n..], .{ .name = "location", .value = "https://www.example.com" });
    const want = try hexToBytesAlloc(std.testing.allocator, "4e8264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3");
    defer std.testing.allocator.free(want);
    try std.testing.expectEqualSlices(u8, want, out[0..n]);
}

test "decoder errors" {
    var d = hpack.Decoder.init(4096);
    var col = Collector{};
    const ctx: ?*anyopaque = @ptrCast(&col);

    // truncated varint
    try std.testing.expectError(hpack.Error.Truncated, d.decodeBlock(&[_]u8{0xff}, ctx, Collector.emitFn));
    // index 0
    try std.testing.expectError(hpack.Error.InvalidIndex, d.decodeBlock(&[_]u8{0x80}, ctx, Collector.emitFn));
    // index past table
    var d2 = hpack.Decoder.init(4096);
    try std.testing.expectError(hpack.Error.InvalidIndex, d2.decodeBlock(&[_]u8{0xff, 0x01}, ctx, Collector.emitFn));
    // table size update too large
    var d3 = hpack.Decoder.init(100);
    try std.testing.expectError(hpack.Error.TableSizeTooLarge, d3.decodeBlock(&[_]u8{0x3f, 0xe1, 0x1f}, ctx, Collector.emitFn));
    // size update after a field with nonempty table
    var d4 = hpack.Decoder.init(4096);
    const blk = try hexToBytesAlloc(std.testing.allocator, "400a637573746f6d2d6b65790d637573746f6d2d6865616465723f00");
    defer std.testing.allocator.free(blk);
    try std.testing.expectError(hpack.Error.TableSizeUpdateNotAtStart, d4.decodeBlock(blk, ctx, Collector.emitFn));
    // bad huffman padding: "a" (00011) + "110" instead of ones.
    // 0x01 literal indexed-name 1, 0x81 huffman len 1, 0x1e payload.
    var d5 = hpack.Decoder.init(4096);
    const bad = try hexToBytesAlloc(std.testing.allocator, "01811e");
    defer std.testing.allocator.free(bad);
    try std.testing.expectError(hpack.Error.InvalidHuffman, d5.decodeBlock(bad, ctx, Collector.emitFn));
}

test "huffman round trip over all byte values" {
    var all: [256]u8 = undefined;
    for (&all, 0..) |*b, i| b.* = @intCast(i);
    var enc: [1024]u8 = undefined;
    const n = try hpack.huffman.encode(&enc, &all);
    try std.testing.expectEqual(hpack.huffman.encodedLen(&all), n);
    var dec: [256]u8 = undefined;
    const m = try hpack.huffman.decode(&dec, enc[0..n]);
    try std.testing.expectEqualSlices(u8, &all, dec[0..m]);
}

test "varint edges" {
    var out: [12]u8 = undefined;
    // prefix 5, value 1337 -> RFC 7541 C.1.3: 1f9a0a
    var n = try hpack.appendVarInt(&out, 5, 1337);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x1f, 0x9a, 0x0a }, out[0..n]);
    const r = try hpack.readVarInt(5, out[0..n]);
    try std.testing.expectEqual(@as(u64, 1337), r.value);
    try std.testing.expectEqual(@as(usize, 3), r.len);
    // prefix 8, value 42
    n = try hpack.appendVarInt(&out, 8, 42);
    try std.testing.expectEqualSlices(u8, &[_]u8{42}, out[0..n]);
    // max u64 encodes but hits the m >= 63 guard on decode — Go's
    // readVarInt has the identical check ("TODO: proper overflow check.
    // making this up."), so this documents matching behavior.
    n = try hpack.appendVarInt(&out, 5, std.math.maxInt(u64));
    try std.testing.expectEqual(@as(usize, 11), n);
    try std.testing.expectError(hpack.Error.VarintOverflow, hpack.readVarInt(5, out[0..n]));
    // large-but-decodable value round-trips
    n = try hpack.appendVarInt(&out, 5, (1 << 60) + 12345);
    const r2 = try hpack.readVarInt(5, out[0..n]);
    try std.testing.expectEqual((1 << 60) + 12345, r2.value);
}

test "indexed name survives eviction of its own entry" {
    // Table size 72 fits exactly aaa:x and bbb:y (36 each). The third field
    // reuses name aaa with incremental indexing; adding it evicts aaa:x
    // itself, compacting the arena the borrowed name points into.
    var d = hpack.Decoder.init(72);
    var col = Collector{};
    const ctx: ?*anyopaque = @ptrCast(&col);
    // literal incremental, new name "aaa"="x"
    const b1 = [_]u8{ 0x40, 0x03, 'a', 'a', 'a', 0x01, 'x' };
    try d.decodeBlock(&b1, ctx, Collector.emitFn);
    try col.check(&[_][]const u8{"aaa"}, &[_][]const u8{"x"});
    // literal incremental, new name "bbb"="y"
    col.len = 0;
    const b2 = [_]u8{ 0x40, 0x03, 'b', 'b', 'b', 0x01, 'y' };
    try d.decodeBlock(&b2, ctx, Collector.emitFn);
    try col.check(&[_][]const u8{"bbb"}, &[_][]const u8{"y"});
    // literal incremental, indexed name 63 (aaa), value "z": 7f00017a
    col.len = 0;
    const b3 = [_]u8{ 0x7f, 0x00, 0x01, 'z' };
    try d.decodeBlock(&b3, ctx, Collector.emitFn);
    try col.check(&[_][]const u8{"aaa"}, &[_][]const u8{"z"});
}

// From feat/h2-conn (#97): an earlier dynamic-indexed emit must survive a
// later evicting add in the same block. Uses this file's Collector.
test "earlier emitted dynamic entry survives later eviction in same block" {
    // Table 64 fits one entry (36) but not two (36+37): the second add
    // evicts and compacts, overwriting arena bytes the first emit aliases.
    var d = hpack.Decoder.init(64);
    var col = Collector{};
    const ctx: ?*anyopaque = @ptrCast(&col);
    // Block 1: table <- (aaa, x) via literal with incremental indexing.
    const setup = [_]u8{ 0x40, 0x03, 'a', 'a', 'a', 0x01, 'x' };
    try d.decodeBlock(&setup, ctx, Collector.emitFn);
    try col.check(&[_][]const u8{"aaa"}, &[_][]const u8{"x"});
    // Block 2: indexed (aaa, x), then incremental (bbb, yy) evicting it.
    col.len = 0;
    const block = [_]u8{ 0xbe, 0x40, 0x03, 'b', 'b', 'b', 0x02, 'y', 'y' };
    try d.decodeBlock(&block, ctx, Collector.emitFn);
    try col.check(
        &[_][]const u8{ "aaa", "bbb" },
        &[_][]const u8{ "x", "yy" },
    );
}
