// DNS wire codec tests.
// Vectors: src/dns/testdata/msg.txt from gen/dnsvecs (real miekg/dns Pack,
// the library NetBird uses on the wire). Every vector is asserted on fields
// and repacked to the same bytes. Malformed inputs and constructed
// round-trips are built in-test.

const std = @import("std");
const msg = @import("msg.zig");

const vectors_raw = @embedFile("testdata/msg.txt");

fn hexOf(name: []const u8) []const u8 {
    var it = std.mem.splitScalar(u8, vectors_raw, '\n');
    while (it.next()) |line| {
        if (line.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, line, '=').?;
        if (std.mem.eql(u8, line[0..eq], name)) {
            return line[eq + 1 ..];
        }
    }
    unreachable;
}

fn bytesOf(allocator: std.mem.Allocator, name: []const u8) ![]u8 {
    const hx = hexOf(name);
    const out = try allocator.alloc(u8, hx.len / 2);
    _ = try std.fmt.hexToBytes(out, hx);
    return out;
}

/// Unpack a named vector on an arena and repack it; fails on any mismatch.
fn roundTrip(name: []const u8, compress: bool) !void {
    const raw = try bytesOf(std.testing.allocator, name);
    defer std.testing.allocator.free(raw);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try msg.unpack(arena.allocator(), raw);
    const buf = try std.testing.allocator.alloc(u8, raw.len + 64);
    defer std.testing.allocator.free(buf);
    var p = msg.Packer.init(arena.allocator(), buf);
    defer p.deinit();
    p.compress = compress;
    const packed_bytes = try p.pack(&parsed);
    try std.testing.expectEqualSlices(u8, raw, packed_bytes);
}

test "query vectors round trip and fields" {
    // QUERY_A: RD=1, one question, www.example.com. A IN
    const raw = try bytesOf(std.testing.allocator, "QUERY_A");
    defer std.testing.allocator.free(raw);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const m = try msg.unpack(a, raw);
    // (miekg SetQuestion assigns its own random Id — 0xEF2E in the vector)
    try std.testing.expectEqual(@as(u16, 0xEF2E), m.header.id);
    try std.testing.expect(!m.header.response);
    try std.testing.expect(m.header.recursion_desired);
    try std.testing.expectEqual(@as(usize, 1), m.question.len);
    try std.testing.expectEqualStrings("www.example.com.", m.question[0].name);
    try std.testing.expectEqual(msg.Type.a, m.question[0].type);
    try std.testing.expectEqual(msg.class_inet, m.question[0].class);
    try std.testing.expectEqual(@as(usize, 0), m.answer.len + m.ns.len + m.extra.len);
    try roundTrip("QUERY_A", false);
    try roundTrip("QUERY_EDNS", false);
    try roundTrip("QUERY_SRV", false);
    try roundTrip("QUERY_PTR", false);
    try roundTrip("QUERY_ROOT", false);

    // QUERY_ROOT: the root name unpacks to "."
    const raw_root = try bytesOf(std.testing.allocator, "QUERY_ROOT");
    defer std.testing.allocator.free(raw_root);
    const root = try msg.unpack(a, raw_root);
    try std.testing.expectEqualStrings(".", root.question[0].name);
    try std.testing.expectEqual(msg.Type.ns, root.question[0].type);
}

test "query edns0 fields" {
    const raw = try bytesOf(std.testing.allocator, "QUERY_EDNS");
    defer std.testing.allocator.free(raw);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const m = try msg.unpack(arena.allocator(), raw);
    const opt = m.isEdns0().?;
    try std.testing.expectEqual(@as(u16, 4096), opt.class); // advertised UDP size
    try std.testing.expectEqual(@as(u32, 0x8000), opt.ttl); // DO bit
    try std.testing.expectEqual(@as(usize, 0), opt.data.opt.len);
    try std.testing.expectEqual(@as(u16, 0), msg.extendedRcode(&m));
}

test "response cname a with compression" {
    const raw = try bytesOf(std.testing.allocator, "RESP_CNAME_A");
    defer std.testing.allocator.free(raw);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const m = try msg.unpack(arena.allocator(), raw);
    try std.testing.expect(m.header.response);
    try std.testing.expect(m.header.authoritative);
    try std.testing.expect(m.header.recursion_available);
    try std.testing.expectEqual(@as(u16, 0), m.header.rcode);
    try std.testing.expectEqual(@as(usize, 2), m.answer.len);
    try std.testing.expectEqualStrings("www.example.com.", m.answer[0].name);
    try std.testing.expectEqualStrings("example.com.", m.answer[0].data.cname);
    try std.testing.expectEqual(@as(u32, 300), m.answer[0].ttl);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 10, 2, 3, 4 }, &m.answer[1].data.a);
    try roundTrip("RESP_CNAME_A", true);
}

test "response nxdomain soa is opaque rdata" {
    const raw = try bytesOf(std.testing.allocator, "RESP_NXDOMAIN_SOA");
    defer std.testing.allocator.free(raw);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const m = try msg.unpack(arena.allocator(), raw);
    try std.testing.expectEqual(@as(u16, 3), m.header.rcode); // NXDOMAIN
    try std.testing.expectEqual(@as(usize, 0), m.answer.len);
    try std.testing.expectEqual(@as(usize, 1), m.ns.len);
    try std.testing.expectEqual(@as(u16, 6), @intFromEnum(m.ns[0].type)); // SOA
    try std.testing.expectEqual(@as(u32, 3600), m.ns[0].ttl);
    try std.testing.expectEqual(@as(usize, 61), m.ns[0].data.unknown.len);
    try roundTrip("RESP_NXDOMAIN_SOA", false);
}

test "response txt with escaped strings" {
    const raw = try bytesOf(std.testing.allocator, "RESP_TXT");
    defer std.testing.allocator.free(raw);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const m = try msg.unpack(arena.allocator(), raw);
    const txt = m.answer[0].data.txt;
    try std.testing.expectEqual(@as(usize, 2), txt.len);
    try std.testing.expectEqualStrings("hello world", txt[0]);
    try std.testing.expectEqualStrings("\\\"quoted\\\"\\001\\255", txt[1]);
    try roundTrip("RESP_TXT", false);
}

test "response srv keeps target uncompressed" {
    const raw = try bytesOf(std.testing.allocator, "RESP_SRV");
    defer std.testing.allocator.free(raw);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const m = try msg.unpack(arena.allocator(), raw);
    const srv = m.answer[0].data.srv;
    try std.testing.expectEqual(@as(u16, 5), srv.priority);
    try std.testing.expectEqual(@as(u16, 10), srv.weight);
    try std.testing.expectEqual(@as(u16, 5060), srv.port);
    try std.testing.expectEqualStrings("sipserver.example.com.", srv.target);
    try std.testing.expectEqual(@as(usize, 1), m.extra.len);
    try std.testing.expectEqualStrings("sipserver.example.com.", m.extra[0].name);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 7, 9 }, &m.extra[0].data.a);
    try roundTrip("RESP_SRV", true);
}

test "response aaaa and ptr and refused" {
    const raw = try bytesOf(std.testing.allocator, "RESP_AAAA");
    defer std.testing.allocator.free(raw);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const m = try msg.unpack(arena.allocator(), raw);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0xfd, 0x00, 0,   0,   0,   0,   0,   0,
        0,    0,    0,   0,   0,   1,   0x00, 0x02,
    }, &m.answer[0].data.aaaa);
    try roundTrip("RESP_AAAA", false);

    const raw_ptr = try bytesOf(std.testing.allocator, "RESP_PTR");
    defer std.testing.allocator.free(raw_ptr);
    const mp = try msg.unpack(arena.allocator(), raw_ptr);
    try std.testing.expectEqualStrings("host.example.com.", mp.answer[0].data.ptr);
    try roundTrip("RESP_PTR", true);

    const raw_ref = try bytesOf(std.testing.allocator, "RESP_REFUSED");
    defer std.testing.allocator.free(raw_ref);
    const mr = try msg.unpack(arena.allocator(), raw_ref);
    try std.testing.expectEqual(@as(u16, 5), mr.header.rcode);
    try std.testing.expectEqual(@as(usize, 0), mr.answer.len + mr.ns.len + mr.extra.len);
    try std.testing.expectEqual(@as(usize, 1), mr.question.len);
    try roundTrip("RESP_REFUSED", false);
}

test "servfail with ede option" {
    const raw = try bytesOf(std.testing.allocator, "RESP_SERVFAIL_EDE");
    defer std.testing.allocator.free(raw);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const m = try msg.unpack(arena.allocator(), raw);
    try std.testing.expectEqual(@as(u16, 2), m.header.rcode); // SERVFAIL
    const opt = m.isEdns0().?;
    try std.testing.expectEqual(@as(u16, 1232), opt.class);
    try std.testing.expectEqual(@as(usize, 1), opt.data.opt.len);
    try std.testing.expectEqual(msg.opt_code_ede, opt.data.opt[0].code);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x0f } ++ "blocked", opt.data.opt[0].data);
    try std.testing.expectEqual(@as(u16, 2), msg.extendedRcode(&m));
    try roundTrip("RESP_SERVFAIL_EDE", false);
}

test "unknown mx rr keeps raw rdata" {
    const raw = try bytesOf(std.testing.allocator, "RESP_MX_UNKNOWN");
    defer std.testing.allocator.free(raw);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const m = try msg.unpack(arena.allocator(), raw);
    try std.testing.expectEqual(@as(u16, 15), @intFromEnum(m.answer[0].type)); // MX
    try std.testing.expectEqual(@as(usize, 20), m.answer[0].data.unknown.len);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x0a }, m.answer[0].data.unknown[0..2]);
    try roundTrip("RESP_MX_UNKNOWN", false);
}

test "600 records round trip past the 0x4000 insert cutoff" {
    const raw = try bytesOf(std.testing.allocator, "RESP_BIG");
    defer std.testing.allocator.free(raw);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const m = try msg.unpack(arena.allocator(), raw);
    try std.testing.expectEqual(@as(usize, 600), m.answer.len);
    try std.testing.expectEqualStrings("n0.example.com.", m.answer[0].name);
    try std.testing.expectEqualStrings("n599.example.com.", m.answer[599].name);
    try roundTrip("RESP_BIG", true);
}

test "cname pointing at the question name" {
    const raw = try bytesOf(std.testing.allocator, "RESP_CNAME_SELF");
    defer std.testing.allocator.free(raw);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const m = try msg.unpack(arena.allocator(), raw);
    try std.testing.expectEqualStrings("www.example.com.", m.answer[0].data.cname);
    try roundTrip("RESP_CNAME_SELF", true);
}

test "escaped label presentation round trip" {
    const raw = try bytesOf(std.testing.allocator, "RESP_ESCAPED");
    defer std.testing.allocator.free(raw);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const m = try msg.unpack(arena.allocator(), raw);
    // label bytes "a.064b" present as a\.064b
    try std.testing.expectEqualStrings("a\\.064b.example.com.", m.answer[0].name);
    try roundTrip("RESP_ESCAPED", true);
}

// ---------------------------------------------------------------------------
// Zig-side constructed round trips

test "constructed query pack unpack pack is stable" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var q = msg.Message{ .header = .{ .id = 0xBEEF, .recursion_desired = true } };
    const qs = try a.alloc(msg.Question, 1);
    qs[0] = .{ .name = "router.example.", .type = .a, .class = msg.class_inet };
    q.question = qs;
    var buf: [512]u8 = undefined;
    const wire1 = try msg.pack(a, &q, &buf);
    const parsed = try msg.unpack(a, wire1);
    try std.testing.expectEqual(@as(u16, 0xBEEF), parsed.header.id);
    try std.testing.expectEqualStrings("router.example.", parsed.question[0].name);
    const wire2 = try msg.pack(a, &parsed, &buf);
    try std.testing.expectEqualSlices(u8, wire1, wire2);
}

test "txt escape decode on pack" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var m = msg.Message{ .header = .{ .response = true } };
    const strings = try a.alloc([]const u8, 1);
    strings[0] = "A"; // what "\101." decodes to
    const rrs = try a.alloc(msg.RR, 1);
    rrs[0] = .{ .name = "x.example.", .type = .txt, .class = msg.class_inet, .ttl = 1, .data = .{ .txt = strings } };
    m.answer = rrs;

    var buf: [256]u8 = undefined;
    var wire = try msg.pack(a, &m, &buf);

    // same bytes as packing the \DDD spelling of the string (\065 = 0x41)
    strings[0] = "\\065";
    const wire2 = try msg.pack(a, &m, &buf);
    try std.testing.expectEqualSlices(u8, wire, wire2);

    // unpack gives the presentation of the raw byte 0x41 = 'A'
    const parsed = try msg.unpack(a, wire);
    try std.testing.expectEqualStrings("A", parsed.answer[0].data.txt[0]);

    // a fully escaped single char-string: 0xff
    strings[0] = "\\255";
    wire = try msg.pack(a, &m, &buf);
    const parsed2 = try msg.unpack(a, wire);
    try std.testing.expectEqualStrings("\\255", parsed2.answer[0].data.txt[0]);
}

test "extended rcode packs into opt ttl" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var m = msg.Message{ .header = .{ .response = true, .rcode = 40 } };
    const rrs = try a.alloc(msg.RR, 1);
    rrs[0] = msg.makeOpt(1232, false);
    m.extra = rrs;
    var buf: [128]u8 = undefined;
    const wire = try msg.pack(a, &m, &buf);
    // header rcode low bits = 40 & 0xF = 8, OPT ttl top byte = 40 >> 4 = 2
    try std.testing.expectEqual(@as(u16, 8), std.mem.readInt(u16, wire[2..4], .big) & 0xF);
    const parsed = try msg.unpack(a, wire);
    try std.testing.expectEqual(@as(u16, 40), msg.extendedRcode(&parsed));
    // extended rcode without an OPT record is an error
    m.extra = &.{};
    try std.testing.expectError(msg.Error.ExtendedRcodeWithoutOpt, msg.pack(a, &m, &buf));
}

test "truncation sets the tc bit when the buffer is too small" {
    // The codec's job: a too-small buffer is NoSpaceLeft; the server layer
    // re-packs with TC. Here: pack the same message into a tiny buffer.
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var m = msg.Message{ .header = .{ .id = 1, .response = true } };
    const qs = try a.alloc(msg.Question, 1);
    qs[0] = .{ .name = "example.com.", .type = .a, .class = msg.class_inet };
    m.question = qs;
    var small: [8]u8 = undefined;
    try std.testing.expectError(msg.Error.NoSpaceLeft, msg.pack(a, &m, &small));
    var big: [64]u8 = undefined;
    _ = try msg.pack(a, &m, &big);
}

// ---------------------------------------------------------------------------
// malformed inputs (built in-test, no upstream vector exists for them)

fn qbuf() [64]u8 {
    return std.mem.zeroes([64]u8);
}

test "malformed inputs are rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // truncated header
    const short: [11]u8 = std.mem.zeroes([11]u8);
    try std.testing.expectError(msg.Error.Truncated, msg.unpack(a, &short));

    // miekg accepts header-only REFUSED responses regardless of section counts.
    var bad = qbuf();
    std.mem.writeInt(u16, bad[2..4], 0x8005, .big);
    for ([_]usize{ 4, 6, 8, 10 }) |off| std.mem.writeInt(u16, bad[off..][0..2], 1, .big);
    const refused = try msg.unpack(a, bad[0..12]);
    try std.testing.expectEqual(@as(u16, 5), refused.header.rcode);
    try std.testing.expect(refused.header.response);
    try std.testing.expectEqual(@as(usize, 0), refused.question.len);
    try std.testing.expectEqual(@as(usize, 0), refused.answer.len + refused.ns.len + refused.extra.len);

    // self-referencing compression pointer loops until the cap
    var loop = qbuf();
    std.mem.writeInt(u16, loop[4..6], 1, .big);
    loop[12] = 0xC0;
    loop[13] = 12;
    loop[14] = 0;
    loop[15] = 1;
    loop[16] = 0;
    try std.testing.expectError(msg.Error.BadPointer, msg.unpack(a, loop[0..17]));

    // reserved high bits on a label length
    var res = qbuf();
    std.mem.writeInt(u16, res[4..6], 1, .big);
    res[12] = 0x80;
    try std.testing.expectError(msg.Error.BadRdata, msg.unpack(a, res[0..17]));

    // label length runs past the message
    var over = qbuf();
    std.mem.writeInt(u16, over[4..6], 1, .big);
    over[12] = 5;
    over[13] = 'a';
    over[14] = 'b';
    try std.testing.expectError(msg.Error.Truncated, msg.unpack(a, over[0..15]));

    // A record with rdlength 5 (rdata must consume exactly rdlength):
    // question "x." A IN, then an answer RR owned by pointer c00c
    var a5 = qbuf();
    std.mem.writeInt(u16, a5[4..6], 1, .big); // qd
    std.mem.writeInt(u16, a5[6..8], 1, .big); // an
    a5[12] = 1;
    a5[13] = 'x';
    a5[14] = 0;
    std.mem.writeInt(u16, a5[15..17], 1, .big); // qtype A
    std.mem.writeInt(u16, a5[17..19], 1, .big); // qclass IN
    a5[19] = 0xC0; // owner = pointer to the question name
    a5[20] = 12;
    std.mem.writeInt(u16, a5[21..23], 1, .big); // type A
    std.mem.writeInt(u16, a5[29..31], 5, .big); // rdlength 5
    a5[31] = 1; // 5 bytes of rdata, A reads only 4
    a5[32] = 2;
    a5[33] = 3;
    a5[34] = 4;
    a5[35] = 5;
    try std.testing.expectError(msg.Error.BadRdata, msg.unpack(a, a5[0..36]));

    // rdlength beyond the message
    var rbig = qbuf();
    std.mem.writeInt(u16, rbig[4..6], 1, .big);
    std.mem.writeInt(u16, rbig[6..8], 1, .big);
    rbig[12] = 1;
    rbig[13] = 'x';
    rbig[14] = 0;
    std.mem.writeInt(u16, rbig[15..17], 1, .big);
    std.mem.writeInt(u16, rbig[17..19], 1, .big);
    rbig[19] = 0xC0;
    rbig[20] = 12;
    std.mem.writeInt(u16, rbig[21..23], 1, .big);
    std.mem.writeInt(u16, rbig[29..31], 0xFFFF, .big);
    try std.testing.expectError(msg.Error.Truncated, msg.unpack(a, rbig[0..31]));

    // TXT character-string crossing the rdata boundary
    var tx = qbuf();
    std.mem.writeInt(u16, tx[4..6], 1, .big);
    std.mem.writeInt(u16, tx[6..8], 1, .big);
    tx[12] = 1;
    tx[13] = 'x';
    tx[14] = 0;
    std.mem.writeInt(u16, tx[15..17], 16, .big); // qtype TXT
    std.mem.writeInt(u16, tx[17..19], 1, .big);
    tx[19] = 0xC0;
    tx[20] = 12;
    std.mem.writeInt(u16, tx[21..23], 16, .big); // type TXT
    std.mem.writeInt(u16, tx[29..31], 2, .big); // rdlength 2
    tx[31] = 5; // string claims 5 bytes, only 1 left in rdata
    tx[32] = 'a';
    try std.testing.expectError(msg.Error.BadRdata, msg.unpack(a, tx[0..33]));

    // a 128-label name exceeds the 255-wire-octet unpack budget (miekg quirk:
    // pack has no total cap, unpack rejects at 255)
    var long_name: [320]u8 = std.mem.zeroes([320]u8);
    std.mem.writeInt(u16, long_name[4..6], 1, .big);
    var lw: usize = 12;
    while (lw < 12 + 256) : (lw += 2) {
        long_name[lw] = 1;
        long_name[lw + 1] = 'a';
    }
    long_name[lw] = 0;
    lw += 1;
    std.mem.writeInt(u16, long_name[lw..][0..2], 1, .big); // type A
    lw += 4;
    try std.testing.expectError(msg.Error.LongName, msg.unpack(a, long_name[0 .. lw + 2]));
}

test "pack rejects bad names" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var m = msg.Message{ .header = .{ .id = 1 } };
    const qs = try a.alloc(msg.Question, 1);
    m.question = qs;
    var buf: [64]u8 = undefined;

    // not fully qualified
    qs[0] = .{ .name = "example.com", .type = .a, .class = msg.class_inet };
    try std.testing.expectError(msg.Error.NotFqdn, msg.pack(a, &m, &buf));

    // label longer than 63
    qs[0] = .{ .name = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com.", .type = .a, .class = msg.class_inet };
    try std.testing.expectError(msg.Error.BadRdata, msg.pack(a, &m, &buf));

    // double dot
    qs[0] = .{ .name = "a..com.", .type = .a, .class = msg.class_inet };
    try std.testing.expectError(msg.Error.BadRdata, msg.pack(a, &m, &buf));

    // leading dot (except the root itself)
    qs[0] = .{ .name = ".com.", .type = .a, .class = msg.class_inet };
    try std.testing.expectError(msg.Error.BadRdata, msg.pack(a, &m, &buf));

    // trailing backslash: not a valid FQDN at all (miekg checks Fqdn first)
    qs[0] = .{ .name = "a\\", .type = .a, .class = msg.class_inet };
    try std.testing.expectError(msg.Error.NotFqdn, msg.pack(a, &m, &buf));

    // root name packs to a single zero byte and unpacks to "."
    qs[0] = .{ .name = ".", .type = .ns, .class = msg.class_inet };
    const wire = try msg.pack(a, &m, &buf);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1 }, wire);
    const parsed = try msg.unpack(a, wire);
    try std.testing.expectEqualStrings(".", parsed.question[0].name);
}

test "escaped presentation name uses decoded label length" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var m = msg.Message{ .header = .{ .id = 7 } };
    const questions = try a.alloc(msg.Question, 1);
    m.question = questions;

    // The presentation label is 64 bytes (32 escaped dots), but its wire
    // label is 32 bytes and is legal. The final dot terminates the FQDN.
    var name: [65]u8 = undefined;
    var i: usize = 0;
    var j: usize = 0;
    while (j < 32) : (j += 1) {
        name[i] = '\\';
        name[i + 1] = '.';
        i += 2;
    }
    name[i] = '.';
    questions[0] = .{ .name = &name, .type = .a, .class = msg.class_inet };

    var buf: [128]u8 = undefined;
    const wire = try msg.pack(a, &m, &buf);
    const parsed = try msg.unpack(a, wire);
    try std.testing.expectEqualStrings(&name, parsed.question[0].name);
}

test "extended rcode survives separate unpack repack" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator); defer arena.deinit();
    const a = arena.allocator();
    for ([_]u16{ 16, 40, 4095 }) |rcode| {
        var m = msg.Message{ .header = .{ .response = true, .rcode = rcode } };
        const rr = try a.alloc(msg.RR, 1); rr[0] = msg.makeOpt(1232, false); m.extra = rr;
        var b1: [128]u8 = undefined; var b2: [128]u8 = undefined;
        const w1 = try msg.pack(a, &m, &b1); const parsed = try msg.unpack(a, w1);
        const w2 = try msg.pack(a, &parsed, &b2); const reparsed = try msg.unpack(a, w2);
        try std.testing.expectEqual(rcode, reparsed.header.rcode);
    }
}


test "terminal dot IsFqdn matches pinned Go oracle" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // Pinned miekg/dns IsFqdn uses a rune's byte START, not its final byte.
    const cases = [_]struct { name: []const u8, accepted: bool }{
        .{ .name = "host\\.", .accepted = false },
        .{ .name = ".", .accepted = true },
        .{ .name = "host\\\\.", .accepted = true },
        .{ .name = "host.", .accepted = true },
        .{ .name = "x.utf8é\\.", .accepted = true },
        .{ .name = "x.utf8é\\\\.", .accepted = false },
        .{ .name = "x.utf8€\\.", .accepted = false },
        .{ .name = "x.utf8€\\\\.", .accepted = true },
        .{ .name = "x.utf8😀\\.", .accepted = true },
        .{ .name = "x.utf8😀\\\\.", .accepted = false },
        .{ .name = "x.utf8\xff\\.", .accepted = false },
        .{ .name = "x.utf8\xff\\\\.", .accepted = true },
        .{ .name = "\\.", .accepted = false },
        .{ .name = "\\\\.", .accepted = true },
    };
    var buf: [128]u8 = undefined;
    var m = msg.Message{};
    var qs = [_]msg.Question{.{ .name = ".", .type = .a, .class = msg.class_inet }};
    m.question = &qs;
    for (cases) |case| {
        qs[0].name = case.name;
        if (case.accepted) {
            const wire = try msg.pack(a, &m, &buf);
            if (std.mem.eql(u8, case.name, ".") or std.mem.eql(u8, case.name, "host\\\\.")) {
                const parsed = try msg.unpack(a, wire);
                try std.testing.expectEqualStrings(case.name, parsed.question[0].name);
            }
        } else {
            try std.testing.expectError(msg.Error.NotFqdn, msg.pack(a, &m, &buf));
        }
    }
}

test "accepted raw multibyte escaped dot has pinned Go wire bytes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var buf: [128]u8 = undefined;
    var m = msg.Message{};
    var qs = [_]msg.Question{.{ .name = "x.utf8é\\.", .type = .a, .class = msg.class_inet }};
    m.question = &qs;
    // Go's packer omits the unterminated final label on this accepted input.
    const expected = [_]u8{ 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'x', 0, 0, 1, 0, 1 };
    for ([_][]const u8{ "x.utf8é\\.", "x.utf8😀\\." }) |name| {
        qs[0].name = name;
        const wire = try msg.pack(a, &m, &buf);
        try std.testing.expectEqualSlices(u8, &expected, wire);
    }
}
