// Port of the SQLite 3.51.3 grammar (parse.y semantics, public domain) as used by netbird v0.80.0, BSD-3-Clause for this Zig code.
const std = @import("std");
const l = @import("lexer.zig");
test "SQLite token boundaries literals comments and byte offsets" {
    var lex = l.Lexer.init("-- hi\nSELECT .5, 5., 1e+10, 0xFF, 1_000, 'a''b', x'Ab', \"a\"\"b\", [z], ?12, :n /*x*/;");
    const kinds = [_]l.Kind{ .word, .number, .comma, .number, .comma, .number, .comma, .number, .comma, .number, .comma, .string, .comma, .blob, .comma, .identifier, .comma, .identifier, .comma, .parameter, .comma, .parameter, .semicolon, .eof };
    for (kinds, 0..) |kind, i| { const t = try lex.next(); try std.testing.expectEqual(kind, t.kind); if (i == 0) { try std.testing.expectEqual(@as(usize, 6), t.start); try std.testing.expect(t.is("select")); } }
}
test "malformed literal diagnostics are byte exact" {
    for ([_][]const u8{ "1e", "0x", "1.2.3", "'oops", "x'1'", "x'gg'", "\"oops", "[oops", "!" }) |s| {
        var lex = l.Lexer.init(s);
        try std.testing.expectError(error.InvalidToken, lex.next());
        try std.testing.expectEqual(@as(usize, 0), lex.diagnostic.offset);
    }
    // SQLite accepts an unterminated block comment as end of input.
    var lex = l.Lexer.init("/* unterminated");
    try std.testing.expectEqual(l.Kind.eof, (try lex.next()).kind);
}
test "SQLite Unicode names quoted escapes and fallback keywords" {
    var lex = l.Lexer.init("café `a``b` $ns::x(foo) @x ? :name");
    for ([_]l.Kind{ .word, .identifier, .parameter, .parameter, .parameter, .parameter, .eof }) |kind| try std.testing.expectEqual(kind, (try lex.next()).kind);
    try std.testing.expect(l.isFallback("key"));
    try std.testing.expect(l.isFallback("action"));
    try std.testing.expect(!l.isFallback("select"));
}
