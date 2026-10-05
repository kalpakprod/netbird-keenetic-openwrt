//! Tokenizer for the proto3 subset. Zero-copy: token text is a slice of the
//! source. Comments (// to end of line, /* ... */) are skipped.

const std = @import("std");

pub const Error = error{
    UnexpectedCharacter,
    UnterminatedString,
    UnterminatedBlockComment,
};

pub const Kind = enum {
    ident,
    int,
    string,
    l_brace,
    r_brace,
    l_bracket,
    r_bracket,
    l_angle,
    r_angle,
    l_paren,
    r_paren,
    equals,
    semicolon,
    comma,
    dot,
    minus,
    eof,
};

pub const Token = struct {
    kind: Kind,
    /// Slice of the source text. For strings: raw content between the quotes.
    text: []const u8,
    /// 1-based line of the token start, for diagnostics.
    line: u32,
    /// True when the source token was a quoted string (option values keep
    /// this distinction).
    quoted: bool = false,
};

pub const Lexer = struct {
    src: []const u8,
    pos: usize = 0,
    line: u32 = 1,

    pub fn init(src: []const u8) Lexer {
        return .{ .src = src };
    }

    fn skipTrivia(l: *Lexer) Error!void {
        while (l.pos < l.src.len) {
            const c = l.src[l.pos];
            switch (c) {
                ' ', '\t', '\r' => l.pos += 1,
                '\n' => {
                    l.pos += 1;
                    l.line += 1;
                },
                '/' => {
                    if (l.pos + 1 >= l.src.len) return Error.UnexpectedCharacter;
                    switch (l.src[l.pos + 1]) {
                        '/' => {
                            while (l.pos < l.src.len and l.src[l.pos] != '\n') l.pos += 1;
                        },
                        '*' => {
                            l.pos += 2;
                            while (true) {
                                if (l.pos + 1 >= l.src.len) return Error.UnterminatedBlockComment;
                                if (l.src[l.pos] == '*' and l.src[l.pos + 1] == '/') {
                                    l.pos += 2;
                                    break;
                                }
                                if (l.src[l.pos] == '\n') l.line += 1;
                                l.pos += 1;
                            }
                        },
                        else => return Error.UnexpectedCharacter,
                    }
                },
                else => return,
            }
        }
    }

    pub fn next(l: *Lexer) Error!Token {
        try l.skipTrivia();
        if (l.pos >= l.src.len) return .{ .kind = .eof, .text = "", .line = l.line };
        const start = l.pos;
        const line = l.line;
        const c = l.src[l.pos];
        const t: Token = switch (c) {
            '{' => .{ .kind = .l_brace, .text = l.src[start .. start + 1], .line = line },
            '}' => .{ .kind = .r_brace, .text = l.src[start .. start + 1], .line = line },
            '[' => .{ .kind = .l_bracket, .text = l.src[start .. start + 1], .line = line },
            ']' => .{ .kind = .r_bracket, .text = l.src[start .. start + 1], .line = line },
            '<' => .{ .kind = .l_angle, .text = l.src[start .. start + 1], .line = line },
            '>' => .{ .kind = .r_angle, .text = l.src[start .. start + 1], .line = line },
            '(' => .{ .kind = .l_paren, .text = l.src[start .. start + 1], .line = line },
            ')' => .{ .kind = .r_paren, .text = l.src[start .. start + 1], .line = line },
            '=' => .{ .kind = .equals, .text = l.src[start .. start + 1], .line = line },
            ';' => .{ .kind = .semicolon, .text = l.src[start .. start + 1], .line = line },
            ',' => .{ .kind = .comma, .text = l.src[start .. start + 1], .line = line },
            '.' => .{ .kind = .dot, .text = l.src[start .. start + 1], .line = line },
            '-' => .{ .kind = .minus, .text = l.src[start .. start + 1], .line = line },
            '"', '\'' => try l.lexString(c, line),
            else => blk: {
                if (isIdentStart(c)) {
                    l.pos += 1;
                    while (l.pos < l.src.len and isIdentContinue(l.src[l.pos])) l.pos += 1;
                    break :blk .{ .kind = .ident, .text = l.src[start..l.pos], .line = line };
                }
                if (c >= '0' and c <= '9') {
                    l.pos += 1;
                    while (l.pos < l.src.len and isIdentContinue(l.src[l.pos])) l.pos += 1;
                    break :blk .{ .kind = .int, .text = l.src[start..l.pos], .line = line };
                }
                return Error.UnexpectedCharacter;
            },
        };
        if (t.kind != .string) l.pos = @max(l.pos, start + 1);
        return t;
    }

    fn lexString(l: *Lexer, quote: u8, line: u32) Error!Token {
        l.pos += 1; // opening quote
        const start = l.pos;
        while (l.pos < l.src.len and l.src[l.pos] != quote) {
            if (l.src[l.pos] == '\n') return Error.UnterminatedString;
            if (l.src[l.pos] == '\\' and l.pos + 1 < l.src.len) l.pos += 1;
            l.pos += 1;
        }
        if (l.pos >= l.src.len) return Error.UnterminatedString;
        const text = l.src[start..l.pos];
        l.pos += 1; // closing quote
        return .{ .kind = .string, .text = text, .line = line, .quoted = true };
    }

    fn isIdentStart(c: u8) bool {
        return (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or c == '_';
    }

    fn isIdentContinue(c: u8) bool {
        return isIdentStart(c) or (c >= '0' and c <= '9');
    }
};

test "lex basic tokens" {
    var lx = Lexer.init("message Foo { string a = 1; }");
    const t1 = try lx.next();
    try std.testing.expectEqual(Kind.ident, t1.kind);
    try std.testing.expectEqualStrings("message", t1.text);
    _ = try lx.next(); // Foo
    const t3 = try lx.next();
    try std.testing.expectEqual(Kind.l_brace, t3.kind);
}

test "lex skips comments and tracks lines" {
    var lx = Lexer.init(
        \\// line comment
        \\a /* block
        \\ comment */ b
        \\ "s"
    );
    const a = try lx.next();
    try std.testing.expectEqual(@as(u32, 2), a.line);
    const b = try lx.next();
    try std.testing.expectEqualStrings("b", b.text);
    try std.testing.expectEqual(@as(u32, 3), b.line);
    const s = try lx.next();
    try std.testing.expectEqual(Kind.string, s.kind);
    try std.testing.expectEqualStrings("s", s.text);
}

test "lex string escapes" {
    var lx = Lexer.init("'a\\'b\\n'");
    const s = try lx.next();
    try std.testing.expectEqualStrings("a\\'b\\n", s.text);
}
