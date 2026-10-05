//! Recursive-descent parser for the proto3 subset used by the NetBird .proto
//! files: messages (nested), enums (top-level and nested), oneof, map fields,
//! repeated/optional labels, reserved numbers/ranges/names, field options
//! (parsed, semantics handled by the generator), imports, package and file
//! options. `service` and `option` statements are skipped. Comments are
//! handled by the lexer.
//!
//! All produced strings are slices of the source or arena allocations; the
//! result lives as long as the arena passed to init().

const std = @import("std");
const ast = @import("ast.zig");
const lex = @import("lexer.zig");

const Token = lex.Token;
const Kind = lex.Kind;

pub const Error = error{
    UnexpectedToken,
    UnexpectedEof,
    BadNumber,
    Syntax, // syntax is not proto3, duplicate enum value, etc.
    DuplicateFieldNumber,
    ReservedConflict,
    BadMapKey,
    DuplicateEnumValue,
    EnumZeroMissing,
    RequiredLabel,
    OutOfMemory,
    UnexpectedCharacter,
    UnterminatedString,
    UnterminatedBlockComment,
};

pub const max_field_number: i32 = 536870911;
pub const first_reserved_number: i32 = 19000;
pub const last_reserved_number: i32 = 19999;

pub const Parser = struct {
    a: std.mem.Allocator,
    lx: lex.Lexer,
    cur: Token,
    /// 1-based line of the token that caused the last error, for diagnostics.
    err_line: u32 = 0,

    pub fn init(a: std.mem.Allocator, src: []const u8) Error!Parser {
        var p = Parser{
            .a = a,
            .lx = lex.Lexer.init(src),
            .cur = undefined,
        };
        p.cur = p.lx.next() catch |e| return p.lexFail(e, 1);
        return p;
    }

    fn lexFail(p: *Parser, e: lex.Error, fallback: u32) Error {
        p.err_line = p.lx.line;
        _ = fallback;
        return switch (e) {
            error.UnexpectedCharacter => Error.UnexpectedToken,
            error.UnterminatedString => Error.UnexpectedToken,
            error.UnterminatedBlockComment => Error.UnexpectedToken,
        };
    }

    fn advance(p: *Parser) Error!void {
        p.cur = p.lx.next() catch |e| return p.lexFail(e, p.cur.line);
    }

    fn fail(p: *Parser, e: Error) Error {
        p.err_line = p.cur.line;
        return e;
    }

    fn expectEof(p: *Parser) Error!void {
        if (p.cur.kind != .eof) return p.fail(Error.UnexpectedToken);
    }

    fn expect(p: *Parser, kind: Kind) Error!Token {
        if (p.cur.kind == .eof) return p.fail(Error.UnexpectedEof);
        if (p.cur.kind != kind) return p.fail(Error.UnexpectedToken);
        const t = p.cur;
        try p.advance();
        return t;
    }

    fn expectIdent(p: *Parser) Error!Token {
        if (p.cur.kind != .ident) return p.fail(Error.UnexpectedToken);
        const t = p.cur;
        try p.advance();
        return t;
    }

    fn isKeyword(p: *const Parser, kw: []const u8) bool {
        return p.cur.kind == .ident and std.mem.eql(u8, p.cur.text, kw);
    }

    fn acceptKeyword(p: *Parser, kw: []const u8) Error!bool {
        if (p.isKeyword(kw)) {
            try p.advance();
            return true;
        }
        return false;
    }

    /// A possibly-dotted, possibly-leading-dot type name: `.a.B` or `a.B` or
    /// `a`. Joined into one arena string.
    fn parseTypeName(p: *Parser) Error![]const u8 {
        var buf: std.ArrayList(u8) = .empty;
        if (p.cur.kind == .dot) {
            try p.advance();
            try buf.append(p.a, '.');
        }
        const first = try p.expectIdent();
        try buf.appendSlice(p.a, first.text);
        while (p.cur.kind == .dot) {
            try p.advance();
            const part = try p.expectIdent();
            try buf.append(p.a, '.');
            try buf.appendSlice(p.a, part.text);
        }
        return buf.items;
    }

    fn parseIntToken(p: *Parser, neg_ok: bool) Error!i64 {
        var negative = false;
        if (p.cur.kind == .minus) {
            if (!neg_ok) return p.fail(Error.BadNumber);
            negative = true;
            try p.advance();
        }
        if (p.cur.kind != .int) return p.fail(Error.BadNumber);
        const v = std.fmt.parseInt(i64, p.cur.text, 0) catch return p.fail(Error.BadNumber);
        try p.advance();
        return if (negative) -v else v;
    }

    fn parseFieldNumber(p: *Parser) Error!i32 {
        const v = try p.parseIntToken(false);
        if (v < 1 or v > max_field_number) return p.fail(Error.BadNumber);
        return @intCast(v);
    }

    /// Skips an `option ... ;` statement, tolerating aggregate `{ ... }`
    /// values.
    fn skipOption(p: *Parser) Error!void {
        // cur is the `option` keyword (or a dot for option-qualified names).
        var depth: usize = 0;
        while (true) {
            switch (p.cur.kind) {
                .semicolon => {
                    if (depth == 0) {
                        try p.advance();
                        return;
                    }
                },
                .l_brace => depth += 1,
                .r_brace => {
                    if (depth == 0) return p.fail(Error.UnexpectedToken);
                    depth -= 1;
                },
                .eof => return p.fail(Error.UnexpectedEof),
                else => {},
            }
            try p.advance();
        }
    }

    /// Skips a `service Name { ... }` block with balanced braces.
    fn skipService(p: *Parser) Error!void {
        _ = try p.expectIdent(); // service name
        _ = try p.expect(.l_brace);
        var depth: usize = 1;
        while (depth > 0) {
            switch (p.cur.kind) {
                .l_brace => depth += 1,
                .r_brace => depth -= 1,
                .eof => return p.fail(Error.UnexpectedEof),
                else => {},
            }
            try p.advance();
        }
    }

    fn parseFieldOptions(p: *Parser) Error![]ast.Option {
        if (p.cur.kind != .l_bracket) return &.{};
        try p.advance();
        var opts: std.ArrayList(ast.Option) = .empty;
        while (true) {
            // Option names may be dotted or parenthesized extensions; the
            // subset only needs simple and dotted names.
            var name: std.ArrayList(u8) = .empty;
            if (p.cur.kind == .l_paren) {
                try p.advance();
                const inner = try p.parseTypeName();
                try name.appendSlice(p.a, inner);
                _ = try p.expect(.r_paren);
            } else {
                const first = try p.expectIdent();
                try name.appendSlice(p.a, first.text);
                while (p.cur.kind == .dot) {
                    try p.advance();
                    const part = try p.expectIdent();
                    try name.append(p.a, '.');
                    try name.appendSlice(p.a, part.text);
                }
            }
            _ = try p.expect(.equals);
            var value: std.ArrayList(u8) = .empty;
            if (p.cur.kind == .string) {
                try value.append(p.a, '"');
                try value.appendSlice(p.a, p.cur.text);
                try value.append(p.a, '"');
                try p.advance();
            } else if (p.cur.kind == .minus) {
                try value.append(p.a, '-');
                try p.advance();
                if (p.cur.kind != .int) return p.fail(Error.BadNumber);
                try value.appendSlice(p.a, p.cur.text);
                try p.advance();
            } else {
                if (p.cur.kind != .ident and p.cur.kind != .int) return p.fail(Error.UnexpectedToken);
                try value.appendSlice(p.a, p.cur.text);
                try p.advance();
            }
            try opts.append(p.a, .{ .name = name.items, .value = value.items });
            if (p.cur.kind == .comma) {
                try p.advance();
                continue;
            }
            break;
        }
        _ = try p.expect(.r_bracket);
        return opts.items;
    }

    fn parseReserved(p: *Parser) Error![]ast.ReservedRange {
        try p.advance(); // `reserved`
        var ranges: std.ArrayList(ast.ReservedRange) = .empty;
        while (true) {
            if (p.cur.kind == .string) {
                // Reserved field names: parsed and ignored (kept for
                // diagnostics only).
                try p.advance();
                try ranges.append(p.a, .{ .start = -1, .end = -1 });
            } else {
                const start = try p.parseFieldNumber();
                var end = start;
                if (p.isKeyword("to")) {
                    try p.advance();
                    if (p.isKeyword("max")) {
                        try p.advance();
                        end = max_field_number;
                    } else {
                        const v = try p.parseIntToken(false);
                        if (v < 1 or v > max_field_number) return p.fail(Error.BadNumber);
                        end = @intCast(v);
                    }
                }
                try ranges.append(p.a, .{ .start = start, .end = end });
            }
            if (p.cur.kind == .comma) {
                try p.advance();
                continue;
            }
            break;
        }
        _ = try p.expect(.semicolon);
        return ranges.items;
    }

    fn parseMapField(p: *Parser) Error!ast.MapField {
        try p.advance(); // `map`
        _ = try p.expect(.l_angle);
        const key_tok = try p.expectIdent();
        const key = ast.Scalar.parse(key_tok.text) orelse return p.fail(Error.BadMapKey);
        switch (key) {
            .float, .double, .bytes, .boolean => return p.fail(Error.BadMapKey),
            else => {},
        }
        _ = try p.expect(.comma);
        const value = try p.parseTypeRef();
        _ = try p.expect(.r_angle);
        const name = try p.expectIdent();
        _ = try p.expect(.equals);
        const number = try p.parseFieldNumber();
        const options = try p.parseFieldOptions();
        _ = try p.expect(.semicolon);
        return .{ .name = name.text, .number = number, .key = key, .value = value, .options = options, .line = name.line };
    }

    fn parseTypeRef(p: *Parser) Error!ast.TypeRef {
        const name = try p.parseTypeName();
        if (name[0] != '.') {
            if (ast.Scalar.parse(name)) |s| return .{ .scalar = s };
        }
        return .{ .named = name };
    }

    fn parseField(p: *Parser) Error!ast.Field {
        var label: ast.Label = .none;
        if (p.isKeyword("repeated")) {
            label = .repeated;
            try p.advance();
        } else if (p.isKeyword("optional")) {
            label = .optional;
            try p.advance();
        } else if (p.isKeyword("required")) {
            return p.fail(Error.RequiredLabel);
        }
        const typ = try p.parseTypeRef();
        const name = try p.expectIdent();
        _ = try p.expect(.equals);
        const number = try p.parseFieldNumber();
        const options = try p.parseFieldOptions();
        _ = try p.expect(.semicolon);
        return .{ .label = label, .typ = typ, .name = name.text, .number = number, .options = options, .line = name.line };
    }

    fn parseOneof(p: *Parser) Error!ast.Oneof {
        try p.advance(); // `oneof`
        const name = try p.expectIdent();
        _ = try p.expect(.l_brace);
        var fields: std.ArrayList(ast.Field) = .empty;
        while (p.cur.kind != .r_brace) {
            if (p.cur.kind == .eof) return p.fail(Error.UnexpectedEof);
            if (p.isKeyword("option")) {
                try p.advance();
                try p.skipOption();
                continue;
            }
            try fields.append(p.a, try p.parseField());
        }
        try p.advance(); // r_brace
        return .{ .name = name.text, .fields = fields.items, .line = name.line };
    }

    fn parseEnum(p: *Parser) Error!ast.Enum {
        try p.advance(); // `enum`
        const name = try p.expectIdent();
        _ = try p.expect(.l_brace);
        var values: std.ArrayList(ast.EnumValue) = .empty;
        var reserved: std.ArrayList(ast.ReservedRange) = .empty;
        var allow_alias = false;
        while (p.cur.kind != .r_brace) {
            if (p.cur.kind == .eof) return p.fail(Error.UnexpectedEof);
            if (p.isKeyword("option")) {
                try p.advance();
                if (p.isKeyword("allow_alias")) {
                    try p.advance();
                    _ = try p.expect(.equals);
                    if (p.cur.kind == .ident and std.mem.eql(u8, p.cur.text, "true")) allow_alias = true;
                }
                try p.skipOption();
                continue;
            }
            if (p.isKeyword("reserved")) {
                const r = try p.parseReserved();
                try reserved.appendSlice(p.a, r);
                continue;
            }
            const vname = try p.expectIdent();
            _ = try p.expect(.equals);
            const num = try p.parseIntToken(true);
            if (num < -2147483648 or num > 2147483647) return p.fail(Error.BadNumber);
            _ = try p.parseFieldOptions();
            _ = try p.expect(.semicolon);
            try values.append(p.a, .{ .name = vname.text, .number = @intCast(num), .line = vname.line });
        }
        try p.advance(); // r_brace
        if (values.items.len == 0) return p.fail(Error.Syntax);
        if (values.items[0].number != 0) return p.fail(Error.EnumZeroMissing);
        if (!allow_alias) {
            for (values.items, 0..) |v, i| {
                for (values.items[i + 1 ..]) |w| {
                    if (v.number == w.number) return p.fail(Error.DuplicateEnumValue);
                }
            }
        }
        return .{ .name = name.text, .values = values.items, .reserved = reserved.items, .line = name.line };
    }

    fn parseMessage(p: *Parser) Error!ast.Message {
        try p.advance(); // `message`
        const name = try p.expectIdent();
        _ = try p.expect(.l_brace);
        var m = ast.Message{ .name = name.text, .line = name.line };
        var fields: std.ArrayList(ast.Field) = .empty;
        var maps: std.ArrayList(ast.MapField) = .empty;
        var oneofs: std.ArrayList(ast.Oneof) = .empty;
        var enums: std.ArrayList(ast.Enum) = .empty;
        var messages: std.ArrayList(ast.Message) = .empty;
        var reserved: std.ArrayList(ast.ReservedRange) = .empty;
        while (p.cur.kind != .r_brace) {
            if (p.cur.kind == .eof) return p.fail(Error.UnexpectedEof);
            if (p.cur.kind == .semicolon) {
                try p.advance();
                continue;
            }
            if (p.isKeyword("option")) {
                try p.advance();
                try p.skipOption();
                continue;
            }
            if (p.isKeyword("reserved")) {
                try reserved.appendSlice(p.a, try p.parseReserved());
                continue;
            }
            if (p.isKeyword("message")) {
                try messages.append(p.a, try p.parseMessage());
                continue;
            }
            if (p.isKeyword("enum")) {
                try enums.append(p.a, try p.parseEnum());
                continue;
            }
            if (p.isKeyword("oneof")) {
                try oneofs.append(p.a, try p.parseOneof());
                continue;
            }
            if (p.isKeyword("map")) {
                try maps.append(p.a, try p.parseMapField());
                continue;
            }
            try fields.append(p.a, try p.parseField());
        }
        try p.advance(); // r_brace
        m.fields = fields.items;
        m.maps = maps.items;
        m.oneofs = oneofs.items;
        m.enums = enums.items;
        m.messages = messages.items;
        m.reserved = reserved.items;
        return m;
    }

    pub fn parse(p: *Parser) Error!ast.File {
        var f = ast.File{ .syntax = "", .package = "" };
        var imports: std.ArrayList(ast.Import) = .empty;
        var messages: std.ArrayList(ast.Message) = .empty;
        var enums: std.ArrayList(ast.Enum) = .empty;
        var have_syntax = false;
        var have_package = false;
        while (p.cur.kind != .eof) {
            if (p.cur.kind == .semicolon) {
                try p.advance();
                continue;
            }
            if (p.isKeyword("syntax")) {
                if (have_syntax) return p.fail(Error.Syntax);
                try p.advance();
                _ = try p.expect(.equals);
                const s = try p.expect(.string);
                if (!std.mem.eql(u8, s.text, "proto3")) return p.fail(Error.Syntax);
                f.syntax = s.text;
                have_syntax = true;
                _ = try p.expect(.semicolon);
                continue;
            }
            if (p.isKeyword("package")) {
                if (have_package) return p.fail(Error.Syntax);
                try p.advance();
                f.package = try p.parseTypeName();
                _ = try p.expect(.semicolon);
                have_package = true;
                continue;
            }
            if (p.isKeyword("import")) {
                try p.advance();
                const public = try p.acceptKeyword("public");
                if (!public) _ = try p.acceptKeyword("weak");
                const path = try p.expect(.string);
                try imports.append(p.a, .{ .path = path.text });
                _ = try p.expect(.semicolon);
                continue;
            }
            if (p.isKeyword("option")) {
                try p.advance();
                try p.skipOption();
                continue;
            }
            if (p.isKeyword("service")) {
                try p.advance();
                try p.skipService();
                continue;
            }
            if (p.isKeyword("reserved")) {
                _ = try p.parseReserved();
                continue;
            }
            if (p.isKeyword("message")) {
                try messages.append(p.a, try p.parseMessage());
                continue;
            }
            if (p.isKeyword("enum")) {
                try enums.append(p.a, try p.parseEnum());
                continue;
            }
            return p.fail(Error.UnexpectedToken);
        }
        if (!have_syntax) {
            p.err_line = p.cur.line;
            return Error.Syntax;
        }
        f.imports = imports.items;
        f.messages = messages.items;
        f.enums = enums.items;
        try p.validate(&f);
        return f;
    }

    fn rangeHas(ranges: []const ast.ReservedRange, n: i32) bool {
        for (ranges) |r| {
            if (r.start <= n and n <= r.end) return true;
        }
        return false;
    }

    fn validateMessage(p: *Parser, m: *const ast.Message) Error!void {
        const numbers_limit = m.fields.len + m.maps.len + blk: {
            var n: usize = 0;
            for (m.oneofs) |o| n += o.fields.len;
            break :blk n;
        };
        var numbers = try p.a.alloc(i32, numbers_limit);
        defer p.a.free(numbers);
        var count: usize = 0;
        for (m.fields) |*f| {
            numbers[count] = f.number;
            count += 1;
        }
        for (m.maps) |*mf| {
            numbers[count] = mf.number;
            count += 1;
        }
        for (m.oneofs) |o| {
            for (o.fields) |*f| {
                numbers[count] = f.number;
                count += 1;
            }
        }
        for (numbers[0..count], 0..) |n, i| {
            if (n >= first_reserved_number and n <= last_reserved_number) return p.fail(Error.BadNumber);
            if (rangeHas(m.reserved, n)) return p.fail(Error.ReservedConflict);
            for (numbers[0..count], 0..) |w, j| {
                if (i != j and w == n) return p.fail(Error.DuplicateFieldNumber);
            }
        }
        for (m.enums) |*e| try p.validateEnum(e);
        for (m.messages) |*sub| try p.validateMessage(sub);
    }

    fn validateEnum(p: *Parser, e: *const ast.Enum) Error!void {
        for (e.values) |v| {
            if (rangeHas(e.reserved, v.number)) return p.fail(Error.ReservedConflict);
        }
    }

    fn validate(p: *Parser, f: *ast.File) Error!void {
        if (!std.mem.eql(u8, f.syntax, "proto3")) return p.fail(Error.Syntax);
        for (f.enums) |*e| try p.validateEnum(e);
        for (f.messages) |*m| try p.validateMessage(m);
    }
};
