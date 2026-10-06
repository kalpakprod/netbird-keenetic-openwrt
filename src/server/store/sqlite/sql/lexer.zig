// Port of the SQLite 3.51.3 grammar (parse.y semantics, public domain) as used by netbird v0.80.0, BSD-3-Clause for this Zig code.
const std = @import("std");
pub const Kind = enum { eof, word, identifier, string, blob, number, parameter, lparen, rparen, comma, dot, semicolon, operator };
pub const Diagnostic = struct { near: []const u8 = "", offset: usize = 0 };
pub const Token = struct {
    kind: Kind,
    text: []const u8,
    start: usize,
    end: usize,
    pub fn is(self: Token, text: []const u8) bool { return std.ascii.eqlIgnoreCase(self.text, text); }
};
pub const Error = error{InvalidToken};
pub const Lexer = struct {
    sql: []const u8,
    pos: usize = 0,
    diagnostic: Diagnostic = .{},
    pub fn init(sql: []const u8) Lexer { return .{ .sql = sql }; }
    fn token(self: *Lexer, kind: Kind, start: usize) Token { return .{ .kind = kind, .text = self.sql[start..self.pos], .start = start, .end = self.pos }; }
    fn invalid(self: *Lexer, start: usize) Error { self.diagnostic = .{ .offset = start, .near = self.sql[start..@min(self.sql.len, @max(start + 1, self.pos))] }; return error.InvalidToken; }
    pub fn next(self: *Lexer) Error!Token {
        const s = self.sql;
        while (self.pos < s.len) {
            if (std.ascii.isWhitespace(s[self.pos])) { self.pos += 1; continue; }
            if (std.mem.startsWith(u8, s[self.pos..], "--")) { while (self.pos < s.len and s[self.pos] != '\n') self.pos += 1; continue; }
            if (std.mem.startsWith(u8, s[self.pos..], "/*")) { self.pos += 2; while (self.pos + 1 < s.len and !std.mem.startsWith(u8, s[self.pos..], "*/")) self.pos += 1; self.pos = @min(s.len, self.pos + 2); continue; }
            break;
        }
        const start = self.pos;
        if (start == s.len) return self.token(.eof, start);
        const c = s[start]; self.pos += 1;
        if ((c == 'x' or c == 'X') and self.pos < s.len and s[self.pos] == '\'') {
            self.pos += 1; const begin = self.pos;
            while (self.pos < s.len and std.ascii.isHex(s[self.pos])) self.pos += 1;
            if (self.pos == s.len or s[self.pos] != '\'' or (self.pos - begin) % 2 != 0) return self.invalid(start);
            self.pos += 1; return self.token(.blob, start);
        }
        if (c == '\'' or c == '"' or c == '`' or c == '[') {
            const close: u8 = if (c == '[') ']' else c;
            while (self.pos < s.len) {
                if (s[self.pos] == close) { self.pos += 1; if (c != '[' and self.pos < s.len and s[self.pos] == close) { self.pos += 1; continue; } return self.token(if (c == '\'') .string else .identifier, start); }
                self.pos += 1;
            }
            return self.invalid(start);
        }
        if (std.ascii.isDigit(c) or (c == '.' and self.pos < s.len and std.ascii.isDigit(s[self.pos]))) {
            if (c == '0' and self.pos < s.len and (s[self.pos] == 'x' or s[self.pos] == 'X')) {
                self.pos += 1; const begin = self.pos;
                while (self.pos < s.len and (std.ascii.isHex(s[self.pos]) or (s[self.pos] == '_' and self.pos > begin and self.pos + 1 < s.len and std.ascii.isHex(s[self.pos + 1])))) self.pos += 1;
                if (self.pos == begin) return self.invalid(start);
            } else {
                self.digits();
                if (c != '.' and self.pos < s.len and s[self.pos] == '.') { self.pos += 1; self.digits(); }
                if (self.pos < s.len and (s[self.pos] == 'e' or s[self.pos] == 'E')) { self.pos += 1; if (self.pos < s.len and (s[self.pos] == '+' or s[self.pos] == '-')) self.pos += 1; const begin = self.pos; self.digits(); if (self.pos == begin) return self.invalid(start); }
            }
            if (self.pos < s.len and (nameStart(s[self.pos]) or s[self.pos] == '.')) return self.invalid(start);
            return self.token(.number, start);
        }
        if (c == '?' or c == ':' or c == '@' or c == '$') {
            if (c == '?') { while (self.pos < s.len and std.ascii.isDigit(s[self.pos])) self.pos += 1; }
            else {
                const begin = self.pos;
                while (self.pos < s.len) {
                    if (nameContinue(s[self.pos])) { self.pos += 1; continue; }
                    if (std.mem.startsWith(u8, s[self.pos..], "::")) { self.pos += 2; continue; }
                    if (s[self.pos] == '(') { self.pos += 1; while (self.pos < s.len and s[self.pos] != ')' and !std.ascii.isWhitespace(s[self.pos])) self.pos += 1; if (self.pos == s.len or s[self.pos] != ')') return self.invalid(start); self.pos += 1; }
                    break;
                }
                if (self.pos == begin) return self.invalid(start);
            }
            return self.token(.parameter, start);
        }
        if (nameStart(c)) { while (self.pos < s.len and nameContinue(s[self.pos])) self.pos += 1; return self.token(.word, start); }
        const kind: Kind = switch (c) { '(' => .lparen, ')' => .rparen, ',' => .comma, '.' => .dot, ';' => .semicolon, '+', '-', '*', '/', '%', '~', '&', '|', '<', '>', '=', '!' => .operator, else => return self.invalid(start) };
        if (kind == .operator and self.pos < s.len) {
            const n = s[self.pos];
            if ((n == '=' and (c == '<' or c == '>' or c == '=' or c == '!')) or (n == c and (c == '<' or c == '>' or c == '|')) or (c == '<' and n == '>')) self.pos += 1;
        }
        if (c == '!' and self.pos == start + 1) return self.invalid(start);
        return self.token(kind, start);
    }
    fn digits(self: *Lexer) void {
        while (self.pos < self.sql.len) { const c = self.sql[self.pos]; if (std.ascii.isDigit(c)) { self.pos += 1; continue; } if (c == '_' and self.pos > 0 and std.ascii.isDigit(self.sql[self.pos - 1]) and self.pos + 1 < self.sql.len and std.ascii.isDigit(self.sql[self.pos + 1])) { self.pos += 1; continue; } break; }
    }
};
fn nameStart(c: u8) bool { return std.ascii.isAlphabetic(c) or c == '_' or c >= 0x80; }
fn nameContinue(c: u8) bool { return nameStart(c) or std.ascii.isDigit(c) or c == '$'; }
pub fn isFallback(s: []const u8) bool {
    var words = std.mem.tokenizeScalar(u8, "ABORT ACTION AFTER ANALYZE ASC ATTACH BEFORE BEGIN BY CASCADE CAST COLUMN CONFLICT DATABASE DEFERRED DESC DETACH DO EACH END EXCLUSIVE EXPLAIN FAIL FOR IGNORE IMMEDIATE INITIALLY INSTEAD LIKE GLOB REGEXP MATCH NO PLAN QUERY KEY OF OFFSET PRAGMA RAISE RECURSIVE RELEASE REPLACE RESTRICT ROLLBACK ROW ROWS SAVEPOINT TEMP TRIGGER VACUUM VIEW VIRTUAL WITH WITHOUT NULLS FIRST LAST CURRENT FOLLOWING PARTITION PRECEDING RANGE UNBOUNDED EXCLUDE GROUPS OTHERS TIES GENERATED ALWAYS MATERIALIZED REINDEX RENAME CURRENT_DATE CURRENT_TIME CURRENT_TIMESTAMP IF", ' ');
    while (words.next()) |word| if (std.ascii.eqlIgnoreCase(s, word)) return true;
    return false;
}
