//! protogen — protobuf code generator for the NetBird Zig port.
//! `protogen parse <file.proto>` parses the proto3 subset and prints the
//! message tree. `protogen generate <file.proto> <out.zig>` emits the Zig
//! codecs (structs + size/encode/decode/deinit on src/proto/wire.zig).

const std = @import("std");
const ast = @import("ast.zig");
const parser = @import("parser.zig");
const gen = @import("gen.zig");

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    var it = std.process.Args.Iterator.init(init.minimal.args);
    _ = it.next(); // program name
    const cmd = it.next() orelse return usage();
    if (std.mem.eql(u8, cmd, "parse")) {
        const path = it.next() orelse return usage();
        const src = std.Io.Dir.cwd().readFileAlloc(init.io, path, a, .limited(64 << 20)) catch |e| {
            std.debug.print("protogen: cannot read {s}: {s}\n", .{ path, @errorName(e) });
            return error.Failure;
        };
        var p = parser.Parser.init(a, src) catch |e| {
            std.debug.print("protogen: {s}: {s}\n", .{ path, @errorName(e) });
            return error.Failure;
        };
        const file = p.parse() catch |e| {
            std.debug.print("protogen: {s}: line {d}: {s}\n", .{ path, p.err_line, @errorName(e) });
            return error.Failure;
        };
        printFile(a, file);
        return;
    }
    if (std.mem.eql(u8, cmd, "generate")) {
        const path = it.next() orelse return usage();
        const out_path = it.next() orelse return usage();
        const src = std.Io.Dir.cwd().readFileAlloc(init.io, path, a, .limited(64 << 20)) catch |e| {
            std.debug.print("protogen: cannot read {s}: {s}\n", .{ path, @errorName(e) });
            return error.Failure;
        };
        var p = parser.Parser.init(a, src) catch |e| {
            std.debug.print("protogen: {s}: {s}\n", .{ path, @errorName(e) });
            return error.Failure;
        };
        const file = p.parse() catch |e| {
            std.debug.print("protogen: {s}: line {d}: {s}\n", .{ path, p.err_line, @errorName(e) });
            return error.Failure;
        };
        const out = gen.generate(a, &file, path) catch |e| {
            std.debug.print("protogen: {s}: {s}\n", .{ path, @errorName(e) });
            return error.Failure;
        };
        std.Io.Dir.cwd().writeFile(init.io, .{ .sub_path = out_path, .data = out }) catch |e| {
            std.debug.print("protogen: cannot write {s}: {s}\n", .{ out_path, @errorName(e) });
            return error.Failure;
        };
        std.debug.print("protogen: {s} -> {s} ({d} bytes, {d} messages)\n", .{ path, out_path, out.len, file.messages.len });
        return;
    }
    return usage();
}

fn usage() error{Failure} {
    std.debug.print("usage: protogen parse <file.proto> | protogen generate <file.proto> <out.zig>\n", .{});
    return error.Failure;
}

fn printFile(a: std.mem.Allocator, f: ast.File) void {
    std.debug.print("syntax {s}\npackage {s}\n", .{ f.syntax, f.package });
    for (f.imports) |imp| std.debug.print("import \"{s}\"\n", .{imp.path});
    for (f.enums) |*e| printEnum(e, "");
    for (f.messages) |*m| printMessage(a, m, "");
}

fn printMessage(a: std.mem.Allocator, m: *const ast.Message, indent: []const u8) void {
    std.debug.print("{s}message {s} {{\n", .{ indent, m.name });
    for (m.fields) |*fld| {
        std.debug.print("{s}  {s}{s} {s} = {d};", .{
            indent,
            labelPrefix(fld.label),
            typeName(fld.typ),
            fld.name,
            fld.number,
        });
        printOptions(fld.options);
    }
    for (m.maps) |*mf| {
        std.debug.print("{s}  map<{s}, {s}> {s} = {d};\n", .{
            indent, @tagName(mf.key), typeName(mf.value), mf.name, mf.number,
        });
    }
    for (m.oneofs) |*o| {
        std.debug.print("{s}  oneof {s} {{\n", .{ indent, o.name });
        for (o.fields) |*fld| {
            std.debug.print("{s}    {s} {s} = {d};\n", .{ indent, typeName(fld.typ), fld.name, fld.number });
        }
        std.debug.print("{s}  }}\n", .{indent});
    }
    for (m.enums) |*e| printEnum(e, indent);
    const sub_indent = std.fmt.allocPrint(a, "{s}  ", .{indent}) catch return;
    for (m.messages) |*sub| printMessage(a, sub, sub_indent);
    if (m.reserved.len > 0) {
        std.debug.print("{s}  reserved", .{indent});
        for (m.reserved) |r| {
            if (r.start < 0) {
                std.debug.print(" name", .{});
            } else if (r.start == r.end) {
                std.debug.print(" {d}", .{r.start});
            } else {
                std.debug.print(" {d} to {d}", .{ r.start, r.end });
            }
        }
        std.debug.print(";\n", .{});
    }
    std.debug.print("{s}}}\n", .{indent});
}

fn printEnum(e: *const ast.Enum, indent: []const u8) void {
    std.debug.print("{s}enum {s} {{\n", .{ indent, e.name });
    for (e.values) |v| std.debug.print("{s}  {s} = {d};\n", .{ indent, v.name, v.number });
    std.debug.print("{s}}}\n", .{indent});
}

fn labelPrefix(l: ast.Label) []const u8 {
    return switch (l) {
        .none => "",
        .optional => "optional ",
        .repeated => "repeated ",
    };
}

fn typeName(t: ast.TypeRef) []const u8 {
    return switch (t) {
        .scalar => |s| @tagName(s),
        .named => |n| n,
    };
}

fn printOptions(opts: []const ast.Option) void {
    if (opts.len == 0) {
        std.debug.print("\n", .{});
        return;
    }
    std.debug.print(" [", .{});
    for (opts, 0..) |o, i| {
        if (i > 0) std.debug.print(", ", .{});
        std.debug.print("{s} = {s}", .{ o.name, o.value });
    }
    std.debug.print("]\n", .{});
}

test {
    _ = @import("lexer.zig");
    _ = @import("parser.zig");
    _ = @import("parser_test.zig");
    _ = @import("gen.zig");
    _ = @import("gen_test.zig");
}
