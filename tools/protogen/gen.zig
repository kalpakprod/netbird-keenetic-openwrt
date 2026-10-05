//! Zig code generator: turns the parsed proto3 subset into Zig structs with
//! size/encode/decode/deinit on top of src/proto/wire.zig.
//!
//! Wire semantics mirrored from protobuf-go:
//! - fields encode in ascending field-number order; zero values skipped
//!   (proto3 implicit presence); proto3-optional fields and message fields
//!   use null presence;
//! - repeated packable scalars encode packed (a single LEN record); the
//!   decoder accepts both packed and unpacked forms;
//! - maps encode as repeated entry messages in deterministic key order; entry
//!   key/value are implicit presence (zero values omitted);
//! - int32/int64/enum sign-extend to 64 bits (negative -> 10-byte varint);
//! - unknown fields and known numbers with an unexpected wire type are
//!   preserved as raw bytes, like default protobuf-go Unmarshal;
//! - nested message recursion is depth-limited (10000).

const std = @import("std");
const ast = @import("ast.zig");

pub const Error = error{
    UnresolvedType,
    OutOfMemory,
};

const ZigKeywordSet = std.StaticStringMap(void).initComptime(.{
    .{ "align", {} },          .{ "and", {} },       .{ "anytype", {} },
    .{ "anyerror", {} },       .{ "asm", {} },       .{ "async", {} },
    .{ "await", {} },          .{ "bool", {} },      .{ "break", {} },
    .{ "callconv", {} },       .{ "catch", {} },     .{ "comptime", {} },
    .{ "continue", {} },       .{ "defer", {} },     .{ "else", {} },
    .{ "enum", {} },           .{ "errdefer", {} },  .{ "error", {} },
    .{ "export", {} },         .{ "extern", {} },    .{ "false", {} },
    .{ "fn", {} },             .{ "for", {} },       .{ "if", {} },
    .{ "inline", {} },         .{ "noalias", {} },   .{ "noinline", {} },
    .{ "nosuspend", {} },      .{ "noreturn", {} },  .{ "opaque", {} },
    .{ "or", {} },             .{ "orelse", {} },    .{ "packed", {} },
    .{ "pub", {} },            .{ "resume", {} },    .{ "return", {} },
    .{ "linksection", {} },    .{ "struct", {} },    .{ "suspend", {} },
    .{ "switch", {} },         .{ "test", {} },      .{ "threadlocal", {} },
    .{ "true", {} },           .{ "try", {} },       .{ "type", {} },
    .{ "undefined", {} },      .{ "union", {} },     .{ "unreachable", {} },
    .{ "usingnamespace", {} }, .{ "var", {} },       .{ "volatile", {} },
    .{ "void", {} },           .{ "while", {} },     .{ "null", {} },
});

/// Quotes a proto identifier for use as a Zig identifier when needed.
pub fn zigName(a: std.mem.Allocator, name: []const u8) Error![]const u8 {
    if (ZigKeywordSet.has(name)) {
        return std.fmt.allocPrint(a, "@\"{s}\"", .{name}) catch Error.OutOfMemory;
    }
    return name;
}

const TypeKind = enum { message, enum_ };

const RegistryEntry = struct {
    kind: TypeKind,
    /// Zig type expression, e.g. "PeerConfig" or "PortInfo.Range".
    zig_path: []const u8,
};

const Kind = enum {
    scalar_single,
    scalar_optional,
    message_single,
    repeated_scalar, // numeric/bool/enum elements: packable
    repeated_string,
    repeated_message,
    map,
};

const FieldDesc = struct {
    /// Zig field name (quoted when needed).
    zig: []const u8,
    /// Raw proto field name (for generated type names like X_Entry).
    raw: []const u8,
    number: i32,
    kind: Kind,
    scalar: ast.Scalar = .int32,
    /// Zig type for message/enum references.
    type_zig: []const u8 = "",
    /// True when a varint scalar carries a named (generated) enum type.
    is_enum: bool = false,
    /// Map-only: key scalar; value kind flags.
    map_key: ast.Scalar = .string,
    map_value_is_message: bool = false,
    map_value_enum: bool = false,
};

const OneofDesc = struct {
    /// Raw proto oneof name; also used (suffixed) as the union type name.
    name: []const u8,
    zig_name: []const u8, // quoted field name
    cases: []FieldDesc,
};

const OrderItem = struct {
    number: i32,
    field: ?*const FieldDesc = null,
    oneof: ?*const OneofDesc = null,
    case: ?*const FieldDesc = null,
};

const Generator = struct {
    a: std.mem.Allocator,
    file: *const ast.File,
    out: std.ArrayList(u8) = .empty,
    registry: std.StringHashMapUnmanaged(RegistryEntry) = .empty,
    imports_timestamp: bool = false,
    imports_duration: bool = false,
    imports_empty: bool = false,

    fn line(g: *Generator, comptime f: []const u8, args: anytype) Error!void {
        const s = std.fmt.allocPrint(g.a, f, args) catch return Error.OutOfMemory;
        defer g.a.free(s);
        g.out.appendSlice(g.a, s) catch return Error.OutOfMemory;
        g.out.appendSlice(g.a, "\n") catch return Error.OutOfMemory;
    }

    fn dup(g: *Generator, s: []const u8) Error![]const u8 {
        return g.a.dupe(u8, s) catch Error.OutOfMemory;
    }

    fn fmt(g: *Generator, comptime f: []const u8, args: anytype) Error![]const u8 {
        return std.fmt.allocPrint(g.a, f, args) catch Error.OutOfMemory;
    }

    fn registerMessage(g: *Generator, m: *const ast.Message, fq_prefix: []const u8, zig_prefix: []const u8) Error!void {
        const fq = try g.fmt("{s}{s}", .{ fq_prefix, m.name });
        const zig_path = if (zig_prefix.len == 0)
            try g.dup(m.name)
        else
            try g.fmt("{s}{s}", .{ zig_prefix, m.name });
        g.registry.put(g.a, fq, .{ .kind = .message, .zig_path = zig_path }) catch return Error.OutOfMemory;
        const sub_fq = try g.fmt("{s}.", .{fq});
        const sub_zig = try g.fmt("{s}.", .{zig_path});
        for (m.messages) |*sub| try g.registerMessage(sub, sub_fq, sub_zig);
        for (m.enums) |*e| {
            const efq = try g.fmt("{s}{s}", .{ sub_fq, e.name });
            const ezig = try g.fmt("{s}{s}", .{ sub_zig, e.name });
            g.registry.put(g.a, efq, .{ .kind = .enum_, .zig_path = ezig }) catch return Error.OutOfMemory;
        }
    }

    fn registerTopEnum(g: *Generator, e: *const ast.Enum) Error!void {
        const fq = try g.fmt("{s}.{s}", .{ g.file.package, e.name });
        g.registry.put(g.a, fq, .{ .kind = .enum_, .zig_path = try g.dup(e.name) }) catch return Error.OutOfMemory;
    }

    fn resolve(g: *Generator, ref: []const u8, scope: []const []const u8) Error![]const u8 {
        if (ref.len > 0 and ref[0] == '.') {
            if (g.lookup(ref[1..])) |z| return z;
            return Error.UnresolvedType;
        }
        var i: usize = scope.len;
        while (i > 0) : (i -= 1) {
            const joined = try g.joinScope(scope[0..i], ref);
            const fq = if (g.file.package.len > 0)
                try g.fmt("{s}.{s}", .{ g.file.package, joined })
            else
                joined;
            if (g.lookup(fq)) |z| return z;
        }
        // Package scope (fields of top-level messages resolve here).
        if (g.file.package.len > 0) {
            const pkg_ref = try g.fmt("{s}.{s}", .{ g.file.package, ref });
            if (g.lookup(pkg_ref)) |z| return z;
        }
        if (g.lookup(ref)) |z| return z;
        return Error.UnresolvedType;
    }

    fn joinScope(g: *Generator, scope: []const []const u8, ref: []const u8) Error![]const u8 {
        if (scope.len == 0) return ref;
        var len: usize = ref.len;
        for (scope) |s| len += s.len + 1;
        const buf = g.a.alloc(u8, len) catch return Error.OutOfMemory;
        var n: usize = 0;
        for (scope) |s| {
            @memcpy(buf[n..][0..s.len], s);
            n += s.len;
            buf[n] = '.';
            n += 1;
        }
        @memcpy(buf[n..], ref);
        return buf;
    }

    fn lookup(g: *Generator, fq: []const u8) ?[]const u8 {
        if (g.registry.get(fq)) |e| return e.zig_path;
        if (std.mem.eql(u8, fq, "google.protobuf.Timestamp") and g.imports_timestamp) return "Timestamp";
        if (std.mem.eql(u8, fq, "google.protobuf.Duration") and g.imports_duration) return "Duration";
        if (std.mem.eql(u8, fq, "google.protobuf.Empty") and g.imports_empty) return "Empty";
        return null;
    }

    fn isEnumRef(g: *Generator, ref: []const u8, scope: []const []const u8) Error!bool {
        var fq: []const u8 = ref;
        if (ref.len > 0 and ref[0] == '.') {
            fq = ref[1..];
        } else {
            var i: usize = scope.len;
            while (i > 0) : (i -= 1) {
                const joined = try g.joinScope(scope[0..i], ref);
                const cand = if (g.file.package.len > 0)
                    try g.fmt("{s}.{s}", .{ g.file.package, joined })
                else
                    joined;
                if (g.registry.get(cand)) |e| return e.kind == .enum_;
            }
            if (g.file.package.len > 0) {
                const pkg_ref = try g.fmt("{s}.{s}", .{ g.file.package, ref });
                if (g.registry.get(pkg_ref)) |e| return e.kind == .enum_;
            }
        }
        if (g.registry.get(fq)) |e| return e.kind == .enum_;
        if (g.lookup(fq) != null) return false;
        return Error.UnresolvedType;
    }

    fn appendScope(g: *Generator, scope: []const []const u8, name: []const u8) Error![]const []const u8 {
        const buf = g.a.alloc([]const u8, scope.len + 1) catch return Error.OutOfMemory;
        @memcpy(buf[0..scope.len], scope);
        buf[scope.len] = name;
        return buf;
    }
};

// Strip checkout/cache prefixes while preserving the NetBird-relative origin.
fn originPath(path: []const u8) []const u8 {
    const markers = [_][]const u8{ "upstream/netbird/", "upstream-v080/" };
    for (markers) |marker| {
        if (std.mem.indexOf(u8, path, marker)) |i| {
            if (i == 0 or path[i - 1] == '/') return path[i + marker.len ..];
        }
    }
    return path;
}

pub fn generate(a: std.mem.Allocator, file: *const ast.File, source_path: []const u8) Error![]const u8 {
    var g = Generator{ .a = a, .file = file };
    for (file.imports) |imp| {
        if (std.mem.endsWith(u8, imp.path, "timestamp.proto")) g.imports_timestamp = true;
        if (std.mem.endsWith(u8, imp.path, "duration.proto")) g.imports_duration = true;
        if (std.mem.endsWith(u8, imp.path, "empty.proto")) g.imports_empty = true;
    }
    const pkg_prefix = if (file.package.len > 0)
        try g.fmt("{s}.", .{file.package})
    else
        "";
    for (file.messages) |*m| try g.registerMessage(m, pkg_prefix, "");
    for (file.enums) |*e| try g.registerTopEnum(e);

    const origin = originPath(source_path);
    const license = blk: {
        const agpl = std.mem.startsWith(u8, origin, "shared/management/") or
            std.mem.startsWith(u8, origin, "shared/signal/") or
            std.mem.startsWith(u8, origin, "management/") or
            std.mem.startsWith(u8, origin, "signal/") or
            std.mem.startsWith(u8, origin, "relay/") or
            std.mem.startsWith(u8, origin, "combined/");
        break :blk if (agpl) "AGPL-3.0" else "BSD-3-Clause";
    };
    try g.line("//! Generated by tools/protogen from {s} - do not edit.", .{origin});
    try g.line("//! Port of netbird {s} (v0.80.0), {s}.", .{ origin, license });
    try g.line("//! Codecs on top of src/proto/wire.zig; marshal order follows", .{});
    try g.line("//! protobuf-go: fields ascending by number, zero values skipped,", .{});
    try g.line("//! packed repeated scalars, map entries in deterministic key order.", .{});
    try g.line("", .{});
    try g.line("const std = @import(\"std\");", .{});
    try g.line("const wire = @import(\"../wire.zig\");", .{});
    try g.line("", .{});
    try g.line("pub const DecodeError = wire.Error || error{{OutOfMemory}};", .{});
    try g.line("", .{});
    try g.line("/// protobuf-go's default recursion limit for nested messages.", .{});
    try g.line("pub const default_recursion_depth: u32 = 10000;", .{});

    if (g.imports_timestamp) {
        try g.line("", .{});
        try emitMessage(&g, &timestamp_msg, "", &.{});
    }
    if (g.imports_duration) {
        try g.line("", .{});
        try emitMessage(&g, &duration_msg, "", &.{});
    }
    if (g.imports_empty) {
        try g.line("", .{});
        try g.line("pub const Empty = struct {{}};", .{});
    }

    for (file.enums) |*e| {
        try g.line("", .{});
        try emitEnum(&g, e, "");
    }
    for (file.messages) |*m| {
        try g.line("", .{});
        try emitMessage(&g, m, "", &.{});
    }

    return g.out.items;
}

// Well-known message shapes (canonical field numbers 1/2).
const wk_ts_fields = [_]ast.Field{
    .{ .label = .none, .typ = .{ .scalar = .int64 }, .name = "seconds", .number = 1 },
    .{ .label = .none, .typ = .{ .scalar = .int32 }, .name = "nanos", .number = 2 },
};
const timestamp_msg = ast.Message{ .name = "Timestamp", .fields = &wk_ts_fields };
const duration_msg = ast.Message{ .name = "Duration", .fields = &wk_ts_fields };

fn emitEnum(g: *Generator, e: *const ast.Enum, indent: []const u8) Error!void {
    try g.line("{s}pub const {s} = enum(i32) {{", .{ indent, e.name });
    for (e.values) |v| {
        try g.line("{s}    {s} = {d},", .{ indent, v.name, v.number });
    }
    try g.line("{s}    _,", .{indent});
    try g.line("{s}}};", .{indent});
}

fn scalarDefault(s: ast.Scalar) []const u8 {
    return switch (s) {
        .boolean => "false",
        .string, .bytes => "\"\"",
        else => "0",
    };
}

fn scalarZigType(s: ast.Scalar) []const u8 {
    return switch (s) {
        .boolean => "bool",
        .int32, .sint32, .sfixed32 => "i32",
        .int64, .sint64, .sfixed64 => "i64",
        .uint32, .fixed32 => "u32",
        .uint64, .fixed64 => "u64",
        .float => "f32",
        .double => "f64",
        .string, .bytes => "[]const u8",
    };
}

fn scalarWireType(s: ast.Scalar) []const u8 {
    return switch (s) {
        .boolean, .int32, .int64, .uint32, .uint64, .sint32, .sint64 => ".varint",
        .fixed32, .sfixed32, .float => ".fixed32",
        .fixed64, .sfixed64, .double => ".fixed64",
        .string, .bytes => ".bytes",
    };
}

fn fieldDesc(g: *Generator, f: *const ast.Field, scope: []const []const u8) Error!FieldDesc {
    var d = FieldDesc{
        .zig = try zigName(g.a, f.name),
        .raw = f.name,
        .number = f.number,
        .kind = .scalar_single,
    };
    switch (f.typ) {
        .scalar => |s| {
            d.scalar = s;
            d.kind = switch (f.label) {
                .repeated => if (s == .string or s == .bytes) Kind.repeated_string else Kind.repeated_scalar,
                .optional => Kind.scalar_optional,
                else => Kind.scalar_single,
            };
        },
        .named => |n| {
            d.type_zig = try g.resolve(n, scope);
            const enum_ref = try g.isEnumRef(n, scope);
            if (f.label == .repeated) {
                d.kind = if (enum_ref) Kind.repeated_scalar else Kind.repeated_message;
                d.is_enum = enum_ref;
                if (enum_ref) d.scalar = .int32;
            } else if (enum_ref) {
                d.kind = .scalar_single;
                d.is_enum = true;
                d.scalar = .int32;
            } else {
                d.kind = .message_single;
            }
        },
    }
    return d;
}

fn mapFieldDesc(g: *Generator, mf: *const ast.MapField, scope: []const []const u8) Error!FieldDesc {
    var d = FieldDesc{
        .zig = try zigName(g.a, mf.name),
        .raw = mf.name,
        .number = mf.number,
        .kind = .map,
    };
    d.map_key = mf.key;
    switch (mf.value) {
        .scalar => |s| d.scalar = s,
        .named => |n| {
            d.type_zig = try g.resolve(n, scope);
            d.map_value_enum = try g.isEnumRef(n, scope);
            d.map_value_is_message = !d.map_value_enum;
            if (d.map_value_enum) d.scalar = .int32;
        },
    }
    return d;
}

/// Presence test for implicit-presence fields; `access` is the value access
/// expression (e.g. "m.f", "v", "el").
fn hasValueExpr(g: *Generator, d: *const FieldDesc, access: []const u8) Error![]const u8 {
    if (d.is_enum) return g.fmt("(@intFromEnum({s}) != 0)", .{access});
    return switch (d.scalar) {
        .boolean => g.fmt("{s}", .{access}),
        .string, .bytes => g.fmt("({s}.len != 0)", .{access}),
        else => g.fmt("({s} != 0)", .{access}),
    };
}

/// u64 value expression for appendVarint/sizeVarint of a signed-varint
/// scalar (int32/int64/uint/sint/bool/enum).
fn varintExpr(g: *Generator, d: *const FieldDesc, access: []const u8) Error![]const u8 {
    if (d.is_enum) return g.fmt("@as(u64, @bitCast(@as(i64, @intFromEnum({s}))))", .{access});
    return switch (d.scalar) {
        .int32 => g.fmt("@as(u64, @bitCast(@as(i64, {s})))", .{access}),
        .int64 => g.fmt("@as(u64, @bitCast({s}))", .{access}),
        .uint32 => g.fmt("@as(u64, {s})", .{access}),
        .uint64 => g.fmt("{s}", .{access}),
        .boolean => g.fmt("@as(u64, if ({s}) 1 else 0)", .{access}),
        .sint32, .sint64 => g.fmt("wire.encodeZigZag({s})", .{access}),
        else => Error.UnresolvedType,
    };
}

/// Byte-size term for one scalar value (after the tag).
fn scalarSizeTerm(g: *Generator, d: *const FieldDesc, access: []const u8) Error![]const u8 {
    return switch (d.scalar) {
        .boolean, .int32, .int64, .uint32, .uint64, .sint32, .sint64 => g.fmt("wire.sizeVarint({s})", .{try varintExpr(g, d, access)}),
        .fixed32, .sfixed32, .float => g.dup("4"),
        .fixed64, .sfixed64, .double => g.dup("8"),
        .string, .bytes => g.fmt("wire.sizeBytes({s}.len)", .{access}),
    };
}

fn varintDecodeExpr(g: *Generator, d: *const FieldDesc) Error![]const u8 {
    if (d.is_enum) return g.fmt("@as({s}, @enumFromInt(@as(i32, @bitCast(@as(u32, @truncate(v))))))", .{d.type_zig});
    return switch (d.scalar) {
        .int32 => g.dup("@as(i32, @bitCast(@as(u32, @truncate(v))))"),
        .int64 => g.dup("@as(i64, @bitCast(v))"),
        .uint32 => g.dup("@as(u32, @truncate(v))"),
        .uint64 => g.dup("v"),
        .boolean => g.dup("(v != 0)"),
        .sint32 => g.dup("@as(i32, @truncate(wire.decodeZigZag(v)))"),
        .sint64 => g.dup("wire.decodeZigZag(v)"),
        else => Error.UnresolvedType,
    };
}

/// Fixed/float decode conversion from the consumed u32/u64 named `fv`.
fn fixedDecodeExpr(g: *Generator, d: *const FieldDesc) Error![]const u8 {
    return switch (d.scalar) {
        .fixed32 => g.dup("fv"),
        .fixed64 => g.dup("fv"),
        .sfixed32 => g.dup("@as(i32, @bitCast(fv))"),
        .sfixed64 => g.dup("@as(i64, @bitCast(fv))"),
        .float => g.dup("@as(f32, @bitCast(fv))"),
        .double => g.dup("@as(f64, @bitCast(fv))"),
        else => Error.UnresolvedType,
    };
}

/// Fixed/float encode argument for appendFixed32/64.
fn fixedEncodeExpr(g: *Generator, d: *const FieldDesc, access: []const u8) Error![]const u8 {
    return switch (d.scalar) {
        .fixed32 => g.fmt("{s}", .{access}),
        .fixed64 => g.fmt("{s}", .{access}),
        .sfixed32 => g.fmt("@as(u32, @bitCast({s}))", .{access}),
        .sfixed64 => g.fmt("@as(u64, @bitCast({s}))", .{access}),
        .float => g.fmt("@as(u32, @bitCast({s}))", .{access}),
        .double => g.fmt("@as(u64, @bitCast({s}))", .{access}),
        else => Error.UnresolvedType,
    };
}

fn emitMessage(g: *Generator, m: *const ast.Message, indent: []const u8, scope: []const []const u8) Error!void {
    const inner_indent = try g.fmt("{s}    ", .{indent});
    const own_scope = try g.appendScope(scope, m.name);
    try g.line("{s}pub const {s} = struct {{", .{ indent, m.name });

    var descs: std.ArrayList(FieldDesc) = .empty;
    for (m.fields) |*f| try descs.append(g.a, try fieldDesc(g, f, own_scope));
    for (m.maps) |*mf| try descs.append(g.a, try mapFieldDesc(g, mf, own_scope));
    var oneofs: std.ArrayList(OneofDesc) = .empty;
    for (m.oneofs) |*o| {
        var cases: std.ArrayList(FieldDesc) = .empty;
        for (o.fields) |*f| try cases.append(g.a, try fieldDesc(g, f, own_scope));
        try oneofs.append(g.a, .{
            .name = o.name,
            .zig_name = try zigName(g.a, o.name),
            .cases = cases.items,
        });
    }

    var order: std.ArrayList(OrderItem) = .empty;
    for (descs.items) |*d| try order.append(g.a, .{ .number = d.number, .field = d });
    for (oneofs.items) |*o| {
        for (o.cases) |*c| try order.append(g.a, .{ .number = c.number, .oneof = o, .case = c });
    }
    std.mem.sort(OrderItem, order.items, {}, orderLess);

    // All fields first: Zig forbids declarations between container fields.
    for (descs.items) |*d| {
        switch (d.kind) {
            .scalar_single => if (d.is_enum) {
                try g.line("{s}    {s}: {s} = @enumFromInt(0),", .{ indent, d.zig, d.type_zig });
            } else {
                try g.line("{s}    {s}: {s} = {s},", .{ indent, d.zig, scalarZigType(d.scalar), scalarDefault(d.scalar) });
            },
            .scalar_optional, .message_single => {
                const ty = if (d.kind == .message_single or d.is_enum) d.type_zig else scalarZigType(d.scalar);
                try g.line("{s}    {s}: ?{s} = null,", .{ indent, d.zig, ty });
            },
            .repeated_scalar => {
                const elem = if (d.is_enum) d.type_zig else scalarZigType(d.scalar);
                try g.line("{s}    {s}: []{s} = &.{{}},", .{ indent, d.zig, elem });
            },
            .repeated_string => try g.line("{s}    {s}: [][]const u8 = &.{{}},", .{ indent, d.zig }),
            .repeated_message => try g.line("{s}    {s}: []{s} = &.{{}},", .{ indent, d.zig, d.type_zig }),
            .map => try g.line("{s}    {s}: []{s}_Entry = &.{{}},", .{ indent, d.zig, d.raw }),
        }
    }
    for (oneofs.items) |*o| {
        try g.line("{s}    {s}: ?{s}_union = null,", .{ indent, o.zig_name, o.name });
    }

    try g.line("{s}    unknown_fields: []const u8 = &.{{}},", .{indent});

    // Map entry types and oneof unions come after every field.
    for (descs.items) |*d| {
        if (d.kind != .map) continue;
        try g.line("{s}    pub const {s}_Entry = struct {{", .{ indent, d.raw });
        try g.line("{s}        key: {s} = {s},", .{ indent, scalarZigType(d.map_key), scalarDefault(d.map_key) });
        if (d.map_value_is_message) {
            try g.line("{s}        value: {s} = .{{}},", .{ indent, d.type_zig });
        } else if (d.map_value_enum) {
            try g.line("{s}        value: {s} = @enumFromInt(0),", .{ indent, d.type_zig });
        } else {
            try g.line("{s}        value: {s} = {s},", .{ indent, scalarZigType(d.scalar), scalarDefault(d.scalar) });
        }
        try g.line("{s}    }};", .{indent});
    }
    for (oneofs.items) |*o| {
        try g.line("{s}    pub const {s}_union = union(enum) {{", .{ indent, o.name });
        for (o.cases) |*c| {
            if (c.kind == .message_single or c.is_enum) {
                try g.line("{s}        {s}: {s},", .{ indent, c.zig, c.type_zig });
            } else {
                try g.line("{s}        {s}: {s},", .{ indent, c.zig, scalarZigType(c.scalar) });
            }
        }
        try g.line("{s}    }};", .{indent});
    }

    for (m.enums) |*e| {
        try g.line("", .{});
        try emitEnum(g, e, inner_indent);
    }
    for (m.messages) |*sub| {
        try g.line("", .{});
        try emitMessage(g, sub, inner_indent, own_scope);
    }

    try g.line("", .{});
    try emitSize(g, indent, order.items);
    try g.line("", .{});
    try emitEncode(g, indent, order.items);
    try g.line("", .{});
    try emitDecode(g, indent, order.items);
    try g.line("", .{});
    try emitDeinit(g, indent, descs.items, oneofs.items);

    try g.line("{s}}};", .{indent});
}

fn orderLess(_: void, x: OrderItem, y: OrderItem) bool {
    return x.number < y.number;
}

fn descUsesAlloc(d: *const FieldDesc) bool {
    return switch (d.kind) {
        .repeated_scalar, .repeated_string, .repeated_message, .map, .message_single => true,
        .scalar_single, .scalar_optional => d.scalar == .string or d.scalar == .bytes,
    };
}

fn caseUsesAlloc(c: *const FieldDesc) bool {
    return c.kind == .message_single or c.scalar == .string or c.scalar == .bytes;
}

/// Emits the size contribution for one scalar/message value with the given
/// presence expression and access (access used for the size term).
fn emitScalarSizeLine(g: *Generator, indent: []const u8, d: *const FieldDesc, has: []const u8, access: []const u8) Error!void {
    switch (d.scalar) {
        .string, .bytes => {
            try g.line("{s}    if ({s}) n += wire.sizeTag({d}) + wire.sizeBytes({s}.len);", .{ indent, has, d.number, access });
        },
        .fixed32, .sfixed32, .float => {
            try g.line("{s}    if ({s}) n += wire.sizeTag({d}) + 4;", .{ indent, has, d.number });
        },
        .fixed64, .sfixed64, .double => {
            try g.line("{s}    if ({s}) n += wire.sizeTag({d}) + 8;", .{ indent, has, d.number });
        },
        else => {
            const ve = try varintExpr(g, d, access);
            try g.line("{s}    if ({s}) n += wire.sizeTag({d}) + wire.sizeVarint({s});", .{ indent, has, d.number, ve });
        },
    }
}

/// Emits the encode statements for one scalar/message value.
fn emitScalarEncodeLines(g: *Generator, indent: []const u8, d: *const FieldDesc, has: []const u8, access: []const u8) Error!void {
    switch (d.scalar) {
        .string, .bytes => {
            try g.line("{s}    if ({s}) {{", .{ indent, has });
            try g.line("{s}        try e.appendTag({d}, .bytes);", .{ indent, d.number });
            try g.line("{s}        try e.appendBytes({s});", .{ indent, access });
            try g.line("{s}    }}", .{indent});
        },
        .fixed32, .sfixed32, .float => {
            const fe = try fixedEncodeExpr(g, d, access);
            try g.line("{s}    if ({s}) {{", .{ indent, has });
            try g.line("{s}        try e.appendTag({d}, .fixed32);", .{ indent, d.number });
            try g.line("{s}        try e.appendFixed32({s});", .{ indent, fe });
            try g.line("{s}    }}", .{indent});
        },
        .fixed64, .sfixed64, .double => {
            const fe = try fixedEncodeExpr(g, d, access);
            try g.line("{s}    if ({s}) {{", .{ indent, has });
            try g.line("{s}        try e.appendTag({d}, .fixed64);", .{ indent, d.number });
            try g.line("{s}        try e.appendFixed64({s});", .{ indent, fe });
            try g.line("{s}    }}", .{indent});
        },
        else => {
            const ve = try varintExpr(g, d, access);
            try g.line("{s}    if ({s}) {{", .{ indent, has });
            try g.line("{s}        try e.appendTag({d}, .varint);", .{ indent, d.number });
            try g.line("{s}        try e.appendVarint({s});", .{ indent, ve });
            try g.line("{s}    }}", .{indent});
        },
    }
}

/// Emits a decode read of one scalar value from `pd` (a wire.Decoder) as an
/// expression string.
fn scalarDecodeExpr(g: *Generator, d: *const FieldDesc, decoder: []const u8) Error![]const u8 {
    return switch (d.scalar) {
        .boolean, .int32, .int64, .uint32, .uint64, .sint32, .sint64 => blk: {
            const conv = try varintDecodeExpr(g, d);
            break :blk g.fmt("blk: {{ const v = try {s}.consumeVarint(); break :blk {s}; }}", .{ decoder, conv });
        },
        .fixed32, .sfixed32, .float => blk: {
            const conv = try fixedDecodeExpr(g, d);
            break :blk g.fmt("blk: {{ const fv = try {s}.consumeFixed32(); break :blk {s}; }}", .{ decoder, conv });
        },
        .fixed64, .sfixed64, .double => blk: {
            const conv = try fixedDecodeExpr(g, d);
            break :blk g.fmt("blk: {{ const fv = try {s}.consumeFixed64(); break :blk {s}; }}", .{ decoder, conv });
        },
        .string, .bytes => Error.UnresolvedType,
    };
}

/// Emits the size() function.
fn emitSize(g: *Generator, indent: []const u8, order: []const OrderItem) Error!void {
    try g.line("{s}pub fn size(m: *const @This()) usize {{", .{indent});
    if (order.len == 0) {
        try g.line("{s}    return m.unknown_fields.len;", .{indent});
        try g.line("{s}}}", .{indent});
        return;
    }
    try g.line("{s}    var n: usize = 0;", .{indent});
    for (order) |item| {
        if (item.field) |d| {
            switch (d.kind) {
                .scalar_single => {
                    const has = try hasValueExpr(g, d, try g.fmt("m.{s}", .{d.zig}));
                    try emitScalarSizeLine(g, indent, d, has, try g.fmt("m.{s}", .{d.zig}));
                },
                .scalar_optional => {
                    try emitOptionalSizeLine(g, indent, d);
                },
                .message_single => {
                    try g.line("{s}    if (m.{s}) |c| n += wire.sizeTag({d}) + wire.sizeBytes(c.size());", .{ indent, d.zig, d.number });
                },
                .repeated_scalar => {
                    const elem_size = try scalarSizeTerm(g, d, "el");
                    try g.line("{s}    if (m.{s}.len != 0) {{", .{ indent, d.zig });
                    try g.line("{s}        var payload: usize = 0;", .{indent});
                    try g.line("{s}        for (m.{s}) |el| payload += {s};", .{ indent, d.zig, elem_size });
                    try g.line("{s}        n += wire.sizeTag({d}) + wire.sizeVarint(payload) + payload;", .{ indent, d.number });
                    try g.line("{s}    }}", .{indent});
                },
                .repeated_string => {
                    try g.line("{s}    for (m.{s}) |el| n += wire.sizeTag({d}) + wire.sizeBytes(el.len);", .{ indent, d.zig, d.number });
                },
                .repeated_message => {
                    try g.line("{s}    for (m.{s}) |*el| n += wire.sizeTag({d}) + wire.sizeBytes(el.size());", .{ indent, d.zig, d.number });
                },
                .map => try emitMapSize(g, indent, d),
            }
        } else {
            try emitOneofSizeArm(g, indent, item.oneof.?, item.case.?);
        }
    }
    try g.line("{s}    return n + m.unknown_fields.len;", .{indent});
    try g.line("{s}}}", .{indent});
}

/// Wraps a size line for optional captures (|v|) correctly: for
/// scalar_optional the presence guard is the capture itself.
fn emitOptionalSizeLine(g: *Generator, indent: []const u8, d: *const FieldDesc) Error!void {
    switch (d.scalar) {
        .string, .bytes => {
            try g.line("{s}    if (m.{s}) |v| n += wire.sizeTag({d}) + wire.sizeBytes(v.len);", .{ indent, d.zig, d.number });
        },
        .fixed32, .sfixed32, .float => {
            try g.line("{s}    if (m.{s}) |v| n += wire.sizeTag({d}) + 4;", .{ indent, d.zig, d.number });
        },
        .fixed64, .sfixed64, .double => {
            try g.line("{s}    if (m.{s}) |v| n += wire.sizeTag({d}) + 8;", .{ indent, d.zig, d.number });
        },
        else => {
            const ve = try varintExpr(g, d, "v");
            try g.line("{s}    if (m.{s}) |v| n += wire.sizeTag({d}) + wire.sizeVarint({s});", .{ indent, d.zig, d.number, ve });
        },
    }
}

fn emitMapSize(g: *Generator, indent: []const u8, d: *const FieldDesc) Error!void {
    try g.line("{s}    for (m.{s}) |*en| {{", .{ indent, d.zig });
    try g.line("{s}        var esz: usize = 0;", .{indent});
    // key
    switch (d.map_key) {
        .string => {
            try g.line("{s}        if (en.key.len != 0) esz += wire.sizeTag(1) + wire.sizeBytes(en.key.len);", .{indent});
        },
        else => {
            const kd = FieldDesc{ .zig = "key", .raw = "key", .number = 1, .kind = .scalar_single, .scalar = d.map_key };
            const ve = try varintExpr(g, &kd, "en.key");
            try g.line("{s}        if (en.key != 0) esz += wire.sizeTag(1) + wire.sizeVarint({s});", .{ indent, ve });
        },
    }
    // value
    if (d.map_value_is_message) {
        try g.line("{s}        esz += wire.sizeTag(2) + wire.sizeBytes(en.value.size());", .{indent});
    } else {
        const vd = FieldDesc{
            .zig = "value",
            .raw = "value",
            .number = 2,
            .kind = .scalar_single,
            .scalar = d.scalar,
            .is_enum = d.map_value_enum,
            .type_zig = d.type_zig,
        };
        switch (d.scalar) {
            .string, .bytes => {
                try g.line("{s}        if (en.value.len != 0) esz += wire.sizeTag(2) + wire.sizeBytes(en.value.len);", .{indent});
            },
            .boolean => {
                try g.line("{s}        if (en.value) esz += wire.sizeTag(2) + 1;", .{indent});
            },
            else => {
                const ve = try varintExpr(g, &vd, "en.value");
                try g.line("{s}        if ({s}) esz += wire.sizeTag(2) + wire.sizeVarint({s});", .{ indent, try hasValueExpr(g, &vd, "en.value"), ve });
            },
        }
    }
    try g.line("{s}        n += wire.sizeTag({d}) + wire.sizeBytes(esz);", .{ indent, d.number });
    try g.line("{s}    }}", .{indent});
}

fn emitOneofSizeArm(g: *Generator, indent: []const u8, o: *const OneofDesc, c: *const FieldDesc) Error!void {
    try g.line("{s}    if (m.{s}) |u| switch (u) {{", .{ indent, o.zig_name });
    if (c.kind == .message_single) {
        try g.line("{s}        .{s} => |c| n += wire.sizeTag({d}) + wire.sizeBytes(c.size()),", .{ indent, c.zig, c.number });
    } else {
        switch (c.scalar) {
            .string, .bytes => {
                try g.line("{s}        .{s} => |v| n += wire.sizeTag({d}) + wire.sizeBytes(v.len),", .{ indent, c.zig, c.number });
            },
            .fixed32, .sfixed32, .float => {
                try g.line("{s}        .{s} => |v| n += wire.sizeTag({d}) + 4,", .{ indent, c.zig, c.number });
            },
            .fixed64, .sfixed64, .double => {
                try g.line("{s}        .{s} => |v| n += wire.sizeTag({d}) + 8,", .{ indent, c.zig, c.number });
            },
            else => {
                const ve = try varintExpr(g, c, "v");
                try g.line("{s}        .{s} => |v| n += wire.sizeTag({d}) + wire.sizeVarint({s}),", .{ indent, c.zig, c.number, ve });
            },
        }
    }
    if (o.cases.len > 1) try g.line("{s}        else => {{}},", .{indent});
    try g.line("{s}    }};", .{indent});
}

/// Optional-capture encode lines: `if (m.X) |v| { ... }`.
fn emitOptionalEncodeLines(g: *Generator, indent: []const u8, d: *const FieldDesc) Error!void {
    switch (d.scalar) {
        .string, .bytes => {
            try g.line("{s}    if (m.{s}) |v| {{", .{ indent, d.zig });
            try g.line("{s}        try e.appendTag({d}, .bytes);", .{ indent, d.number });
            try g.line("{s}        try e.appendBytes(v);", .{indent});
            try g.line("{s}    }}", .{indent});
        },
        .fixed32, .sfixed32, .float => {
            try g.line("{s}    if (m.{s}) |v| {{", .{ indent, d.zig });
            try g.line("{s}        try e.appendTag({d}, .fixed32);", .{ indent, d.number });
            try g.line("{s}        try e.appendFixed32({s});", .{ indent, try fixedEncodeExpr(g, d, "v") });
            try g.line("{s}    }}", .{indent});
        },
        .fixed64, .sfixed64, .double => {
            try g.line("{s}    if (m.{s}) |v| {{", .{ indent, d.zig });
            try g.line("{s}        try e.appendTag({d}, .fixed64);", .{ indent, d.number });
            try g.line("{s}        try e.appendFixed64({s});", .{ indent, try fixedEncodeExpr(g, d, "v") });
            try g.line("{s}    }}", .{indent});
        },
        else => {
            try g.line("{s}    if (m.{s}) |v| {{", .{ indent, d.zig });
            try g.line("{s}        try e.appendTag({d}, .varint);", .{ indent, d.number });
            try g.line("{s}        try e.appendVarint({s});", .{ indent, try varintExpr(g, d, "v") });
            try g.line("{s}    }}", .{indent});
        },
    }
}

/// Encode lines for one message-typed value reached via `access` (a const
/// pointer expression), with tag N.
fn emitMessageEncodeLines(g: *Generator, indent: []const u8, number: i32, access: []const u8) Error!void {
    try g.line("{s}        const sz = {s}.size();", .{ indent, access });
    try g.line("{s}        try e.appendTag({d}, .bytes);", .{ indent, number });
    try g.line("{s}        try e.appendVarint(sz);", .{indent});
    try g.line("{s}        try {s}.encode(e.buf[e.len..][0..sz]);", .{ indent, access });
    try g.line("{s}        e.len += sz;", .{indent});
}

fn emitEncode(g: *Generator, indent: []const u8, order: []const OrderItem) Error!void {
    try g.line("{s}pub fn encode(m: *const @This(), out: []u8) wire.Error!void {{", .{indent});

    try g.line("{s}    var e = wire.Encoder.init(out);", .{indent});
    for (order) |item| {
        if (item.field) |d| {
            switch (d.kind) {
                .scalar_single => {
                    const access = try g.fmt("m.{s}", .{d.zig});
                    const has = try hasValueExpr(g, d, access);
                    try emitScalarEncodeLines(g, indent, d, has, access);
                },
                .scalar_optional => try emitOptionalEncodeLines(g, indent, d),
                .message_single => {
                    try g.line("{s}    if (m.{s}) |*c| {{", .{ indent, d.zig });
                    try emitMessageEncodeLines(g, indent, d.number, "c");
                    try g.line("{s}    }}", .{indent});
                },
                .repeated_scalar => {
                    const elem_size = try scalarSizeTerm(g, d, "el");
                    try g.line("{s}    if (m.{s}.len != 0) {{", .{ indent, d.zig });
                    try g.line("{s}        var payload: usize = 0;", .{indent});
                    try g.line("{s}        for (m.{s}) |el| payload += {s};", .{ indent, d.zig, elem_size });
                    try g.line("{s}        try e.appendTag({d}, .bytes);", .{ indent, d.number });
                    try g.line("{s}        try e.appendVarint(payload);", .{indent});
                    try g.line("{s}        for (m.{s}) |el| try {s};", .{ indent, d.zig, try scalarEncodeStmt(g, d, "el") });
                    try g.line("{s}    }}", .{indent});
                },
                .repeated_string => {
                    try g.line("{s}    for (m.{s}) |el| {{", .{ indent, d.zig });
                    try g.line("{s}        try e.appendTag({d}, .bytes);", .{ indent, d.number });
                    try g.line("{s}        try e.appendBytes(el);", .{indent});
                    try g.line("{s}    }}", .{indent});
                },
                .repeated_message => {
                    try g.line("{s}    for (m.{s}) |*el| {{", .{ indent, d.zig });
                    try emitMessageEncodeLines(g, indent, d.number, "el");
                    try g.line("{s}    }}", .{indent});
                },
                .map => try emitMapEncode(g, indent, d),
            }
        } else {
            try emitOneofEncodeArm(g, indent, item.oneof.?, item.case.?);
        }
    }
    try g.line("{s}    if (m.unknown_fields.len > e.buf.len - e.len) return error.NoSpaceLeft;", .{indent});
    try g.line("{s}    @memcpy(e.buf[e.len..][0..m.unknown_fields.len], m.unknown_fields);", .{indent});
    try g.line("{s}    e.len += m.unknown_fields.len;", .{indent});
    try g.line("{s}}}", .{indent});
}

/// A single append statement (without `try`) for one packed element named
/// `el`.
fn scalarEncodeStmt(g: *Generator, d: *const FieldDesc, access: []const u8) Error![]const u8 {
    return switch (d.scalar) {
        .boolean => g.fmt("e.appendVarint(@as(u64, if ({s}) 1 else 0))", .{access}),
        .int32, .int64, .uint32, .uint64, .sint32, .sint64 => g.fmt("e.appendVarint({s})", .{try varintExpr(g, d, access)}),
        .fixed32, .sfixed32, .float => g.fmt("e.appendFixed32({s})", .{try fixedEncodeExpr(g, d, access)}),
        .fixed64, .sfixed64, .double => g.fmt("e.appendFixed64({s})", .{try fixedEncodeExpr(g, d, access)}),
        .string, .bytes => Error.UnresolvedType,
    };
}

fn emitMapEncode(g: *Generator, indent: []const u8, d: *const FieldDesc) Error!void {
    const less = switch (d.map_key) {
        .string, .bytes => try g.dup("std.mem.order(u8, candidate.key, en.key) == .lt"),
        .boolean => try g.dup("!candidate.key and en.key"),
        else => try g.dup("candidate.key < en.key"),
    };
    const greater = switch (d.map_key) {
        .string, .bytes => try g.dup("std.mem.order(u8, candidate.key, previous.key) == .gt"),
        .boolean => try g.dup("candidate.key and !previous.key"),
        else => try g.dup("candidate.key > previous.key"),
    };
    try g.line("{s}    {{", .{indent});
    try g.line("{s}    var previous_entry: ?*const {s}_Entry = null;", .{indent, d.raw});
    try g.line("{s}    while (true) {{", .{indent});
    try g.line("{s}        var next_entry: ?*const {s}_Entry = null;", .{indent, d.raw});
    try g.line("{s}        for (m.{s}) |*candidate| {{", .{indent, d.zig});
    try g.line("{s}            if (previous_entry) |previous| if (!({s})) continue;", .{indent, greater});
    try g.line("{s}            if (next_entry) |en| {{ if ({s}) next_entry = candidate; }} else next_entry = candidate;", .{indent, less});
    try g.line("{s}        }}", .{indent});
    try g.line("{s}        const en = next_entry orelse break;", .{indent});
    try g.line("{s}        previous_entry = en;", .{indent});
    try g.line("{s}        var esz: usize = 0;", .{indent});
    try emitMapEntrySizeLines(g, indent, d);
    try g.line("{s}        try e.appendTag({d}, .bytes);", .{ indent, d.number });
    try g.line("{s}        try e.appendVarint(esz);", .{indent});
    // key
    switch (d.map_key) {
        .string, .bytes => {
            try g.line("{s}        if (en.key.len != 0) {{", .{indent});
            try g.line("{s}            try e.appendTag(1, .bytes);", .{indent});
            try g.line("{s}            try e.appendBytes(en.key);", .{indent});
            try g.line("{s}        }}", .{indent});
        },
        .fixed32, .sfixed32, .float => {
            const kd = FieldDesc{ .zig = "key", .raw = "key", .number = 1, .kind = .scalar_single, .scalar = d.map_key };
            try g.line("{s}        if (en.key != 0) {{", .{indent});
            try g.line("{s}            try e.appendTag(1, .fixed32);", .{indent});
            try g.line("{s}            try e.appendFixed32({s});", .{ indent, try fixedEncodeExpr(g, &kd, "en.key") });
            try g.line("{s}        }}", .{indent});
        },
        .fixed64, .sfixed64, .double => {
            const kd = FieldDesc{ .zig = "key", .raw = "key", .number = 1, .kind = .scalar_single, .scalar = d.map_key };
            try g.line("{s}        if (en.key != 0) {{", .{indent});
            try g.line("{s}            try e.appendTag(1, .fixed64);", .{indent});
            try g.line("{s}            try e.appendFixed64({s});", .{ indent, try fixedEncodeExpr(g, &kd, "en.key") });
            try g.line("{s}        }}", .{indent});
        },
        else => {
            const kd = FieldDesc{ .zig = "key", .raw = "key", .number = 1, .kind = .scalar_single, .scalar = d.map_key };
            try g.line("{s}        if (en.key != 0) {{", .{indent});
            try g.line("{s}            try e.appendTag(1, .varint);", .{indent});
            try g.line("{s}            try e.appendVarint({s});", .{ indent, try varintExpr(g, &kd, "en.key") });
            try g.line("{s}        }}", .{indent});
        },
    }
    // value
    if (d.map_value_is_message) {
        try emitMessageEncodeLines(g, indent, 2, "en.value");
    } else {
        const vd = FieldDesc{
            .zig = "value",
            .raw = "value",
            .number = 2,
            .kind = .scalar_single,
            .scalar = d.scalar,
            .is_enum = d.map_value_enum,
            .type_zig = d.type_zig,
        };
        switch (d.scalar) {
            .string, .bytes => {
                try g.line("{s}        if (en.value.len != 0) {{", .{indent});
                try g.line("{s}            try e.appendTag(2, .bytes);", .{indent});
                try g.line("{s}            try e.appendBytes(en.value);", .{indent});
                try g.line("{s}        }}", .{indent});
            },
            else => {
                const stmt = try scalarEncodeStmt(g, &vd, "en.value");
                try g.line("{s}        if ({s}) try {s};", .{ indent, try hasValueExpr(g, &vd, "en.value"), stmt });
            },
        }
    }
    try g.line("{s}    }}", .{indent});
    try g.line("{s}    }}", .{indent});
}

fn emitMapEntrySizeLines(g: *Generator, indent: []const u8, d: *const FieldDesc) Error!void {
    switch (d.map_key) {
        .string, .bytes => {
            try g.line("{s}        if (en.key.len != 0) esz += wire.sizeTag(1) + wire.sizeBytes(en.key.len);", .{indent});
        },
        .fixed32, .sfixed32, .float => {
            try g.line("{s}        if (en.key != 0) esz += wire.sizeTag(1) + 4;", .{indent});
        },
        .fixed64, .sfixed64, .double => {
            try g.line("{s}        if (en.key != 0) esz += wire.sizeTag(1) + 8;", .{indent});
        },
        else => {
            const kd = FieldDesc{ .zig = "key", .raw = "key", .number = 1, .kind = .scalar_single, .scalar = d.map_key };
            try g.line("{s}        if (en.key != 0) esz += wire.sizeTag(1) + wire.sizeVarint({s});", .{ indent, try varintExpr(g, &kd, "en.key") });
        },
    }
    if (d.map_value_is_message) {
        try g.line("{s}        esz += wire.sizeTag(2) + wire.sizeBytes(en.value.size());", .{indent});
    } else {
        switch (d.scalar) {
            .string, .bytes => {
                try g.line("{s}        if (en.value.len != 0) esz += wire.sizeTag(2) + wire.sizeBytes(en.value.len);", .{indent});
            },
            .fixed32, .sfixed32, .float => {
                try g.line("{s}        if (en.value != 0) esz += wire.sizeTag(2) + 4;", .{indent});
            },
            .fixed64, .sfixed64, .double => {
                try g.line("{s}        if (en.value != 0) esz += wire.sizeTag(2) + 8;", .{indent});
            },
            else => {
                const vd = FieldDesc{
                    .zig = "value",
                    .raw = "value",
                    .number = 2,
                    .kind = .scalar_single,
                    .scalar = d.scalar,
                    .is_enum = d.map_value_enum,
                    .type_zig = d.type_zig,
                };
                try g.line("{s}        if ({s}) esz += wire.sizeTag(2) + wire.sizeVarint({s});", .{ indent, try hasValueExpr(g, &vd, "en.value"), try varintExpr(g, &vd, "en.value") });
            },
        }
    }
}

fn emitOneofEncodeArm(g: *Generator, indent: []const u8, o: *const OneofDesc, c: *const FieldDesc) Error!void {
    try g.line("{s}    if (m.{s}) |u| switch (u) {{", .{ indent, o.zig_name });
    if (c.kind == .message_single) {
        try g.line("{s}        .{s} => |c| {{", .{ indent, c.zig });
        try emitMessageEncodeLines(g, indent, c.number, "c");
        try g.line("{s}        }},", .{indent});
    } else {
        switch (c.scalar) {
            .string, .bytes => {
                try g.line("{s}        .{s} => |v| {{", .{ indent, c.zig });
                try g.line("{s}            try e.appendTag({d}, .bytes);", .{ indent, c.number });
                try g.line("{s}            try e.appendBytes(v);", .{indent});
                try g.line("{s}        }},", .{indent});
            },
            .fixed32, .sfixed32, .float => {
                try g.line("{s}        .{s} => |v| {{", .{ indent, c.zig });
                try g.line("{s}            try e.appendTag({d}, .fixed32);", .{ indent, c.number });
                try g.line("{s}            try e.appendFixed32({s});", .{ indent, try fixedEncodeExpr(g, c, "v") });
                try g.line("{s}        }},", .{indent});
            },
            .fixed64, .sfixed64, .double => {
                try g.line("{s}        .{s} => |v| {{", .{ indent, c.zig });
                try g.line("{s}            try e.appendTag({d}, .fixed64);", .{ indent, c.number });
                try g.line("{s}            try e.appendFixed64({s});", .{ indent, try fixedEncodeExpr(g, c, "v") });
                try g.line("{s}        }},", .{indent});
            },
            else => {
                try g.line("{s}        .{s} => |v| {{", .{ indent, c.zig });
                try g.line("{s}            try e.appendTag({d}, .varint);", .{ indent, c.number });
                try g.line("{s}            try e.appendVarint({s});", .{ indent, try varintExpr(g, c, "v") });
                try g.line("{s}        }},", .{indent});
            },
        }
    }
    if (o.cases.len > 1) try g.line("{s}        else => {{}},", .{indent});
    try g.line("{s}    }};", .{indent});
}

fn emitDecode(g: *Generator, indent: []const u8, order: []const OrderItem) Error!void {
    try g.line("{s}pub fn decode(a: std.mem.Allocator, buf: []const u8) DecodeError!@This() {{", .{indent});
    try g.line("{s}    return @This().decodeWithDepth(a, buf, default_recursion_depth);", .{indent});
    try g.line("{s}}}", .{indent});
    try g.line("", .{});
    try g.line("{s}pub fn decodeWithDepth(a: std.mem.Allocator, buf: []const u8, depth: u32) DecodeError!@This() {{", .{indent});
    try g.line("{s}    if (depth == 0) return error.RecursionDepth;", .{indent});
    try g.line("{s}    var m = @This(){{}};", .{indent});
    try g.line("{s}    errdefer m.deinit(a);", .{indent});
    try g.line("{s}    try m.mergeWithDepth(a, buf, depth);", .{indent});
    try g.line("{s}    return m;", .{indent});
    try g.line("{s}}}", .{indent});
    try g.line("{s}pub fn mergeWithDepth(m: *@This(), a: std.mem.Allocator, buf: []const u8, depth: u32) DecodeError!void {{", .{indent});
    try g.line("{s}    if (depth == 0) return error.RecursionDepth;", .{indent});
    try g.line("{s}    var unknown: std.ArrayList(u8) = .{{ .items = @constCast(m.unknown_fields), .capacity = m.unknown_fields.len, .pointer_stability = .{{}} }};", .{indent});
    try g.line("{s}    m.unknown_fields = &.{{}};", .{indent});
    try g.line("{s}    defer unknown.deinit(a);", .{indent});
    try g.line("{s}    var d = wire.Decoder.init(buf);", .{indent});
    // Local accumulation lists for repeated/map fields.
    for (order) |item| {
        const d = item.field orelse continue;
        switch (d.kind) {
            .repeated_scalar => {
                const elem = if (d.is_enum) d.type_zig else scalarZigType(d.scalar);
                try g.line("{s}    var list_{s}: std.ArrayList({s}) = .empty;", .{ indent, d.raw, elem });
            },
            .repeated_string => {
                try g.line("{s}    var list_{s}: std.ArrayList([]const u8) = .empty;", .{ indent, d.raw });
            },
            .repeated_message => {
                try g.line("{s}    var list_{s}: std.ArrayList({s}) = .empty;", .{ indent, d.raw, d.type_zig });
            },
            .map => {
                try g.line("{s}    var list_{s}: std.ArrayList({s}_Entry) = .empty;", .{ indent, d.raw, d.raw });
            },
            else => {},
        }
        switch (d.kind) {
            .repeated_scalar, .repeated_string, .repeated_message, .map => {
                try g.line("{s}    list_{s} = .{{ .items = m.{s}, .capacity = m.{s}.len, .pointer_stability = .{{}} }};", .{ indent, d.raw, d.zig, d.zig });
                try g.line("{s}    m.{s} = &.{{}};", .{ indent, d.zig });
            },
            else => {},
        }
    }
    for (order) |item| {
        const d = item.field orelse continue;
        if (d.kind == .repeated_scalar or d.kind == .repeated_string or d.kind == .repeated_message or d.kind == .map) {
            try g.line("{s}    errdefer list_{s}.deinit(a);", .{ indent, d.raw });
        }
        if (d.kind == .repeated_string) {
            try g.line("{s}    errdefer for (list_{s}.items) |v| if (v.len != 0) a.free(v);", .{ indent, d.raw });
        }
        if (d.kind == .repeated_message) {
            try g.line("{s}    errdefer for (list_{s}.items) |*v| v.deinit(a);", .{indent, d.raw});
        }
        if (d.kind == .map) {
            try g.line("{s}    errdefer for (list_{s}.items) |*en| {{", .{indent, d.raw});
            if (d.map_key == .string or d.map_key == .bytes) try g.line("{s}        if (en.key.len != 0) a.free(en.key);", .{indent});
            if (d.map_value_is_message) try g.line("{s}        en.value.deinit(a);", .{indent}) else if (d.scalar == .string or d.scalar == .bytes) try g.line("{s}        if (en.value.len != 0) a.free(en.value);", .{indent});
            try g.line("{s}    }}", .{indent});
        }
    }
    try g.line("{s}    while (!d.done()) {{", .{indent});
    try g.line("{s}        const tag = try d.consumeTag();", .{indent});
    try g.line("{s}        const tag_end = d.pos;", .{indent});
    try g.line("{s}        switch (tag.num) {{", .{indent});
    for (order) |item| {
        if (item.field) |d| {
            try emitFieldDecodeArm(g, indent, d);
        } else {
            try emitOneofDecodeArm(g, indent, item.oneof.?, item.case.?);
        }
    }
    try g.line("{s}            else => {{", .{indent});
    try g.line("{s}                _ = try d.skipField(tag.num, tag.typ);", .{indent});
    try g.line("{s}                var tb: [10]u8 = undefined; var te = wire.Encoder.init(&tb); try te.appendTag(tag.num, tag.typ); try unknown.appendSlice(a, tb[0..te.len]); try unknown.appendSlice(a, buf[tag_end..d.pos]);", .{indent});
    try g.line("{s}            }},", .{indent});
    try g.line("{s}        }}", .{indent});
    try g.line("{s}    }}", .{indent});
    for (order) |item| {
        const d = item.field orelse continue;
        switch (d.kind) {
            .repeated_scalar, .repeated_string, .repeated_message, .map => {
                try g.line("{s}    m.{s} = list_{s}.toOwnedSlice(a) catch return error.OutOfMemory;", .{ indent, d.zig, d.raw });
            },
            else => {},
        }
    }
    try g.line("{s}    m.unknown_fields = try unknown.toOwnedSlice(a);", .{indent});
    try g.line("{s}}}", .{indent});
}

fn emitFieldDecodeArm(g: *Generator, indent: []const u8, d: *const FieldDesc) Error!void {
    const arm_indent = try g.fmt("{s}            ", .{indent});
    const skip = try g.fmt("{s}_ = try d.skipField(tag.num, tag.typ); var tb: [10]u8 = undefined; var te = wire.Encoder.init(&tb); try te.appendTag(tag.num, tag.typ); try unknown.appendSlice(a, tb[0..te.len]); try unknown.appendSlice(a, buf[tag_end..d.pos]);", .{arm_indent});
    switch (d.kind) {
        .scalar_single, .scalar_optional => {
            switch (d.scalar) {
                .string, .bytes => {
                    try g.line("{s}{d} => if (tag.typ == .bytes) {{", .{ arm_indent, d.number });
                    try g.line("{s}    const b = try d.consumeBytes();", .{arm_indent});
                    try g.line("{s}    const owned = a.dupe(u8, b) catch return error.OutOfMemory;", .{arm_indent});
                    if (d.kind == .scalar_optional) {
                        try g.line("{s}    if (m.{s}) |old| if (old.len != 0) a.free(old);", .{ arm_indent, d.zig });
                    } else {
                        try g.line("{s}    if (m.{s}.len != 0) a.free(m.{s});", .{ arm_indent, d.zig, d.zig });
                    }
                    try g.line("{s}    m.{s} = owned;", .{ arm_indent, d.zig });
                    try g.line("{s}}} else {{", .{arm_indent});
                    try g.line("{s}    {s}", .{ arm_indent, skip });
                    try g.line("{s}}},", .{arm_indent});
                },
                .fixed32, .sfixed32, .float => {
                    try g.line("{s}{d} => if (tag.typ == .fixed32) {{", .{ arm_indent, d.number });
                    try g.line("{s}    m.{s} = {s};", .{ arm_indent, d.zig, try scalarDecodeExpr(g, d, "d") });
                    try g.line("{s}}} else {{", .{arm_indent});
                    try g.line("{s}    {s}", .{ arm_indent, skip });
                    try g.line("{s}}},", .{arm_indent});
                },
                .fixed64, .sfixed64, .double => {
                    try g.line("{s}{d} => if (tag.typ == .fixed64) {{", .{ arm_indent, d.number });
                    try g.line("{s}    m.{s} = {s};", .{ arm_indent, d.zig, try scalarDecodeExpr(g, d, "d") });
                    try g.line("{s}}} else {{", .{arm_indent});
                    try g.line("{s}    {s}", .{ arm_indent, skip });
                    try g.line("{s}}},", .{arm_indent});
                },
                else => {
                    try g.line("{s}{d} => if (tag.typ == .varint) {{", .{ arm_indent, d.number });
                    try g.line("{s}    m.{s} = {s};", .{ arm_indent, d.zig, try scalarDecodeExpr(g, d, "d") });
                    try g.line("{s}}} else {{", .{arm_indent});
                    try g.line("{s}    {s}", .{ arm_indent, skip });
                    try g.line("{s}}},", .{arm_indent});
                },
            }
        },
        .message_single => {
            try g.line("{s}{d} => if (tag.typ == .bytes) {{", .{ arm_indent, d.number });
            try g.line("{s}    const b = try d.consumeBytes();", .{arm_indent});
            try g.line("{s}    if (depth == 0) return error.RecursionDepth;", .{arm_indent});
            try g.line("{s}    if (m.{s}) |*child| {{", .{ arm_indent, d.zig });
            try g.line("{s}        try child.mergeWithDepth(a, b, depth - 1);", .{arm_indent});
            try g.line("{s}    }} else {{", .{arm_indent});
            try g.line("{s}        m.{s} = try {s}.decodeWithDepth(a, b, depth - 1);", .{ arm_indent, d.zig, d.type_zig });
            try g.line("{s}    }}", .{arm_indent});
            try g.line("{s}}} else {{", .{arm_indent});
            try g.line("{s}    {s}", .{ arm_indent, skip });
            try g.line("{s}}},", .{arm_indent});
        },
        .repeated_scalar => {
            try g.line("{s}{d} => switch (tag.typ) {{", .{ arm_indent, d.number });
            try g.line("{s}    .bytes => {{", .{arm_indent});
            try g.line("{s}        const pb = try d.consumeBytes();", .{arm_indent});
            try g.line("{s}        var pd = wire.Decoder.init(pb);", .{arm_indent});
            try g.line("{s}        while (!pd.done()) {{", .{arm_indent});
            try g.line("{s}            const el = {s};", .{ arm_indent, try scalarDecodeExpr(g, d, "pd") });
            try g.line("{s}            try list_{s}.append(a, el);", .{ arm_indent, d.raw });
            try g.line("{s}        }}", .{arm_indent});
            try g.line("{s}    }},", .{arm_indent});
            try g.line("{s}    {s} => {{", .{ arm_indent, scalarWireType(d.scalar) });
            try g.line("{s}        const el = {s};", .{ arm_indent, try scalarDecodeExpr(g, d, "d") });
            try g.line("{s}        try list_{s}.append(a, el);", .{ arm_indent, d.raw });
            try g.line("{s}    }},", .{arm_indent});
            try g.line("{s}    else => {{", .{arm_indent});
            try g.line("{s}        _ = try d.skipField(tag.num, tag.typ); var tb: [10]u8 = undefined; var te = wire.Encoder.init(&tb); try te.appendTag(tag.num, tag.typ); try unknown.appendSlice(a, tb[0..te.len]); try unknown.appendSlice(a, buf[tag_end..d.pos]);", .{arm_indent});
            try g.line("{s}    }},", .{arm_indent});
            try g.line("{s}}},", .{arm_indent});
        },
        .repeated_string => {
            try g.line("{s}{d} => if (tag.typ == .bytes) {{", .{ arm_indent, d.number });
            try g.line("{s}    const b = try d.consumeBytes();", .{arm_indent});
            try g.line("{s}    const owned = a.dupe(u8, b) catch return error.OutOfMemory;", .{arm_indent});
            try g.line("{s}    errdefer a.free(owned);", .{arm_indent});
            try g.line("{s}    try list_{s}.append(a, owned);", .{ arm_indent, d.raw });
            try g.line("{s}}} else {{", .{arm_indent});
            try g.line("{s}    {s}", .{ arm_indent, skip });
            try g.line("{s}}},", .{arm_indent});
        },
        .repeated_message => {
            try g.line("{s}{d} => if (tag.typ == .bytes) {{", .{ arm_indent, d.number });
            try g.line("{s}    const b = try d.consumeBytes();", .{arm_indent});
            try g.line("{s}    if (depth == 0) return error.RecursionDepth;", .{arm_indent});
            try g.line("{s}    var child = try {s}.decodeWithDepth(a, b, depth - 1); errdefer child.deinit(a); try list_{s}.append(a, child);", .{ arm_indent, d.type_zig, d.raw });
            try g.line("{s}}} else {{", .{arm_indent});
            try g.line("{s}    {s}", .{ arm_indent, skip });
            try g.line("{s}}},", .{arm_indent});
        },
        .map => {
            try g.line("{s}{d} => if (tag.typ == .bytes) {{", .{ arm_indent, d.number });
            try g.line("{s}    const eb = try d.consumeBytes();", .{arm_indent});
            try g.line("{s}    var en = {s}_Entry{{}};", .{ arm_indent, d.raw });
            try g.line("{s}    var en_owned = true;", .{arm_indent});
            try g.line("{s}    errdefer if (en_owned) {{", .{arm_indent});
            if (d.map_key == .string or d.map_key == .bytes) try g.line("{s}        if (en.key.len != 0) a.free(en.key);", .{arm_indent});
            if (d.map_value_is_message) try g.line("{s}        en.value.deinit(a);", .{arm_indent}) else if (d.scalar == .string or d.scalar == .bytes) try g.line("{s}        if (en.value.len != 0) a.free(en.value);", .{arm_indent});
            try g.line("{s}    }};", .{arm_indent});
            try g.line("{s}    var ed = wire.Decoder.init(eb);", .{arm_indent});
            try g.line("{s}    while (!ed.done()) {{", .{arm_indent});
            try g.line("{s}        const etag = try ed.consumeTag();", .{arm_indent});
            try g.line("{s}        switch (etag.num) {{", .{arm_indent});
            try emitMapKeyDecodeArm(g, arm_indent, d);
            try emitMapValueDecodeArm(g, arm_indent, d);
            try g.line("{s}            else => {{", .{arm_indent});
            try g.line("{s}                _ = try ed.skipField(etag.num, etag.typ);", .{arm_indent});
            try g.line("{s}            }},", .{arm_indent});
            try g.line("{s}        }}", .{arm_indent});
            try g.line("{s}    }}", .{arm_indent});
            const equal = if (d.map_key == .string or d.map_key == .bytes) "std.mem.eql(u8, old.key, en.key)" else "old.key == en.key";
            try g.line("{s}    var replaced = false;", .{arm_indent});
            try g.line("{s}    for (list_{s}.items) |*old| {{", .{arm_indent, d.raw});
            try g.line("{s}        if ({s}) {{", .{arm_indent, equal});
            if (d.map_key == .string or d.map_key == .bytes) try g.line("{s}            if (old.key.len != 0) a.free(old.key);", .{arm_indent});
            if (d.map_value_is_message) {
                try g.line("{s}            old.value.deinit(a);", .{arm_indent});
            } else if (d.scalar == .string or d.scalar == .bytes) {
                try g.line("{s}            if (old.value.len != 0) a.free(old.value);", .{arm_indent});
            }
            try g.line("{s}            old.* = en;", .{arm_indent});
            try g.line("{s}            replaced = true;", .{arm_indent});
            try g.line("{s}            break;", .{arm_indent});
            try g.line("{s}        }}", .{arm_indent});
            try g.line("{s}    }}", .{arm_indent});
            try g.line("{s}    if (!replaced) try list_{s}.append(a, en);", .{ arm_indent, d.raw });
            try g.line("{s}    en_owned = false;", .{arm_indent});
            try g.line("{s}}} else {{", .{arm_indent});
            try g.line("{s}    {s}", .{ arm_indent, skip });
            try g.line("{s}}},", .{arm_indent});
        },
    }
}

fn emitMapKeyDecodeArm(g: *Generator, indent: []const u8, d: *const FieldDesc) Error!void {
    const inner = try g.fmt("{s}    ", .{indent});
    switch (d.map_key) {
        .string, .bytes => {
            try g.line("{s}1 => if (etag.typ == .bytes) {{", .{indent});
            try g.line("{s}const b = try ed.consumeBytes();", .{inner});
            try g.line("{s}en.key = a.dupe(u8, b) catch return error.OutOfMemory;", .{inner});
            try g.line("{s}}} else {{", .{indent});
            try g.line("{s}_ = try ed.skipField(etag.num, etag.typ);", .{inner});
            try g.line("{s}}},", .{indent});
        },
        else => {
            const kd = FieldDesc{ .zig = "key", .raw = "key", .number = 1, .kind = .scalar_single, .scalar = d.map_key };
            const wt = scalarWireType(d.map_key);
            try g.line("{s}1 => if (etag.typ == {s}) {{", .{ indent, wt });
            try g.line("{s}en.key = {s};", .{ inner, try scalarDecodeExpr(g, &kd, "ed") });
            try g.line("{s}}} else {{", .{indent});
            try g.line("{s}_ = try ed.skipField(etag.num, etag.typ);", .{inner});
            try g.line("{s}}},", .{indent});
        },
    }
}

fn emitMapValueDecodeArm(g: *Generator, indent: []const u8, d: *const FieldDesc) Error!void {
    const inner = try g.fmt("{s}    ", .{indent});
    if (d.map_value_is_message) {
        try g.line("{s}2 => if (etag.typ == .bytes) {{", .{indent});
        try g.line("{s}const b = try ed.consumeBytes();", .{inner});
        try g.line("{s}if (depth == 0) return error.RecursionDepth;", .{inner});
        try g.line("{s}en.value = try {s}.decodeWithDepth(a, b, depth - 1);", .{ inner, d.type_zig });
        try g.line("{s}}} else {{", .{indent});
        try g.line("{s}_ = try ed.skipField(etag.num, etag.typ);", .{inner});
        try g.line("{s}}},", .{indent});
        return;
    }
    const vd = FieldDesc{
        .zig = "value",
        .raw = "value",
        .number = 2,
        .kind = .scalar_single,
        .scalar = d.scalar,
        .is_enum = d.map_value_enum,
        .type_zig = d.type_zig,
    };
    switch (d.scalar) {
        .string, .bytes => {
            try g.line("{s}2 => if (etag.typ == .bytes) {{", .{indent});
            try g.line("{s}const b = try ed.consumeBytes();", .{inner});
            try g.line("{s}en.value = a.dupe(u8, b) catch return error.OutOfMemory;", .{inner});
            try g.line("{s}}} else {{", .{indent});
            try g.line("{s}_ = try ed.skipField(etag.num, etag.typ);", .{inner});
            try g.line("{s}}},", .{indent});
        },
        else => {
            try g.line("{s}2 => if (etag.typ == {s}) {{", .{ indent, scalarWireType(d.scalar) });
            try g.line("{s}en.value = {s};", .{ inner, try scalarDecodeExpr(g, &vd, "ed") });
            try g.line("{s}}} else {{", .{indent});
            try g.line("{s}_ = try ed.skipField(etag.num, etag.typ);", .{inner});
            try g.line("{s}}},", .{indent});
        },
    }
}

fn emitOneofRelease(g: *Generator, indent: []const u8, o: *const OneofDesc) Error!void {
    try g.line("{s}    if (m.{s}) |*old| switch (old.*) {{", .{indent, o.zig_name});
    for (o.cases) |*v| {
        if (v.kind == .message_single) {
            try g.line("{s}        .{s} => |*previous_child| previous_child.deinit(a),", .{indent, v.zig});
        } else if (v.scalar == .string or v.scalar == .bytes) {
            try g.line("{s}        .{s} => |bytes| if (bytes.len != 0) a.free(bytes),", .{indent, v.zig});
        } else {
            try g.line("{s}        .{s} => {{}},", .{indent, v.zig});
        }
    }
    try g.line("{s}    }};", .{indent});
    try g.line("{s}    m.{s} = null;", .{indent, o.zig_name});
}

fn emitOneofDecodeArm(g: *Generator, indent: []const u8, o: *const OneofDesc, c: *const FieldDesc) Error!void {
    const arm_indent = try g.fmt("{s}            ", .{indent});
    const wt = if (c.kind == .message_single) ".bytes" else scalarWireType(c.scalar);
    try g.line("{s}{d} => if (tag.typ == {s}) {{", .{ arm_indent, c.number, wt });
    if (c.kind == .message_single) {
        try g.line("{s}    const b = try d.consumeBytes();", .{arm_indent});
        try g.line("{s}    if (m.{s}) |*old| {{", .{arm_indent, o.zig_name});
        try g.line("{s}        if (old.* == .{s}) {{ try old.{s}.mergeWithDepth(a, b, depth - 1); continue; }}", .{arm_indent, c.zig, c.zig});
        try g.line("{s}    }}", .{arm_indent});
        try g.line("{s}    const child = try {s}.decodeWithDepth(a, b, depth - 1);", .{arm_indent, c.type_zig});
        try emitOneofRelease(g, arm_indent, o);
        try g.line("{s}    m.{s} = .{{ .{s} = child }};", .{arm_indent, o.zig_name, c.zig});
    } else if (c.scalar == .string or c.scalar == .bytes) {
        try g.line("{s}    const b = try d.consumeBytes();", .{arm_indent});
        try g.line("{s}    const owned = try a.dupe(u8, b);", .{arm_indent});
        try emitOneofRelease(g, arm_indent, o);
        try g.line("{s}    m.{s} = .{{ .{s} = owned }};", .{arm_indent, o.zig_name, c.zig});
    } else {
        try g.line("{s}    const value = {s};", .{arm_indent, try scalarDecodeExpr(g, c, "d")});
        try emitOneofRelease(g, arm_indent, o);
        try g.line("{s}    m.{s} = .{{ .{s} = value }};", .{arm_indent, o.zig_name, c.zig});
    }
    try g.line("{s}}} else {{", .{arm_indent});
    try g.line("{s}    _ = try d.skipField(tag.num, tag.typ); var tb: [10]u8 = undefined; var te = wire.Encoder.init(&tb); try te.appendTag(tag.num, tag.typ); try unknown.appendSlice(a, tb[0..te.len]); try unknown.appendSlice(a, buf[tag_end..d.pos]);", .{arm_indent});
    try g.line("{s}}},", .{arm_indent});
}

fn emitDeinit(g: *Generator, indent: []const u8, descs: []const FieldDesc, oneofs: []const OneofDesc) Error!void {
    try g.line("{s}pub fn deinit(m: *@This(), a: std.mem.Allocator) void {{", .{indent});
    for (descs) |*d| {
        switch (d.kind) {
            .scalar_single => if (d.scalar == .string or d.scalar == .bytes) {
                try g.line("{s}    if (m.{s}.len != 0) a.free(m.{s});", .{ indent, d.zig, d.zig });
            },
            .scalar_optional => if (d.scalar == .string or d.scalar == .bytes) {
                try g.line("{s}    if (m.{s}) |s| if (s.len != 0) a.free(s);", .{ indent, d.zig });
            },
            .message_single => {
                try g.line("{s}    if (m.{s}) |*c| c.deinit(a);", .{ indent, d.zig });
            },
            .repeated_scalar => {
                try g.line("{s}    if (m.{s}.len != 0) a.free(m.{s});", .{ indent, d.zig, d.zig });
            },
            .repeated_string => {
                try g.line("{s}    for (m.{s}) |s| if (s.len != 0) a.free(s);", .{ indent, d.zig });
                try g.line("{s}    if (m.{s}.len != 0) a.free(m.{s});", .{ indent, d.zig, d.zig });
            },
            .repeated_message => {
                try g.line("{s}    for (m.{s}) |*c| c.deinit(a);", .{ indent, d.zig });
                try g.line("{s}    if (m.{s}.len != 0) a.free(m.{s});", .{ indent, d.zig, d.zig });
            },
            .map => {
                try g.line("{s}    for (m.{s}) |*en| {{", .{ indent, d.zig });
                if (d.map_key == .string or d.map_key == .bytes) {
                    try g.line("{s}        if (en.key.len != 0) a.free(en.key);", .{indent});
                }
                if (d.map_value_is_message) {
                    try g.line("{s}        en.value.deinit(a);", .{indent});
                } else if (d.scalar == .string or d.scalar == .bytes) {
                    try g.line("{s}        if (en.value.len != 0) a.free(en.value);", .{indent});
                }
                try g.line("{s}    }}", .{indent});
                try g.line("{s}    if (m.{s}.len != 0) a.free(m.{s});", .{ indent, d.zig, d.zig });
            },
        }
    }
    for (oneofs) |*o| {
        try g.line("{s}    if (m.{s}) |*u| {{", .{ indent, o.zig_name });
        try g.line("{s}        switch (u.*) {{", .{indent});
        for (o.cases) |*c| {
            if (c.kind == .message_single) {
                try g.line("{s}            .{s} => |*c| c.deinit(a),", .{ indent, c.zig });
            } else if (c.scalar == .string or c.scalar == .bytes) {
                try g.line("{s}            .{s} => |s| if (s.len != 0) a.free(s),", .{ indent, c.zig });
            } else {
                try g.line("{s}            .{s} => {{}},", .{ indent, c.zig });
            }
        }
        try g.line("{s}        }}", .{indent});
        try g.line("{s}    }}", .{indent});
    }
    try g.line("{s}    if (m.unknown_fields.len != 0) a.free(m.unknown_fields);", .{indent});
    try g.line("{s}}}", .{indent});
}
