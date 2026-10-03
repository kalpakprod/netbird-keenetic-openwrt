//! AST for the proto3 subset used by the NetBird .proto files.
//! All strings are slices of the source text (or arena-joined dotted names);
//! the AST is valid as long as the arena is.

const std = @import("std");

/// proto3 scalar types, mirroring the wire types they map to.
pub const Scalar = enum {
    boolean,
    int32,
    int64,
    uint32,
    uint64,
    sint32,
    sint64,
    fixed32,
    fixed64,
    sfixed32,
    sfixed64,
    float,
    double,
    string,
    bytes,

    pub fn parse(name: []const u8) ?Scalar {
        const map = std.StaticStringMap(Scalar).initComptime(.{
            .{ "bool", .boolean },    .{ "int32", .int32 },       .{ "int64", .int64 },
            .{ "uint32", .uint32 },   .{ "uint64", .uint64 },     .{ "sint32", .sint32 },
            .{ "sint64", .sint64 },   .{ "fixed32", .fixed32 },   .{ "fixed64", .fixed64 },
            .{ "sfixed32", .sfixed32 }, .{ "sfixed64", .sfixed64 }, .{ "float", .float },
            .{ "double", .double },   .{ "string", .string },     .{ "bytes", .bytes },
        });
        return map.get(name);
    }

    /// True when the wire encoding is length-prefixed (string, bytes,
    /// embedded messages, packed repeated scalars).
    pub fn isLengthDelimited(s: Scalar) bool {
        return s == .string or s == .bytes;
    }

    /// True when a repeated field of this scalar is packed by default in
    /// proto3 (everything except string and bytes).
    pub fn packable(s: Scalar) bool {
        return !s.isLengthDelimited();
    }
};

/// A field type: a scalar, or a named reference to a message/enum. Named
/// references may be dotted (google.protobuf.Timestamp, PortInfo.Range) and
/// may start with a leading dot (fully qualified); resolution happens in the
/// generator, where the whole package is known.
pub const TypeRef = union(enum) {
    scalar: Scalar,
    named: []const u8,
};

pub const Label = enum { none, optional, repeated };

pub const Option = struct {
    name: []const u8,
    /// Raw token text: identifiers and numbers verbatim, strings with quotes.
    value: []const u8,
};

pub const Field = struct {
    label: Label,
    typ: TypeRef,
    name: []const u8,
    number: i32,
    options: []const Option = &.{},
    line: u32 = 0,

    pub fn isMap(f: *const Field) bool {
        return switch (f.typ) {
            .named => |n| std.mem.eql(u8, n, map_marker),
            else => false,
        };
    }

    pub const map_marker = "\x00map";
};

/// A map field: key must be an integral or string scalar.
pub const MapField = struct {
    name: []const u8,
    number: i32,
    key: Scalar,
    value: TypeRef,
    options: []const Option = &.{},
    line: u32,
};

pub const EnumValue = struct {
    name: []const u8,
    number: i32,
    line: u32,
};

pub const ReservedRange = struct {
    /// Inclusive; a single number has start == end.
    start: i32,
    end: i32,
};

pub const Enum = struct {
    name: []const u8,
    values: []const EnumValue,
    reserved: []const ReservedRange = &.{},
    line: u32 = 0,
};

pub const Oneof = struct {
    name: []const u8,
    fields: []const Field,
    line: u32 = 0,
};

pub const Message = struct {
    name: []const u8,
    /// Plain and map fields in declaration order (oneof fields live in
    /// `.oneofs`, not here).
    fields: []const Field = &.{},
    maps: []const MapField = &.{},
    oneofs: []const Oneof = &.{},
    enums: []const Enum = &.{},
    messages: []const Message = &.{},
    reserved: []const ReservedRange = &.{},
    line: u32 = 0,
};

pub const Import = struct {
    path: []const u8,
};

pub const File = struct {
    syntax: []const u8,
    package: []const u8,
    imports: []const Import = &.{},
    messages: []const Message = &.{},
    enums: []const Enum = &.{},
};
