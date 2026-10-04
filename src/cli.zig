// M8 foreground CLI: dependency-free argument parser (std only).
// Transport-independent: parses argv into owned Options and performs
// nothing. No daemon/M9 flags.

const std = @import("std");

pub const Command = enum {
    version,
    status,
    login,
    up,
    down,
    help,
};

pub const Options = struct {
    alloc: std.mem.Allocator,
    command: Command = .help,
    config: ?[]u8 = null,
    setup_key: ?[]u8 = null,
    management_url: ?[]u8 = null,
    foreground: bool = false,
    json: bool = false,

    pub fn deinit(o: *Options) void {
        if (o.config) |p| o.alloc.free(p);
        if (o.setup_key) |k| o.alloc.free(k);
        if (o.management_url) |u| o.alloc.free(u);
        o.* = undefined;
    }
};

pub const Error = error{
    UnknownCommand,
    UnknownFlag,
    MissingValue,
    EmptyValue,
    DuplicateSetupKey,
    UnexpectedPositional,
    OutOfMemory,
};

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

fn isFlag(s: []const u8) bool {
    return s.len > 1 and s[0] == '-';
}

fn parseCommand(s: []const u8) ?Command {
    if (eql(s, "version")) return .version;
    if (eql(s, "status")) return .status;
    if (eql(s, "login")) return .login;
    if (eql(s, "up")) return .up;
    if (eql(s, "down")) return .down;
    if (eql(s, "help")) return .help;
    return null;
}

/// Take a new owned value for a repeatable string flag (last wins).
fn takeOwned(o: *Options, old: ?[]u8, val: []const u8) Error![]u8 {
    const n = try o.alloc.dupe(u8, val);
    if (old) |p| o.alloc.free(p);
    return n;
}

/// Parse argv (argv[0] is the program name and is skipped). Every value is
/// copied: the result never aliases argv. Flags may come before or after
/// the command. `--help` anywhere selects the help command.
pub fn parse(alloc: std.mem.Allocator, argv: []const []const u8) Error!Options {
    var o = Options{ .alloc = alloc };
    errdefer o.deinit();
    if (argv.len == 0) return o;
    var seen_command = false;
    var i: usize = 1;
    while (i < argv.len) {
        const a = argv[i];
        if (isFlag(a)) {
            if (eql(a, "--help")) {
                o.command = .help;
                seen_command = true;
            } else if (eql(a, "--foreground") or eql(a, "-F")) {
                o.foreground = true;
            } else if (eql(a, "--json")) {
                o.json = true;
            } else if (eql(a, "--config") or eql(a, "-c")) {
                i += 1;
                if (i >= argv.len) return Error.MissingValue;
                if (argv[i].len == 0) return Error.EmptyValue;
                o.config = try takeOwned(&o, o.config, argv[i]);
            } else if (eql(a, "--setup-key")) {
                i += 1;
                if (i >= argv.len) return Error.MissingValue;
                if (argv[i].len == 0) return Error.EmptyValue;
                if (o.setup_key != null) return Error.DuplicateSetupKey;
                o.setup_key = try alloc.dupe(u8, argv[i]);
            } else if (eql(a, "--management-url")) {
                i += 1;
                if (i >= argv.len) return Error.MissingValue;
                if (argv[i].len == 0) return Error.EmptyValue;
                o.management_url = try takeOwned(&o, o.management_url, argv[i]);
            } else {
                return Error.UnknownFlag;
            }
        } else {
            if (seen_command) return Error.UnexpectedPositional;
            seen_command = true;
            o.command = parseCommand(a) orelse return Error.UnknownCommand;
        }
        i += 1;
    }
    return o;
}

pub fn usage(w: *std.Io.Writer) std.Io.Writer.Error!void {
    try w.writeAll(
        \\usage: netbird <command> [flags]
        \\
        \\commands:
        \\  version    print version
        \\  status     show connection status
        \\  login      log in with a setup key
        \\  up         connect (foreground with -F)
        \\  down       disconnect
        \\  help       show this help
        \\
        \\flags:
        \\  -c, --config PATH     config file path
        \\  --setup-key KEY        setup key for login/up
        \\  --management-url URL   management server URL
        \\  -F, --foreground       run up in the foreground
        \\  --json                 JSON output (status)
        \\  --help                 show this help
        \\
    );
}
