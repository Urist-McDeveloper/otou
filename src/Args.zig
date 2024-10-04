const std = @import("std");
const Allocator = std.mem.Allocator;

const version = "0.0.1";
const usage =
    \\Usage: otou [OPTIONS] COMMAND
    \\
    \\Options:
    \\  -c, --config PATH   use PATH instead of default config file location
    \\  -h, --help          print this message and exit
    \\  -v, --version       print version and exit
    \\
    \\Commands:
    \\  genkey              generate a random 32-byte secret key
    \\  run                 start daemon
    \\  down                shut down daemon and restore network configuration
    \\  status              display status of daemon
    \\  reload              apply configuration changes to the running daemon
;

pub const Command = enum {
    genkey,
    run,
    down,
    status,
    reload,

    fn from(str: []const u8) ?Command {
        inline for (@typeInfo(Command).Enum.fields) |field| {
            if (std.mem.eql(u8, field.name, str)) {
                return @enumFromInt(field.value);
            }
        }
        return null;
    }
};

raw: []const [:0]u8,
config_path: ?[]const u8,
command: Command,

pub fn deinit(args: @This(), a: Allocator) void {
    std.process.argsFree(a, args.raw);
}

pub fn init(a: Allocator) !@This() {
    const raw = try std.process.argsAlloc(a);
    errdefer std.process.argsFree(a, raw);

    var config: ?[]const u8 = null;
    var command: ?Command = null;

    var i: usize = 1;
    while (i < raw.len) : (i += 1) {
        const arg = raw[i];

        if (isOpt(arg, "help")) printAndExit(0, usage, .{});
        if (isOpt(arg, "version")) printAndExit(0, version, .{});
        if (isOpt(arg, "config")) {
            i += 1;
            if (i < raw.len) {
                config = raw[i];
                continue;
            } else {
                printAndExit(1, "missing PATH parameter for {s}", .{arg});
            }
        }

        if (command == null) {
            command = Command.from(arg) orelse printAndExit(1, "unknown command: {s}", .{arg});
            continue;
        } else {
            printAndExit(1, "command {s} does not accept any arguments", .{@tagName(command.?)});
        }
    }

    return .{
        .raw = raw,
        .config_path = config,
        .command = command orelse printAndExit(1, usage, .{}),
    };
}

fn isOpt(arg: []const u8, comptime opt: []const u8) bool {
    return std.mem.eql(u8, "--" ++ opt, arg) or std.mem.eql(u8, "-" ++ opt[0..1], arg);
}

inline fn printAndExit(code: u1, comptime fmt: []const u8, args: anytype) noreturn {
    const file = if (code == 0) std.io.getStdOut() else std.io.getStdErr();
    file.writer().print(fmt ++ "\n", args) catch {};
    std.process.exit(code);
}
