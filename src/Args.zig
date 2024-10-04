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
    \\Common commands:
    \\  genkey              generate a random 32-byte secret key
    \\  run                 start main process
    \\
    \\Client mode commands:
    \\  routes <up|down>    set/reset gateway routes
;

pub const Command = enum {
    genkey,
    run,
    routes_up,
    routes_down,

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

    var iter = ArgIter{ .raw = raw };
    while (iter.next()) |arg| {
        if (isOpt(arg, "help")) printAndExit(0, usage, .{});
        if (isOpt(arg, "version")) printAndExit(0, version, .{});

        if (isOpt(arg, "config")) {
            config = iter.next() orelse printAndExit(1, "missing PATH parameter for {s}", .{arg});
            continue;
        }

        if (is(arg, "routes")) {
            const next = iter.next() orelse printAndExit(1, "missing <up|down> parameter for routes", .{});

            if (is(next, "up")) {
                command = .routes_up;
                continue;
            }
            if (is(next, "down")) {
                command = .routes_down;
                continue;
            }
            printAndExit(1, "unknown parameter for routes: {s}", .{next});
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

const ArgIter = struct {
    raw: []const []const u8,
    idx: usize = 1,

    pub fn next(self: *ArgIter) ?[]const u8 {
        if (self.idx < self.raw.len) {
            const arg = self.raw[self.idx];
            self.idx += 1;

            return arg;
        } else {
            return null;
        }
    }
};

fn isOpt(arg: []const u8, comptime opt: []const u8) bool {
    return std.mem.eql(u8, arg, "--" ++ opt) or std.mem.eql(u8, arg, "-" ++ opt[0..1]);
}

fn is(arg: []const u8, comptime cmd: []const u8) bool {
    return std.mem.eql(u8, cmd, arg);
}

inline fn printAndExit(code: u1, comptime fmt: []const u8, args: anytype) noreturn {
    const file = if (code == 0) std.io.getStdOut() else std.io.getStdErr();
    file.writer().print(fmt ++ "\n", args) catch {};
    std.process.exit(code);
}
