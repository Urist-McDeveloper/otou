const std = @import("std");

const log = std.log.scoped(.cmd);
const Allocator = std.mem.Allocator;
const Child = std.process.Child;

pub const RunError = error{CmdError} || Child.RunError;
pub const ShellError = std.fmt.AllocPrintError || RunError;

/// Run `cmd`, wait for it to finish and return stdout.
pub fn run(a: Allocator, cmd: []const []const u8) RunError![]const u8 {
    const result = try Child.run(.{ .allocator = a, .argv = cmd, .max_output_bytes = 102400 });
    errdefer a.free(result.stdout);
    defer a.free(result.stderr);

    if (result.term == .Exited and result.term.Exited == 0) {
        return result.stdout;
    } else {
        const merged = merge(a, cmd) catch null;
        defer if (merged) |m| a.free(m);

        const stdout = result.stdout;
        var stderr = result.stderr;

        if (stderr.len > 0 and stderr[stderr.len - 1] == '\n') {
            stderr = stderr[0 .. stderr.len - 1];
        }

        log.err("{?s}\n\tstdout:\n{s}\tstderr:\n{s}", .{ merged, stdout, stderr });
        return error.CmdError;
    }
}

/// Run `cmd`, wait for it to finish and discard any output.
pub fn execute(a: Allocator, cmd: []const []const u8) RunError!void {
    a.free(try run(a, cmd));
}

/// Run formatted shell command, wait for it to finish and return stdout.
pub fn shell(a: Allocator, comptime fmt: []const u8, args: anytype) ShellError![]const u8 {
    const cmd = try std.fmt.allocPrint(a, fmt, args);
    defer a.free(cmd);

    return run(a, &.{ "sh", "-c", cmd });
}

/// Run formatted shell command, wait for it to finish and discard any output.
pub fn executeShell(a: Allocator, comptime fmt: []const u8, args: anytype) ShellError!void {
    a.free(try shell(a, fmt, args));
}

/// Merge `cmd` into a single slice.
fn merge(a: Allocator, cmd: []const []const u8) ![]const u8 {
    var merged = std.ArrayList(u8).init(a);
    for (cmd, 0..) |arg, i| {
        if (i != 0) try merged.append(' ');
        try merged.appendSlice(arg);
    }
    return merged.toOwnedSlice();
}
