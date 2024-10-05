const std = @import("std");
const builtin = @import("builtin");

const Args = @import("Args.zig");
const Channel = @import("Channel.zig");
const Client = @import("Client.zig");
const Config = @import("Config.zig");
const Server = @import("Server.zig");
const Tun = @import("Tun.zig");

const ip = @import("ip.zig");
const net = std.net;
const posix = std.posix;
const routes = @import("routes.zig");

const assert = std.debug.assert;
const log = std.log;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const a = gpa.allocator();

    const args = try Args.init(a);
    defer args.deinit(a);

    if (args.command == .genkey) {
        var key: [32]u8 = undefined;
        try posix.getrandom(&key);
        try std.io.getStdOut().writer().print("{x:0>64}\n", .{std.mem.readInt(u256, &key, .little)});
    } else {
        const parsed = try Config.parse(a, args.config_path);
        defer parsed.deinit();
        const cfg = parsed.value;

        switch (args.command) {
            .run => {
                const tun_keep = if (cfg.client) |c| c.tun_keep else false;

                var tun = try Tun.open(a, cfg.tun_name, cfg.tun_addr, tun_keep);
                defer tun.close();

                if (cfg.client != null) {
                    try run(Client, tun, cfg);
                } else {
                    try run(Server, tun, cfg);
                }
            },
            .routes_up => try routes.up(a, cfg),
            .routes_down => try routes.down(a, cfg),
            else => unreachable,
        }
    }
}

fn run(comptime T: type, tun: Tun, cfg: Config) !void {
    var ctx = try T.init(tun, cfg);
    defer ctx.deinit();

    const htp_thread = try std.Thread.spawn(.{}, T.hostToPeer, .{&ctx});
    const pth_thread = try std.Thread.spawn(.{}, T.peerToHost, .{&ctx});

    htp_thread.join();
    pth_thread.join();
}

test {
    _ = @import("Args.zig");
    _ = @import("Channel.zig");
    _ = @import("Client.zig");
    _ = @import("cmd.zig");
    _ = @import("Config.zig");
    _ = @import("ip.zig");
    _ = @import("routes.zig");
    _ = @import("Server.zig");
    _ = @import("Tun.zig");
}
