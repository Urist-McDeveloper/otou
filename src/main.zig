const std = @import("std");
const builtin = @import("builtin");

const Args = @import("Args.zig");
const Channel = @import("Channel.zig");
const Config = @import("Config.zig");
const Tun = @import("Tun.zig");

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

                try Worker.run(tun, cfg);
            },
            .routes_up => try routes.up(a, cfg),
            .routes_down => try routes.down(a, cfg),
            else => unreachable,
        }
    }
}

pub const Worker = struct {
    const Thread = std.Thread;
    const Mutex = Thread.Mutex;

    ch: Channel,
    tun: Tun,

    peer_addr_fixed: ?net.Address,
    peer_addr_dyn: ?net.Address,

    pub fn run(tun: Tun, cfg: Config) !void {
        var ctx = Worker{
            .ch = try Channel.init(try cfg.parseKey(), try cfg.parseBind()),
            .tun = tun,
            .peer_addr_fixed = if (cfg.client) |c| try c.parseServerAddr() else null,
            .peer_addr_dyn = null,
        };
        defer ctx.deinit();

        const htp_thread = try Thread.spawn(.{}, Worker.hostToPeerLoop, .{&ctx});
        const pth_thread = try Thread.spawn(.{}, Worker.peerToHostLoop, .{&ctx});

        htp_thread.join();
        pth_thread.join();
    }

    fn deinit(ctx: *Worker) void {
        ctx.ch.deinit();
        ctx.* = undefined;
    }

    fn hostToPeerLoop(ctx: *Worker) !void {
        const scoped = log.scoped(.host_to_peer);
        var e: Channel.Envelope = undefined;

        while (true) {
            const recv = try ctx.tun.recv(e.getMaxDataSlice());
            e.setPayload(recv);

            const addr = ctx.peer_addr_fixed orelse ctx.peer_addr_dyn orelse {
                scoped.warn("peer address unknown", .{});
                continue;
            };

            ctx.ch.send(addr, &e) catch |err| switch (err) {
                posix.SendError.NetworkUnreachable => scoped.err("network unreachable", .{}),
                posix.SendToError.UnreachableAddress => scoped.err("unreachable address {}", .{addr}),
                else => return err,
            };
        }
    }

    fn peerToHostLoop(ctx: *Worker) !void {
        const scoped = log.scoped(.peer_to_host);
        var e: Channel.Envelope = undefined;

        while (true) {
            const addr = ctx.ch.recv(&e) catch |err| switch (err) {
                error.Garbage => {
                    scoped.debug("dropping malformed packet", .{});
                    continue;
                },
                error.Forged => {
                    scoped.debug("dropping forged packet", .{});
                    continue;
                },
                else => return err,
            };
            ctx.peer_addr_dyn = addr;
            try ctx.tun.send(e.getConstPayload());
        }
    }
};

test {
    _ = @import("Args.zig");
    _ = @import("Channel.zig");
    _ = @import("cmd.zig");
    _ = @import("Config.zig");
    _ = @import("ip.zig");
    _ = @import("routes.zig");
    _ = @import("Tun.zig");
}
