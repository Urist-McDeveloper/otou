const std = @import("std");
const builtin = @import("builtin");

const Args = @import("Args.zig");
const Channel = @import("Channel.zig");
const Config = @import("Config.zig");
const Tun = @import("Tun.zig");

const net = std.net;
const posix = std.posix;

const assert = std.debug.assert;
const log = std.log;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const a = gpa.allocator();

    const args = try Args.init(a);
    defer args.deinit(a);

    switch (args.command) {
        .genkey => {
            var key: [32]u8 = undefined;
            try posix.getrandom(&key);
            try std.io.getStdOut().writer().print("{x:0>64}\n", .{std.mem.readInt(u256, &key, .little)});
        },
        .run => {
            const parsed = try Config.parse(a, args.config_path);
            defer parsed.deinit();
            const common = parsed.value.common;

            var tun = try Tun.open(a, common.tun_name, common.tun_addr, common.tun_keep);
            defer tun.close();

            try Worker.run(tun, parsed.value);
        },
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
            .ch = try Channel.init(try cfg.common.parseKey(), try cfg.common.parseBind()),
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
        while (true) {
            const recv = try ctx.tun.recv(ctx.ch.getDataSlice());
            const addr = ctx.peer_addr_fixed orelse ctx.peer_addr_dyn orelse {
                scoped.warn("peer address unknown", .{});
                continue;
            };

            ctx.ch.send(addr, recv.len) catch |e| switch (e) {
                posix.SendError.NetworkUnreachable => scoped.err("network unreachable", .{}),
                posix.SendToError.UnreachableAddress => scoped.err("unreachable address {}", .{addr}),
                else => return e,
            };
        }
    }

    fn peerToHostLoop(ctx: *Worker) !void {
        const scoped = log.scoped(.peer_to_host);
        while (true) {
            const recv = ctx.ch.recv() catch |err| switch (err) {
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
            ctx.peer_addr_dyn = recv.from;
            try ctx.tun.send(recv.data);
        }
    }
};

test {
    _ = @import("Args.zig");
    _ = @import("Channel.zig");
    _ = @import("cmd.zig");
    _ = @import("Config.zig");
    _ = @import("ip.zig");
    _ = @import("Tun.zig");
}
