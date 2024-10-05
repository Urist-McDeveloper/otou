const std = @import("std");
const builtin = @import("builtin");
const ip = @import("ip.zig");

const Channel = @import("Channel.zig");
const Config = @import("Config.zig");
const Tun = @import("Tun.zig");

const Self = @This();
const Address = std.net.Address;

const time = std.time;
const posix = std.posix;

ch: Channel,
tun: Tun,
tun_addr: u32,
known: [256]bool,
peers: [256]PeerAddr,

pub fn init(tun: Tun, cfg: Config) !Self {
    const server = cfg.server orelse unreachable;

    // check if used clock is available
    _ = try now();

    var self = Self{
        .ch = try Channel.init(try cfg.parseKey(), try cfg.parseBind()),
        .tun = tun,
        .tun_addr = try cfg.parseTunAddr(),
        .known = [_]bool{false} ** 256,
        .peers = [_]PeerAddr{.{}} ** 256,
    };
    for (server.peers) |peer| {
        const peer_ip = try peer.parseIp();
        const idx = peer_ip & 0xff;
        self.known[idx] = true;
    }
    return self;
}

pub fn deinit(self: *Self) void {
    self.ch.deinit();
    self.* = undefined;
}

pub fn peerToHost(self: *Self) !void {
    const log = std.log.scoped(.peer_to_host);
    var e: Channel.Envelope = undefined;

    while (true) {
        const addr = self.ch.recv(&e) catch |err| switch (err) {
            error.NotIp4 => {
                log.debug("dropping packet received from IPv6 address", .{});
                continue;
            },
            error.Garbage => {
                log.debug("dropping malformed packet", .{});
                continue;
            },
            error.Forged => {
                log.debug("dropping forged packet", .{});
                continue;
            },
            else => return err,
        };

        const packet = e.getConstPayload();
        const info = ip.PacketInfo.parse(packet) catch |err| {
            switch (err) {
                error.NotIp4 => log.debug("dropping IPv6 packet", .{}),
                error.MalformedPacket => log.warn("recv malformed IPv4 packet", .{}),
            }
            continue;
        };
        log.debug("recv {} (header_len = {})", .{ info, packet.len - info.payload.len });

        const tun_net = 0xffffff00 & self.tun_addr;
        const src_net = 0xffffff00 & info.src;
        const src_idx = 0x000000ff & info.src;

        if (tun_net != src_net) {
            log.debug("dropping packet from different subnet", .{});
            continue;
        }
        if (!self.known[src_idx]) {
            log.debug("dropping packet from unknown peer", .{});
            continue;
        }

        const instant = now() catch unreachable;
        self.peers[src_idx].set(instant, addr) catch unreachable;

        try self.tun.send(packet);
    }
}

pub fn hostToPeer(self: *Self) !void {
    const log = std.log.scoped(.host_to_peer);
    var e: Channel.Envelope = undefined;

    while (true) {
        const packet = try self.tun.recv(e.getMaxDataSlice());
        e.setPayload(packet);

        const info = ip.PacketInfo.parse(packet) catch |err| {
            switch (err) {
                error.NotIp4 => log.debug("dropping IPv6 packet", .{}),
                error.MalformedPacket => log.warn("recv malformed IPv4 packet", .{}),
            }
            continue;
        };
        log.debug("recv {} (header_len = {})", .{ info, packet.len - info.payload.len });

        const tun_net = 0xffffff00 & self.tun_addr;
        const dst_net = 0xffffff00 & info.dst;
        const dst_idx = 0x000000ff & info.dst;

        if (tun_net != dst_net) {
            log.debug("dropping packet to different subnet", .{});
            continue;
        }
        if (!self.known[dst_idx]) {
            log.debug("dropping packet to unknown peer", .{});
            continue;
        }

        const instant = now() catch unreachable;
        const peer_addr = self.peers[dst_idx].get(instant) orelse {
            log.debug("peer address unknown", .{});
            continue;
        };

        self.ch.send(peer_addr, &e) catch |err| switch (err) {
            std.posix.SendError.NetworkUnreachable => log.err("network unreachable", .{}),
            std.posix.SendToError.UnreachableAddress => log.err("unreachable address {}", .{peer_addr}),
            else => return err,
        };
    }
}

/// Current timestamp in milliseconds.
fn now() posix.ClockGetTimeError!i64 {
    const clock_id = switch (builtin.os.tag) {
        .linux => posix.CLOCK.MONOTONIC_COARSE,
        else => unreachable,
    };

    var ts: posix.timespec = undefined;
    try posix.clock_gettime(clock_id, &ts);

    return ts.tv_sec * time.ms_per_s + @divTrunc(ts.tv_nsec, time.ns_per_ms);
}

/// IPv4 address and port with expiration and guaranteed atomic updates.
const PeerAddr = struct {
    /// How long (in milliseconds) to keep peer addresses after each update.
    const shelf_life = 10 * time.ms_per_s;

    repr: u64 = 0,
    atime: i64 = std.math.minInt(i64),

    pub fn get(self: *const PeerAddr, instant: i64) ?Address {
        if (@atomicLoad(i64, &self.atime, .acquire) + shelf_life < instant) {
            return null;
        } else {
            const repr = @atomicLoad(u64, &self.repr, .acquire);
            return .{ .in = .{ .sa = .{
                .addr = @intCast(repr >> 32),
                .port = @intCast(repr & 0xffff),
            } } };
        }
    }

    pub fn set(self: *PeerAddr, instant: i64, addr: Address) ip.VersionError!void {
        if (addr.any.family != posix.AF.INET) return ip.VersionError.NotIp4;

        const addr_: u64 = addr.in.sa.addr;
        const port_: u64 = addr.in.sa.port;
        @atomicStore(u64, &self.repr, (addr_ << 32) | port_, .release);
        @atomicStore(i64, &self.atime, instant, .release);
    }
};
