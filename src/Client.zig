const std = @import("std");
const ip = @import("ip.zig");

const Channel = @import("Channel.zig");
const Config = @import("Config.zig");
const Tun = @import("Tun.zig");

const Self = @This();
const Address = std.net.Address;

tun: Tun,
ch: Channel,
srv_addr: Address,

pub fn init(tun: Tun, cfg: Config) !Self {
    const client = cfg.client orelse unreachable;
    return .{
        .tun = tun,
        .ch = try Channel.init(try cfg.parseKey(), try cfg.parseBind()),
        .srv_addr = try client.parseServerAddr(),
    };
}

pub fn deinit(self: *Self) void {
    self.ch.deinit();
    self.* = undefined;
}

pub fn peerToHost(self: *Self) !void {
    const log = std.log.scoped(.peer_to_host);
    var e: Channel.Envelope = undefined;

    while (true) {
        // TODO: check sender?
        _ = self.ch.recv(&e) catch |err| switch (err) {
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

        // TODO: check src and dst of packet?
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

        // TODO: check src and dst of packet?
        self.ch.send(self.srv_addr, &e) catch |err| switch (err) {
            std.posix.SendError.NetworkUnreachable => log.err("network unreachable", .{}),
            std.posix.SendToError.UnreachableAddress => log.err("unreachable address {}", .{self.srv_addr}),
            else => return err,
        };
    }
}
