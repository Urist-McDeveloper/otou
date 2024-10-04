const std = @import("std");
const builtin = @import("builtin");
const Config = @import("Config.zig");

const Allocator = std.mem.Allocator;
const log = std.log.scoped(.routes);

pub fn up(a: Allocator, cfg: Config) !void {
    const server_ip = try parseServerIp(cfg);
    return impl.up(a, cfg.tun_name, server_ip);
}

pub fn down(a: Allocator, cfg: Config) !void {
    const server_ip = try parseServerIp(cfg);
    return impl.down(a, server_ip);
}

fn parseServerIp(cfg: Config) ![]const u8 {
    const client = cfg.client orelse {
        log.err("routes command can only run in client mode", .{});
        return error.InvalidMode;
    };

    var split = std.mem.splitScalar(u8, client.server_addr, ':');
    return split.first();
}

const impl = switch (builtin.os.tag) {
    .linux => linux,
    else => unreachable,
};

const linux = struct {
    const cmd = @import("cmd.zig");

    pub fn up(a: Allocator, tun_name: []const u8, server_ip: []const u8) !void {
        const result = try cmd.shell(a, "ip route | grep '^default' | cut -d' ' -f3", .{});
        defer a.free(result);

        if (result.len > 0) {
            const gateway = result[0 .. result.len - 1];
            log.debug("setting up bypass route for {s} via {s}", .{server_ip, gateway});
            try cmd.execute(a, &.{ "ip", "route", "replace", server_ip, "via", gateway, "metric", "10" });
        } else {
            log.warn("default route does not exist, cannot set up bypass route for {s}", .{server_ip});
        }

        log.debug("setting up blackhole route for {s}", .{server_ip});
        try cmd.execute(a, &.{ "ip", "route", "replace", "blackhole", server_ip, "metric", "100" });

        if (try hasTun(a, tun_name)) {
            log.debug("setting up gateway routes through {s}", .{tun_name});
            try cmd.execute(a, &.{ "ip", "route", "replace", "128.0.0.0/1", "dev", tun_name });
            try cmd.execute(a, &.{ "ip", "route", "replace", "0.0.0.0/1", "dev", tun_name });
        } else {
            log.warn("{s} does not exist, cannot set up gateway routes", .{tun_name});
        }
    }

    pub fn down(a: Allocator, server_ip: []const u8) !void {
        if (try hasRoute(a, .{ .route = "128.0.0.0/1" })) {
            log.debug("deleting gateway route 128.0.0.0/1", .{});
            try cmd.execute(a, &.{ "ip", "route", "del", "128.0.0.0/1" });
        }
        if (try hasRoute(a, .{ .route = "0.0.0.0/1" })) {
            log.debug("deleting gateway route 0.0.0.0/1", .{});
            try cmd.execute(a, &.{ "ip", "route", "del", "0.0.0.0/1" });
        }
        if (try hasRoute(a, .{ .route = server_ip, .blackhole = true })) {
            log.debug("deleting blackhole route for {s}", .{server_ip});
            try cmd.execute(a, &.{ "ip", "route", "del", "blackhole", server_ip });
        }
        if (try hasRoute(a, .{ .route = server_ip })) {
            log.debug("deleting bypass route for {s}", .{server_ip});
            try cmd.execute(a, &.{ "ip", "route", "del", server_ip });
        }
    }

    fn hasTun(a: Allocator, tun_name: []const u8) !bool {
        return hasOutput(a, "ip link | grep '[0-9]: {s}:'", .{tun_name});
    }

    fn hasRoute(a: Allocator, args: struct { route: []const u8, blackhole: bool = false }) !bool {
        return if (args.blackhole)
            hasOutput(a, "ip route | grep '^blackhole {s}'", .{args.route})
        else
            hasOutput(a, "ip route | grep '^{s}'", .{args.route});
    }

    fn hasOutput(a: Allocator, comptime fmt: []const u8, args: anytype) !bool {
        const result = try cmd.shell(a, fmt ++ " || echo -n ''", args);
        defer a.free(result);

        return result.len > 0;
    }
};
