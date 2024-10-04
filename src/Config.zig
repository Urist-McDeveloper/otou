const std = @import("std");
const builtin = @import("builtin");

const ip = @import("ip.zig");

const log = std.log.scoped(.cfg);
const Allocator = std.mem.Allocator;
const Config = @This();

pub const Client = struct {
    tun_keep: bool,
    server_addr: []const u8,

    pub fn parseServerAddr(self: Client) ip.WithPort.ParseError!std.net.Address {
        return ip.WithPort.parseAddress(self.server_addr);
    }
};

pub const Server = struct {
    peers: []const Peer,

    pub const Peer = struct {
        ip: []const u8,
        label: ?[]const u8 = null,

        pub fn parseIp(self: Peer) !u32 {
            return ip.parse(self.ip);
        }
    };
};

tun_name: []const u8,
tun_addr: []const u8,
bind: []const u8,
key: []const u8,
client: ?Client = null,
server: ?Server = null,

pub fn parseTunAddr(self: Config) ip.ParseError!u32 {
    return ip.parse(self.tun_addr);
}

pub fn parseBind(self: Config) ip.WithPort.ParseError!std.net.Address {
    return ip.WithPort.parseAddress(self.bind);
}

pub fn parseKey(self: Config) std.fmt.ParseIntError![32]u8 {
    const parsed = try std.fmt.parseInt(u256, self.key, 16);
    if (parsed == 0 and !builtin.is_test and builtin.mode != .Debug) {
        log.err("cowardly refusing to use the all-zero key from example configurations", .{});
        std.process.exit(1);
    }

    var buf: [32]u8 = undefined;
    std.mem.writeInt(u256, &buf, parsed, .little);
    return buf;
}

pub fn parse(a: Allocator, path: ?[]const u8) !std.json.Parsed(Config) {
    const path_ = path orelse switch (builtin.os.tag) {
        .linux => "/etc/otou.json",
        else => unreachable,
    };
    log.debug("loading configuration from {s}", .{path_});

    const raw = try std.fs.cwd().readFileAlloc(a, path_, 1 << 16);
    defer a.free(raw);

    return parseFromSlice(a, raw);
}

fn parseFromSlice(a: Allocator, raw: []const u8) !std.json.Parsed(Config) {
    const parsed = try std.json.parseFromSlice(Config, a, raw, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = true,
    });
    errdefer parsed.deinit();

    try Validator.validate(&parsed.value);
    return parsed;
}

const Validator = struct {
    has_errors: bool = false,

    pub fn validate(c: *const Config) !void {
        var v = Validator{};

        if (c.client == null and c.server == null) v.fail("both client and server are null");
        if (c.client != null and c.server != null) v.fail("both client and server are not null");

        if (c.tun_name.len == 0) v.fail("tun_name is empty");
        if (c.tun_name.len > 15) v.fail("tun_name is longer than 15 bytes");
        _ = c.parseBind() catch v.fail("bind is malformed");
        _ = c.parseKey() catch v.fail("key is not 32 bytes in hex encoding");

        const tun_addr: ?u32 = c.parseTunAddr() catch blk: {
            v.fail("tun_addr is malformed");
            break :blk null;
        };

        if (tun_addr) |addr| {
            const host = addr & 0x000000ff;
            if (host == 0) v.fail("tun_addr is a network address (last octet is 0)");
            if (host == 255) v.fail("tun_addr is a broadcast address (last octet is 255)");
        }

        if (c.client) |client| {
            _ = client.parseServerAddr() catch v.fail("client.server_addr is malformed");
        }

        if (c.server) |server| {
            v.validatePeers(tun_addr, server.peers);
        }

        return v.finish();
    }

    fn validatePeers(v: *Validator, tun_addr: ?u32, peers: []const Server.Peer) void {
        if (peers.len == 0) {
            v.fail("server.peers is empty");
            return;
        }

        const tun_addr_ = tun_addr orelse return;
        const tun_net = tun_addr_ & 0xffffff00;
        const tun_host = tun_addr_ & 0x000000ff;

        var peer_hosts = [_]bool{false} ** 256;
        peer_hosts[tun_host] = true;

        for (peers, 0..) |peer, i| {
            const peer_ip = peer.parseIp() catch {
                v.failWithArgs("server.peers[{}].ip is malformed", .{i});
                continue;
            };

            const peer_net = peer_ip & 0xffffff00;
            const peer_host = peer_ip & 0x000000ff;

            if (peer_host == 0) v.failWithArgs("server.peers[{}].ip is a network address (last octet is 0)", .{i});
            if (peer_host == 255) v.failWithArgs("server.peers[{}].ip is a broadcast address (last octet is 255)", .{i});

            if (peer_net != tun_net) {
                v.failWithArgs("server.peers[{}].ip a tun_addr", .{i});
            } else if (peer_hosts[peer_host]) {
                v.failWithArgs("server.peers[{}].ip is a duplicate", .{i});
            } else {
                peer_hosts[peer_host] = true;
            }
        }
    }

    fn finish(self: Validator) !void {
        if (self.has_errors) {
            if (builtin.is_test) {
                return error.ValidationFailed;
            } else {
                std.process.exit(1);
            }
        }
    }

    fn fail(self: *Validator, comptime fmt: []const u8) void {
        self.failWithArgs(fmt, .{});
    }

    fn failWithArgs(self: *Validator, comptime fmt: []const u8, args: anytype) void {
        self.has_errors = true;
        log.err(fmt, args);
    }
};

const client_example_json = @embedFile("config_client_example.json");
const server_example_json = @embedFile("config_server_example.json");

test "parse client_example.json" {
    (try parseFromSlice(std.testing.allocator, client_example_json)).deinit();
}

test "parse server_example.json" {
    (try parseFromSlice(std.testing.allocator, server_example_json)).deinit();
}
