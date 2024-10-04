const std = @import("std");
const builtin = @import("builtin");

const ip = @import("ip.zig");

const log = std.log.scoped(.cfg);
const Allocator = std.mem.Allocator;

pub const Ipc = struct {
    pid_file: []const u8,
    sock_file: []const u8,
};

pub const Common = struct {
    tun_name: []const u8,
    tun_addr: []const u8,
    tun_keep: bool,
    bind: []const u8,
    key: []const u8,

    pub fn parseTunAddr(self: Common) ip.ParseError!u32 {
        return ip.parse(self.tun_addr);
    }

    pub fn parseBind(self: Common) ip.WithPort.ParseError!std.net.Address {
        return ip.WithPort.parseAddress(self.bind);
    }

    pub fn parseKey(self: Common) std.fmt.ParseIntError![32]u8 {
        const parsed = try std.fmt.parseInt(u256, self.key, 16);
        if (parsed == 0 and !builtin.is_test and builtin.mode != .Debug) {
            log.err("cowardly refusing to use the all-zero key from example configurations", .{});
            std.process.exit(1);
        }

        var buf: [32]u8 = undefined;
        std.mem.writeInt(u256, &buf, parsed, .little);
        return buf;
    }
};

pub const Client = struct {
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

pub const Full = struct {
    ipc: Ipc,
    common: Common,
    client: ?Client = null,
    server: ?Server = null,

    pub fn parse(a: Allocator, path: ?[]const u8) !std.json.Parsed(Full) {
        const parsed = try parseFromFile(Full, a, path);
        try Validator.validateFull(parsed.value);
        return parsed;
    }
};

pub const IpcOnly = struct {
    ipc: Ipc,

    pub fn parse(a: Allocator, path: ?[]const u8) !std.json.Parsed(IpcOnly) {
        const parsed = try parseFromFile(IpcOnly, a, path);
        try Validator.validateIpcOnly(parsed.value);
        return parsed;
    }
};

fn parseFromFile(comptime T: type, a: Allocator, path: ?[]const u8) !std.json.Parsed(T) {
    const path_ = path orelse switch (builtin.os.tag) {
        .linux => "/etc/otou.json",
        else => unreachable,
    };
    log.info("loading configuration from \"{s}\"", .{path_});

    const raw = try std.fs.cwd().readFileAlloc(a, path_, 1 << 16);
    defer a.free(raw);

    return parseFromSlice(T, a, raw);
}

fn parseFromSlice(comptime T: type, a: Allocator, raw: []const u8) !std.json.Parsed(T) {
    return std.json.parseFromSlice(T, a, raw, .{ .allocate = .alloc_always, .ignore_unknown_fields = true });
}

const Validator = struct {
    has_errors: bool = false,

    pub fn validateIpcOnly(c: IpcOnly) !void {
        var v = Validator{};

        if (c.ipc.pid_file.len == 0) v.fail("ipc.pid_file is empty");
        if (c.ipc.sock_file.len == 0) v.fail("ipc.sock_file is empty");

        return v.finish();
    }

    pub fn validateFull(c: Full) !void {
        var v = Validator{};

        if (c.client == null and c.server == null) v.fail("both client and server are null");
        if (c.client != null and c.server != null) v.fail("both client and server are not null");

        if (c.ipc.pid_file.len == 0) v.fail("ipc.pid_file is empty");
        if (c.ipc.sock_file.len == 0) v.fail("ipc.sock_file is empty");

        if (c.common.tun_name.len == 0) v.fail("common.tun_name is empty");
        if (c.common.tun_name.len > 8) v.fail("common.tun_name is longer than 8 bytes");
        _ = c.common.parseBind() catch v.fail("common.bind is malformed");
        _ = c.common.parseKey() catch v.fail("common.key is not 32 bytes in hex encoding");

        const tun_addr: ?u32 = c.common.parseTunAddr() catch blk: {
            v.fail("common.tun_addr is malformed");
            break :blk null;
        };
        if (tun_addr) |addr| {
            const host = addr & 0x000000ff;
            if (host == 0) v.fail("common.tun_addr is a network address (last octet is 0)");
            if (host == 255) v.fail("common.tun_addr is a broadcast address (last octet is 255)");
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
                v.failWithArgs("server.peers[{}].ip a common.tun_addr", .{i});
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

test "Full.parse client_example.json" {
    const parsed = try parseFromSlice(Full, std.testing.allocator, client_example_json);
    defer parsed.deinit();
    try Validator.validateFull(parsed.value);
}

test "Full.parse server_example.json" {
    const parsed = try parseFromSlice(Full, std.testing.allocator, server_example_json);
    defer parsed.deinit();
    try Validator.validateFull(parsed.value);
}

test "IpcOnly.parse client_example.json" {
    const parsed = try parseFromSlice(IpcOnly, std.testing.allocator, client_example_json);
    defer parsed.deinit();
    try Validator.validateIpcOnly(parsed.value);
}

test "IpcOnly.parse server_example.json" {
    const parsed = try parseFromSlice(IpcOnly, std.testing.allocator, server_example_json);
    defer parsed.deinit();
    try Validator.validateIpcOnly(parsed.value);
}
