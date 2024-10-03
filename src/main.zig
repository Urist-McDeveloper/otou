const std = @import("std");
const builtin = @import("builtin");
const config = @import("config.zig");

const net = std.net;
const posix = std.posix;

const assert = std.debug.assert;
const log = std.log;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const a = gpa.allocator();

    const args = try config.Args.init(a);
    defer args.deinit(a);

    switch (args.command) {
        .genkey => {
            var key: [32]u8 = undefined;
            try posix.getrandom(&key);
            try std.io.getStdOut().writer().print("{x:0>64}\n", .{std.mem.readInt(u256, &key, .little)});
        },
        .run => {
            const parsed = try config.Full.parse(a, args.config_path);
            defer parsed.deinit();

            var tun = try Tun.open("tun-otou");
            defer tun.close();

            try Worker.run(tun, parsed.value);
        },
        else => {
            const parsed = try config.IpcOnly.parse(a, args.config_path);
            defer parsed.deinit();

            try runIpc(a, args.command, parsed.value.ipc);
        },
    }
}

pub fn runIpc(a: std.mem.Allocator, command: config.Command, ipc: config.Ipc) !void {
    _ = a;
    _ = command;
    _ = ipc;

    return error.NotImplemented;
}

pub const SecureSocket = struct {
    const Self = @This();
    const Blake3 = std.crypto.hash.Blake3;
    const Aegis128L = std.crypto.aead.aegis.Aegis128L;

    pub const max_msg_size = 1460; // to fit in 1500 MTU with 40 bytes of IPv4 packet overhead
    pub const header_size = 40; // 24 byte nonce, 16 byte tag
    pub const max_data_len = max_msg_size - header_size;

    sock: posix.socket_t,
    recv_buf: [max_msg_size]u8 = undefined,
    send_buf: [max_msg_size]u8 = undefined,

    key: [32]u8,
    rng: std.Random.ChaCha,

    pub const InitError = posix.SocketError || posix.BindError || posix.GetRandomError;
    pub const RecvError = error{ Garbage, Forged } || posix.RecvFromError;
    pub const SendError = posix.SendToError;

    pub const RecvData = struct {
        from: net.Address,
        data: []u8,
    };

    pub fn init(key: [32]u8, bind: ?net.Address) InitError!Self {
        const sock = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
        errdefer net.Stream.close(.{ .handle = sock });

        if (bind) |addr| {
            try posix.bind(sock, &addr.any, addr.getOsSockLen());
        }

        var rng_seed: [32]u8 = undefined;
        try posix.getrandom(&rng_seed);

        return Self{
            .sock = sock,
            .key = key,
            .rng = std.Random.ChaCha.init(rng_seed),
        };
    }

    pub fn deinit(self: *Self) void {
        net.Stream.close(.{ .handle = self.sock });
        self.* = undefined;
    }

    pub fn recv(self: *Self) RecvError!RecvData {
        var from_raw: posix.sockaddr align(4) = undefined;
        var from_len: posix.socklen_t = @intCast(@sizeOf(posix.sockaddr));

        const msg_size = try posix.recvfrom(self.sock, &self.recv_buf, 0, &from_raw, &from_len);
        const addr = net.Address.initPosix(&from_raw);

        if (msg_size < header_size) return error.Garbage;

        const msg_nonce = self.recv_buf[0..24];
        const msg_tag = self.recv_buf[24..40];

        var derived: [64]u8 = undefined;
        Blake3.hash(msg_nonce, &derived, .{ .key = self.key });

        const msg_key = derived[0..16];
        const msg_iv = derived[16..32];
        const msg_ad = derived[32..64];

        const msg_data = self.recv_buf[header_size..msg_size];
        Aegis128L.decrypt(msg_data, msg_data, msg_tag.*, msg_ad, msg_iv.*, msg_key.*) catch return error.Forged;

        return RecvData{ .from = addr, .data = msg_data };
    }

    pub fn send(self: *Self, addr: net.Address, data_len: usize) SendError!void {
        assert(data_len <= max_data_len);

        const msg_nonce = self.send_buf[0..24];
        const msg_tag = self.send_buf[24..40];
        self.rng.fill(msg_nonce);

        var derived: [64]u8 = undefined;
        Blake3.hash(msg_nonce, &derived, .{ .key = self.key });

        const msg_key = derived[0..16];
        const msg_iv = derived[16..32];
        const msg_ad = derived[32..64];

        const msg_data = self.send_buf[header_size..][0..data_len];
        Aegis128L.encrypt(msg_data, msg_tag, msg_data, msg_ad, msg_iv.*, msg_key.*);

        const msg_size = header_size + data_len;
        const sent = try posix.sendto(self.sock, self.send_buf[0..msg_size], 0, &addr.any, addr.getOsSockLen());

        // sanity check, should never fail
        assert(sent == msg_size);
    }

    /// Slice of bytes that will be sent in the next `self.send` call.
    pub fn getDataSlice(self: *Self) []u8 {
        return self.send_buf[header_size..][0..max_data_len];
    }
};

pub const Worker = struct {
    const Thread = std.Thread;
    const Mutex = Thread.Mutex;

    sock: SecureSocket,
    tun: Tun,

    peer_addr_fixed: ?net.Address,
    peer_addr_dyn: ?net.Address,

    pub fn run(tun: Tun, cfg: config.Full) !void {
        var ctx = Worker{
            .sock = try SecureSocket.init(try cfg.common.parseKey(), try cfg.common.parseBind()),
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
        ctx.sock.deinit();
        ctx.* = undefined;
    }

    fn hostToPeerLoop(ctx: *Worker) !void {
        const scoped = log.scoped(.host_to_peer);
        while (true) {
            const recv = try ctx.tun.recv(ctx.sock.getDataSlice());
            const addr = ctx.peer_addr_fixed orelse ctx.peer_addr_dyn orelse {
                scoped.warn("peer address unknown", .{});
                continue;
            };

            ctx.sock.send(addr, recv.len) catch |e| switch (e) {
                posix.SendError.NetworkUnreachable => scoped.err("network unreachable", .{}),
                posix.SendToError.UnreachableAddress => scoped.err("unreachable address {}", .{addr}),
                else => return e,
            };
        }
    }

    fn peerToHostLoop(ctx: *Worker) !void {
        const scoped = log.scoped(.peer_to_host);
        while (true) {
            const recv = ctx.sock.recv() catch |err| switch (err) {
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

const tun_mtu = SecureSocket.max_data_len;
const Tun = switch (builtin.os.tag) {
    .linux => LinuxTun,
    else => unreachable,
};

const LinuxTun = struct {
    const linux = std.os.linux;
    const Self = @This();

    fd: linux.fd_t,

    // cannot @cInclude("linux/if_tun.h") without linking libc so hard coding it is
    const IFF_TUN = 0x0001;
    const IFF_NO_PI = 0x1000;
    const TUNSETIFF = 1074025674;
    const SIOCGIFMTU = 0x8921;
    const SIOCSIFMTU = 0x8922;

    pub fn open(name: []const u8) !Self {
        assert(name.len < linux.IFNAMESIZE);
        log.info("opening {s}", .{name});

        const fd = try posix.open("/dev/net/tun", .{ .ACCMODE = .RDWR }, 0);
        errdefer posix.close(fd);

        var name_arr = [1]u8{0} ** linux.IFNAMESIZE;
        @memcpy(name_arr[0..name.len], name);

        var ifr = linux.ifreq{
            .ifrn = .{ .name = name_arr },
            .ifru = .{ .flags = IFF_TUN | IFF_NO_PI },
        };

        switch (posix.errno(linux.ioctl(fd, TUNSETIFF, @intFromPtr(&ifr)))) {
            .SUCCESS => {},
            .PERM => return error.AccessDenied,
            .BUSY => return error.AlreadyInUse,
            else => |err| {
                log.err("failed to open {s}: {s}", .{ name, @tagName(err) });
                return posix.unexpectedErrno(err);
            },
        }

        const sock_fd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
        defer posix.close(sock_fd);

        switch (posix.errno(linux.ioctl(sock_fd, SIOCGIFMTU, @intFromPtr(&ifr)))) {
            .SUCCESS => {},
            .PERM => return error.AccessDenied,
            else => |err| {
                log.err("failed to get MTU of {s}: {s}", .{ name, @tagName(err) });
                return posix.unexpectedErrno(err);
            },
        }

        if (ifr.ifru.mtu != tun_mtu) {
            log.info("old MTU = {}, setting to {}", .{ ifr.ifru.mtu, tun_mtu });
            ifr.ifru = .{ .mtu = tun_mtu };

            switch (posix.errno(linux.ioctl(sock_fd, SIOCSIFMTU, @intFromPtr(&ifr)))) {
                .SUCCESS => {},
                .PERM => return error.AccessDenied,
                else => |err| {
                    log.err("failed to set mtu of {s}: {s}", .{ name, @tagName(err) });
                    return posix.unexpectedErrno(err);
                },
            }
        } else {
            log.info("MTU is already {}", .{tun_mtu});
        }

        return Self{ .fd = fd };
    }

    pub fn close(self: *Self) void {
        posix.close(self.fd);
        self.* = undefined;
    }

    pub fn recv(self: *Self, buf: []u8) posix.ReadError![]u8 {
        const size = try posix.read(self.fd, buf);
        return buf[0..size];
    }

    pub fn send(self: *const Self, buf: []u8) posix.WriteError!void {
        const size = try posix.write(self.fd, buf);
        // sanity check, should never fail
        assert(size == buf.len);
    }
};

test {
    _ = @import("config.zig");
    _ = @import("ip.zig");
}
