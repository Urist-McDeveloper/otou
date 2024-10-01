const std = @import("std");
const builtin = @import("builtin");

const net = std.net;
const posix = std.posix;

const assert = std.debug.assert;
const log = std.log;

const test_key_str = "bfeab420066cafde41f8d7c7e5b4854454ac21a64e83ca14d731f1107e8fa362";
const test_key = std.mem.toBytes(std.fmt.parseInt(u256, test_key_str, 16) catch unreachable);

pub const Args = struct {
    bind: ?net.Address = null,
    peer: ?net.Address = null,

    pub fn printUsageAndExit() noreturn {
        stderr("Usage: otou [--bind IP] [--peer IP]\n", .{});
        stderr("At least one option must be set.\n", .{});
        std.process.exit(1);
    }

    pub fn parse(raw: []const [:0]const u8) Args {
        var parsed = Args{};
        var i: usize = 1;

        while (i < raw.len) : (i += 1) {
            const this_arg = raw[i];
            const next_arg = if (i + 1 == raw.len) null else raw[i + 1];

            if (std.mem.eql(u8, "--bind", this_arg)) {
                parsed.bind = parseAddr(next_arg orelse printUsageAndExit());
            }
            if (std.mem.eql(u8, "--peer", this_arg)) {
                parsed.peer = parseAddr(next_arg orelse printUsageAndExit());
            }
        }

        if (parsed.bind == null and parsed.peer == null) {
            printUsageAndExit();
        } else {
            return parsed;
        }
    }

    fn parseAddr(raw: []const u8) net.Address {
        return net.Address.parseIp(raw, 1037) catch {
            stderr("malformed address: {s}\n\n", .{raw});
            printUsageAndExit();
        };
    }

    fn stderr(comptime fmt: []const u8, args: anytype) void {
        std.io.getStdErr().writer().print(fmt, args) catch {};
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const a = gpa.allocator();

    const raw_args = try std.process.argsAlloc(a);
    const args = Args.parse(raw_args);
    std.process.argsFree(a, raw_args);

    var tun = try Tun.open("tun-otou");
    defer tun.close();

    try Worker.run(tun, test_key, args.bind, args.peer);
}

pub const SecureSocket = struct {
    const Self = @This();
    const Blake3 = std.crypto.hash.Blake3;
    const Aegis128L = std.crypto.aead.aegis.Aegis128L;

    const max_msg_size = 1460; // to fit in 1500 MTU
    const header_size = 40; // 24 byte nonce, 16 byte tag
    const max_data_len = max_msg_size - header_size;

    sock: posix.socket_t,
    recv_buf: [max_msg_size]u8 = undefined,
    send_buf: [max_msg_size]u8 = undefined,

    bytes_tx: usize = 0,
    bytes_rx: usize = 0,

    key: [32]u8,
    rng: std.Random.ChaCha,

    pub const AuthError = error{Forged};
    pub const InitError = posix.SocketError || posix.BindError || posix.GetRandomError;
    pub const RecvError = posix.RecvFromError;
    pub const SendError = posix.SendToError;

    pub const RecvData = struct {
        from: net.Address,
        data: AuthError![]u8,
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

        const forged = RecvData{ .from = addr, .data = AuthError.Forged };
        if (header_size > msg_size) return forged;

        const msg_nonce = self.recv_buf[0..24];
        const msg_tag = self.recv_buf[24..40];

        var derived: [64]u8 = undefined;
        Blake3.hash(msg_nonce, &derived, .{ .key = self.key });

        const msg_key = derived[0..16];
        const msg_iv = derived[16..32];
        const msg_ad = derived[32..64];

        const msg_data = self.recv_buf[header_size..msg_size];
        Aegis128L.decrypt(msg_data, msg_data, msg_tag.*, msg_ad, msg_iv.*, msg_key.*) catch return forged;

        _ = @atomicRmw(usize, &self.bytes_rx, .Add, msg_size, .release);
        return RecvData{ .from = addr, .data = msg_data };
    }

    pub fn send(self: *Self, addr: net.Address, data_len: usize) SendError!void {
        assert(data_len <= max_data_len);

        const msg_nonce = self.send_buf[0..24];
        self.rng.fill(msg_nonce);

        var derived: [64]u8 = undefined;
        Blake3.hash(msg_nonce, &derived, .{ .key = self.key });

        const msg_key = derived[0..16];
        const msg_iv = derived[16..32];
        const msg_ad = derived[32..64];

        const msg_tag = self.send_buf[24..40];
        const msg_data = self.send_buf[header_size..][0..data_len];
        Aegis128L.encrypt(msg_data, msg_tag, msg_data, msg_ad, msg_iv.*, msg_key.*);

        const msg_size = header_size + data_len;
        const sent = try posix.sendto(self.sock, self.send_buf[0..msg_size], 0, &addr.any, addr.getOsSockLen());

        _ = @atomicRmw(usize, &self.bytes_tx, .Add, msg_size, .release);
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

    pub fn run(tun: Tun, key: [32]u8, bind_addr: ?net.Address, peer_addr: ?net.Address) !void {
        assert(bind_addr != null or peer_addr != null);

        var ctx = Worker{
            .sock = try SecureSocket.init(key, bind_addr),
            .tun = tun,
            .peer_addr_fixed = peer_addr,
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
        while (true) {
            const recv = try ctx.tun.recv(ctx.sock.getDataSlice());
            const addr = ctx.peer_addr_fixed orelse ctx.peer_addr_dyn orelse {
                log.warn("peer_send: peer address unknown", .{});
                continue;
            };

            ctx.sock.send(addr, recv.len) catch |e| switch (e) {
                posix.SendError.NetworkUnreachable => log.err("peer_send: network unreachable", .{}),
                posix.SendToError.UnreachableAddress => log.err("peer_send: unreachable address ({})", .{addr}),
                else => return e,
            };
        }
    }

    fn peerToHostLoop(ctx: *Worker) !void {
        while (true) {
            const recv = try ctx.sock.recv();
            const data = recv.data catch {
                log.warn("peer_recv: forged packet from {}", .{recv.from});
                continue;
            };
            ctx.peer_addr_dyn = recv.from;
            try ctx.tun.send(data);
        }
    }
};

const tun_mtu = 1420;
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

        switch(posix.errno(linux.ioctl(sock_fd, SIOCGIFMTU, @intFromPtr(&ifr)))) {
            .SUCCESS => {},
            .PERM => return error.AccessDenied,
            else => |err| {
                log.err("failed to get MTU of {s}: {s}", .{ name, @tagName(err) });
                return posix.unexpectedErrno(err);
            },
        }

        if (ifr.ifru.mtu != tun_mtu) {
            log.info("old MTU = {}, setting to {}", .{ifr.ifru.mtu, tun_mtu});
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
