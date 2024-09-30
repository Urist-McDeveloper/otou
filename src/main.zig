const std = @import("std");
const builtin = @import("builtin");

const ip = @import("ip.zig");

const net = std.net;
const posix = std.posix;

const assert = std.debug.assert;
const log = std.log;

fn printUsageAndExit() noreturn {
    const writer = std.io.getStdErr().writer();
    writer.print("usage: otou [server <bind_ip>|client <server_ip>]\n", .{}) catch {};
    std.process.exit(1);
}

pub fn main() !void {
    var args = std.process.args();
    defer args.deinit();

    _ = args.next().?;
    const mode = args.next() orelse printUsageAndExit();
    const ipv4 = args.next() orelse printUsageAndExit();
    const addr = net.Address.parseIp4(ipv4, 1037) catch printUsageAndExit();

    if (std.mem.eql(u8, "server", mode)) {
        var tun = try Tun.open("tun-otou");
        defer tun.close();

        try runServer(&tun, addr);
    } else if (std.mem.eql(u8, "client", mode)) {
        var tun = try Tun.open("tun-otou");
        defer tun.close();

        try runClient(&tun, addr);
    } else {
        printUsageAndExit();
    }
}

fn runClient(tun: *Tun, addr: net.Address) !void {
    var sock = try UdpSocket.open();
    defer sock.close();

    const Ctx = struct {
        tun: *Tun,
        sock: *UdpSocket,
        addr: net.Address,

        fn host_to_peer(ctx: *@This()) !void {
            while (true) {
                const recv = try ctx.tun.recv();
                const packet = ip.PacketInfo.parse(recv) catch |e| {
                    log.debug("dropping host packet: {s}", .{@errorName(e)});
                    continue;
                };

                try ctx.sock.send(.{ .addr = ctx.addr, .data = recv });
                log.debug("sent {} bytes to peer | {}", .{ recv.len, packet });
            }
        }

        fn peer_to_host(ctx: *@This()) !void {
            while (true) {
                const recv = try ctx.sock.recv();
                const packet = ip.PacketInfo.parse(recv.data) catch |e| {
                    log.debug("dropping peer packet: {s}", .{ @errorName(e) });
                    continue;
                };

                try ctx.tun.send(recv.data);
                log.debug("sent {} bytes to host | {}", .{ recv.data.len, packet });
            }
        }
    };

    var ctx = Ctx{ .tun = tun, .sock = &sock, .addr = addr };
    const htp_thread = try std.Thread.spawn(.{}, Ctx.host_to_peer, .{&ctx});
    const pth_thread = try std.Thread.spawn(.{}, Ctx.peer_to_host, .{&ctx});

    htp_thread.join();
    pth_thread.join();
}

fn runServer(tun: *Tun, addr: net.Address) !void {
    var sock = try UdpSocket.open();
    defer sock.close();
    try sock.bind(addr);

    const Ctx = struct {
        tun: *Tun,
        sock: *UdpSocket,
        peer_mutex: std.Thread.Mutex = .{},
        peer_addr: ?net.Address = null,

        fn peer_to_inet(ctx: *@This()) !void {
            while (true) {
                const recv = try ctx.sock.recv();
                const packet = ip.PacketInfo.parse(recv.data) catch |e| {
                    log.debug("dropping peer packet: {s}", .{ @errorName(e) });
                    continue;
                };

                ctx.peer_mutex.lock();
                ctx.peer_addr = recv.addr;
                ctx.peer_mutex.unlock();

                try ctx.tun.send(recv.data);
                log.debug("sent {} bytes to inet | {}", .{ recv.data.len, packet });
            }
        }

        fn inet_to_peer(ctx: *@This()) !void {
            while (true) {
                const recv = try ctx.tun.recv();
                const packet = ip.PacketInfo.parse(recv) catch |e| {
                    log.debug("dropping inet packet: {s}", .{ @errorName(e) });
                    continue;
                };

                ctx.peer_mutex.lock();
                const peer_addr = ctx.peer_addr;
                ctx.peer_mutex.unlock();

                if (peer_addr) |a| {
                    try ctx.sock.send(.{ .addr = a, .data = recv });
                    log.debug("sent {} bytes to peer | {}", .{ recv.len, packet });
                } else {
                    log.debug("dropping inet packet because peer has no address | {}", .{packet});
                }
            }
        }
    };

    var ctx = Ctx{ .tun = tun, .sock = &sock };
    const pti_thread = try std.Thread.spawn(.{}, Ctx.peer_to_inet, .{&ctx});
    const itp_thread = try std.Thread.spawn(.{}, Ctx.inet_to_peer, .{&ctx});

    pti_thread.join();
    itp_thread.join();
}

pub const Datagram = struct {
    addr: net.Address,
    data: []u8,
};

pub const UdpSocket = struct {
    const Self = @This();

    inner: posix.socket_t,
    recv_buf: [1 << 16]u8 = undefined,

    pub fn open() posix.SocketError!Self {
        return Self{ .inner = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0) };
    }

    pub fn close(sock: *Self) void {
        net.Stream.close(.{ .handle = sock.inner });
        sock.* = undefined;
    }

    pub fn bind(sock: *Self, addr: net.Address) posix.BindError!void {
        try posix.bind(sock.inner, &addr.any, addr.getOsSockLen());
    }

    pub fn recv(sock: *Self) posix.RecvFromError!Datagram {
        var from_raw: posix.sockaddr align(4) = undefined;
        var from_len: posix.socklen_t = @intCast(@sizeOf(posix.sockaddr));

        const size = try posix.recvfrom(sock.inner, &sock.recv_buf, 0, &from_raw, &from_len);
        const addr = net.Address.initPosix(&from_raw);

        return Datagram{ .addr = addr, .data = sock.recv_buf[0..size] };
    }

    pub fn send(sock: *const Self, dgram: Datagram) posix.SendToError!void {
        const size = try posix.sendto(sock.inner, dgram.data, 0, &dgram.addr.any, dgram.addr.getOsSockLen());
        assert(size == dgram.data.len);
    }
};

const Tun = switch (builtin.os.tag) {
    .linux => LinuxTun,
    else => unreachable,
};

const LinuxTun = struct {
    const linux = std.os.linux;
    const Self = @This();

    fd: linux.fd_t,
    recv_buf: [1 << 16]u8 = undefined,

    // cannot @cInclude("linux/if_tun.h") without linking libc so hard coding it is
    const IFF_TUN = 0x0001;
    const IFF_NO_PI = 0x1000;
    const TUNSETIFF = 1074025674;

    pub fn open(name: []const u8) !Self {
        assert(name.len < linux.IFNAMESIZE);
        log.debug("opening {s}", .{name});

        const fd = try posix.open("/dev/net/tun", .{ .ACCMODE = .RDWR }, 0);
        errdefer posix.close(fd);

        var name_arr = [1]u8{0} ** linux.IFNAMESIZE;
        @memcpy(name_arr[0..name.len], name);

        const ifr = linux.ifreq{
            .ifrn = .{ .name = name_arr },
            .ifru = .{ .flags = IFF_TUN | IFF_NO_PI },
        };

        const rc = linux.ioctl(fd, TUNSETIFF, @intFromPtr(&ifr));
        return switch (posix.errno(rc)) {
            .SUCCESS => Self{ .fd = fd },
            .PERM => error.AccessDenied,
            else => |err| blk: {
                log.err("failed to open {s}: {}", .{ name, err });
                break :blk posix.unexpectedErrno(err);
            },
        };
    }

    pub fn close(self: *Self) void {
        posix.close(self.fd);
        self.* = undefined;
    }

    pub fn recv(self: *Self) posix.ReadError![]u8 {
        const size = try posix.read(self.fd, &self.recv_buf);
        return self.recv_buf[0..size];
    }

    pub fn send(self: *const Self, buf: []u8) posix.WriteError!void {
        const size = try posix.write(self.fd, buf);
        assert(size == buf.len);
    }
};
