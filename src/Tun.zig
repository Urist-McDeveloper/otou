const std = @import("std");
const builtin = @import("builtin");
const cmd = @import("cmd.zig");

const Tun = @This();
const mtu = @import("Channel.zig").Envelope.max_data_len;

const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const log = std.log.scoped(.tun);

impl: Impl,

pub fn open(a: Allocator, name: []const u8, addr: []const u8, keep: bool) !Tun {
    return .{ .impl = try Impl.open(a, name, addr, keep) };
}

pub fn close(tun: Tun) void {
    tun.impl.close();
}

pub fn send(tun: Tun, buf: []const u8) !void {
    return tun.impl.send(buf);
}

pub fn recv(tun: Tun, buf: []u8) ![]u8 {
    return tun.impl.recv(buf);
}

const Impl = switch (builtin.os.tag) {
    .linux => LinuxImpl,
    else => unreachable,
};

const LinuxImpl = struct {
    const linux = std.os.linux;
    const posix = std.posix;

    fd: linux.fd_t,

    // cannot include libc headers without linking libc so hard coding it is
    const IoctlReq = struct { code: u32, desc: []const u8 };

    // from <linux/if.h>
    const IFF_UP = 0x0001;
    const IFF_MULTICAST = 0x1000;

    // from <linux/if_tun.h>
    const IFF_TUN = 0x0001;
    const IFF_NO_PI = 0x1000;
    const IFF_PERSIST = 0x0800;
    const TUNGETIFF = IoctlReq{ .code = 2147767506, .desc = "get TUN config" };
    const TUNSETIFF = IoctlReq{ .code = 1074025674, .desc = "open TUN" };
    const TUNSETPERSIST = IoctlReq{ .code = 1074025675, .desc = "make TUN persistent" };

    // from <linux/sockios.h>
    const SIOCGIFFLAGS = IoctlReq{ .code = 0x8913, .desc = "get interface flags" };
    const SIOCSIFFLAGS = IoctlReq{ .code = 0x8914, .desc = "set interface flags" };
    const SIOCGIFMTU = IoctlReq{ .code = 0x8921, .desc = "get interface MTU" };
    const SIOCSIFMTU = IoctlReq{ .code = 0x8922, .desc = "set interface MTU" };

    pub fn open(a: Allocator, name: []const u8, addr: []const u8, keep: bool) !LinuxImpl {
        assert(name.len <= linux.IFNAMESIZE);
        log.info("opening {s}:", .{name});

        const fd = try posix.open("/dev/net/tun", .{ .ACCMODE = .RDWR }, 0);
        errdefer posix.close(fd);

        var name_arr = [1]u8{0} ** linux.IFNAMESIZE;
        @memcpy(name_arr[0..name.len], name);

        var ifr = linux.ifreq{
            .ifrn = .{ .name = name_arr },
            .ifru = .{ .flags = IFF_TUN | IFF_NO_PI },
        };
        try ioctl(fd, TUNSETIFF, @intFromPtr(&ifr));

        if (!std.mem.eql(u8, &name_arr, &ifr.ifrn.name)) {
            log.err("TUN name changed from {s} to {s}", .{ &name_arr, &ifr.ifrn.name });
            return error.NameChanged;
        }

        const sock_fd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
        defer posix.close(sock_fd);

        try ioctl(sock_fd, SIOCGIFMTU, @intFromPtr(&ifr));
        if (ifr.ifru.mtu != mtu) {
            log.info("|> setting MTU to {}", .{mtu});
            ifr.ifru = .{ .mtu = mtu };
            try ioctl(sock_fd, SIOCSIFMTU, @intFromPtr(&ifr));
        }

        // set address *before* UP flag
        try setAddr(a, name, addr);

        try ioctl(sock_fd, SIOCGIFFLAGS, @intFromPtr(&ifr));
        var flags = ifr.ifru.flags;

        if (flags & IFF_UP == 0) {
            log.info("|> settings UP flag", .{});
            flags |= IFF_UP;
        }
        if (flags & IFF_MULTICAST != 0) {
            log.info("|> removing MULTICAST flag", .{});
            flags &= ~@as(i16, IFF_MULTICAST);
        }

        if (flags != ifr.ifru.flags) {
            ifr.ifru = .{ .flags = flags };
            try ioctl(sock_fd, SIOCSIFFLAGS, @intFromPtr(&ifr));
        }

        if (keep) {
            try ioctl(fd, TUNGETIFF, @intFromPtr(&ifr));
            if (ifr.ifru.flags & IFF_PERSIST == 0) {
                log.info("|> making persistent", .{});
                try ioctl(fd, TUNSETPERSIST, 1);
            }
        }

        log.info("|> ready to go!", .{});
        return .{ .fd = fd };
    }

    fn ioctl(fd: linux.fd_t, req: IoctlReq, arg: usize) !void {
        switch (posix.errno(linux.ioctl(fd, req.code, arg))) {
            .SUCCESS => {},
            .PERM => return error.AccessDenied,
            else => |err| {
                log.err("failed to {s}: {s}", .{ req.desc, @tagName(err) });
                return posix.unexpectedErrno(err);
            },
        }
    }

    fn setAddr(a: Allocator, tun: []const u8, addr: []const u8) !void {
        var masked_buf: [18]u8 = undefined;
        const masked = std.fmt.bufPrint(&masked_buf, "{s}/24", .{addr}) catch return error.MalformedAddress;

        const assigned = try cmd.shell(a, "ip addr show '{s}' | grep -o 'inet [^ ]*' | cut -d' ' -f2", .{tun});
        defer a.free(assigned);

        var assigned_iter = std.mem.splitScalar(u8, assigned, '\n');
        while (assigned_iter.next()) |x| {
            if (std.mem.eql(u8, masked, x)) return;
        }

        log.info("|> assigning address {s}", .{masked});
        try cmd.execute(a, &.{ "ip", "addr", "replace", masked, "dev", tun });
    }

    pub fn close(self: LinuxImpl) void {
        posix.close(self.fd);
    }

    pub fn send(self: LinuxImpl, buf: []const u8) posix.WriteError!void {
        const size = try posix.write(self.fd, buf);
        // sanity check, should never fail
        assert(size == buf.len);
    }

    pub fn recv(self: LinuxImpl, buf: []u8) posix.ReadError![]u8 {
        const size = try posix.read(self.fd, buf);
        return buf[0..size];
    }
};
