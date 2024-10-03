const std = @import("std");
const ip = @This();

const assert = std.debug.assert;
const Address = std.net.Address;

/// Returns IPv4 address in **native byte order**.
pub fn parse(str: []const u8) error{MalformedIp}!u32 {
    var result: u32 = 0;
    var split = std.mem.splitScalar(u8, str, '.');

    for (0..4) |_| {
        const seg = split.next() orelse return error.MalformedIp;
        const val = std.fmt.parseInt(u8, seg, 10) catch return error.MalformedIp;
        result = result << 8 | val;
    }
    if (split.next() != null) return error.MalformedIp;

    return result;
}

/// Returns IPv4 address in **native byte order**.
pub fn from(addr: Address) error{NotIp4}!u32 {
    if (addr.any.family == std.posix.AF.INET) {
        return std.mem.bigToNative(u32, addr.in.sa.addr);
    } else {
        return error.NotIp4;
    }
}

/// IPv4 address and port in **native byte order**.
pub const WithPort = struct {
    ip: u32,
    port: u16,

    pub fn parse(str: []const u8) error{ MalformedIp, MalformedPort }!WithPort {
        var ip_port_split = std.mem.splitScalar(u8, str, ':');
        const ip_str = ip_port_split.first();
        const port_str = ip_port_split.rest();

        return .{
            .ip = try ip.parse(ip_str),
            .port = std.fmt.parseInt(u16, port_str, 10) catch return error.MalformedPort,
        };
    }

    pub fn parseAddress(str: []const u8) error{ MalformedIp, MalformedPort }!Address {
        return (try WithPort.parse(str)).toAddress();
    }

    pub fn from(addr: Address) error{NotIp4}!WithPort {
        if (addr.any.family == std.posix.AF.INET) {
            return WithPort{
                .ip = std.mem.bigToNative(u32, addr.in.sa.addr),
                .port = std.mem.bigToNative(u16, addr.in.sa.port),
            };
        } else {
            return error.NotIp4;
        }
    }

    pub fn toAddress(self: WithPort) Address {
        return .{ .in = .{ .sa = .{
            .addr = std.mem.nativeToBig(u32, self.ip),
            .port = std.mem.nativeToBig(u16, self.port),
        } } };
    }
};

/// IPv4 address (in **native byte order**) and mask length.
pub const WithMask = struct {
    ip: u32,
    mask: u8,

    pub const ANY = WithMask{ .ip = 0, .mask = 0 };

    pub fn parse(str: []const u8) error{ MalformedIp, MalformedMask }!WithMask {
        var ip_mask_split = std.mem.splitScalar(u8, str, '/');
        const ip_str = ip_mask_split.first();
        const mask_str = ip_mask_split.rest();

        const mask = std.fmt.parseInt(u8, mask_str, 10) catch return error.MalformedMask;
        if (mask > 32) return error.MalformedMask;

        return .{ .ip = try ip.parse(ip_str), .mask = mask };
    }

    /// Checks whether the given IPv4 address (in **native byte order**) is in the same subnet as `self`.
    pub fn sameSubnet(self: WithMask, addr: u32) bool {
        assert(self.mask <= 32);
        if (self.mask == 0) return true;

        const mask = ~(std.math.shl(u32, 1, 32 - self.mask) - 1);
        return (self.ip & mask) == (addr & mask);
    }
};

test "parse fails on malformed input" {
    try std.testing.expectError(error.MalformedIp, parse("0.0.0"));
    try std.testing.expectError(error.MalformedIp, parse("0.0.0.0.0"));
    try std.testing.expectError(error.MalformedIp, parse("0.0.0.0:0"));
    try std.testing.expectError(error.MalformedIp, parse("0.0.0.0/0"));
    try std.testing.expectError(error.MalformedIp, parse("0.0.0.256"));
    try std.testing.expectError(error.MalformedIp, parse("a.b.c.d"));
}

test "parse matches Address.parseIp4" {
    const actual = try parse("1.2.3.45");
    const expect = try Address.parseIp4("1.2.3.45", 0);

    try std.testing.expectEqualDeep(expect.in.sa.addr, std.mem.nativeToBig(u32, actual));
}

test "WithPort.parse matches Address.parseIp4" {
    const actual = try WithPort.parseAddress("123.45.67.89:12345");
    const expect = try Address.parseIp4("123.45.67.89", 12345);

    try std.testing.expectEqualDeep(expect.in, actual.in);
}

test "WithMask.parse correct mask" {
    try std.testing.expectEqual(32, (try WithMask.parse("0.0.0.0/32")).mask);
    try std.testing.expectEqual(0, (try WithMask.parse("0.0.0.0/0")).mask);

    try std.testing.expectError(error.MalformedMask, WithMask.parse("0.0.0.0/33"));
    try std.testing.expectError(error.MalformedMask, WithMask.parse("0.0.0.0/abcd"));
}

test "WithMask.inSubnet" {
    const Test = struct {
        fn sameSubnet(masked: []const u8, addr: []const u8) !void {
            const a = try WithMask.parse(masked);
            const b = try parse(addr);
            try std.testing.expect(a.sameSubnet(b));
        }

        fn diffSubnet(masked: []const u8, addr: []const u8) !void {
            const a = try WithMask.parse(masked);
            const b = try parse(addr);
            try std.testing.expect(!a.sameSubnet(b));
        }
    };

    try Test.sameSubnet("0.1.2.3/0", "0.1.2.3");
    try Test.sameSubnet("0.1.2.3/0", "0.1.2.4");
    try Test.sameSubnet("0.1.2.3/0", "0.1.3.4");
    try Test.sameSubnet("0.1.2.3/0", "0.1.4.4");

    try Test.sameSubnet("0.1.2.3/22", "0.1.2.3");
    try Test.sameSubnet("0.1.2.3/22", "0.1.2.4");
    try Test.sameSubnet("0.1.2.3/22", "0.1.3.4");
    try Test.diffSubnet("0.1.2.3/22", "0.1.4.4");

    try Test.sameSubnet("0.1.2.3/24", "0.1.2.3");
    try Test.sameSubnet("0.1.2.3/24", "0.1.2.4");
    try Test.diffSubnet("0.1.2.3/24", "0.1.3.4");
    try Test.diffSubnet("0.1.2.3/24", "0.1.4.4");

    try Test.sameSubnet("0.1.2.3/32", "0.1.2.3");
    try Test.diffSubnet("0.1.2.3/32", "0.1.2.4");
    try Test.diffSubnet("0.1.2.3/32", "0.1.3.4");
    try Test.diffSubnet("0.1.2.3/32", "0.1.4.4");
}
