const std = @import("std");
const ip = @This();

const assert = std.debug.assert;
const Address = std.net.Address;

pub const ParseError = error{MalformedIp};
pub const FromError = error{NotIp4};

/// Returns IPv4 address in **native byte order**.
pub fn parse(str: []const u8) ParseError!u32 {
    var result: u32 = 0;
    var split = std.mem.splitScalar(u8, str, '.');

    for (0..4) |_| {
        const seg = split.next() orelse return ParseError.MalformedIp;
        const val = std.fmt.parseInt(u8, seg, 10) catch return ParseError.MalformedIp;
        result = result << 8 | val;
    }
    if (split.next() != null) return ParseError.MalformedIp;

    return result;
}

/// Returns IPv4 address in **native byte order**.
pub fn from(addr: Address) FromError!u32 {
    if (addr.any.family == std.posix.AF.INET) {
        return std.mem.bigToNative(u32, addr.in.sa.addr);
    } else {
        return FromError.NotIp4;
    }
}

/// IPv4 address and port in **native byte order**.
pub const WithPort = struct {
    ip: u32,
    port: u16,

    pub const ParseError = ip.ParseError || error{MalformedPort};

    pub fn parse(str: []const u8) WithPort.ParseError!WithPort {
        var ip_port_split = std.mem.splitScalar(u8, str, ':');
        const ip_str = ip_port_split.first();
        const port_str = ip_port_split.rest();

        return .{
            .ip = try ip.parse(ip_str),
            .port = std.fmt.parseInt(u16, port_str, 10) catch return error.MalformedPort,
        };
    }

    pub fn parseAddress(str: []const u8) WithPort.ParseError!Address {
        return (try WithPort.parse(str)).toAddress();
    }

    pub fn from(addr: Address) FromError!WithPort {
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

test "parse fails on malformed input" {
    try std.testing.expectError(ParseError.MalformedIp, parse("0.0.0"));
    try std.testing.expectError(ParseError.MalformedIp, parse("0.0.0.0.0"));
    try std.testing.expectError(ParseError.MalformedIp, parse("0.0.0.0:0"));
    try std.testing.expectError(ParseError.MalformedIp, parse("0.0.0.0/0"));
    try std.testing.expectError(ParseError.MalformedIp, parse("0.0.0.256"));
    try std.testing.expectError(ParseError.MalformedIp, parse("a.b.c.d"));
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
