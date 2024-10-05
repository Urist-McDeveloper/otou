const std = @import("std");
const ip = @This();

const assert = std.debug.assert;
const Address = std.net.Address;

pub const ParseError = error{MalformedIp};
pub const VersionError = error{NotIp4};

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
pub fn from(addr: Address) VersionError!u32 {
    if (addr.any.family == std.posix.AF.INET) {
        return std.mem.bigToNative(u32, addr.in.sa.addr);
    } else {
        return VersionError.NotIp4;
    }
}

pub const PacketInfo = struct {
    /// Source address in **native byte order**.
    src: u32,
    /// Destination address in **native byte order**.
    dst: u32,
    /// Payload
    payload: []const u8,

    pub const ParseError = VersionError || error{MalformedPacket};

    pub fn parse(packet: []const u8) PacketInfo.ParseError!PacketInfo {
        if (packet.len < 20) return error.MalformedPacket;
        if (packet[0] & 0xf0 == 0x60) return error.NotIp4;
        if (packet[0] & 0xf0 != 0x40) return error.MalformedPacket;

        const header_len = 4 * (packet[0] & 0x0f);
        if (header_len < 20 or header_len > packet.len) return error.MalformedPacket;

        const total_len = std.mem.readInt(u16, packet[2..4], .big);
        if (total_len != packet.len) return error.MalformedPacket;

        return PacketInfo{
            .src = std.mem.readInt(u32, packet[12..16], .big),
            .dst = std.mem.readInt(u32, packet[16..20], .big),
            .payload = packet[header_len..],
        };
    }

    pub fn format(self: PacketInfo, comptime _: []const u8, _: std.fmt.FormatOptions, out: anytype) !void {
        try std.fmt.format(out, "{}.{}.{}.{} -> {}.{}.{}.{} ({} bytes)", .{
            0xff & (self.src >> 24),
            0xff & (self.src >> 16),
            0xff & (self.src >> 8),
            0xff & (self.src),
            0xff & (self.dst >> 24),
            0xff & (self.dst >> 16),
            0xff & (self.dst >> 8),
            0xff & (self.dst),
            self.payload.len,
        });
    }
};

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

    pub fn from(addr: Address) VersionError!WithPort {
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
