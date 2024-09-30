const std = @import("std");

pub const Proto = enum(u8) {
    icmp = 0x01,
    tcp = 0x06,
    udp = 0x11,
    unknown = 0xff,

    pub fn parse(code: u8) Proto {
        inline for (@typeInfo(Proto).Enum.fields) |f| {
            if (code == f.value) return @enumFromInt(f.value);
        }
        return Proto.unknown;
    }
};

pub const ParseIpPacketError = error{ UnsupportedVersion, TooShort, Malformed };

pub const PacketInfo = union(enum) {
    v4: v4.Packet,
    v6: void, // TODO: add IPv6 support

    pub fn parse(packet: []u8) ParseIpPacketError!PacketInfo {
        const version = packet[0] >> 4;
        return switch (version) {
            4 => .{ .v4 = try v4.parse(packet) },
            else => ParseIpPacketError.UnsupportedVersion,
        };
    }

    pub fn protocol(p: PacketInfo) Proto {
        return switch (p) {
            .v4 => |p4| p4.protocol(),
            .v6 => Proto.unknown,
        };
    }

    pub fn format(p: PacketInfo, comptime fmt: []const u8, options: std.fmt.FormatOptions, out: anytype) !void {
        return switch (p) {
            .v4 => |p4| p4.format(fmt, options, out),
            .v6 => {},
        };
    }
};

pub const v4 = struct {
    pub const RawHeader = packed struct {
        ihl: u4,
        version: u4,
        enc: u2,
        dscp: u6,
        total_len: u16,
        identity: u16,
        fragment_offset_p1: u5,
        flags: u3,
        fragment_offset_p2: u8,
        ttl: u8,
        protocol: u8,
        checksum: u16,
        src: u32,
        dst: u32,
    };

    pub const Packet = struct {
        header: RawHeader,
        options: []u8,
        data: []u8,

        pub fn protocol(p: Packet) Proto {
            return Proto.parse(p.header.protocol);
        }

        pub fn src(p: Packet) [4]u8 {
            return std.mem.toBytes(p.header.src);
        }

        pub fn dst(p: Packet) [4]u8 {
            return std.mem.toBytes(p.header.dst);
        }

        pub fn format(p: Packet, comptime _: []const u8, _: std.fmt.FormatOptions, out: anytype) !void {
            try std.fmt.format(out, "IPv4 {s} ", .{@tagName(p.protocol())});
            try formatAddress(out, p.src());
            try std.fmt.format(out, " -> ", .{});
            try formatAddress(out, p.dst());
            try std.fmt.format(out, " ({} bytes of payload)", .{p.data.len});
        }

        fn formatAddress(out: anytype, a: [4]u8) !void {
            try std.fmt.format(out, "{}.{}.{}.{}", .{ a[0], a[1], a[2], a[3] });
        }
    };

    pub fn parse(packet: []u8) ParseIpPacketError!Packet {
        if (packet.len < 20) return error.TooShort;

        const header = std.mem.bytesToValue(RawHeader, packet[0..20]);
        if (header.version != 4) return error.UnsupportedVersion;

        const total_len = std.mem.bigToNative(u16, header.total_len);
        const ihl = @as(u16, header.ihl) * 4;

        if (total_len != packet.len) return ParseIpPacketError.Malformed;
        if (ihl > total_len) return ParseIpPacketError.Malformed;
        if (ihl < 20) return ParseIpPacketError.Malformed;

        return Packet{
            .header = header,
            .options = packet[20..ihl],
            .data = packet[ihl..],
        };
    }
};
