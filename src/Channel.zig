const std = @import("std");
const ip = @import("ip.zig");

const assert = std.debug.assert;
const net = std.net;
const posix = std.posix;

const Self = @This();
const Rng = std.Random.ChaCha;
const Aegis128L = std.crypto.aead.aegis.Aegis128L;

pub const AuthError = error{ Garbage, Forged };
pub const InitError = posix.SocketError || posix.BindError || posix.GetRandomError;
pub const RecvError = AuthError || ip.VersionError || posix.RecvFromError;
pub const SendError = posix.SendToError;

pub const Envelope = extern struct {
    const assumed_mtu = 1500;
    const ip4_overhead = 20; // could be more but options field is very rarely used
    const udp_overhead = 8;
    pub const max_size = assumed_mtu - ip4_overhead - udp_overhead;

    const unencrypted_size = 16 + 20; // tag + nonce
    const header_size = unencrypted_size + 4; // tag + nonce + metadata

    const min_padding = 1;
    const max_padding = 8;

    pub const max_data_len = max_size - header_size - max_padding;

    tag: [16]u8,
    nonce: [20]u8,
    metadata: [4]u8,
    payload_buf: [max_data_len + max_padding]u8,
    // not counted in max_size because this field is never on the wire
    payload_len: u32,

    pub fn getMaxDataSlice(self: *Envelope) []u8 {
        return self.payload_buf[0..max_data_len];
    }

    pub fn getPayload(self: *Envelope) []u8 {
        assert(self.payload_len <= max_data_len);
        return self.payload_buf[0..self.payload_len];
    }

    pub fn getConstPayload(self: *const Envelope) []const u8 {
        assert(self.payload_len <= max_data_len);
        return self.payload_buf[0..self.payload_len];
    }

    pub fn setPayload(self: *Envelope, data: []const u8) void {
        assert(data.len <= max_data_len);

        self.payload_len = @intCast(data.len);
        const payload = self.payload_buf[0..data.len];

        if (payload.ptr != data.ptr) {
            @memcpy(payload, data);
        }
    }

    fn encrypt(self: *Envelope, key: [32]u8, rng: *Rng) []const u8 {
        assert(self.payload_len <= max_data_len);

        // nonce and metadata
        rng.fill(&self.nonce);
        rng.fill(&self.metadata);
        // padding at the end of the payload
        rng.fill(self.payload_buf[self.payload_len..][0..max_padding]);

        const metadata = std.mem.readInt(u32, &self.metadata, .little);
        const padding = 1 + metadata & 7;

        const data = self.encryptedSlice(self.payload_len + padding);
        const key16 = key[0..16].*;
        const iv16 = key[16..32].*;
        Aegis128L.encrypt(data, &self.tag, data, &self.nonce, iv16, key16);

        return std.mem.asBytes(self)[0 .. unencrypted_size + data.len];
    }

    /// `size` is the total number of received bytes.
    fn decrypt(self: *Envelope, key: [32]u8, size: usize) AuthError!void {
        assert(size <= max_size);
        if (size < header_size + min_padding) return AuthError.Garbage;

        const data = self.encryptedSlice(size - header_size);
        const key16 = key[0..16].*;
        const iv16 = key[16..32].*;
        Aegis128L.decrypt(data, data, self.tag, &self.nonce, iv16, key16) catch return AuthError.Forged;

        const metadata = std.mem.readInt(u32, &self.metadata, .little);
        const padding = 1 + metadata & 7;

        if (size < header_size + padding) {
            return error.Forged;
        } else {
            self.payload_len = @intCast(size - header_size - padding);
        }
    }

    fn encryptedSlice(self: *Envelope, padded_data_len: usize) []u8 {
        return std.mem.asBytes(self)[unencrypted_size .. header_size + padded_data_len];
    }
};

sock: posix.socket_t,
key: [32]u8,
rng: Rng,

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

pub fn recv(self: *Self, envelope: *Envelope) RecvError!net.Address {
    var from_raw: posix.sockaddr align(4) = undefined;
    var from_len: posix.socklen_t = @intCast(@sizeOf(posix.sockaddr));

    const size = try posix.recvfrom(self.sock, std.mem.asBytes(envelope), 0, &from_raw, &from_len);
    if (from_raw.family != posix.AF.INET) return ip.VersionError.NotIp4;

    try envelope.decrypt(self.key, size);
    return net.Address.initPosix(&from_raw);
}

pub fn send(self: *Self, addr: net.Address, envelope: *Envelope) SendError!void {
    const data = envelope.encrypt(self.key, &self.rng);
    const sent = try posix.sendto(self.sock, data, 0, &addr.any, addr.getOsSockLen());

    // sanity check, should never fail
    assert(sent == data.len);
}

test "sent packets are received" {
    var key: [32]u8 = undefined;
    try posix.getrandom(&key);

    var ch = try init(key, try net.Address.parseIp4("127.0.0.1", 0));
    var e: Envelope = undefined;

    var s_addr: posix.sockaddr align(4) = undefined;
    var s_len: posix.socklen_t = @sizeOf(posix.sockaddr);
    try posix.getsockname(ch.sock, &s_addr, &s_len);
    const ch_addr = net.Address.initPosix(&s_addr);

    var sent: [32]u8 = undefined;
    try posix.getrandom(&sent);

    e.setPayload(&sent);
    try ch.send(ch_addr, &e);

    _ = try ch.recv(&e);
    try std.testing.expectEqualSlices(u8, &sent, e.getPayload());
}
