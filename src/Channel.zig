const std = @import("std");

const assert = std.debug.assert;
const net = std.net;
const posix = std.posix;

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

test "sent packets are received" {
    const key: [32]u8 = undefined;
    var ch = try init(key, try net.Address.parseIp4("127.0.0.1", 0));

    var s_addr: posix.sockaddr align(4) = undefined;
    var s_len: posix.socklen_t = @sizeOf(posix.sockaddr);
    try posix.getsockname(ch.sock, &s_addr, &s_len);
    const ch_addr = net.Address.initPosix(&s_addr);

    var sent: [32]u8 = undefined;
    try posix.getrandom(&sent);

    @memcpy(ch.getDataSlice()[0..32], &sent);
    try ch.send(ch_addr, 32);

    const recieved = try ch.recv();
    try std.testing.expectEqualSlices(u8, &sent, recieved.data);
}
