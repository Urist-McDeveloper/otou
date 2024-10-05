const std = @import("std");

const Allocator = std.mem.Allocator;
const Arena = std.heap.ArenaAllocator;

const Timer = std.time.Timer;
const ns_per_ms = std.time.ns_per_s;

pub const Algorithm = struct {
    pub const in_len = 64;
    pub const out_len = 64;

    name: []const u8,
    func: fn ([in_len]u8, *[out_len]u8) void,

    pub fn bench(alg: Algorithm, a: Allocator, iter: usize) !u64 {
        const ins = try a.alloc([in_len]u8, iter);
        const outs = try a.alloc([out_len]u8, iter);

        for (ins) |*in| {
            try std.posix.getrandom(in);
        }

        var timer = try Timer.start();
        for (ins, outs) |in, *out| {
            alg.func(in, out);
            std.mem.doNotOptimizeAway(out);
        }
        const nanos = timer.read();
        return @divFloor(std.time.ns_per_ms * iter, @as(usize, nanos));
    }
};

pub const hash = struct {
    const Blake3 = std.crypto.hash.Blake3;
    const TurboShake = std.crypto.hash.sha3.TurboShake(128, null);
    const XChaCha20 = std.crypto.stream.chacha.XChaCha20IETF;

    fn blake(in: [64]u8, out: *[64]u8) void {
        Blake3.hash(in[32..56], out, .{ .key = in[0..32].* });
    }

    fn chacha(in: [64]u8, out: *[64]u8) void {
        @memset(out, 0);
        XChaCha20.xor(out, out, 0, in[0..32].*, in[32..56].*);
    }

    fn shake(in: [64]u8, out: *[64]u8) void {
        var instance = TurboShake.init(.{});
        instance.update(in[0..56]);
        instance.squeeze(out);
    }

    pub const algorithms = [_]Algorithm{
        .{ .name = "blake3", .func = blake },
        .{ .name = "xchacha20", .func = chacha },
        .{ .name = "turboshake128", .func = shake },
    };
};

pub const aead = struct {
    const Aegis = std.crypto.aead.aegis.Aegis128L;
    const ChaCha = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
    const XChaCha = std.crypto.aead.chacha_poly.XChaCha20Poly1305;

    fn generic(comptime T: type, comptime key_len: usize, comptime iv_len: usize, in: [64]u8, out: *[64]u8) void {
        const key = in[0..key_len];
        const iv = in[key_len..][0..iv_len];
        const ad = in[key_len + iv_len ..];

        const tag = out[0..16];
        const data = out[16..64];

        T.encrypt(data, tag, data, ad, iv.*, key.*);
        T.decrypt(data, data, tag.*, ad, iv.*, key.*) catch unreachable;
    }

    fn withBlake3(comptime T: type, comptime key_len: usize, comptime iv_len: usize, in: [64]u8, out: *[64]u8) void {
        var buf: [64]u8 = undefined;
        std.crypto.hash.Blake3.hash(in[32..56], &buf, .{ .key = in[0..32].* });

        generic(T, key_len, iv_len, buf, out);
    }

    fn aegis(in: [64]u8, out: *[64]u8) void {
        generic(Aegis, 16, 16, in, out);
    }

    fn chacha(in: [64]u8, out: *[64]u8) void {
        generic(ChaCha, 32, 12, in, out);
    }

    fn xchacha(in: [64]u8, out: *[64]u8) void {
        generic(XChaCha, 32, 24, in, out);
    }

    fn aegisWithBlake(in: [64]u8, out: *[64]u8) void {
        withBlake3(Aegis, 16, 16, in, out);
    }

    fn chachaWithBlake(in: [64]u8, out: *[64]u8) void {
        withBlake3(ChaCha, 32, 12, in, out);
    }

    fn xchachaWithBlake(in: [64]u8, out: *[64]u8) void {
        withBlake3(XChaCha, 32, 24, in, out);
    }

    pub const algorithms = [_]Algorithm{
        .{ .name = "aegis128L", .func = aegis },
        .{ .name = "chacha20poly1305", .func = chacha },
        .{ .name = "xchacha20poly1305", .func = xchacha },
        .{ .name = "blake3+aegis128L", .func = aegisWithBlake },
        .{ .name = "blake3+chacha20poly1305", .func = chachaWithBlake },
        .{ .name = "blake3+xchacha20poly1305", .func = xchachaWithBlake },
    };
};

fn bench(arena: *Arena, iter: usize, family: []const u8, comptime T: type) !void {
    std.debug.print("{s}:\n", .{family});

    const a = arena.allocator();
    defer _ = arena.reset(.retain_capacity);

    inline for (T.algorithms) |alg| {
        std.debug.print("{s:>30} = {:>6} op/ms\n", .{ alg.name, try alg.bench(a, iter) });
    }
}

pub fn main() !void {
    var arena = Arena.init(std.heap.page_allocator);
    defer arena.deinit();

    var args = std.process.args();
    _ = args.next().?;
    const iter = if (args.next()) |it| try std.fmt.parseInt(usize, it, 10) else 1000;
    args.deinit();

    std.debug.print("Running benchmark with {} iterations.\n", .{iter});
    try bench(&arena, iter, "Hashes", hash);
    try bench(&arena, iter, "AEAD", aead);
}
