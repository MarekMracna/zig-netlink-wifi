const std = @import("std");
const util = @import("util.zig");
const Builder = @import("Builder.zig");
const Parser = @import("Parser.zig");

pub const Mac = extern struct {
    bytes: [6]u8,

    pub fn format(mac: Mac, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        const b = std.mem.asBytes(&mac);
        try writer.print(
            "{x}:{x}:{x}:{x}:{x}:{x}",
            .{ b[0], b[1], b[2], b[3], b[4], b[5] },
        );
    }
};

test "mac is correct size" {
    try std.testing.expectEqual(6, @sizeOf(Mac));
}

pub const Flags = packed struct(u32) {
    pub usingnamespace util.FlagsMixin(@This());

    up: bool = false, // interface is up. Can be toggled through sysfs.
    broadcast: bool = false, // broadcast address valid. Volatile.
    debug: bool = false, // turn on debugging. Can be toggled through sysfs.
    loopback: bool = false, // is a loopback net. Volatile.
    pointopoint: bool = false, // interface is has p-p link. Volatile.
    notrailers: bool = false, // avoid use of trailers. Can be toggled through sysfs.
    running: bool = false, // interface RFC2863 OPER_UP. Volatile.
    noarp: bool = false, // no ARP protocol. Can be toggled through sysfs. Volatile.
    promisc: bool = false, // receive all packets. Can be toggled through sysfs.
    allmulti: bool = false, // receive all multicast packets. Can be toggled through
    master: bool = false, // master of a load balancer. Volatile.
    slave: bool = false, // slave of a load balancer. Volatile.
    multicast: bool = false, // Supports multicast. Can be toggled through sysfs.
    portsel: bool = false, // can set media type. Can be toggled through sysfs.
    automedia: bool = false, // auto media select active. Can be toggled through sysfs.
    dynamic: bool = false, // dialup device with changing addresses. Can be toggled
    lower_up: bool = false, // driver signals L1 up. Volatile.
    dormant: bool = false, // driver signals dormant. Volatile.
    echo: bool = false, // echo sent packets. Volatile.
    _pad: u13 = 0,
};

test "mixin works" {
    try std.testing.expect(@hasDecl(Flags, "format"));
    const f: Flags = .{};
    var buf: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    const writer = stream.writer();
    try f.format("", .{}, writer);
    try std.testing.expectEqualStrings("if.Flags{}", stream.getWritten());
    try std.testing.expectFmt("if.Flags{}", "{}", .{Flags{}});
}
