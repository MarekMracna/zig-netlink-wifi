const std = @import("std");
const Parser = @import("Parser.zig");
const Builder = @import("Builder.zig");

pub const BaseUnit = enum {
    meter,
    second,
    bel,
    watt,
    bel_milliwatt,
    byte,
    byte_per_second,
    bit_per_second,
    hertz,

    pub fn symbol(self: BaseUnit) []const u8 {
        return switch (self) {
            .meter => "m",
            .second => "s",
            .bel => "B",
            .watt => "W",
            .bel_milliwatt => "Bm",
            .byte => "B",
            .byte_per_second => "bps",
            .bit_per_second => "bit/s",
            .hertz => "Hz",
        };
    }
};

pub const Prefix = enum(i8) {
    pico = -12,
    nano = -9,
    micro = -6,
    milli = -3,
    centi = -2,
    deci = -1,
    none = 0,
    deca = 1,
    hecto = 2,
    kilo = 3,
    mega = 6,
    giga = 9,
    tera = 12,

    pub fn symbol(self: Prefix) []const u8 {
        return switch (self) {
            .pico => "p",
            .nano => "n",
            .micro => "µ",
            .milli => "m",
            .centi => "c",
            .deci => "d",
            .none => "",
            .deca => "da",
            .hecto => "h",
            .kilo => "k",
            .mega => "M",
            .giga => "G",
            .tera => "T",
        };
    }

    pub fn exponent(self: Prefix) i8 {
        return @intFromEnum(self);
    }
};

pub fn UnitScaled(comptime T: type, comptime prefix: Prefix, comptime base: BaseUnit, comptime scale: anytype) type {
    return struct {
        value: T,

        const Self = @This();
        pub fn parse(parser: *Parser) !Self {
            return .{ .value = try parser.parse(T) };
        }

        pub fn build(self: Self, builder: *Builder) !void {
            try builder.append(self.value);
        }

        pub fn format(self: Self, _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
            const Value = switch (@typeInfo(T)) {
                .int => i128,
                .float => f64,
                else => unreachable,
            };
            const value: Value = switch (@typeInfo(T)) {
                .int => self.value,
                .float => @floatCast(self.value),
                else => unreachable,
            };
            try writer.print(
                "{} {s}{s}",
                .{ scale * value, prefix.symbol(), base.symbol() },
            );
        }
    };
}

pub fn Unit(comptime T: type, comptime prefix: Prefix, comptime base: BaseUnit) type {
    return UnitScaled(T, prefix, base, 1);
}
