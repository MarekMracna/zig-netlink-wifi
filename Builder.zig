const std = @import("std");

const Builder = @This();

const Hole = struct {
    pos: usize,
    len: usize,
};

buf: []u8,
pos: usize,

pub fn init(buf: []u8) Builder {
    return .{ .buf = buf, .pos = 0 };
}

pub fn append(builder: *Builder, value: anytype) !void {
    const T = @TypeOf(value);
    switch (@typeInfo(T)) {
        .@"enum", .@"struct", .@"union" => {
            if (@hasDecl(T, "build")) {
                return value.build(builder);
            }
        },
        else => {},
    }
    try builder.appendSlice(std.mem.asBytes(&value)[0..]);
}
pub fn appendSlice(builder: *Builder, slice: []const u8) !void {
    const len = slice.len;
    if (len > builder.remainingCapacity()) {
        return error.OutOfBounds;
    }
    const dst = builder.buf[builder.pos .. builder.pos + len];
    @memcpy(dst, slice);
    builder.pos += len;
}
pub fn hole(builder: *Builder, len: usize) !Hole {
    const newpos = builder.pos + len;
    if (newpos > builder.buf.len) {
        return error.OutOfBounds;
    }
    const oldpos = builder.pos;
    builder.pos = newpos;
    return .{
        .pos = oldpos,
        .len = len,
    };
}
pub fn fill(builder: *Builder, to_fill: Hole, value: anytype) !void {
    const oldpos = builder.pos;
    builder.pos = to_fill.pos;
    try builder.append(value);
    const len = builder.pos - to_fill.pos;
    if (len != to_fill.len) {
        return error.HoleOverflow;
    }
    builder.pos = oldpos;
}
pub fn alignTo(builder: *Builder, alignment: u29) !void {
    const newpos = std.mem.alignForward(usize, builder.pos, alignment);
    if (newpos > builder.buf.len) {
        return error.OutOfBounds;
    }
    @memset(builder.buf[builder.pos..newpos], 0);
    builder.pos = newpos;
}
pub fn remainingCapacity(builder: *const Builder) usize {
    return builder.buf.len - builder.pos;
}
pub fn msg(builder: *const Builder) []const u8 {
    return builder.buf[0..builder.pos];
}
