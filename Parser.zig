const std = @import("std");

const Parser = @This();

buf: []const u8,
pos: usize,
pub fn init(buf: []const u8) Parser {
    return .{ .buf = buf, .pos = 0 };
}
pub fn parse(parser: *Parser, comptime T: type) !T {
    switch (@typeInfo(T)) {
        .@"enum", .@"struct", .@"union" => {
            if (@hasDecl(T, "parse")) {
                return T.parse(parser);
            }
        },
        else => {},
    }
    const len = @sizeOf(T);
    const slice = try parser.parseSlice(len);
    return std.mem.bytesAsValue(T, slice[0..len]).*;
}
pub fn parseSlice(parser: *Parser, len: usize) ![]const u8 {
    if (parser.pos + len > parser.buf.len) {
        return error.OutOfBounds;
    }
    const slice = parser.buf[parser.pos..][0..len];
    parser.pos += len;
    return slice;
}
pub fn parseSliceSentinel(parser: *Parser, comptime sentinel: u8) ![:sentinel]const u8 {
    const oldpos = parser.pos;
    while (parser.pos < parser.buf.len) : (parser.pos += 1) {
        if (parser.buf[parser.pos] == sentinel) {
            return parser.buf[oldpos..parser.pos :sentinel];
        }
    }
    return error.OutOfBounds;
}
pub fn alignTo(parser: *Parser, alignment: u29) !void {
    const newpos = std.mem.alignForward(usize, parser.pos, alignment);
    if (newpos > parser.buf.len) {
        return error.OutOfBounds;
    }
    parser.pos = newpos;
}
