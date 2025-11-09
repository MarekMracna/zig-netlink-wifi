const std = @import("std");
const builtin = std.builtin;
const linux = std.os.linux;

pub const Error = blk: {
    const enum_ti = @typeInfo(linux.E).@"enum";
    var set: [enum_ti.fields.len]builtin.Type.Error = undefined;
    for (enum_ti.fields, &set) |field, *err| {
        err.* = .{ .name = field.name };
    }
    //const errset: ?[]builtin.Type.Error = &set;
    break :blk @Type(.{ .error_set = &set });
};

pub fn fromInt(rc: anytype) Error {
    const signed: isize = rc;
    const int = if (signed > -4096 and signed < 0) -signed else 0;
    const e: linux.E = @enumFromInt(int);
    const ei = @typeInfo(linux.E).@"enum";
    inline for (ei.fields) |field| {
        if (e == @field(linux.E, field.name))
            return @field(Error, field.name);
    }
    unreachable;
}

test "Errno" {
    const Closure = struct {
        pub fn throw() !void {
            return @field(Error, "PERM");
        }
    };
    try std.testing.expectError(Error.PERM, Closure.throw());
}
