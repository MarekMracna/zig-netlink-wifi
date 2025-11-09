const std = @import("std");

pub fn enumFromInt(E: type, int: anytype) ?E {
    inline for (@typeInfo(E).@"enum".fields) |field| {
        if (field.value == int) {
            return @enumFromInt(int);
        }
    }
    return null;
}

pub fn FlagsMixin(PS: type) type {
    const S = @typeInfo(PS).@"struct";
    return struct {
        pub fn format(self: PS, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
            try writer.print("{s}{{", .{@typeName(PS)});
            var sep: []const u8 = "";
            inline for (S.fields) |field| {
                if (field.type == bool) {
                    if (@field(self, field.name)) {
                        try writer.print("{s} .{s}", .{ sep, field.name });
                        sep = ",";
                    }
                }
            }
            if (sep.len == 1)
                try writer.writeAll(" ");
            try writer.writeAll("}");
        }

        pub fn fromParts(fs: []const PS) PS {
            var int: S.backing_integer.? = 0;
            for (fs) |f| {
                int |= @bitCast(f);
            }
            return @bitCast(int);
        }
    };
}
