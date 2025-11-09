const std = @import("std");
const nl = @import("netlink.zig");
const c = @cImport({
    @cInclude("linux/genetlink.h");
});
const Builder = @import("Builder.zig");
const Parser = @import("Parser.zig");
const errno = @import("errno.zig");

pub const Family = struct {
    name: []const u8,
    id: nl.MessageType,

    pub const CTRL: Family = .{
        .name = "Controller",
        .id = .fromInt(c.GENL_ID_CTRL),
    };

    pub fn get(sock: nl.Socket, name: []const u8) !Family {
        var msgbuf: [32 * 1024]u8 = undefined;
        var strbuf: [128]u8 = undefined;
        var builder: Builder = .init(&msgbuf);
        try builder.append(CtrlPacket{
            .family = .CTRL,
            .flags = .{ .request = true, .ack = true },
            .seq = 1,
            .pid = 0,
            .cmd = .getfamily,
            .attrs = &.{.{
                .payload = .{ .family_name = .init(try std.fmt.bufPrint(&strbuf, "{s}\x00", .{name})) },
            }},
        });
        var messages = try sock.req(builder.msg());

        const family: Family = blk: {
            while (try messages.next(&msgbuf)) |response| {
                if (response.hdr.type == Family.CTRL.id) {
                    var attr_p: Parser = .init(response.data);
                    _ = try attr_p.parse(Header);
                    while (attr_p.parse(CtrlAttr)) |attr| {
                        switch (attr.payload) {
                            .family_id => |id| {
                                break :blk .{
                                    .name = name,
                                    .id = @enumFromInt(id),
                                };
                            },
                            else => {},
                        }
                    } else |_| {}
                }
            }
            return error.FailedToGetFamilyId;
        };
        try messages.flush();

        return family;
    }
};

pub fn Packet(CmdT: type, AttrT: type) type {
    return struct {
        const Self = @This();

        const NlPacket = nl.Packet(Header, AttrT);

        family: Family,
        flags: nl.Flags,
        seq: u32,
        pid: u32,
        cmd: CmdT,
        attrs: []const AttrT,

        pub fn build(self: Self, builder: *Builder) !void {
            try builder.append(NlPacket{
                .type = self.family.id,
                .flags = self.flags,
                .seq = self.seq,
                .pid = self.pid,
                .payload = .{ .cmd = @intFromEnum(self.cmd) },
                .attrs = self.attrs,
            });
        }
    };
}

pub const CmdBase = u8;

pub const CtrlCmd = enum(CmdBase) {
    unspec,
    newfamily,
    delfamily,
    getfamily,
    newops,
    delops,
    getops,
    newmcast_grp,
    delmcast_grp,
    getmcast_grp,
    getpolicy,
};

pub const CtrlPacket = Packet(CtrlCmd, CtrlAttr);

pub const CtrlAttr = nl.Attr(union(enum(nl.AttrBase)) {
    unspec: void,
    family_id: u16,
    family_name: nl.AttrString,
    version: u32,
    hdrsize: u32,
    maxattr: u32,
    ops: nl.AttrNestedArray(OpAttr),
    mcast_groups: nl.AttrNestedArray(McastGrpAttr),
    policy: nl.AttrBinary,
    op_policy: nl.AttrBinary,
    op: nl.AttrBinary,
});

pub const OpAttr = nl.Attr(union(enum(nl.AttrBase)) {
    unspec,
    id: u32,
    flags: u32,
});

pub const McastGrpAttr = nl.Attr(union(enum(nl.AttrBase)) {
    unspec,
    name: nl.AttrString,
    id: u32,
});

pub const PolicyAttr = nl.Attr(union(enum(nl.AttrBase)) {
    unspec,
    do: nl.AttrBinary,
    dump: nl.AttrBinary,
});

pub const Header = packed struct {
    cmd: CmdBase,
    version: u8 = 1,
    _reserved: u16 = 0,
};

test "Attr enum has correct values" {
    try std.testing.expectEqual(c.CTRL_ATTR_FAMILY_NAME, @as(u16, @intFromEnum(CtrlAttr.Tag.family_name)));
}
