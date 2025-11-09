const std = @import("std");
const lx = std.os.linux;
const c = @cImport({
    @cInclude("linux/netlink.h");
});
const Builder = @import("Builder.zig");
const Parser = @import("Parser.zig");
const errno = @import("errno.zig");
const util = @import("util.zig");

pub const Socket = struct {
    fd: i32,

    pub const Protocol = enum(u32) {
        route = 0, // routing/device hook
        unused = 1, // unused number
        usersock = 2, // reserved for user mode socket protocols
        firewall = 3, // unused number, formerly ip_queue
        sock_diag = 4, // socket monitoring
        nflog = 5, // netfilter/iptables ulog
        xfrm = 6, // ipsec
        selinux = 7, // selinux event notifications
        iscsi = 8, // open-iscsi
        audit = 9, // auditing
        fib_lookup = 10,
        connector = 11,
        netfilter = 12, // netfilter subsystem
        ip6_fw = 13,
        dnrtmsg = 14, // decnet routing messages (obsolete)
        kobject_uevent = 15, // kernel messages to userspace
        generic = 16,
        // leave room for dm (dm events)
        scsitransport = 18, // scsi transports
        ecryptfs = 19,
        rdma = 20,
        crypto = 21, // crypto layer
        smc = 22, // smc monitoring

        const inet_diag: Protocol = .sock_diag;
    };

    pub fn open(protocol: Protocol) !Socket {
        const sock_fd: i32 = @intCast(lx.socket(lx.AF.NETLINK, lx.SOCK.RAW, @intFromEnum(protocol)));
        if (sock_fd == -1) {
            return error.FailedToOpenSocket;
        }

        const sockaddr: *const lx.sockaddr = @ptrCast(&lx.sockaddr.nl{
            .pid = 0,
            .groups = 0,
        });

        if (-1 == @as(isize, @bitCast(
            lx.bind(sock_fd, sockaddr, @sizeOf(@TypeOf(sockaddr))),
        ))) {
            return error.FailedToBindSocket;
        }

        const one: c_int = 1;
        if (-1 == @as(isize, @bitCast(lx.setsockopt(sock_fd, lx.SOL.NETLINK, c.NETLINK_EXT_ACK, std.mem.asBytes(&one).ptr, @sizeOf(c_int))))) {
            return error.FailedToSetExtAck;
        }

        return .{ .fd = sock_fd };
    }

    pub fn req(sock: Socket, message: []const u8) !Messages {
        if (-1 == @as(isize, @bitCast(
            lx.sendto(sock.fd, message.ptr, message.len, 0, null, 0),
        ))) {
            return error.FailedToSendHeader;
        }
        return .init(sock);
    }
};

pub const Message = struct {
    hdr: Header,
    data: []const u8,
};

const Messages = struct {
    sock: Socket,
    state: State,

    const State = union(enum) {
        nodata,
        parsing: []const u8,
        done,
    };

    pub fn init(sock: Socket) Messages {
        return .{ .sock = sock, .state = .{ .nodata = {} } };
    }

    pub fn next(messages: *Messages, buf: []u8) !?Message {
        while (true) {
            switch (messages.state) {
                .done => return null,
                .nodata => {
                    const msglen = lx.recvfrom(messages.sock.fd, buf.ptr, buf.len, 0, null, null);
                    if (@as(isize, @bitCast(msglen)) == -1) {
                        return error.FailedToRecieve;
                    }
                    messages.state = .{ .parsing = buf[0..msglen] };
                },
                .parsing => |resp| if (try messages.parse(resp)) |msg| {
                    return msg;
                },
            }
        }
    }

    fn parse(messages: *Messages, resp: []const u8) !?Message {
        // state = parsing
        if (resp.len == 0) {
            messages.state = .{ .nodata = {} };
            return null;
        }
        var parser: Parser = .init(resp);
        const rechdr = try parser.parse(Header);
        if (rechdr.len > resp.len) {
            return error.CorruptedHeaderLen;
        }

        switch (rechdr.type) {
            .@"error" => {
                try parser.alignTo(4);
                const err = try parser.parse(ErrorHeader);
                const neg_errno = err.neg_errno;
                if (neg_errno != 0) {
                    return errno.fromInt(neg_errno);
                }
                // ACK
                if (rechdr.flags.mods.ack.ext_tlvs) {
                    std.log.debug("EXTACK", .{});
                    _ = parser.parseSlice(err.hdr.len - @sizeOf(Header)) catch |e| {
                        std.log.debug("{}", .{err.hdr.len - @sizeOf(Header)});
                        std.log.debug("{}", .{std.fmt.fmtSliceHexLower(parser.buf[parser.pos..])});
                        return e;
                    };
                    try parser.alignTo(4);
                    std.log.debug("{}", .{std.fmt.fmtSliceHexLower(parser.buf[parser.pos..])});
                    while (parser.parse(ErrorAttr)) |attr| {
                        std.log.warn("EXT_ACK: {}", .{attr});
                    } else |_| {}
                }
                // ACK
                messages.state = .{ .done = {} };
            },
            .done => {
                try parser.alignTo(4);
                while (parser.parse(ErrorAttr)) |attr| {
                    std.log.info("EXT_ACK: {}", .{attr});
                } else |_| {}
                messages.state = .{ .done = {} };
            },
            else => {
                const next_msg = std.mem.alignForward(usize, rechdr.len, 4);
                messages.state = .{ .parsing = resp[next_msg..] };
                try parser.alignTo(4);
                return .{
                    .hdr = rechdr,
                    .data = resp[0..rechdr.len][parser.pos..],
                };
            },
        }
        return null;
    }
    pub fn flush(messages: *Messages) !void {
        var buf: [32 * 1024]u8 = undefined;
        while (try messages.next(&buf)) |_| {}
    }

    fn FindMessage(Handler: type) type {
        const OrigRes = @typeInfo(Handler).@"fn".return_type.?;
        return @typeInfo(OrigRes).error_union.payload;
    }

    pub fn findMessage(messages: *Messages, buf: []u8, handler: anytype, ctx: anytype) !FindMessage(@TypeOf(handler)) {
        const res = blk: {
            while (try messages.next(buf)) |response| {
                if (try handler(ctx, response)) |found| {
                    break :blk found;
                }
            }
            return null;
        };
        try messages.flush();
        return res;
    }
};

pub const MessageType = enum(u16) {
    noop = 1,
    @"error" = 2,
    done = 3,
    overrun = 4,
    _,
    pub fn fromInt(int: u16) MessageType {
        return @enumFromInt(int);
    }
    pub fn fromEnum(val: anytype) MessageType {
        return .fromInt(@intFromEnum(val));
    }
};

pub const Flags = packed struct(u16) {
    pub usingnamespace util.FlagsMixin(@This());
    request: bool = false,
    multipart: bool = false,
    ack: bool = false,
    echo: bool = false,
    dump_interrupted: bool = false,
    dump_filtered: bool = false,
    _pad1: u2 = 0,
    mods: packed union {
        get: packed struct(u4) {
            specify_tree_root: bool = false,
            match: bool = false,
            atomic: bool = false,
            _pad: u1 = 0,
        },
        new: packed struct(u4) {
            replace: bool = false,
            exclude: bool = false,
            create: bool = false,
            append: bool = false,
        },
        delete: packed struct(u4) {
            nonrec: bool = false,
            bulk: bool = false,
            _pad: u2 = 0,
        },
        ack: packed struct(u4) {
            capped: bool = false,
            ext_tlvs: bool = false,
            _pad: u2 = 0,
        },
        none: u4,
    } = .{ .none = 0 },
    _pad: u4 = 0,
    pub const dump: Flags = .{
        .mods = .{ .get = .{ .specify_tree_root = true, .match = true } },
    };
};

pub const Header = packed struct(u128) {
    len: u32,
    type: MessageType,
    flags: Flags,
    seq: u32,
    pid: u32,
};

pub const ErrorHeader = extern struct {
    neg_errno: i32,
    hdr: Header align(1),
};

pub const ErrorAttr = Attr(union(enum(AttrBase)) {
    unused: void,
    msg: AttrString, // error message string
    offs: u32, // offset of the invalid attribute in the original message, counting from the beginning of the header
    cookie: AttrBinary, // arbitrary subsystem specific cookie to be used - in the success case - to identify a created object or operation or similar
    policy: PolicyTypeAttr, // policy for a rejected attribute
    miss_type: AttrType, // type of a missing required attribute, .miss_nest will not be present if the attribute was missing at the message level
    miss_nest: AttrBinary, // FIXME: determine the correct type // offset of the nest where attribute was missing
});

pub const AttrInvalid = struct {
    id: AttrBase,
    slice: []const u8,

    pub fn init(id: AttrBase, slice: []const u8) AttrInvalid {
        return .{ .id = id, .slice = slice };
    }
    pub fn parse(_: *Parser) !AttrInvalid {
        @compileError("invalid netlink attribute cannot be parsed");
    }
    pub fn build(_: AttrInvalid, _: *Builder) !void {
        @compileError("invalid netlink attribute cannot be built");
    }
    pub fn format(self: AttrInvalid, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        try writer.print("INVALID(id={}) [{}]{{", .{ self.id, self.slice.len });
        if (self.slice.len <= 16) {
            try writer.print("{}", .{std.fmt.fmtSliceHexLower(self.slice)});
        } else {
            try writer.print("{}...", .{std.fmt.fmtSliceHexLower(self.slice[0..16])});
        }
        try writer.writeAll("}");
    }
};

pub const AttrBinary = struct {
    slice: []const u8,

    pub fn init(slice: []const u8) AttrBinary {
        return .{ .slice = slice };
    }
    pub fn parse(parser: *Parser) !AttrBinary {
        const slice = parser.buf[parser.pos..];
        parser.pos = parser.buf.len;
        return .{ .slice = slice };
    }
    pub fn build(self: AttrBinary, builder: *Builder) !void {
        try builder.appendSlice(self.slice);
    }
    pub fn format(self: AttrBinary, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        try writer.print("[{}]{{", .{self.slice.len});
        if (self.slice.len <= 16) {
            try writer.print("{}", .{std.fmt.fmtSliceHexLower(self.slice)});
        } else {
            try writer.print("{}...", .{std.fmt.fmtSliceHexLower(self.slice[0..16])});
        }
        try writer.writeAll("}");
    }
};

pub const AttrString = struct {
    slice: []const u8,

    pub fn init(slice: []const u8) AttrString {
        return .{ .slice = slice };
    }
    pub fn parse(parser: *Parser) !AttrString {
        const slice = parser.buf[parser.pos..];
        parser.pos = parser.buf.len;
        return .{ .slice = slice };
    }
    pub fn build(self: AttrString, builder: *Builder) !void {
        try builder.appendSlice(self.slice);
    }
    pub fn format(self: AttrString, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        try writer.print("\"{s}\"", .{self.slice});
    }
};

pub const AttrNulString = struct {
    slice: [:0]const u8,

    pub fn init(slice: [:0]const u8) AttrNulString {
        return .{ .slice = slice };
    }
    pub fn parse(parser: *Parser) !AttrNulString {
        return .{ .slice = try parser.parseSliceSentinel(0) };
    }
    pub fn build(self: AttrNulString, builder: *Builder) !void {
        try builder.appendSlice(self.slice);
        try builder.appendSlice(&.{0});
    }
    pub fn format(self: AttrNulString, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        try writer.print("\"{s}\"", .{self.slice});
    }
};

pub fn AttrNested(A: type) type {
    const Iterator = struct {
        parser: Parser,
        pub fn next(self: *@This()) ?A {
            //self.parser.alignTo(4) catch return null;
            if (self.parser.pos == self.parser.buf.len) {
                return null;
            }
            return self.parser.parse(A) catch |e| {
                if (e != error.OutOfBounds) {
                    std.log.debug("while parsing nested attribute: {}", .{e});
                }
                return null;
            };
        }
    };
    return struct {
        pub const _Marker = AttrMarker;
        const Self = @This();
        slice: []const u8,
        pub fn parse(parser: *Parser) !Self {
            const slice = parser.buf[parser.pos..];
            parser.pos = parser.buf.len;
            return .{ .slice = slice };
        }
        pub fn build(self: Self, builder: *Builder) !void {
            try builder.appendSlice(self.slice);
        }
        pub fn iterator(self: Self) Iterator {
            return .{ .parser = .init(self.slice) };
        }
        pub fn format(self: Self, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
            //try writer.print("{s}{{ ", .{@typeName(Self)});
            try writer.writeAll("{");
            var it = self.iterator();
            var sep: []const u8 = "";
            while (it.next()) |attr| {
                try writer.print("{s} {}", .{ sep, attr });
                sep = ",";
            }
            try writer.writeAll(" }");
        }
    };
}

pub fn AttrNestedArray(A: type) type {
    const Nested = AttrNested(A);
    const Element = struct {
        index: u16,
        attr: Nested,
        pub fn parse(parser: *Parser) !@This() {
            try parser.alignTo(4);
            const hdr = try parser.parse(AttrHeader);
            const slice = try parser.parseSlice(hdr.len - @sizeOf(AttrHeader));
            var attr_p: Parser = .init(slice);
            const attr = try attr_p.parse(Nested);
            return .{
                .index = hdr.type,
                .attr = attr,
            };
        }
    };
    const Iterator = struct {
        parser: Parser,
        pub fn next(self: *@This()) ?Element {
            //self.parser.alignTo(4) catch return null;
            if (self.parser.pos == self.parser.buf.len) {
                return null;
            }
            return self.parser.parse(Element) catch |e| {
                if (e != error.OutOfBounds) {
                    std.log.debug("while parsing nested array: {}", .{e});
                }
                return null;
            };
        }
    };
    return struct {
        pub const _Marker = AttrMarker;
        const Self = @This();
        slice: []const u8,
        pub fn parse(parser: *Parser) !Self {
            const slice = parser.buf[parser.pos..];
            parser.pos = parser.buf.len;
            return .{ .slice = slice };
        }
        pub fn build(self: Self, builder: *Builder) !void {
            try builder.appendSlice(self.slice);
        }
        pub fn iterator(self: Self) Iterator {
            return .{ .parser = .init(self.slice) };
        }
        pub fn format(self: Self, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
            //try writer.print("{s}{{\n", .{@typeName(Self)});
            try writer.writeAll("{\n");
            var it = self.iterator();
            while (it.next()) |elem| {
                try writer.print("  [{}] = {},\n", .{ elem.index, elem.attr });
            }
            try writer.writeAll("}");
        }
    };
}

const AttrType = enum(u32) {
    invalid, // unused
    flag, // flag attribute (present/not present)
    u8, // 8-bit unsigned attribute
    u16, // 16-bit unsigned attribute
    u32, // 32-bit unsigned attribute
    u64, // 64-bit unsigned attribute
    s8, // 8-bit signed attribute
    s16, // 16-bit signed attribute
    s32, // 32-bit signed attribute
    s64, // 64-bit signed attribute
    binary, // binary data, min/max length may be specified
    string, // string, min/max length may be specified
    nul_string, // NUL-terminated string, min/max length may be specified
    nested, // nested, i.e. the content of this attribute consists of sub-attributes. The nested policy and maxtype inside may be specified.
    nested_array, // nested array, i.e. the content of this attribute contains sub-attributes whose type is irrelevant (just used to separate the array entries) and each such array entry has attributes again, the policy for those inner ones and the corresponding maxtype may be specified.
    bitfield32, // Bitfield32 attribute
};

const PolicyTypeAttr = Attr(enum(AttrBase) {
    unspec, // unused
    type, // type of the attribute, AttrType
    min_value_s, // minimum value for signed integers (i64)
    max_value_s, // maximum value for signed integers (i64)
    min_value_u, // minimum value for unsigned integers (u64)
    max_value_u, // maximum value for unsigned integers (u64)
    min_length, // minimum length for binary attributes, no minimum if not given (u32)
    max_length, // maximum length for binary attributes, no maximum if not given (u32)
    policy_idx, // sub policy for nested and nested array types (u32)
    policy_maxtype, // maximum sub policy attribute for nested and nested array types, this can in theory be < the size of the policy pointed to by the index, if limited inside the nesting (u32)
    bitfield32_mask, // valid mask for the bitfield32 type (u32)
    mask, // mask of valid bits for unsigned integers (u64)
    pad, // pad attribute for 64-bit alignment
});

pub const AttrBase = u16;

const AttrHeader = packed struct {
    len: u16,
    type: u16,
};

pub fn Packet(PayloadT: type, AttrT: type) type {
    return struct {
        const Self = @This();

        type: MessageType,
        flags: Flags,
        seq: u32,
        pid: u32,
        payload: PayloadT,
        attrs: []const AttrT,

        pub fn build(self: Self, builder: *Builder) !void {
            try builder.alignTo(4);
            const start_pos = builder.pos;
            const hole = try builder.hole(@sizeOf(Header));
            try builder.alignTo(4);
            try builder.append(self.payload);
            for (self.attrs) |attr| {
                try builder.append(attr);
            }
            const end_pos = builder.pos;
            try builder.alignTo(4);
            try builder.fill(hole, Header{
                .len = @intCast(end_pos - start_pos),
                .type = self.type,
                .flags = self.flags,
                .seq = self.seq,
                .pid = self.pid,
            });
        }
    };
}

const AttrMarker = opaque {};

pub fn Attr(Base: type) type {
    const ti = @typeInfo(Base);
    const is_union = switch (ti) {
        .@"union" => true,
        .@"enum" => false,
        else => @compileError("Attr must be enum or tagged union"),
    };

    const Enum = if (is_union) ti.@"union".tag_type.? else Base;
    const eti = @typeInfo(Enum);
    if (eti != .@"enum") {
        @compileError("netlink Attr must be an enum");
    }
    const ei = eti.@"enum";
    if (ei.tag_type != AttrBase) {
        @compileError("netlink Attr must have a u16 base int");
    }
    // if (!ei.is_exhaustive) {
    //     @compileError("netlink Attr must use an exhaustive enum");
    // }

    const Payload = if (is_union) Base else @Type(.{ .@"union" = .{
        .layout = .auto,
        .tag_type = Enum,
        .fields = blk: {
            var fields: [ei.fields.len]std.builtin.Type.UnionField = undefined;
            for (ei.fields, &fields) |ef, *uf| {
                uf.* = .{
                    .name = ef.name,
                    .type = AttrBinary,
                    .alignment = @alignOf(AttrBinary),
                };
            }
            break :blk &fields;
        },
        .decls = &.{},
    } });
    //const pi = @typeInfo(Payload).@"union";
    return struct {
        const Self = @This();
        pub const Tag = Enum;
        pub const Data = Payload;
        pub const _Marker = AttrMarker;

        payload: Payload,

        pub fn parse(parser: *Parser) !Self {
            try parser.alignTo(4);
            const hdr = try parser.parse(AttrHeader);
            try parser.alignTo(4);
            if (hdr.len < @sizeOf(AttrHeader)) {
                return error.CorruptedAttrHeader;
            }
            const slice = try parser.parseSlice(hdr.len - @sizeOf(AttrHeader));
            const tag: Enum = util.enumFromInt(Enum, hdr.type) orelse {
                std.log.debug("invalid tag value: {}", .{hdr.type});
                if (ei.is_exhaustive) {
                    return error.InvalidTagValue;
                } else {
                    return .{ .payload = .{
                        .__non_exhaustive = .init(slice),
                    } };
                }
            };
            var p: Parser = .init(slice); // NOTE: New parser to stay within bounds

            //            const tagname = @tagName(tag); // NOTE: We know the tag is valid thanks to enumFromInt
            switch (tag) {
                inline else => |t| {
                    const T = @TypeOf(@field(@unionInit(Payload, @tagName(t), undefined), @tagName(t)));
                    const payload: T = try p.parse(T);
                    return .{ .payload = @unionInit(Payload, @tagName(t), payload) };
                },
            }
            // inline for (pi.fields) |field| {
            //     if (std.mem.eql(u8, tagname, field.name)) {
            //         const payload = try p.parse(field.type);
            //         return .{
            //             .payload = @unionInit(Payload, field.name, payload),
            //         };
            //     }
            // }
            unreachable;
        }
        pub fn build(attr: Self, builder: *Builder) !void {
            try builder.alignTo(4);
            const start_pos = builder.pos;
            const hole = try builder.hole(@sizeOf(AttrHeader));
            try builder.alignTo(4);
            switch (attr.payload) {
                inline else => |p| try builder.append(p),
            }
            const end_pos = builder.pos;
            try builder.fill(hole, AttrHeader{
                .type = @intFromEnum(attr.payload),
                .len = @intCast(end_pos - start_pos),
            });
        }
        pub fn format(attr: Self, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
            const tagname_o = std.enums.tagName(Enum, attr.payload);
            //try writer.print("{s}{{ ", .{@typeName(if (is_union) Payload else Enum)});
            try writer.writeAll("{ ");
            if (tagname_o) |tagname| {
                try writer.print("{s}", .{tagname});
            } else {
                try writer.print("({})", .{@intFromEnum(attr.payload)});
            }
            switch (attr.payload) {
                inline else => |payload| {
                    try writer.print(" : {}", .{payload});
                },
            }
            try writer.writeAll(" }");
        }
    };
}

test "tagged union void field" {
    const U = union(enum(u16)) {
        a: void,
        b: usize,
    };
    const T = @TypeOf(@field(@unionInit(U, "a", undefined), "a"));
    try std.testing.expectEqual(void, T);
}

test "Flags union produces correct bits" {
    const dump: Flags = .dump;
    try std.testing.expectEqual(c.NLM_F_DUMP, @as(u16, @bitCast(dump)));

    const flags: Flags = .{
        .multipart = true,
        .dump_filtered = true,
        .mods = .{ .new = .{
            .replace = true,
            .append = true,
        } },
    };
    const cflags = c.NLM_F_MULTI | c.NLM_F_DUMP_FILTERED | c.NLM_F_REPLACE | c.NLM_F_APPEND;
    try std.testing.expectEqual(cflags, @as(u16, @bitCast(flags)));
}

test "Header produces correct bits" {
    const chdr = c.nlmsghdr{
        .nlmsg_len = @sizeOf(c.nlmsghdr),
        .nlmsg_type = c.NLMSG_MIN_TYPE,
        .nlmsg_flags = c.NLM_F_REQUEST | c.NLM_F_ACK,
        .nlmsg_seq = 2,
        .nlmsg_pid = 0,
    };

    const hdr: Header = .{
        .len = @sizeOf(Header),
        .type = .fromInt(c.NLMSG_MIN_TYPE),
        .flags = .{ .request = true, .ack = true },
        .seq = 2,
        .pid = 0,
    };
    try std.testing.expectEqual(chdr, @as(c.nlmsghdr, @bitCast(hdr)));
}
