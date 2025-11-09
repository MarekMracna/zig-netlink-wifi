const std = @import("std");
const nl = @import("netlink.zig");
const genl = @import("genetlink.zig");
const rtnl = @import("rtnetlink.zig");
const nl80211 = @import("nl80211.zig");
const ieee80211 = @import("ieee80211.zig");
const ifla = @import("ifla.zig");
const Builder = @import("Builder.zig");
const Parser = @import("Parser.zig");
const Mac = @import("if.zig").Mac;
const Unit = @import("units.zig").Unit;

const InterfaceParser = struct {
    nl80211_fam: genl.Family,

    const Result = struct {
        ifindex: u32,
        station_mac: Mac,
    };

    pub fn init(nl80211_fam: genl.Family) InterfaceParser {
        return .{ .nl80211_fam = nl80211_fam };
    }

    fn prepareMsg(self: InterfaceParser, buf: []u8) ![]const u8 {
        var builder: Builder = .init(buf);
        try builder.append(nl80211.Packet{
            .family = self.nl80211_fam,
            .flags = .fromParts(
                &.{ .{ .request = true, .ack = true }, .dump },
            ),
            .seq = 3,
            .pid = 0,
            .cmd = .get_interface,
            .attrs = &.{},
        });
        return builder.msg();
    }

    fn parseInterface(self: InterfaceParser, sock: nl.Socket, buf: []u8) !Result {
        const msg = try self.prepareMsg(buf);
        var msg_it = try sock.req(msg);
        const ifindex_opt = try msg_it.findMessage(buf, parseResponse, self);
        return ifindex_opt orelse error.FailedToFindIfIndex;
    }

    fn parseResponse(self: InterfaceParser, response: nl.Message) !?Result {
        if (response.hdr.type != self.nl80211_fam.id) {
            return null;
        }
        var attr_p: Parser = .init(response.data);
        _ = try attr_p.parse(genl.Header);
        return parseData(&attr_p);
    }

    fn parseData(attr_p: *Parser) ?Result {
        var res_ifindex: ?u32 = null;
        var res_mac: ?Mac = null;
        while (attr_p.parse(nl80211.Attr)) |attr| {
            std.log.debug("{}", .{attr});
            switch (attr.payload) {
                .ifindex => |ifindex| res_ifindex = ifindex,
                .mac => |mac| res_mac = mac,
                else => {},
            }
        } else |_| {}
        return .{
            .ifindex = res_ifindex orelse return null,
            .station_mac = res_mac orelse return null,
        };
    }
};

const ScanParser = struct {
    nl80211_fam: genl.Family,
    ifindex: u32,

    pub fn init(nl80211_fam: genl.Family, ifindex: u32) ScanParser {
        return .{ .nl80211_fam = nl80211_fam, .ifindex = ifindex };
    }

    fn prepareMsg(self: ScanParser, buf: []u8) ![]const u8 {
        var builder: Builder = .init(buf);
        try builder.append(nl80211.Packet{
            .family = self.nl80211_fam,
            .flags = .fromParts(&.{ .{ .request = true, .ack = true }, .dump }),
            .seq = 4,
            .pid = 0,
            .cmd = .get_scan,
            .attrs = &.{.{ .payload = .{
                .ifindex = self.ifindex,
            } }},
        });
        return builder.msg();
    }

    pub fn parseScan(self: ScanParser, sock: nl.Socket, buf: []u8) !nl80211.Ssid {
        const msg = try self.prepareMsg(buf);
        var msg_it = try sock.req(msg);
        const res_opt = try msg_it.findMessage(buf, handleMessage, self);
        return res_opt orelse error.FailedToGetScanData;
    }

    fn handleMessage(self: ScanParser, response: nl.Message) !?nl80211.Ssid {
        if (response.hdr.type != self.nl80211_fam.id) {
            return null;
        }
        var attr_p: Parser = .init(response.data);
        _ = try attr_p.parse(genl.Header);
        var res: ?nl80211.Ssid = null;
        while (attr_p.parse(nl80211.Attr)) |attr| {
            if (attr.payload == .bss) {
                if (parseBss(attr.payload.bss.slice)) |ssid| {
                    res = ssid;
                }
            }
        } else |_| {}
        return res;
    }

    fn parseBss(data: []const u8) ?nl80211.Ssid {
        var parser: Parser = .init(data);
        var res: ?nl80211.Ssid = null;
        while (parser.parse(nl80211.Bss)) |bss| {
            if (bss.payload == .information_elements) {
                if (parseIEs(bss.payload.information_elements.slice)) |ssid| {
                    res = ssid;
                }
            }
        } else |_| {}
        return res;
    }

    fn parseIEs(data: []const u8) ?nl80211.Ssid {
        var parser: Parser = .init(data);
        var res: ?nl80211.Ssid = null;
        while (parser.parse(ieee80211.Ie)) |ie| {
            if (ie == .ssid) {
                res = ie.ssid;
            }
        } else |_| {}
        return res;
    }
};

const StationParser = struct {
    nl80211_fam: genl.Family,
    ifindex: u32,
    station_mac: Mac,

    pub const Result = Unit(i8, .deci, .bel_milliwatt);

    pub fn init(nl80211_fam: genl.Family, ifindex: u32, station_mac: Mac) StationParser {
        return .{
            .nl80211_fam = nl80211_fam,
            .ifindex = ifindex,
            .station_mac = station_mac,
        };
    }

    fn prepareMsg(self: StationParser, buf: []u8) ![]const u8 {
        var builder: Builder = .init(buf);
        try builder.append(nl80211.Packet{
            .family = self.nl80211_fam,
            .flags = .fromParts(&.{ .{ .request = true, .ack = true }, .dump }),
            .seq = 6,
            .pid = 0,
            .cmd = .get_station,
            .attrs = &.{
                .{ .payload = .{ .ifindex = self.ifindex } },
                .{ .payload = .{ .mac = self.station_mac } },
            },
        });
        return builder.msg();
    }

    pub fn parseStation(self: StationParser, sock: nl.Socket, buf: []u8) !Result {
        const msg = try self.prepareMsg(buf);
        var msg_it = try sock.req(msg);
        const res_opt = try msg_it.findMessage(buf, handleMessage, self);
        return res_opt orelse error.FailedToGetStationData;
    }

    fn handleMessage(self: StationParser, response: nl.Message) !?Result {
        if (response.hdr.type != self.nl80211_fam.id) {
            return null;
        }
        var attr_p: Parser = .init(response.data);
        _ = try attr_p.parse(genl.Header);
        while (attr_p.parse(nl80211.Attr)) |attr| {
            if (attr.payload == .sta_info) {
                return parseStaInfo(attr.payload.sta_info.slice);
            }
        } else |_| {}
        return null;
    }
    fn parseStaInfo(sta_info: []const u8) !?Result {
        var parser: Parser = .init(sta_info);
        while (parser.parse(nl80211.StaInfo)) |si| {
            if (si.payload == .signal) {
                return si.payload.signal;
            }
        } else |_| {}
        return null;
    }
};

pub fn main() !void {
    const sock: nl.Socket = try .open(.generic);
    var msgbuf: [32 * 1024]u8 = undefined;

    const nl80211_fam: genl.Family = try .get(sock, "nl80211");

    const interface_parser: InterfaceParser = .init(nl80211_fam);
    const interface_res = try interface_parser.parseInterface(sock, &msgbuf);
    const ifindex = interface_res.ifindex;
    const station_mac = interface_res.station_mac;

    const station_parser: StationParser = .init(nl80211_fam, ifindex, station_mac);
    const signal = try station_parser.parseStation(sock, &msgbuf);

    const scan_parser: ScanParser = .init(nl80211_fam, ifindex);
    const ssid = try scan_parser.parseScan(sock, &msgbuf);

    const stdout = std.io.getStdOut().writer();

    if (std.unicode.utf8ValidateSlice(ssid.bytes)) {
        try stdout.print("{s} {}\n", .{ ssid.bytes, signal });
    } else {
        return error.SsidInvalidUtf8;
    }

    try rt();
}

fn fam() !void {
    const sock: nl.Socket = try .open(.generic);
    var msgbuf: [32 * 1024]u8 = undefined;
    var builder: Builder = .init(&msgbuf);
    try builder.append(genl.CtrlPacket{
        .family = .CTRL,
        .flags = .{ .request = true, .ack = true },
        .seq = 5,
        .pid = 0,
        .cmd = .getfamily,
        .attrs = &.{.{
            .payload = .{ .family_name = .init("nl80211\x00") },
        }},
    });
    var messages = try sock.req(builder.msg());
    while (try messages.next(&msgbuf)) |msg| {
        var parser: Parser = .init(msg.data);
        _ = try parser.parse(genl.Header);
        while (parser.parse(genl.CtrlAttr)) |attr| {
            switch (attr.payload) {
                .ops => |arr| {
                    std.log.debug("{}", .{arr});
                },
                .mcast_groups => |arr| {
                    std.log.debug("{}", .{arr});
                },
                else => std.log.debug("{}", .{attr}),
            }
        } else |_| {}
    }
}

fn rt() !void {
    const rtsock: nl.Socket = try .open(.route);
    const pid = std.os.linux.getpid();

    var msgbuf: [32 * 1024]u8 = undefined;
    {
        var builder: Builder = .init(&msgbuf);
        try builder.append(rtnl.Packet{
            .type = .fromEnum(rtnl.MessageType.getlink),
            .seq = 1,
            .pid = @bitCast(pid),
            .flags = .fromParts(&.{ .{ .request = true }, .dump }),
            .payload = .{ .family = .packet },
            .attrs = &.{},
        });
        var msg_it = try rtsock.req(builder.msg());
        while (try msg_it.next(&msgbuf)) |response| {
            var p: Parser = .init(response.data);
            const ifinfomsg = try p.parse(rtnl.IfInfoMsg);
            std.log.debug("{}", .{ifinfomsg});
            while (p.parse(ifla.Attr)) |attr| {
                std.log.debug("{}", .{attr});
            } else |_| {}
        }
    }
}
