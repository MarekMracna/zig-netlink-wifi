const std = @import("std");

const nl = @import("netlink.zig");
const nl80211 = @import("nl80211.zig");
const util = @import("util.zig");

const Builder = @import("Builder.zig");
const Parser = @import("Parser.zig");

// Table 9-92 — Element IDs
pub const Ie = union(enum(u8)) {
    pub const Header = packed struct {
        id: u8,
        len: u8,
    };
    pub const Tag = std.meta.Tag(Ie);

    ssid: nl80211.Ssid = 0,
    rates: nl.AttrBinary = 1,
    fh_param: nl.AttrBinary = 2,
    ds_param: nl.AttrBinary = 3,
    cf_param: nl.AttrBinary = 4,
    tim: nl.AttrBinary = 5,
    ibss_param: nl.AttrBinary = 6,
    country: Country = 7,
    request: nl.AttrBinary = 10,
    bss_load: nl.AttrBinary = 11,
    edca_param: nl.AttrBinary = 12,
    tspec: nl.AttrBinary = 13,
    tclas: nl.AttrBinary = 14,
    schedule: nl.AttrBinary = 15,
    challenge_text: nl.AttrBinary = 16,
    power_constraint: nl.AttrBinary = 32,
    power_capability: nl.AttrBinary = 33,
    tpc_request: nl.AttrBinary = 34,
    tpc_report: nl.AttrBinary = 35,
    supported_channels: nl.AttrBinary = 36,
    channel_switch_announcement: nl.AttrBinary = 37,
    measurement_request: nl.AttrBinary = 38,
    measurement_report: nl.AttrBinary = 39,
    quiet: nl.AttrBinary = 40,
    ibss_dfs: nl.AttrBinary = 41,
    erp_info: nl.AttrBinary = 42,
    ts_delay: nl.AttrBinary = 43,
    tclas_processing: nl.AttrBinary = 44,
    ht_capabilities: nl.AttrBinary = 45,
    qos_capability: nl.AttrBinary = 46,
    rsn: nl.AttrBinary = 48,
    ext_rates: nl.AttrBinary = 50,
    ap_channel_report: nl.AttrBinary = 51,
    neighbor_report: nl.AttrBinary = 52,
    rcpi: nl.AttrBinary = 53,
    mobility_domain: nl.AttrBinary = 54,
    fast_bss_transition: nl.AttrBinary = 55,
    timeout_interval: nl.AttrBinary = 56,
    ric_data: nl.AttrBinary = 57,
    dse_registered_location: nl.AttrBinary = 58,
    ht_operation: nl.AttrBinary = 61,
    rm_enabled_capabilities: nl.AttrBinary = 70,
    extended_capabilities: nl.AttrBinary = 127,
    vht_capabilities: nl.AttrBinary = 191,
    vht_operation: nl.AttrBinary = 192,
    transmit_power_envelope: nl.AttrBinary = 195,
    vendor: nl.AttrBinary = 221,
    __invalid: nl.AttrInvalid,

    pub fn parse(parser: *Parser) !Ie {
        const hdr = try parser.parse(Header);
        const data = try parser.parseSlice(hdr.len);
        const tag = util.enumFromInt(Tag, hdr.id) orelse return .{
            .__invalid = .init(hdr.id, data),
        };
        var payload_p: Parser = .init(data);
        switch (tag) {
            .__invalid => unreachable,
            inline else => |t| {
                const Payload = @TypeOf(@field(@unionInit(Ie, @tagName(t), undefined), @tagName(t)));
                const payload = try payload_p.parse(Payload);
                return @unionInit(Ie, @tagName(t), payload);
            },
        }
    }

    pub fn format(ie: Ie, _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        switch (ie) {
            .__invalid => |invalid| {
                try writer.print("{{ {} }}", .{invalid});
            },
            inline else => |payload, tag| {
                try writer.print("{{ {s} : {} }}", .{ @tagName(tag), payload });
            },
        }
    }
};

const Country = struct {
    country_string: [3]u8,
    triplets_slice: []const u8,

    pub fn parse(parser: *Parser) !Country {
        const country_slice = try parser.parseSlice(3);
        const buf = parser.buf[parser.pos..];
        const triplets_count = buf.len / 3;
        const triplets_slice = buf[0 .. 3 * triplets_count];
        return .{
            .country_string = country_slice[0..3].*,
            .triplets_slice = triplets_slice,
        };
    }

    pub fn format(self: Country, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        try writer.print("\"{s}\" [TODO triplets]", .{self.country_string[0..]});
    }
};
