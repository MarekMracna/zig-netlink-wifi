const nl = @import("netlink.zig");
const if_arp = @import("if_arp.zig");
const IF = @import("if.zig");
const Af = @import("socket.zig").Af;

const GenMsg = packed struct {
    family: Af,
};

pub const IfInfoMsg = packed struct {
    family: Af,
    _pad: u8,
    type: if_arp.ArpHrd,
    index: i32,
    flags: IF.Flags,
    change: IF.Flags,
};

pub const Packet = nl.Packet(GenMsg, Attr);

const Attr = nl.Attr(enum(nl.AttrBase) { a });

pub const MessageType = enum(u16) {
    newlink = 16,
    dellink,
    getlink,
    setlink,

    newaddr = 20,
    deladdr,
    getaddr,

    newroute = 24,
    delroute,
    getroute,

    newneigh = 28,
    delneigh,
    getneigh,

    newrule = 32,
    delrule,
    getrule,

    newqdisc = 36,
    delqdisc,
    getqdisc,

    newtclass = 40,
    deltclass,
    gettclass,

    newtfilter = 44,
    deltfilter,
    gettfilter,

    newaction = 48,
    delaction,
    getaction,

    newprefix = 52,

    getmulticast = 58,

    getanycast = 62,

    newneightbl = 64,
    getneightbl = 66,
    setneightbl,

    newnduseropt = 68,

    newaddrlabel = 72,
    deladdrlabel,
    getaddrlabel,

    getdcb = 78,
    setdcb,

    newnetconf = 80,
    delnetconf,
    getnetconf = 82,

    newmdb = 84,
    delmdb = 85,
    getmdb = 86,

    newnsid = 88,
    delnsid = 89,
    getnsid = 90,

    newstats = 92,
    getstats = 94,
    setstats,

    newcachereport = 96,

    newchain = 100,
    delchain,
    getchain,

    newnexthop = 104,
    delnexthop,
    getnexthop,

    newlinkprop = 108,
    dellinkprop,
    getlinkprop,

    newvlan = 112,
    delvlan,
    getvlan,

    newnexthopbucket = 116,
    delnexthopbucket,
    getnexthopbucket,

    newtunnel = 120,
    deltunnel,
    gettunnel,
};
