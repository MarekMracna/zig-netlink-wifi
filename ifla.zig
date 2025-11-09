const nl = @import("netlink.zig");
const Mac = @import("if.zig").Mac;
pub const Attr = nl.Attr(union(enum(nl.AttrBase)) {
    unspec: void,
    address: Mac,
    broadcast: Mac,
    ifname: nl.AttrString,
    mtu: u32,
    link: u32,
    qdisc: nl.AttrString,
    stats: nl.AttrBinary, // TODO: rtnl_link_stats
    cost: nl.AttrString,
    priority: nl.AttrString,
    master: u32,
    wireless: nl.AttrString, //  Wireless Extension event - see wireless.h
    protinfo: nl.AttrString, //  Protocol specific information for a link
    txqlen: u32,
    map: nl.AttrBinary, // TODO: rtnl_link_ifmap
    weight: u32,
    operstate: u8,
    linkmode: u8,
    linkinfo: nl.AttrBinary, // TODO: linkinfo_attrs
    net_ns_pid: u32,
    ifalias: nl.AttrString,
    num_vf: u32, //  Number of VFs if device is SR-IOV PF
    vfinfo_list: nl.AttrBinary, // TODO: vfinfo_list_attrs
    stats64: nl.AttrBinary, // TODO: rtnl_link_stats64
    vf_ports: nl.AttrBinary, // TODO: vf_ports_attrs
    port_self: nl.AttrBinary, // TODO: port_self_attrs
    af_spec: nl.AttrBinary, // TODO: af_spec_attrs
    group: u32, //  Group the device belongs to
    net_ns_fd: u32,
    ext_mask: nl.AttrBinary, // TODO: rtext_filter //  Extended info mask, VFs, etc
    promiscuity: u32, //  Promiscuity count: > 0 means acts PROMISC
    num_tx_queues: u32,
    num_rx_queues: u32,
    carrier: u8,
    phys_port_id: nl.AttrBinary,
    carrier_changes: u32,
    phys_switch_id: nl.AttrBinary,
    link_netnsid: i32,
    phys_port_name: nl.AttrString,
    proto_down: u8,
    gso_max_segs: u32,
    gso_max_size: u32,
    pad: nl.AttrBinary, // TODO: pad
    xdp: nl.AttrBinary, // TODO: xdp_attrs
    event: u32,
    new_netnsid: i32,
    if_netnsid: i32,
    carrier_up_count: u32,
    carrier_down_count: u32,
    new_ifindex: i32,
    min_mtu: u32,
    max_mtu: u32,
    prop_list: nl.AttrBinary, // TODO: prop_list_link_attrs
    alt_ifname: nl.AttrString, //  Alternative ifname
    perm_address: Mac,
    proto_down_reason: nl.AttrString,

    parent_dev_name: nl.AttrString, // device (sysfs) name as parent, used instead of link where there's no parent netdev
    parent_dev_bus_name: nl.AttrString,
    gro_max_size: u32,
    tso_max_size: u32,
    tso_max_segs: u32,
    allmulti: u32, //  Allmulti count: > 0 means acts ALLMULTI

    devlink_port: nl.AttrBinary,

    gso_ipv4_max_size: u32,
    gro_ipv4_max_size: u32,
    dpll_pin: nl.AttrBinary, // TODO: link_dpll_pin_attrs
    max_pacing_offload_horizon: u32,
    netns_immutable: u8,
});
