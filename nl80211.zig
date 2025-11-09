const std = @import("std");
const nl = @import("netlink.zig");
const genl = @import("genetlink.zig");
const Mac = @import("if.zig").Mac;
const Unit = @import("units.zig").Unit;
const UnitScaled = @import("units.zig").UnitScaled;

const Builder = @import("Builder.zig");
const Parser = @import("Parser.zig");

pub const Packet = genl.Packet(Cmd, Attr);

pub const Ssid = struct {
    bytes: []const u8,

    pub fn parse(parser: *Parser) !Ssid {
        const bin = try parser.parse(nl.AttrBinary);
        return .{ .bytes = bin.slice };
    }

    pub fn build(ssid: Ssid, builder: *Builder) !void {
        try builder.appendSlice(ssid.bytes);
    }

    pub fn format(ssid: Ssid, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        if (std.unicode.utf8ValidateSlice(ssid.bytes)) {
            try writer.print("\"{s}\"", .{ssid.bytes});
        } else {
            try writer.print("{}", .{std.fmt.fmtSliceHexLower(ssid.bytes)});
        }
    }
};

pub const Cmd = enum(genl.CmdBase) {
    unspec,

    get_wiphy, // can dump
    set_wiphy,
    new_wiphy,
    del_wiphy,

    get_interface, // can dump
    set_interface,
    new_interface,
    del_interface,

    get_key,
    set_key,
    new_key,
    del_key,

    get_beacon,
    set_beacon,
    start_ap,
    stop_ap,

    get_station,
    set_station,
    new_station,
    del_station,

    get_mpath,
    set_mpath,
    new_mpath,
    del_mpath,

    set_bss,

    set_reg,
    req_set_reg,

    get_mesh_config,
    set_mesh_config,

    set_mgmt_extra_ie, // reserved; not used

    get_reg,

    get_scan,
    trigger_scan,
    new_scan_results,
    scan_aborted,

    reg_change,

    authenticate,
    associate,
    deauthenticate,
    disassociate,

    michael_mic_failure,

    reg_beacon_hint,

    join_ibss,
    leave_ibss,

    testmode,

    connect,
    roam,
    disconnect,

    set_wiphy_netns,

    get_survey,
    new_survey_results,

    set_pmksa,
    del_pmksa,
    flush_pmksa,

    remain_on_channel,
    cancel_remain_on_channel,

    set_tx_bitrate_mask,

    register_frame,
    frame,
    frame_tx_status,

    set_power_save,
    get_power_save,

    set_cqm,
    notify_cqm,

    set_channel,
    set_wds_peer,

    frame_wait_cancel,

    join_mesh,
    leave_mesh,

    unprot_deauthenticate,
    unprot_disassociate,

    new_peer_candidate,

    get_wowlan,
    set_wowlan,

    start_sched_scan,
    stop_sched_scan,
    sched_scan_results,
    sched_scan_stopped,

    set_rekey_offload,

    pmksa_candidate,

    tdls_oper,
    tdls_mgmt,

    unexpected_frame,

    probe_client,

    register_beacons,

    unexpected_4addr_frame,

    set_noack_map,

    ch_switch_notify,

    start_p2p_device,
    stop_p2p_device,

    conn_failed,

    set_mcast_rate,

    set_mac_acl,

    radar_detect,

    get_protocol_features,

    update_ft_ies,
    ft_event,

    crit_protocol_start,
    crit_protocol_stop,

    get_coalesce,
    set_coalesce,

    channel_switch,

    vendor,

    set_qos_map,

    add_tx_ts,
    del_tx_ts,

    get_mpp,

    join_ocb,
    leave_ocb,

    ch_switch_started_notify,

    tdls_channel_switch,
    tdls_cancel_channel_switch,

    wiphy_reg_change,

    abort_scan,

    start_nan,
    stop_nan,
    add_nan_function,
    del_nan_function,
    change_nan_config,
    nan_match,

    set_multicast_to_unicast,

    update_connect_params,

    set_pmk,
    del_pmk,

    port_authorized,

    reload_regdb,

    external_auth,

    sta_opmode_changed,

    control_port_frame,

    get_ftm_responder_stats,

    peer_measurement_start,
    peer_measurement_result,
    peer_measurement_complete,

    notify_radar,

    update_owe_info,

    probe_mesh_link,

    set_tid_config,

    unprot_beacon,

    control_port_frame_tx_status,

    set_sar_specs,

    obss_color_collision,

    color_change_request,

    color_change_started,
    color_change_aborted,
    color_change_completed,

    set_fils_aad,

    assoc_comeback,

    add_link,
    remove_link,

    add_link_sta,
    modify_link_sta,
    remove_link_sta,

    set_hw_timestamp,

    links_removed,

    set_tid_to_link_mapping,

    pub const new_beacon: Cmd = .start_ap;
    pub const del_beacon: Cmd = .stop_ap;

    pub const register_action: Cmd = .register_frame;
    pub const action: Cmd = .frame;
    pub const action_tx_status: Cmd = .frame_tx_status;
};

pub const IfType = enum(u32) {
    unspecified, // unspecified type, driver decides
    adhoc, // independent BSS member
    station, // managed BSS member
    ap, // access point
    ap_vlan, // VLAN interface for access points; VLAN interfaces are a bit special in that they must always be tied to a pre-existing AP type interface.
    wds, // wireless distribution interface
    monitor, // monitor interface receiving all frames
    mesh_point, // mesh point
    p2p_client, // P2P client
    p2p_go, // P2P group owner
    p2p_device, // P2P device interface type, this is not a netdev and therefore can't be created in the normal ways, use the Cmd.start_p2p_device and Cmd.stop_p2p_device commands to create and destroy one
    ocb, // Outside Context of a BSS. This mode corresponds to the MIB variable dot11OCBActivated=true
    nan, // NAN device interface type (not a netdev)
};

pub const ChanWidth = enum(u32) {
    @"20_noht", // 20 MHz, non-HT channel
    @"20", // 20 MHz HT channel
    @"40", // 40 MHz channel, the Attr.center_freq1 attribute must be provided as well
    @"80", // 80 MHz channel, the Attr.center_freq1 attribute must be provided as well
    @"80p80", // 80+80 MHz channel, the Attr.center_freq1 and Attr.center_freq2 attributes must be provided as well
    @"160", // 160 MHz channel, the Attr.center_freq1 attribute must be provided as well
    @"5", // 5 MHz OFDM channel
    @"10", // 10 MHz OFDM channel
    @"1", // 1 MHz OFDM channel
    @"2", // 2 MHz OFDM channel
    @"4", // 4 MHz OFDM channel
    @"8", // 8 MHz OFDM channel
    @"16", // 16 MHz OFDM channel
    @"320", // 320 MHz channel, the Attr.center_freq1 attribute must be provided as well
};

pub const Attr = nl.Attr(union(enum(nl.AttrBase)) {
    unspec: void,

    wiphy: u32,
    wiphy_name: nl.AttrString,

    ifindex: u32,
    ifname: nl.AttrString,
    iftype: IfType,

    mac: Mac,

    key_data: nl.AttrBinary,
    key_idx: nl.AttrBinary,
    key_cipher: nl.AttrBinary,
    key_seq: nl.AttrBinary,
    key_default: nl.AttrBinary,

    beacon_interval: nl.AttrBinary,
    dtim_period: nl.AttrBinary,
    beacon_head: nl.AttrBinary,
    beacon_tail: nl.AttrBinary,

    sta_aid: nl.AttrBinary,
    sta_flags: nl.AttrBinary,
    sta_listen_interval: nl.AttrBinary,
    sta_supported_rates: nl.AttrBinary,
    sta_vlan: nl.AttrBinary,
    sta_info: nl.AttrBinary,

    wiphy_bands: nl.AttrBinary,

    mntr_flags: nl.AttrBinary,

    mesh_id: nl.AttrBinary,
    sta_plink_action: nl.AttrBinary,
    mpath_next_hop: nl.AttrBinary,
    mpath_info: nl.AttrBinary,

    bss_cts_prot: nl.AttrBinary,
    bss_short_preamble: nl.AttrBinary,
    bss_short_slot_time: nl.AttrBinary,

    ht_capability: nl.AttrBinary,

    supported_iftypes: nl.AttrBinary,

    reg_alpha2: nl.AttrBinary,
    reg_rules: nl.AttrBinary,

    mesh_config: nl.AttrBinary,

    bss_basic_rates: nl.AttrBinary,

    wiphy_txq_params: nl.AttrBinary,
    wiphy_freq: u32,
    wiphy_channel_type: nl.AttrBinary,

    key_default_mgmt: nl.AttrBinary,

    mgmt_subtype: nl.AttrBinary,
    ie: nl.AttrBinary,

    max_num_scan_ssids: nl.AttrBinary,

    scan_frequencies: nl.AttrBinary,
    scan_ssids: nl.AttrBinary,
    generation: u32,
    bss: nl.AttrBinary,

    reg_initiator: nl.AttrBinary,
    reg_type: nl.AttrBinary,

    supported_commands: nl.AttrBinary,

    frame: nl.AttrBinary,
    ssid: Ssid,
    auth_type: nl.AttrBinary,
    reason_code: nl.AttrBinary,

    key_type: nl.AttrBinary,

    max_scan_ie_len: nl.AttrBinary,
    cipher_suites: nl.AttrBinary,

    freq_before: nl.AttrBinary,
    freq_after: nl.AttrBinary,

    freq_fixed: nl.AttrBinary,

    wiphy_retry_short: nl.AttrBinary,
    wiphy_retry_long: nl.AttrBinary,
    wiphy_frag_threshold: nl.AttrBinary,
    wiphy_rts_threshold: nl.AttrBinary,

    timed_out: nl.AttrBinary,

    use_mfp: nl.AttrBinary,

    sta_flags2: nl.AttrBinary,

    control_port: nl.AttrBinary,

    testdata: nl.AttrBinary,

    privacy: nl.AttrBinary,

    disconnected_by_ap: nl.AttrBinary,
    status_code: nl.AttrBinary,

    cipher_suites_pairwise: nl.AttrBinary,
    cipher_suite_group: nl.AttrBinary,
    wpa_versions: nl.AttrBinary,
    akm_suites: nl.AttrBinary,

    req_ie: nl.AttrBinary,
    resp_ie: nl.AttrBinary,

    prev_bssid: nl.AttrBinary,

    key: nl.AttrBinary,
    keys: nl.AttrBinary,

    pid: nl.AttrBinary,

    @"4addr": bool,

    survey_info: nl.AttrBinary,

    pmkid: nl.AttrBinary,
    max_num_pmkids: nl.AttrBinary,

    duration: nl.AttrBinary,

    cookie: nl.AttrBinary,

    wiphy_coverage_class: nl.AttrBinary,

    tx_rates: nl.AttrBinary,

    frame_match: nl.AttrBinary,

    ack: nl.AttrBinary,

    ps_state: nl.AttrBinary,

    cqm: nl.AttrBinary,

    local_state_change: nl.AttrBinary,

    ap_isolate: nl.AttrBinary,

    wiphy_tx_power_setting: nl.AttrBinary,
    wiphy_tx_power_level: u32,

    tx_frame_types: nl.AttrBinary,
    rx_frame_types: nl.AttrBinary,
    frame_type: nl.AttrBinary,

    control_port_ethertype: nl.AttrBinary,
    control_port_no_encrypt: nl.AttrBinary,

    support_ibss_rsn: nl.AttrBinary,

    wiphy_antenna_tx: nl.AttrBinary,
    wiphy_antenna_rx: nl.AttrBinary,

    mcast_rate: nl.AttrBinary,

    offchannel_tx_ok: nl.AttrBinary,

    bss_ht_opmode: nl.AttrBinary,

    key_default_types: nl.AttrBinary,

    max_remain_on_channel_duration: nl.AttrBinary,

    mesh_setup: nl.AttrBinary,

    wiphy_antenna_avail_tx: nl.AttrBinary,
    wiphy_antenna_avail_rx: nl.AttrBinary,

    support_mesh_auth: nl.AttrBinary,
    sta_plink_state: nl.AttrBinary,

    wowlan_triggers: nl.AttrBinary,
    wowlan_triggers_supported: nl.AttrBinary,

    sched_scan_interval: nl.AttrBinary,

    interface_combinations: nl.AttrBinary,
    software_iftypes: nl.AttrBinary,

    rekey_data: nl.AttrBinary,

    max_num_sched_scan_ssids: nl.AttrBinary,
    max_sched_scan_ie_len: nl.AttrBinary,

    scan_supp_rates: nl.AttrBinary,

    hidden_ssid: nl.AttrBinary,

    ie_probe_resp: nl.AttrBinary,
    ie_assoc_resp: nl.AttrBinary,

    sta_wme: nl.AttrBinary,
    support_ap_uapsd: nl.AttrBinary,

    roam_support: nl.AttrBinary,

    sched_scan_match: nl.AttrBinary,
    max_match_sets: nl.AttrBinary,

    pmksa_candidate: nl.AttrBinary,

    tx_no_cck_rate: nl.AttrBinary,

    tdls_action: nl.AttrBinary,
    tdls_dialog_token: nl.AttrBinary,
    tdls_operation: nl.AttrBinary,
    tdls_support: nl.AttrBinary,
    tdls_external_setup: nl.AttrBinary,

    device_ap_sme: nl.AttrBinary,

    dont_wait_for_ack: nl.AttrBinary,

    feature_flags: nl.AttrBinary,

    probe_resp_offload: nl.AttrBinary,

    probe_resp: nl.AttrBinary,

    dfs_region: nl.AttrBinary,

    disable_ht: nl.AttrBinary,
    ht_capability_mask: nl.AttrBinary,

    noack_map: nl.AttrBinary,

    inactivity_timeout: nl.AttrBinary,

    rx_signal_dbm: nl.AttrBinary,

    bg_scan_period: nl.AttrBinary,

    wdev: u64,

    user_reg_hint_type: nl.AttrBinary,

    conn_failed_reason: nl.AttrBinary,

    auth_data: nl.AttrBinary,

    vht_capability: nl.AttrBinary,

    scan_flags: nl.AttrBinary,

    channel_width: ChanWidth,
    center_freq1: u32,
    center_freq2: u32,

    p2p_ctwindow: nl.AttrBinary,
    p2p_oppps: nl.AttrBinary,

    local_mesh_power_mode: nl.AttrBinary,

    acl_policy: nl.AttrBinary,

    mac_addrs: nl.AttrBinary,

    mac_acl_max: nl.AttrBinary,

    radar_event: nl.AttrBinary,

    ext_capa: nl.AttrBinary,
    ext_capa_mask: nl.AttrBinary,

    sta_capability: nl.AttrBinary,
    sta_ext_capability: nl.AttrBinary,

    protocol_features: nl.AttrBinary,
    split_wiphy_dump: nl.AttrBinary,

    disable_vht: nl.AttrBinary,
    vht_capability_mask: nl.AttrBinary,

    mdid: nl.AttrBinary,
    ie_ric: nl.AttrBinary,

    crit_prot_id: nl.AttrBinary,
    max_crit_prot_duration: nl.AttrBinary,

    peer_aid: nl.AttrBinary,

    coalesce_rule: nl.AttrBinary,

    ch_switch_count: nl.AttrBinary,
    ch_switch_block_tx: nl.AttrBinary,
    csa_ies: nl.AttrBinary,
    cntdwn_offs_beacon: nl.AttrBinary,
    cntdwn_offs_presp: nl.AttrBinary,

    rxmgmt_flags: nl.AttrBinary,

    sta_supported_channels: nl.AttrBinary,

    sta_supported_oper_classes: nl.AttrBinary,

    handle_dfs: nl.AttrBinary,

    support_5_mhz: nl.AttrBinary,
    support_10_mhz: nl.AttrBinary,

    opmode_notif: nl.AttrBinary,

    vendor_id: nl.AttrBinary,
    vendor_subcmd: nl.AttrBinary,
    vendor_data: nl.AttrBinary,
    vendor_events: nl.AttrBinary,

    qos_map: nl.AttrBinary,

    mac_hint: nl.AttrBinary,
    wiphy_freq_hint: nl.AttrBinary,

    max_ap_assoc_sta: nl.AttrBinary,

    tdls_peer_capability: nl.AttrBinary,

    socket_owner: nl.AttrBinary,

    csa_c_offsets_tx: nl.AttrBinary,
    max_csa_counters: nl.AttrBinary,

    tdls_initiator: nl.AttrBinary,

    use_rrm: nl.AttrBinary,

    wiphy_dyn_ack: nl.AttrBinary,

    tsid: nl.AttrBinary,
    user_prio: nl.AttrBinary,
    admitted_time: nl.AttrBinary,

    smps_mode: nl.AttrBinary,

    oper_class: nl.AttrBinary,

    mac_mask: nl.AttrBinary,

    wiphy_self_managed_reg: nl.AttrBinary,

    ext_features: nl.AttrBinary,

    survey_radio_stats: nl.AttrBinary,

    netns_fd: nl.AttrBinary,

    sched_scan_delay: nl.AttrBinary,

    reg_indoor: nl.AttrBinary,

    max_num_sched_scan_plans: nl.AttrBinary,
    max_scan_plan_interval: nl.AttrBinary,
    max_scan_plan_iterations: nl.AttrBinary,
    sched_scan_plans: nl.AttrBinary,

    pbss: nl.AttrBinary,

    bss_select: nl.AttrBinary,

    sta_support_p2p_ps: nl.AttrBinary,

    pad: nl.AttrBinary,

    iftype_ext_capa: nl.AttrBinary,

    mu_mimo_group_data: nl.AttrBinary,
    mu_mimo_follow_mac_addr: nl.AttrBinary,

    scan_start_time_tsf: nl.AttrBinary,
    scan_start_time_tsf_bssid: nl.AttrBinary,
    measurement_duration: nl.AttrBinary,
    measurement_duration_mandatory: nl.AttrBinary,

    mesh_peer_aid: nl.AttrBinary,

    nan_master_pref: nl.AttrBinary,
    bands: nl.AttrBinary,
    nan_func: nl.AttrBinary,
    nan_match: nl.AttrBinary,

    fils_kek: nl.AttrBinary,
    fils_nonces: nl.AttrBinary,

    multicast_to_unicast_enabled: nl.AttrBinary,

    bssid: nl.AttrBinary,

    sched_scan_relative_rssi: nl.AttrBinary,
    sched_scan_rssi_adjust: nl.AttrBinary,

    timeout_reason: nl.AttrBinary,

    fils_erp_username: nl.AttrBinary,
    fils_erp_realm: nl.AttrBinary,
    fils_erp_next_seq_num: nl.AttrBinary,
    fils_erp_rrk: nl.AttrBinary,
    fils_cache_id: nl.AttrBinary,

    pmk: nl.AttrBinary,

    sched_scan_multi: nl.AttrBinary,
    sched_scan_max_reqs: nl.AttrBinary,

    want_1x_4way_hs: nl.AttrBinary,
    pmkr0_name: nl.AttrBinary,
    port_authorized: nl.AttrBinary,

    external_auth_action: nl.AttrBinary,
    external_auth_support: nl.AttrBinary,

    nss: nl.AttrBinary,
    ack_signal: nl.AttrBinary,

    control_port_over_nl80211: nl.AttrBinary,

    txq_stats: TxqStatsAttr,
    txq_limit: nl.AttrBinary,
    txq_memory_limit: nl.AttrBinary,
    txq_quantum: nl.AttrBinary,

    he_capability: nl.AttrBinary,

    ftm_responder: nl.AttrBinary,

    ftm_responder_stats: nl.AttrBinary,

    timeout: nl.AttrBinary,

    peer_measurements: nl.AttrBinary,

    airtime_weight: nl.AttrBinary,
    sta_tx_power_setting: nl.AttrBinary,
    sta_tx_power: nl.AttrBinary,

    sae_password: nl.AttrBinary,

    twt_responder: nl.AttrBinary,

    he_obss_pd: nl.AttrBinary,

    wiphy_edmg_channels: nl.AttrBinary,
    wiphy_edmg_bw_config: nl.AttrBinary,

    vlan_id: nl.AttrBinary,

    he_bss_color: nl.AttrBinary,

    iftype_akm_suites: nl.AttrBinary,

    tid_config: nl.AttrBinary,

    control_port_no_preauth: nl.AttrBinary,

    pmk_lifetime: nl.AttrBinary,
    pmk_reauth_threshold: nl.AttrBinary,

    receive_multicast: nl.AttrBinary,
    wiphy_freq_offset: u32,
    center_freq1_offset: nl.AttrBinary,
    scan_freq_khz: nl.AttrBinary,

    he_6ghz_capability: nl.AttrBinary,

    fils_discovery: nl.AttrBinary,

    unsol_bcast_probe_resp: nl.AttrBinary,

    s1g_capability: nl.AttrBinary,
    s1g_capability_mask: nl.AttrBinary,

    sae_pwe: nl.AttrBinary,

    reconnect_requested: nl.AttrBinary,

    sar_spec: nl.AttrBinary,

    disable_he: nl.AttrBinary,

    obss_color_bitmap: nl.AttrBinary,

    color_change_count: nl.AttrBinary,
    color_change_color: nl.AttrBinary,
    color_change_elems: nl.AttrBinary,

    mbssid_config: nl.AttrBinary,
    mbssid_elems: nl.AttrBinary,

    radar_background: nl.AttrBinary,

    ap_settings_flags: nl.AttrBinary,

    eht_capability: nl.AttrBinary,

    disable_eht: nl.AttrBinary,

    mlo_links: nl.AttrBinary,
    mlo_link_id: nl.AttrBinary,
    mld_addr: nl.AttrBinary,

    mlo_support: nl.AttrBinary,

    max_num_akm_suites: nl.AttrBinary,

    eml_capability: nl.AttrBinary,
    mld_capa_and_ops: nl.AttrBinary,

    tx_hw_timestamp: nl.AttrBinary,
    rx_hw_timestamp: nl.AttrBinary,
    td_bitmap: nl.AttrBinary,

    punct_bitmap: nl.AttrBinary,

    max_hw_timestamp_peers: nl.AttrBinary,
    hw_timestamp_enabled: nl.AttrBinary,

    ema_rnr_elems: nl.AttrBinary,

    mlo_link_disabled: nl.AttrBinary,

    bss_dump_include_use_data: nl.AttrBinary,

    mlo_ttlm_dlink: nl.AttrBinary,
    mlo_ttlm_ulink: nl.AttrBinary,

    assoc_spp_amsdu: nl.AttrBinary,

    wiphy_radios: nl.AttrBinary,
    wiphy_interface_combinations: nl.AttrBinary,

    vif_radio_mask: u32,
});

pub const Bss = nl.Attr(union(enum(nl.AttrBase)) {
    pub const BssId = struct {
        const Self = BssId;
        bytes: [6]u8,
        pub fn parse(parser: *Parser) !Self {
            const slice = try parser.parseSlice(6);
            return .{ .bytes = slice[0..6].* };
        }
        pub fn build(self: Self, builder: *Builder) !void {
            try builder.appendSlice(self.bytes[0..]);
        }
        pub fn format(self: Self, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
            const b = std.mem.asBytes(&self.bytes);
            try writer.print(
                "{x}:{x}:{x}:{x}:{x}:{x}",
                .{ b[0], b[1], b[2], b[3], b[4], b[5] },
            );
        }
    };

    __invalid: void,
    bssid: BssId, // BSSID of the BSS (6 octets)
    frequency: Unit(u32, .mega, .hertz), // frequency in MHz (u32)
    tsf: u64, // TSF of the received probe response/beacon (u64) (if .presp_data is present then this is known to be from a probe response, otherwise it may be from the same beacon that the .beacon_tsf will be from)
    beacon_interval: u16, // beacon interval of the (I)BSS (u16)
    capability: u16, // capability field (CPU order, u16)
    information_elements: nl.AttrBinary, // binary attribute containing the raw information elements from the probe response/beacon (bin); if the .beacon_ies attribute is present and the data is different then the IEs here are from a Probe Response frame; otherwise they are from a Beacon frame. However, if the driver does not indicate the source of the IEs, these IEs may be from either frame subtype. If present, the .presp_data attribute indicates that the data here is known to be from a probe response, without any heuristics.
    signal_mbm: UnitScaled(i32, .deci, .bel_milliwatt, 100), // signal strength of probe response/beacon in mBm (100 * dBm) (s32)
    signal_unspec: u8, // signal strength of the probe response/beacon in unspecified units, scaled to 0..100 (u8)
    status: nl.AttrBinary, // status, if this BSS is "used"
    seen_ms_ago: Unit(u32, .milli, .second), // age of this BSS entry in ms
    beacon_ies: nl.AttrBinary, // binary attribute containing the raw information elements from a Beacon frame (bin); not present if no Beacon frame has yet been received
    chan_width: u32, // channel width of the control channel (u32, ScanWidth) - No longer used!
    beacon_tsf: u64, // TSF of the last received beacon (u64) (not present if no beacon frame has been received yet)
    presp_data: void, // the data in .information_elements and .tsf is known to be from a probe response (flag attribute)
    last_seen_boottime: Unit(u64, .nano, .second), // CLOCK_BOOTTIME timestamp when this entry was last updated by a received frame. The value is expected to be accurate to about 10ms. (u64, nanoseconds)
    pad: nl.AttrBinary, // attribute used for padding for 64-bit alignment
    parent_tsf: u64, // the time at the start of reception of the first octet of the timestamp field of the last beacon/probe received for this BSS. The time is the TSF of the BSS specified by .parent_bssid. (u64).
    parent_bssid: BssId, // the BSS according to which .parent_tsf is set.
    chain_signal: nl.AttrNested(I8dBm), // per-chain signal strength of last BSS update. Contains a nested array of signal strength attributes (u8, dBm), using the nesting index as the antenna number.
    frequency_offset: Unit(u32, .kilo, .hertz), // frequency offset in KHz
    mlo_link_id: u8, // MLO link ID of the BSS (u8).
    mld_addr: nl.AttrBinary, // MLD address of this BSS if connected to it.
    use_for: nl.AttrBinary, // u32 bitmap attribute indicating what the BSS can be used for, see UseFor.
    cannot_use_reasons: nl.AttrBinary, // Indicates the reason that this BSS cannot be used for all or some of the possible uses by the device reporting it, even though its presence was detected. This is a u64 attribute containing a bitmap of values from .CannotUseReasons, note that the attribute may be missing if no reasons are specified.
});

pub const TxqStatsAttr = nl.Attr(union(enum(nl.AttrBase)) {
    _invalid: void, // attribute number 0 is reserved
    backlog_bytes: u32, // number of bytes currently backlogged
    backlog_packets: nl.AttrBinary, // number of packets currently backlogged
    flows: nl.AttrBinary, // total number of new flows seen
    drops: nl.AttrBinary, // total number of packet drops
    ecn_marks: nl.AttrBinary, // total number of packet ECN marks
    overlimit: nl.AttrBinary, // number of drops due to queue space overflow
    overmemory: nl.AttrBinary, // number of drops due to memory limit overflow (only for per-phy stats)
    collisions: nl.AttrBinary, // number of hash collisions
    tx_bytes: nl.AttrBinary, // total number of bytes dequeued from TXQ
    tx_packets: nl.AttrBinary, // total number of packets dequeued from TXQ
    max_flows: nl.AttrBinary, // number of flow buckets for PHY
});

const I8dBm = Unit(i8, .deci, .bel_milliwatt);
const U32Byte = Unit(u32, .none, .byte);
const U64Byte = Unit(u64, .none, .byte);

pub const StaInfo = nl.Attr(union(enum(nl.AttrBase)) {
    _invalid: void,
    inactive_time: Unit(u32, .milli, .second), // time since last activity (u32, msecs)
    rx_bytes: U32Byte, // total received bytes (MPDU length) (u32, from this station)
    tx_bytes: U32Byte, // total transmitted bytes (MPDU length) (u32, to this station)
    llid: nl.AttrBinary, // the station's mesh LLID
    plid: nl.AttrBinary, // the station's mesh PLID
    plink_state: nl.AttrBinary, // peer link state for the station (see %enum nl80211_plink_state)
    signal: I8dBm, // signal strength of last received PPDU (u8, dBm)
    tx_bitrate: nl.AttrNested(RateInfo), // current unicast tx rate, nested attribute containing info as possible, see &enum nl80211_rate_info
    rx_packets: u32, // total received packet (MSDUs and MMPDUs) (u32, from this station)
    tx_packets: u32, // total transmitted packets (MSDUs and MMPDUs) (u32, to this station)
    tx_retries: u32, // total retries (MPDUs) (u32, to this station)
    tx_failed: u32, // total failed packets (MPDUs) (u32, to this station)
    signal_avg: I8dBm, // signal strength average (u8, dBm)
    rx_bitrate: nl.AttrNested(RateInfo), // last unicast data frame rx rate, nested attribute, like .tx_bitrate.
    bss_param: nl.AttrBinary, // current station's view of BSS, nested attribute containing info as possible, see &enum nl80211_sta_bss_param
    connected_time: u32, // time since the station is last connected
    sta_flags: nl.AttrBinary, // Contains a struct nl80211_sta_flag_update.
    beacon_loss: u32, // count of times beacon loss was detected (u32)
    t_offset: i64, // timing offset with respect to this STA (s64)
    local_pm: nl.AttrBinary, // local mesh STA link-specific power mode
    peer_pm: nl.AttrBinary, // peer mesh STA link-specific power mode
    nonpeer_pm: nl.AttrBinary, // neighbor mesh STA power save mode towards non-peer STA
    rx_bytes64: U64Byte, // total received bytes (MPDU length) (u64, from this station)
    tx_bytes64: U64Byte, // total transmitted bytes (MPDU length) (u64, to this station)
    chain_signal: nl.AttrNestedArray(I8dBm), // per-chain signal strength of last PPDU. Contains a nested array of signal strength attributes (u8, dBm)
    chain_signal_avg: nl.AttrNestedArray(I8dBm), // per-chain signal strength average. Same format as .chain_signal.
    expected_throughput: Unit(u32, .kilo, .byte_per_second), // expected throughput considering also the 802.11 header (u32, kbps)
    rx_drop_misc: u64, // RX packets dropped for unspecified reasons
    beacon_rx: u64, // number of beacons received from this peer (u64)
    beacon_signal_avg: I8dBm, // signal strength average for beacons only (u8, dBm)
    tid_stats: nl.AttrBinary, // per-TID statistics (see &enum nl80211_tid_stats) This is a nested attribute where each the inner attribute number is the TID+1 and the special TID 16 (i.e. value 17) is used for non-QoS frames; each one of those is again nested with &enum nl80211_tid_stats attributes carrying the actual values.
    rx_duration: Unit(u64, .micro, .second), // aggregate PPDU duration for all frames received from the station (u64, usec)
    pad: nl.AttrBinary, // attribute used for padding for 64-bit alignment
    ack_signal: I8dBm, // signal strength of the last ACK frame(u8, dBm)
    ack_signal_avg: I8dBm, // avg signal strength of ACK frames (s8, dBm)
    rx_mpdus: u32, // total number of received packets (MPDUs) (u32, from this station)
    fcs_error_count: u32, // total number of packets (MPDUs) received with an FCS error (u32, from this station). This count may not include some packets with an FCS error due to TA corruption. Hence this counter might not be fully accurate.
    connected_to_gate: bool, // set to true if STA has a path to a mesh gate (u8, 0 or 1)
    tx_duration: Unit(u64, .micro, .second), // aggregate PPDU duration for all frames sent to the station (u64, usec)
    airtime_weight: u16, // current airtime weight for station (u16)
    airtime_link_metric: nl.AttrBinary, // airtime link metric for mesh station
    assoc_at_boottime: Unit(u64, .nano, .second), // Timestamp (CLOCK_BOOTTIME, nanoseconds) of STA's association
    connected_to_as: bool, // set to true if STA has a path to a authentication server (u8, 0 or 1)
});

pub const RateInfo = nl.Attr(union(enum(nl.AttrBase)) {
    _invalid: void,
    bitrate: UnitScaled(u16, .kilo, .bit_per_second, 100), // total bitrate (u16, 100kbit/s)
    mcs: u8, // mcs index for 802.11n (u8)
    @"40_mhz_width", // 40 MHz dualchannel bitrate
    short_gi, // 400ns guard interval
    bitrate32: UnitScaled(u32, .kilo, .bit_per_second, 100), // total bitrate (u32, 100kbit/s)
    vht_mcs: u8, // MCS index for VHT (u8)
    vht_nss: u8, // number of streams in VHT (u8)
    @"80_mhz_width", // 80 MHz VHT rate
    @"80p80_mhz_width", // unused - 80+80 is treated the same as 160 for purposes of the bitrates
    @"160_mhz_width", // 160 MHz VHT rate
    @"10_mhz_width", // 10 MHz width - note that this is a legacy rate and will be reported as the actual bitrate, i.e. half the base (20 MHz) rate
    @"5_mhz_width", // 5 MHz width - note that this is a legacy rate and will be reported as the actual bitrate, i.e. a quarter of the base (20 MHz) rate
    he_mcs: u8, // HE MCS index (u8, 0-11)
    he_nss: u8, // HE NSS value (u8, 1-8)
    he_gi: nl.AttrBinary, // HE guard interval identifier (u8, see &enum nl80211_he_gi)
    he_dcm: u8, // HE DCM value (u8, 0/1)
    he_ru_alloc: nl.AttrBinary, // HE RU allocation, if not present then non-OFDMA was used (u8, see &enum nl80211_he_ru_alloc)
    @"320_mhz_width", // 320 MHz bitrate
    eht_mcs: u8, // EHT MCS index (u8, 0-15)
    eht_nss: u8, // EHT NSS value (u8, 1-8)
    eht_gi: nl.AttrBinary, // EHT guard interval identifier (u8, see &enum nl80211_eht_gi)
    eht_ru_alloc: nl.AttrBinary, // EHT RU allocation, if not present then non-OFDMA was used (u8, see &enum nl80211_eht_ru_alloc)
    s1g_mcs: u8, // S1G MCS index (u8, 0-10)
    s1g_nss: u8, // S1G NSS value (u8, 1-4)
    @"1_mhz_width", // 1 MHz S1G rate
    @"2_mhz_width", // 2 MHz S1G rate
    @"4_mhz_width", // 4 MHz S1G rate
    @"8_mhz_width", // 8 MHz S1G rate
    @"16_mhz_width", // 16 MHz S1G rate
});
