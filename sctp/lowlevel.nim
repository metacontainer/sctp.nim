import sctp/compile, posix

const usrsctp = "<usrsctplib/usrsctp.h>"

include sctp/consts

type
  sctp_assoc_t* = uint32
  sctp_common_header* {.importc: "struct sctp_common_header", header: usrsctp, bycopy.} = object
    source_port* {.importc: "source_port".}: uint16
    destination_port* {.importc: "destination_port".}: uint16
    verification_tag* {.importc: "verification_tag".}: uint32
    crc32c* {.importc: "crc32c".}: uint32

  sockaddr_conn* {.importc: "struct sockaddr_conn", header: usrsctp, bycopy.} = object
    sconn_family* {.importc: "sconn_family".}: uint16
    sconn_port* {.importc: "sconn_port".}: uint16
    sconn_addr* {.importc: "sconn_addr".}: pointer

  sctp_sockstore* {.importc: "union sctp_sockstore", header: usrsctp, bycopy.} = object {.
      union.}
    sconn* {.importc: "sconn".}: sockaddr_conn
    #sa* {.importc: "sa".}: sockaddr

  sctp_rcvinfo* {.importc: "struct sctp_rcvinfo", header: usrsctp, bycopy.} = object
    rcv_sid* {.importc: "rcv_sid".}: uint16
    rcv_ssn* {.importc: "rcv_ssn".}: uint16
    rcv_flags* {.importc: "rcv_flags".}: uint16
    rcv_ppid* {.importc: "rcv_ppid".}: uint32
    rcv_tsn* {.importc: "rcv_tsn".}: uint32
    rcv_cumtsn* {.importc: "rcv_cumtsn".}: uint32
    rcv_context* {.importc: "rcv_context".}: uint32
    rcv_assoc_id* {.importc: "rcv_assoc_id".}: sctp_assoc_t

  sctp_nxtinfo* {.importc: "struct sctp_nxtinfo", header: usrsctp, bycopy.} = object
    nxt_sid* {.importc: "nxt_sid".}: uint16
    nxt_flags* {.importc: "nxt_flags".}: uint16
    nxt_ppid* {.importc: "nxt_ppid".}: uint32
    nxt_length* {.importc: "nxt_length".}: uint32
    nxt_assoc_id* {.importc: "nxt_assoc_id".}: sctp_assoc_t

  sctp_recvv_rn* {.importc: "struct sctp_recvv_rn", header: usrsctp, bycopy.} = object
    recvv_rcvinfo* {.importc: "recvv_rcvinfo".}: sctp_rcvinfo
    recvv_nxtinfo* {.importc: "recvv_nxtinfo".}: sctp_nxtinfo

  sctp_snd_all_completes* {.importc: "struct sctp_snd_all_completes", header: usrsctp,
                           bycopy.} = object
    sall_stream* {.importc: "sall_stream".}: uint16
    sall_flags* {.importc: "sall_flags".}: uint16
    sall_ppid* {.importc: "sall_ppid".}: uint32
    sall_context* {.importc: "sall_context".}: uint32
    sall_num_sent* {.importc: "sall_num_sent".}: uint32
    sall_num_failed* {.importc: "sall_num_failed".}: uint32

  sctp_sndinfo* {.importc: "struct sctp_sndinfo", header: usrsctp, bycopy.} = object
    snd_sid* {.importc: "snd_sid".}: uint16
    snd_flags* {.importc: "snd_flags".}: uint16
    snd_ppid* {.importc: "snd_ppid".}: uint32
    snd_context* {.importc: "snd_context".}: uint32
    snd_assoc_id* {.importc: "snd_assoc_id".}: sctp_assoc_t

  sctp_prinfo* {.importc: "struct sctp_prinfo", header: usrsctp, bycopy.} = object
    pr_policy* {.importc: "pr_policy".}: uint16
    pr_value* {.importc: "pr_value".}: uint32

  sctp_authinfo* {.importc: "struct sctp_authinfo", header: usrsctp, bycopy.} = object
    auth_keynumber* {.importc: "auth_keynumber".}: uint16

  sctp_sendv_spa* {.importc: "struct sctp_sendv_spa", header: usrsctp, bycopy.} = object
    sendv_flags* {.importc: "sendv_flags".}: uint32
    sendv_sndinfo* {.importc: "sendv_sndinfo".}: sctp_sndinfo
    sendv_prinfo* {.importc: "sendv_prinfo".}: sctp_prinfo
    sendv_authinfo* {.importc: "sendv_authinfo".}: sctp_authinfo

  sctp_udpencaps* {.importc: "struct sctp_udpencaps", header: usrsctp, bycopy.} = object
    sue_address* {.importc: "sue_address".}: SockaddrStorage
    sue_assoc_id* {.importc: "sue_assoc_id".}: uint32
    sue_port* {.importc: "sue_port".}: uint16

  sctp_assoc_change* {.importc: "struct sctp_assoc_change", header: usrsctp, bycopy.} = object
    sac_type* {.importc: "sac_type".}: uint16
    sac_flags* {.importc: "sac_flags".}: uint16
    sac_length* {.importc: "sac_length".}: uint32
    sac_state* {.importc: "sac_state".}: uint16
    sac_error* {.importc: "sac_error".}: uint16
    sac_outbound_streams* {.importc: "sac_outbound_streams".}: uint16
    sac_inbound_streams* {.importc: "sac_inbound_streams".}: uint16
    sac_assoc_id* {.importc: "sac_assoc_id".}: sctp_assoc_t
    sac_info* {.importc: "sac_info".}: ptr uint8

  sctp_paddr_change* {.importc: "struct sctp_paddr_change", header: usrsctp, bycopy.} = object
    spc_type* {.importc: "spc_type".}: uint16
    spc_flags* {.importc: "spc_flags".}: uint16
    spc_length* {.importc: "spc_length".}: uint32
    spc_aaddr* {.importc: "spc_aaddr".}: SockaddrStorage
    spc_state* {.importc: "spc_state".}: uint32
    spc_error* {.importc: "spc_error".}: uint32
    spc_assoc_id* {.importc: "spc_assoc_id".}: sctp_assoc_t
    spc_padding* {.importc: "spc_padding".}: array[4, uint8]

  sctp_remote_error* {.importc: "struct sctp_remote_error", header: usrsctp, bycopy.} = object
    sre_type* {.importc: "sre_type".}: uint16
    sre_flags* {.importc: "sre_flags".}: uint16
    sre_length* {.importc: "sre_length".}: uint32
    sre_error* {.importc: "sre_error".}: uint16
    sre_assoc_id* {.importc: "sre_assoc_id".}: sctp_assoc_t
    sre_data* {.importc: "sre_data".}: array[4, uint8]

  sctp_shutdown_event* {.importc: "struct sctp_shutdown_event", header: usrsctp, bycopy.} = object
    sse_type* {.importc: "sse_type".}: uint16
    sse_flags* {.importc: "sse_flags".}: uint16
    sse_length* {.importc: "sse_length".}: uint32
    sse_assoc_id* {.importc: "sse_assoc_id".}: sctp_assoc_t

  sctp_adaptation_event* {.importc: "struct sctp_adaptation_event", header: usrsctp, bycopy.} = object
    sai_type* {.importc: "sai_type".}: uint16
    sai_flags* {.importc: "sai_flags".}: uint16
    sai_length* {.importc: "sai_length".}: uint32
    sai_adaptation_ind* {.importc: "sai_adaptation_ind".}: uint32
    sai_assoc_id* {.importc: "sai_assoc_id".}: sctp_assoc_t

  sctp_pdapi_event* {.importc: "struct sctp_pdapi_event", header: usrsctp, bycopy.} = object
    pdapi_type* {.importc: "pdapi_type".}: uint16
    pdapi_flags* {.importc: "pdapi_flags".}: uint16
    pdapi_length* {.importc: "pdapi_length".}: uint32
    pdapi_indication* {.importc: "pdapi_indication".}: uint32
    pdapi_stream* {.importc: "pdapi_stream".}: uint32
    pdapi_seq* {.importc: "pdapi_seq".}: uint32
    pdapi_assoc_id* {.importc: "pdapi_assoc_id".}: sctp_assoc_t

  sctp_authkey_event* {.importc: "struct sctp_authkey_event", header: usrsctp, bycopy.} = object
    auth_type* {.importc: "auth_type".}: uint16
    auth_flags* {.importc: "auth_flags".}: uint16
    auth_length* {.importc: "auth_length".}: uint32
    auth_keynumber* {.importc: "auth_keynumber".}: uint16
    auth_indication* {.importc: "auth_indication".}: uint32
    auth_assoc_id* {.importc: "auth_assoc_id".}: sctp_assoc_t

  sctp_sender_dry_event* {.importc: "struct sctp_sender_dry_event", header: usrsctp, bycopy.} = object
    sender_dry_type* {.importc: "sender_dry_type".}: uint16
    sender_dry_flags* {.importc: "sender_dry_flags".}: uint16
    sender_dry_length* {.importc: "sender_dry_length".}: uint32
    sender_dry_assoc_id* {.importc: "sender_dry_assoc_id".}: sctp_assoc_t

  sctp_stream_reset_event* {.importc: "struct sctp_stream_reset_event", header: usrsctp,
                            bycopy.} = object
    strreset_type* {.importc: "strreset_type".}: uint16
    strreset_flags* {.importc: "strreset_flags".}: uint16
    strreset_length* {.importc: "strreset_length".}: uint32
    strreset_assoc_id* {.importc: "strreset_assoc_id".}: sctp_assoc_t
    strreset_stream_list* {.importc: "strreset_stream_list".}: ptr uint16

  sctp_assoc_reset_event* {.importc: "struct sctp_assoc_reset_event", header: usrsctp,
                           bycopy.} = object
    assocreset_type* {.importc: "assocreset_type".}: uint16
    assocreset_flags* {.importc: "assocreset_flags".}: uint16
    assocreset_length* {.importc: "assocreset_length".}: uint32
    assocreset_assoc_id* {.importc: "assocreset_assoc_id".}: sctp_assoc_t
    assocreset_local_tsn* {.importc: "assocreset_local_tsn".}: uint32
    assocreset_remote_tsn* {.importc: "assocreset_remote_tsn".}: uint32

  sctp_stream_change_event* {.importc: "struct sctp_stream_change_event", header: usrsctp,
                             bycopy.} = object
    strchange_type* {.importc: "strchange_type".}: uint16
    strchange_flags* {.importc: "strchange_flags".}: uint16
    strchange_length* {.importc: "strchange_length".}: uint32
    strchange_assoc_id* {.importc: "strchange_assoc_id".}: sctp_assoc_t
    strchange_instrms* {.importc: "strchange_instrms".}: uint16
    strchange_outstrms* {.importc: "strchange_outstrms".}: uint16

  sctp_send_failed_event* {.importc: "struct sctp_send_failed_event", header: usrsctp,
                           bycopy.} = object
    ssfe_type* {.importc: "ssfe_type".}: uint16
    ssfe_flags* {.importc: "ssfe_flags".}: uint16
    ssfe_length* {.importc: "ssfe_length".}: uint32
    ssfe_error* {.importc: "ssfe_error".}: uint32
    ssfe_info* {.importc: "ssfe_info".}: sctp_sndinfo
    ssfe_assoc_id* {.importc: "ssfe_assoc_id".}: sctp_assoc_t
    ssfe_data* {.importc: "ssfe_data".}: ptr uint8

  sctp_event* {.importc: "struct sctp_event", header: usrsctp, bycopy.} = object
    se_assoc_id* {.importc: "se_assoc_id".}: sctp_assoc_t
    se_type* {.importc: "se_type".}: uint16
    se_on* {.importc: "se_on".}: uint8

  sctp_tlv_3794735878* {.importc: "no_name", header: usrsctp, bycopy.} = object
    sn_type* {.importc: "sn_type".}: uint16
    sn_flags* {.importc: "sn_flags".}: uint16
    sn_length* {.importc: "sn_length".}: uint32

  sctp_notification* {.importc: "struct sctp_notification", header: usrsctp, bycopy.} = object {.
      union.}
    sn_header* {.importc: "sn_header".}: sctp_tlv_3794735878
    sn_assoc_change* {.importc: "sn_assoc_change".}: sctp_assoc_change
    sn_paddr_change* {.importc: "sn_paddr_change".}: sctp_paddr_change
    sn_remote_error* {.importc: "sn_remote_error".}: sctp_remote_error
    sn_shutdown_event* {.importc: "sn_shutdown_event".}: sctp_shutdown_event
    sn_adaptation_event* {.importc: "sn_adaptation_event".}: sctp_adaptation_event
    sn_pdapi_event* {.importc: "sn_pdapi_event".}: sctp_pdapi_event
    sn_auth_event* {.importc: "sn_auth_event".}: sctp_authkey_event
    sn_sender_dry_event* {.importc: "sn_sender_dry_event".}: sctp_sender_dry_event
    sn_send_failed_event* {.importc: "sn_send_failed_event".}: sctp_send_failed_event
    sn_strreset_event* {.importc: "sn_strreset_event".}: sctp_stream_reset_event
    sn_assocreset_event* {.importc: "sn_assocreset_event".}: sctp_assoc_reset_event
    sn_strchange_event* {.importc: "sn_strchange_event".}: sctp_stream_change_event

  sctp_event_subscribe* {.importc: "struct sctp_event_subscribe", header: usrsctp, bycopy.} = object
    sctp_data_io_event* {.importc: "struct sctp_data_io_event".}: uint8
    sctp_association_event* {.importc: "struct sctp_association_event".}: uint8
    sctp_address_event* {.importc: "struct sctp_address_event".}: uint8
    sctp_send_failure_event* {.importc: "struct sctp_send_failure_event".}: uint8
    sctp_peer_error_event* {.importc: "struct sctp_peer_error_event".}: uint8
    sctp_shutdown_event* {.importc: "struct sctp_shutdown_event".}: uint8
    sctp_partial_delivery_event* {.importc: "struct sctp_partial_delivery_event".}: uint8
    sctp_adaptation_layer_event* {.importc: "struct sctp_adaptation_layer_event".}: uint8
    sctp_authentication_event* {.importc: "struct sctp_authentication_event".}: uint8
    sctp_sender_dry_event* {.importc: "struct sctp_sender_dry_event".}: uint8
    sctp_stream_reset_event* {.importc: "struct sctp_stream_reset_event".}: uint8

  sctp_initmsg* {.importc: "struct sctp_initmsg", header: usrsctp, bycopy.} = object
    sinit_num_ostreams* {.importc: "sinit_num_ostreams".}: uint16
    sinit_max_instreams* {.importc: "sinit_max_instreams".}: uint16
    sinit_max_attempts* {.importc: "sinit_max_attempts".}: uint16
    sinit_max_init_timeo* {.importc: "sinit_max_init_timeo".}: uint16

  sctp_rtoinfo* {.importc: "struct sctp_rtoinfo", header: usrsctp, bycopy.} = object
    srto_assoc_id* {.importc: "srto_assoc_id".}: sctp_assoc_t
    srto_initial* {.importc: "srto_initial".}: uint32
    srto_max* {.importc: "srto_max".}: uint32
    srto_min* {.importc: "srto_min".}: uint32

  sctp_assocparams* {.importc: "struct sctp_assocparams", header: usrsctp, bycopy.} = object
    sasoc_assoc_id* {.importc: "sasoc_assoc_id".}: sctp_assoc_t
    sasoc_peer_rwnd* {.importc: "sasoc_peer_rwnd".}: uint32
    sasoc_local_rwnd* {.importc: "sasoc_local_rwnd".}: uint32
    sasoc_cookie_life* {.importc: "sasoc_cookie_life".}: uint32
    sasoc_asocmaxrxt* {.importc: "sasoc_asocmaxrxt".}: uint16
    sasoc_number_peer_destinations* {.importc: "sasoc_number_peer_destinations".}: uint16

  sctp_setprim* {.importc: "struct sctp_setprim", header: usrsctp, bycopy.} = object
    ssp_addr* {.importc: "ssp_addr".}: SockaddrStorage
    ssp_assoc_id* {.importc: "ssp_assoc_id".}: sctp_assoc_t
    ssp_padding* {.importc: "ssp_padding".}: array[4, uint8]

  sctp_setadaptation* {.importc: "struct sctp_setadaptation", header: usrsctp, bycopy.} = object
    ssb_adaptation_ind* {.importc: "ssb_adaptation_ind".}: uint32

  sctp_paddrparams* {.importc: "struct sctp_paddrparams", header: usrsctp, bycopy.} = object
    spp_address* {.importc: "spp_address".}: SockaddrStorage
    spp_assoc_id* {.importc: "spp_assoc_id".}: sctp_assoc_t
    spp_hbinterval* {.importc: "spp_hbinterval".}: uint32
    spp_pathmtu* {.importc: "spp_pathmtu".}: uint32
    spp_flags* {.importc: "spp_flags".}: uint32
    spp_ipv6_flowlabel* {.importc: "spp_ipv6_flowlabel".}: uint32
    spp_pathmaxrxt* {.importc: "spp_pathmaxrxt".}: uint16
    spp_dscp* {.importc: "spp_dscp".}: uint8

  sctp_assoc_value* {.importc: "struct sctp_assoc_value", header: usrsctp, bycopy.} = object
    assoc_id* {.importc: "assoc_id".}: sctp_assoc_t
    assoc_value* {.importc: "assoc_value".}: uint32

  sctp_reset_streams* {.importc: "struct sctp_reset_streams", header: usrsctp, bycopy.} = object
    srs_assoc_id* {.importc: "srs_assoc_id".}: sctp_assoc_t
    srs_flags* {.importc: "srs_flags".}: uint16
    srs_number_streams* {.importc: "srs_number_streams".}: uint16
    srs_stream_list* {.importc: "srs_stream_list".}: ptr uint16

  sctp_add_streams* {.importc: "struct sctp_add_streams", header: usrsctp, bycopy.} = object
    sas_assoc_id* {.importc: "sas_assoc_id".}: sctp_assoc_t
    sas_instrms* {.importc: "sas_instrms".}: uint16
    sas_outstrms* {.importc: "sas_outstrms".}: uint16

  sctp_hmacalgo* {.importc: "struct sctp_hmacalgo", header: usrsctp, bycopy.} = object
    shmac_number_of_idents* {.importc: "shmac_number_of_idents".}: uint32
    shmac_idents* {.importc: "shmac_idents".}: ptr uint16

  sctp_sack_info* {.importc: "struct sctp_sack_info", header: usrsctp, bycopy.} = object
    sack_assoc_id* {.importc: "sack_assoc_id".}: sctp_assoc_t
    sack_delay* {.importc: "sack_delay".}: uint32
    sack_freq* {.importc: "sack_freq".}: uint32

  sctp_default_prinfo* {.importc: "struct sctp_default_prinfo", header: usrsctp, bycopy.} = object
    pr_policy* {.importc: "pr_policy".}: uint16
    pr_value* {.importc: "pr_value".}: uint32
    pr_assoc_id* {.importc: "pr_assoc_id".}: sctp_assoc_t

  sctp_paddrinfo* {.importc: "struct sctp_paddrinfo", header: usrsctp, bycopy.} = object
    spinfo_address* {.importc: "spinfo_address".}: SockaddrStorage
    spinfo_assoc_id* {.importc: "spinfo_assoc_id".}: sctp_assoc_t
    spinfo_state* {.importc: "spinfo_state".}: int32
    spinfo_cwnd* {.importc: "spinfo_cwnd".}: uint32
    spinfo_srtt* {.importc: "spinfo_srtt".}: uint32
    spinfo_rto* {.importc: "spinfo_rto".}: uint32
    spinfo_mtu* {.importc: "spinfo_mtu".}: uint32

  sctp_status* {.importc: "struct sctp_status", header: usrsctp, bycopy.} = object
    sstat_assoc_id* {.importc: "sstat_assoc_id".}: sctp_assoc_t
    sstat_state* {.importc: "sstat_state".}: int32
    sstat_rwnd* {.importc: "sstat_rwnd".}: uint32
    sstat_unackdata* {.importc: "sstat_unackdata".}: uint16
    sstat_penddata* {.importc: "sstat_penddata".}: uint16
    sstat_instrms* {.importc: "sstat_instrms".}: uint16
    sstat_outstrms* {.importc: "sstat_outstrms".}: uint16
    sstat_fragmentation_point* {.importc: "sstat_fragmentation_point".}: uint32
    sstat_primary* {.importc: "sstat_primary".}: sctp_paddrinfo

  sctp_authchunks* {.importc: "struct sctp_authchunks", header: usrsctp, bycopy.} = object
    gauth_assoc_id* {.importc: "gauth_assoc_id".}: sctp_assoc_t
    gauth_chunks* {.importc: "gauth_chunks".}: ptr uint8

  sctp_assoc_ids* {.importc: "struct sctp_assoc_ids", header: usrsctp, bycopy.} = object
    gaids_number_of_ids* {.importc: "gaids_number_of_ids".}: uint32
    gaids_assoc_id* {.importc: "gaids_assoc_id".}: ptr sctp_assoc_t

  sctp_setpeerprim* {.importc: "struct sctp_setpeerprim", header: usrsctp, bycopy.} = object
    sspp_addr* {.importc: "sspp_addr".}: SockaddrStorage
    sspp_assoc_id* {.importc: "sspp_assoc_id".}: sctp_assoc_t
    sspp_padding* {.importc: "sspp_padding".}: array[4, uint8]

  sctp_authchunk* {.importc: "struct sctp_authchunk", header: usrsctp, bycopy.} = object
    sauth_chunk* {.importc: "sauth_chunk".}: uint8

  sctp_get_nonce_values* {.importc: "struct sctp_get_nonce_values", header: usrsctp, bycopy.} = object
    gn_assoc_id* {.importc: "gn_assoc_id".}: sctp_assoc_t
    gn_peers_tag* {.importc: "gn_peers_tag".}: uint32
    gn_local_tag* {.importc: "gn_local_tag".}: uint32

  sctp_authkey* {.importc: "struct sctp_authkey", header: usrsctp, bycopy.} = object
    sca_assoc_id* {.importc: "sca_assoc_id".}: sctp_assoc_t
    sca_keynumber* {.importc: "sca_keynumber".}: uint16
    sca_keylength* {.importc: "sca_keylength".}: uint16
    sca_key* {.importc: "sca_key".}: ptr uint8

  sctp_authkeyid* {.importc: "struct sctp_authkeyid", header: usrsctp, bycopy.} = object
    scact_assoc_id* {.importc: "scact_assoc_id".}: sctp_assoc_t
    scact_keynumber* {.importc: "scact_keynumber".}: uint16

  sctp_cc_option* {.importc: "struct sctp_cc_option", header: usrsctp, bycopy.} = object
    option* {.importc: "option".}: cint
    aid_value* {.importc: "aid_value".}: sctp_assoc_value

  sctp_stream_value* {.importc: "struct sctp_stream_value", header: usrsctp, bycopy.} = object
    assoc_id* {.importc: "assoc_id".}: sctp_assoc_t
    stream_id* {.importc: "stream_id".}: uint16
    stream_value* {.importc: "stream_value".}: uint16

  sctp_timeouts* {.importc: "struct sctp_timeouts", header: usrsctp, bycopy.} = object
    stimo_assoc_id* {.importc: "stimo_assoc_id".}: sctp_assoc_t
    stimo_init* {.importc: "stimo_init".}: uint32
    stimo_data* {.importc: "stimo_data".}: uint32
    stimo_sack* {.importc: "stimo_sack".}: uint32
    stimo_shutdown* {.importc: "stimo_shutdown".}: uint32
    stimo_heartbeat* {.importc: "stimo_heartbeat".}: uint32
    stimo_cookie* {.importc: "stimo_cookie".}: uint32
    stimo_shutdownack* {.importc: "stimo_shutdownack".}: uint32

  sctp_prstatus* {.importc: "struct sctp_prstatus", header: usrsctp, bycopy.} = object
    sprstat_assoc_id* {.importc: "sprstat_assoc_id".}: sctp_assoc_t
    sprstat_sid* {.importc: "sprstat_sid".}: uint16
    sprstat_policy* {.importc: "sprstat_policy".}: uint16
    sprstat_abandoned_unsent* {.importc: "sprstat_abandoned_unsent".}: uint64
    sprstat_abandoned_sent* {.importc: "sprstat_abandoned_sent".}: uint64

  sctp_socket* = object
  socket = sctp_socket

proc usrsctp_init*(a2: uint16; a3: proc (`addr`: pointer; buffer: pointer;
                                      length: csize; tos: uint8; set_df: uint8): cint {.cdecl.};
                  a4: proc (format: cstring) {.varargs, cdecl.}) {.importc: "usrsctp_init",
    header: usrsctp.}
proc usrsctp_socket*(domain: cint; `type`: cint; protocol: cint; receive_cb: proc (
    sock: ptr socket; `addr`: sctp_sockstore; data: pointer; datalen: csize;
    a6: sctp_rcvinfo; flags: cint; ulp_info: pointer): cint {.cdecl.};
                    send_cb: proc (sock: ptr socket; sb_free: uint32): cint {.cdecl.};
                    sb_threshold: uint32; ulp_info: pointer): ptr socket {.
    importc: "usrsctp_socket", header: usrsctp.}
proc usrsctp_setsockopt*(so: ptr socket; level: cint; option_name: cint;
                        option_value: pointer; option_len: Socklen): cint {.
    importc: "usrsctp_setsockopt", header: usrsctp.}
proc usrsctp_getsockopt*(so: ptr socket; level: cint; option_name: cint;
                        option_value: pointer; option_len: ptr Socklen): cint {.
    importc: "usrsctp_getsockopt", header: usrsctp.}
proc usrsctp_opt_info*(so: ptr socket; id: sctp_assoc_t; opt: cint; arg: pointer;
                      size: ptr Socklen): cint {.importc: "usrsctp_opt_info",
    header: usrsctp.}
proc usrsctp_getpaddrs*(so: ptr socket; id: sctp_assoc_t; raddrs: ptr ptr Sockaddr): cint {.
    importc: "usrsctp_getpaddrs", header: usrsctp.}
proc usrsctp_freepaddrs*(addrs: ptr Sockaddr) {.importc: "usrsctp_freepaddrs",
    header: usrsctp.}
proc usrsctp_getladdrs*(so: ptr socket; id: sctp_assoc_t; raddrs: ptr ptr Sockaddr): cint {.
    importc: "usrsctp_getladdrs", header: usrsctp.}
proc usrsctp_freeladdrs*(addrs: ptr Sockaddr) {.importc: "usrsctp_freeladdrs",
    header: usrsctp.}
proc usrsctp_sendv*(so: ptr socket; data: pointer; len: csize; to: ptr Sockaddr;
                   addrcnt: cint; info: pointer; infolen: Socklen; infotype: cuint;
                   flags: cint): int {.importc: "usrsctp_sendv", header: usrsctp.}
proc usrsctp_recvv*(so: ptr socket; dbuf: pointer; len: csize; `from`: ptr Sockaddr;
                   fromlen: ptr Socklen; info: pointer; infolen: ptr Socklen;
                   infotype: ptr cuint; msg_flags: ptr cint): int {.
    importc: "usrsctp_recvv", header: usrsctp.}
proc usrsctp_bind*(so: ptr socket; name: ptr Sockaddr; namelen: Socklen): cint {.
    importc: "usrsctp_bind", header: usrsctp.}
proc usrsctp_bindx*(so: ptr socket; addrs: ptr Sockaddr; addrcnt: cint; flags: cint): cint {.
    importc: "usrsctp_bindx", header: usrsctp.}
proc usrsctp_listen*(so: ptr socket; backlog: cint): cint {.importc: "usrsctp_listen",
    header: usrsctp.}
proc usrsctp_accept*(so: ptr socket; aname: ptr Sockaddr; anamelen: ptr Socklen): ptr socket {.
    importc: "usrsctp_accept", header: usrsctp.}
proc usrsctp_peeloff*(a2: ptr socket; a3: sctp_assoc_t): ptr socket {.
    importc: "usrsctp_peeloff", header: usrsctp.}
proc usrsctp_connect*(so: ptr socket; name: ptr Sockaddr; namelen: Socklen): cint {.
    importc: "usrsctp_connect", header: usrsctp.}
proc usrsctp_connectx*(so: ptr socket; addrs: ptr Sockaddr; addrcnt: cint;
                      id: ptr sctp_assoc_t): cint {.importc: "usrsctp_connectx",
    header: usrsctp.}
proc usrsctp_close*(so: ptr socket) {.importc: "usrsctp_close", header: usrsctp.}
proc usrsctp_getassocid*(a2: ptr socket; a3: ptr Sockaddr): sctp_assoc_t {.
    importc: "usrsctp_getassocid", header: usrsctp.}
proc usrsctp_finish*(): cint {.importc: "usrsctp_finish", header: usrsctp.}
proc usrsctp_shutdown*(so: ptr socket; how: cint): cint {.importc: "usrsctp_shutdown",
    header: usrsctp.}
proc usrsctp_conninput*(a2: pointer; a3: pointer; a4: csize; a5: uint8) {.
    importc: "usrsctp_conninput", header: usrsctp.}
proc usrsctp_set_non_blocking*(a2: ptr socket; a3: cint): cint {.
    importc: "usrsctp_set_non_blocking", header: usrsctp.}
proc usrsctp_get_non_blocking*(a2: ptr socket): cint {.
    importc: "usrsctp_get_non_blocking", header: usrsctp.}
proc usrsctp_register_address*(a2: pointer) {.importc: "usrsctp_register_address",
    header: usrsctp.}
proc usrsctp_deregister_address*(a2: pointer) {.
    importc: "usrsctp_deregister_address", header: usrsctp.}
proc usrsctp_set_ulpinfo*(a2: ptr socket; a3: pointer): cint {.
    importc: "usrsctp_set_ulpinfo", header: usrsctp.}
proc usrsctp_dumppacket*(a2: pointer; a3: csize; a4: cint): cstring {.
    importc: "usrsctp_dumppacket", header: usrsctp.}
proc usrsctp_freedumpbuffer*(a2: cstring) {.importc: "usrsctp_freedumpbuffer",
    header: usrsctp.}
proc usrsctp_enable_crc32c_offload*() {.importc: "usrsctp_enable_crc32c_offload",
                                      header: usrsctp.}
proc usrsctp_disable_crc32c_offload*() {.importc: "usrsctp_disable_crc32c_offload",
                                       header: usrsctp.}
proc usrsctp_crc32c*(a2: pointer; a3: csize): uint32 {.importc: "usrsctp_crc32c",
    header: usrsctp.}
proc usrsctp_sysctl_set_sctp_sendspace*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_sendspace", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_sendspace*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_sendspace", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_recvspace*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_recvspace", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_recvspace*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_recvspace", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_auto_asconf*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_auto_asconf", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_auto_asconf*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_auto_asconf", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_multiple_asconfs*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_multiple_asconfs", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_multiple_asconfs*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_multiple_asconfs", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_ecn_enable*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_ecn_enable", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_ecn_enable*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_ecn_enable", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_pr_enable*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_pr_enable", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_pr_enable*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_pr_enable", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_auth_enable*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_auth_enable", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_auth_enable*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_auth_enable", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_asconf_enable*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_asconf_enable", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_asconf_enable*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_asconf_enable", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_reconfig_enable*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_reconfig_enable", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_reconfig_enable*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_reconfig_enable", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_nrsack_enable*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_nrsack_enable", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_nrsack_enable*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_nrsack_enable", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_pktdrop_enable*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_pktdrop_enable", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_pktdrop_enable*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_pktdrop_enable", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_no_csum_on_loopback*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_no_csum_on_loopback", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_no_csum_on_loopback*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_no_csum_on_loopback", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_peer_chunk_oh*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_peer_chunk_oh", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_peer_chunk_oh*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_peer_chunk_oh", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_max_burst_default*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_max_burst_default", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_max_burst_default*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_max_burst_default", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_max_chunks_on_queue*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_max_chunks_on_queue", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_max_chunks_on_queue*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_max_chunks_on_queue", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_hashtblsize*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_hashtblsize", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_hashtblsize*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_hashtblsize", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_pcbtblsize*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_pcbtblsize", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_pcbtblsize*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_pcbtblsize", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_min_split_point*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_min_split_point", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_min_split_point*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_min_split_point", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_chunkscale*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_chunkscale", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_chunkscale*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_chunkscale", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_delayed_sack_time_default*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_delayed_sack_time_default", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_delayed_sack_time_default*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_delayed_sack_time_default", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_sack_freq_default*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_sack_freq_default", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_sack_freq_default*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_sack_freq_default", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_system_free_resc_limit*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_system_free_resc_limit", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_system_free_resc_limit*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_system_free_resc_limit", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_asoc_free_resc_limit*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_asoc_free_resc_limit", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_asoc_free_resc_limit*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_asoc_free_resc_limit", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_heartbeat_interval_default*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_heartbeat_interval_default", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_heartbeat_interval_default*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_heartbeat_interval_default", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_pmtu_raise_time_default*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_pmtu_raise_time_default", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_pmtu_raise_time_default*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_pmtu_raise_time_default", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_shutdown_guard_time_default*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_shutdown_guard_time_default",
    header: usrsctp.}
proc usrsctp_sysctl_get_sctp_shutdown_guard_time_default*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_shutdown_guard_time_default",
    header: usrsctp.}
proc usrsctp_sysctl_set_sctp_secret_lifetime_default*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_secret_lifetime_default", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_secret_lifetime_default*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_secret_lifetime_default", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_rto_max_default*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_rto_max_default", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_rto_max_default*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_rto_max_default", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_rto_min_default*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_rto_min_default", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_rto_min_default*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_rto_min_default", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_rto_initial_default*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_rto_initial_default", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_rto_initial_default*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_rto_initial_default", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_init_rto_max_default*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_init_rto_max_default", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_init_rto_max_default*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_init_rto_max_default", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_valid_cookie_life_default*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_valid_cookie_life_default", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_valid_cookie_life_default*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_valid_cookie_life_default", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_init_rtx_max_default*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_init_rtx_max_default", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_init_rtx_max_default*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_init_rtx_max_default", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_assoc_rtx_max_default*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_assoc_rtx_max_default", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_assoc_rtx_max_default*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_assoc_rtx_max_default", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_path_rtx_max_default*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_path_rtx_max_default", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_path_rtx_max_default*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_path_rtx_max_default", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_add_more_threshold*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_add_more_threshold", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_add_more_threshold*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_add_more_threshold", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_nr_incoming_streams_default*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_nr_incoming_streams_default",
    header: usrsctp.}
proc usrsctp_sysctl_get_sctp_nr_incoming_streams_default*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_nr_incoming_streams_default",
    header: usrsctp.}
proc usrsctp_sysctl_set_sctp_nr_outgoing_streams_default*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_nr_outgoing_streams_default",
    header: usrsctp.}
proc usrsctp_sysctl_get_sctp_nr_outgoing_streams_default*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_nr_outgoing_streams_default",
    header: usrsctp.}
proc usrsctp_sysctl_set_sctp_cmt_on_off*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_cmt_on_off", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_cmt_on_off*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_cmt_on_off", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_cmt_use_dac*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_cmt_use_dac", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_cmt_use_dac*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_cmt_use_dac", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_use_cwnd_based_maxburst*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_use_cwnd_based_maxburst", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_use_cwnd_based_maxburst*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_use_cwnd_based_maxburst", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_nat_friendly*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_nat_friendly", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_nat_friendly*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_nat_friendly", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_L2_abc_variable*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_L2_abc_variable", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_L2_abc_variable*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_L2_abc_variable", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_mbuf_threshold_count*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_mbuf_threshold_count", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_mbuf_threshold_count*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_mbuf_threshold_count", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_do_drain*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_do_drain", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_do_drain*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_do_drain", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_hb_maxburst*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_hb_maxburst", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_hb_maxburst*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_hb_maxburst", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_abort_if_one_2_one_hits_limit*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_abort_if_one_2_one_hits_limit",
    header: usrsctp.}
proc usrsctp_sysctl_get_sctp_abort_if_one_2_one_hits_limit*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_abort_if_one_2_one_hits_limit",
    header: usrsctp.}
proc usrsctp_sysctl_set_sctp_min_residual*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_min_residual", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_min_residual*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_min_residual", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_max_retran_chunk*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_max_retran_chunk", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_max_retran_chunk*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_max_retran_chunk", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_logging_level*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_logging_level", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_logging_level*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_logging_level", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_default_cc_module*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_default_cc_module", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_default_cc_module*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_default_cc_module", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_default_frag_interleave*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_default_frag_interleave", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_default_frag_interleave*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_default_frag_interleave", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_mobility_base*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_mobility_base", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_mobility_base*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_mobility_base", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_mobility_fasthandoff*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_mobility_fasthandoff", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_mobility_fasthandoff*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_mobility_fasthandoff", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_inits_include_nat_friendly*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_inits_include_nat_friendly", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_inits_include_nat_friendly*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_inits_include_nat_friendly", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_udp_tunneling_port*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_udp_tunneling_port", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_udp_tunneling_port*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_udp_tunneling_port", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_enable_sack_immediately*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_enable_sack_immediately", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_enable_sack_immediately*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_enable_sack_immediately", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_vtag_time_wait*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_vtag_time_wait", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_vtag_time_wait*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_vtag_time_wait", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_blackhole*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_blackhole", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_blackhole*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_blackhole", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_diag_info_code*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_diag_info_code", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_diag_info_code*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_diag_info_code", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_fr_max_burst_default*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_fr_max_burst_default", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_fr_max_burst_default*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_fr_max_burst_default", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_path_pf_threshold*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_path_pf_threshold", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_path_pf_threshold*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_path_pf_threshold", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_default_ss_module*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_default_ss_module", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_default_ss_module*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_default_ss_module", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_rttvar_bw*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_rttvar_bw", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_rttvar_bw*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_rttvar_bw", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_rttvar_rtt*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_rttvar_rtt", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_rttvar_rtt*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_rttvar_rtt", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_rttvar_eqret*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_rttvar_eqret", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_rttvar_eqret*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_rttvar_eqret", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_steady_step*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_steady_step", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_steady_step*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_steady_step", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_use_dccc_ecn*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_use_dccc_ecn", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_use_dccc_ecn*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_use_dccc_ecn", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_buffer_splitting*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_buffer_splitting", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_buffer_splitting*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_buffer_splitting", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_initial_cwnd*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_initial_cwnd", header: usrsctp.}
proc usrsctp_sysctl_get_sctp_initial_cwnd*(): uint32 {.
    importc: "usrsctp_sysctl_get_sctp_initial_cwnd", header: usrsctp.}
proc usrsctp_sysctl_set_sctp_debug_on*(value: uint32) {.
    importc: "usrsctp_sysctl_set_sctp_debug_on", header: usrsctp.}

type
  sctp_timeval* {.importc: "struct sctp_timeval", header: usrsctp, bycopy.} = object
    tv_sec* {.importc: "tv_sec".}: uint32
    tv_usec* {.importc: "tv_usec".}: uint32

  sctpstat* {.importc: "sctpstat", header: usrsctp, bycopy.} = object
    sctps_discontinuitytime* {.importc: "sctps_discontinuitytime".}: sctp_timeval
    sctps_currestab* {.importc: "sctps_currestab".}: uint32
    sctps_activeestab* {.importc: "sctps_activeestab".}: uint32
    sctps_restartestab* {.importc: "sctps_restartestab".}: uint32
    sctps_collisionestab* {.importc: "sctps_collisionestab".}: uint32
    sctps_passiveestab* {.importc: "sctps_passiveestab".}: uint32
    sctps_aborted* {.importc: "sctps_aborted".}: uint32
    sctps_shutdown* {.importc: "sctps_shutdown".}: uint32
    sctps_outoftheblue* {.importc: "sctps_outoftheblue".}: uint32
    sctps_checksumerrors* {.importc: "sctps_checksumerrors".}: uint32
    sctps_outcontrolchunks* {.importc: "sctps_outcontrolchunks".}: uint32
    sctps_outorderchunks* {.importc: "sctps_outorderchunks".}: uint32
    sctps_outunorderchunks* {.importc: "sctps_outunorderchunks".}: uint32
    sctps_incontrolchunks* {.importc: "sctps_incontrolchunks".}: uint32
    sctps_inorderchunks* {.importc: "sctps_inorderchunks".}: uint32
    sctps_inunorderchunks* {.importc: "sctps_inunorderchunks".}: uint32
    sctps_fragusrmsgs* {.importc: "sctps_fragusrmsgs".}: uint32
    sctps_reasmusrmsgs* {.importc: "sctps_reasmusrmsgs".}: uint32
    sctps_outpackets* {.importc: "sctps_outpackets".}: uint32
    sctps_inpackets* {.importc: "sctps_inpackets".}: uint32
    sctps_recvpackets* {.importc: "sctps_recvpackets".}: uint32
    sctps_recvdatagrams* {.importc: "sctps_recvdatagrams".}: uint32
    sctps_recvpktwithdata* {.importc: "sctps_recvpktwithdata".}: uint32
    sctps_recvsacks* {.importc: "sctps_recvsacks".}: uint32
    sctps_recvdata* {.importc: "sctps_recvdata".}: uint32
    sctps_recvdupdata* {.importc: "sctps_recvdupdata".}: uint32
    sctps_recvheartbeat* {.importc: "sctps_recvheartbeat".}: uint32
    sctps_recvheartbeatack* {.importc: "sctps_recvheartbeatack".}: uint32
    sctps_recvecne* {.importc: "sctps_recvecne".}: uint32
    sctps_recvauth* {.importc: "sctps_recvauth".}: uint32
    sctps_recvauthmissing* {.importc: "sctps_recvauthmissing".}: uint32
    sctps_recvivalhmacid* {.importc: "sctps_recvivalhmacid".}: uint32
    sctps_recvivalkeyid* {.importc: "sctps_recvivalkeyid".}: uint32
    sctps_recvauthfailed* {.importc: "sctps_recvauthfailed".}: uint32
    sctps_recvexpress* {.importc: "sctps_recvexpress".}: uint32
    sctps_recvexpressm* {.importc: "sctps_recvexpressm".}: uint32
    sctps_recv_spare* {.importc: "sctps_recv_spare".}: uint32
    sctps_recvswcrc* {.importc: "sctps_recvswcrc".}: uint32
    sctps_recvhwcrc* {.importc: "sctps_recvhwcrc".}: uint32
    sctps_sendpackets* {.importc: "sctps_sendpackets".}: uint32
    sctps_sendsacks* {.importc: "sctps_sendsacks".}: uint32
    sctps_senddata* {.importc: "sctps_senddata".}: uint32
    sctps_sendretransdata* {.importc: "sctps_sendretransdata".}: uint32
    sctps_sendfastretrans* {.importc: "sctps_sendfastretrans".}: uint32
    sctps_sendmultfastretrans* {.importc: "sctps_sendmultfastretrans".}: uint32
    sctps_sendheartbeat* {.importc: "sctps_sendheartbeat".}: uint32
    sctps_sendecne* {.importc: "sctps_sendecne".}: uint32
    sctps_sendauth* {.importc: "sctps_sendauth".}: uint32
    sctps_senderrors* {.importc: "sctps_senderrors".}: uint32
    sctps_send_spare* {.importc: "sctps_send_spare".}: uint32
    sctps_sendswcrc* {.importc: "sctps_sendswcrc".}: uint32
    sctps_sendhwcrc* {.importc: "sctps_sendhwcrc".}: uint32
    sctps_pdrpfmbox* {.importc: "sctps_pdrpfmbox".}: uint32
    sctps_pdrpfehos* {.importc: "sctps_pdrpfehos".}: uint32
    sctps_pdrpmbda* {.importc: "sctps_pdrpmbda".}: uint32
    sctps_pdrpmbct* {.importc: "sctps_pdrpmbct".}: uint32
    sctps_pdrpbwrpt* {.importc: "sctps_pdrpbwrpt".}: uint32
    sctps_pdrpcrupt* {.importc: "sctps_pdrpcrupt".}: uint32
    sctps_pdrpnedat* {.importc: "sctps_pdrpnedat".}: uint32
    sctps_pdrppdbrk* {.importc: "sctps_pdrppdbrk".}: uint32
    sctps_pdrptsnnf* {.importc: "sctps_pdrptsnnf".}: uint32
    sctps_pdrpdnfnd* {.importc: "sctps_pdrpdnfnd".}: uint32
    sctps_pdrpdiwnp* {.importc: "sctps_pdrpdiwnp".}: uint32
    sctps_pdrpdizrw* {.importc: "sctps_pdrpdizrw".}: uint32
    sctps_pdrpbadd* {.importc: "sctps_pdrpbadd".}: uint32
    sctps_pdrpmark* {.importc: "sctps_pdrpmark".}: uint32
    sctps_timoiterator* {.importc: "sctps_timoiterator".}: uint32
    sctps_timodata* {.importc: "sctps_timodata".}: uint32
    sctps_timowindowprobe* {.importc: "sctps_timowindowprobe".}: uint32
    sctps_timoinit* {.importc: "sctps_timoinit".}: uint32
    sctps_timosack* {.importc: "sctps_timosack".}: uint32
    sctps_timoshutdown* {.importc: "sctps_timoshutdown".}: uint32
    sctps_timoheartbeat* {.importc: "sctps_timoheartbeat".}: uint32
    sctps_timocookie* {.importc: "sctps_timocookie".}: uint32
    sctps_timosecret* {.importc: "sctps_timosecret".}: uint32
    sctps_timopathmtu* {.importc: "sctps_timopathmtu".}: uint32
    sctps_timoshutdownack* {.importc: "sctps_timoshutdownack".}: uint32
    sctps_timoshutdownguard* {.importc: "sctps_timoshutdownguard".}: uint32
    sctps_timostrmrst* {.importc: "sctps_timostrmrst".}: uint32
    sctps_timoearlyfr* {.importc: "sctps_timoearlyfr".}: uint32
    sctps_timoasconf* {.importc: "sctps_timoasconf".}: uint32
    sctps_timodelprim* {.importc: "sctps_timodelprim".}: uint32
    sctps_timoautoclose* {.importc: "sctps_timoautoclose".}: uint32
    sctps_timoassockill* {.importc: "sctps_timoassockill".}: uint32
    sctps_timoinpkill* {.importc: "sctps_timoinpkill".}: uint32
    sctps_spare* {.importc: "sctps_spare".}: array[11, uint32]
    sctps_hdrops* {.importc: "sctps_hdrops".}: uint32
    sctps_badsum* {.importc: "sctps_badsum".}: uint32
    sctps_noport* {.importc: "sctps_noport".}: uint32
    sctps_badvtag* {.importc: "sctps_badvtag".}: uint32
    sctps_badsid* {.importc: "sctps_badsid".}: uint32
    sctps_nomem* {.importc: "sctps_nomem".}: uint32
    sctps_fastretransinrtt* {.importc: "sctps_fastretransinrtt".}: uint32
    sctps_markedretrans* {.importc: "sctps_markedretrans".}: uint32
    sctps_naglesent* {.importc: "sctps_naglesent".}: uint32
    sctps_naglequeued* {.importc: "sctps_naglequeued".}: uint32
    sctps_maxburstqueued* {.importc: "sctps_maxburstqueued".}: uint32
    sctps_ifnomemqueued* {.importc: "sctps_ifnomemqueued".}: uint32
    sctps_windowprobed* {.importc: "sctps_windowprobed".}: uint32
    sctps_lowlevelerr* {.importc: "sctps_lowlevelerr".}: uint32
    sctps_lowlevelerrusr* {.importc: "sctps_lowlevelerrusr".}: uint32
    sctps_datadropchklmt* {.importc: "sctps_datadropchklmt".}: uint32
    sctps_datadroprwnd* {.importc: "sctps_datadroprwnd".}: uint32
    sctps_ecnereducedcwnd* {.importc: "sctps_ecnereducedcwnd".}: uint32
    sctps_vtagexpress* {.importc: "sctps_vtagexpress".}: uint32
    sctps_vtagbogus* {.importc: "sctps_vtagbogus".}: uint32
    sctps_primary_randry* {.importc: "sctps_primary_randry".}: uint32
    sctps_cmt_randry* {.importc: "sctps_cmt_randry".}: uint32
    sctps_slowpath_sack* {.importc: "sctps_slowpath_sack".}: uint32
    sctps_wu_sacks_sent* {.importc: "sctps_wu_sacks_sent".}: uint32
    sctps_sends_with_flags* {.importc: "sctps_sends_with_flags".}: uint32
    sctps_sends_with_unord* {.importc: "sctps_sends_with_unord".}: uint32
    sctps_sends_with_eof* {.importc: "sctps_sends_with_eof".}: uint32
    sctps_sends_with_abort* {.importc: "sctps_sends_with_abort".}: uint32
    sctps_protocol_drain_calls* {.importc: "sctps_protocol_drain_calls".}: uint32
    sctps_protocol_drains_done* {.importc: "sctps_protocol_drains_done".}: uint32
    sctps_read_peeks* {.importc: "sctps_read_peeks".}: uint32
    sctps_cached_chk* {.importc: "sctps_cached_chk".}: uint32
    sctps_cached_strmoq* {.importc: "sctps_cached_strmoq".}: uint32
    sctps_left_abandon* {.importc: "sctps_left_abandon".}: uint32
    sctps_send_burst_avoid* {.importc: "sctps_send_burst_avoid".}: uint32
    sctps_send_cwnd_avoid* {.importc: "sctps_send_cwnd_avoid".}: uint32
    sctps_fwdtsn_map_over* {.importc: "sctps_fwdtsn_map_over".}: uint32
    sctps_queue_upd_ecne* {.importc: "sctps_queue_upd_ecne".}: uint32
    sctps_reserved* {.importc: "sctps_reserved".}: array[31, uint32]


proc usrsctp_get_stat*(a2: ptr sctpstat) {.importc: "usrsctp_get_stat",
                                       header: usrsctp.}
