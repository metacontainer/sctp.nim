import os

const basePath = splitPath(currentSourcePath()).head & "/../usrsctp/"
const libPath = basePath & "/usrsctplib/"

when defined(linux):
  {.passc: "-D__Userspace_os_Linux".}

when defined(sctpDebug):
  {.passc: "-DSCTP_DEBUG".}

{.passc: "-D__Userspace__ -DSCTP_SIMPLE_ALLOCATOR -DSCTP_PROCESS_LEVEL_LOCKS -D_GNU_SOURCE -I" & libPath & " -I" & basePath.}
{.compile: libPath & "user_mbuf.c".}
{.compile: libPath & "user_socket.c".}
{.compile: libPath & "netinet6/sctp6_usrreq.c".}
{.compile: libPath & "user_recv_thread.c".}
{.compile: libPath & "netinet/sctp_crc32.c".}
{.compile: libPath & "netinet/sctp_bsd_addr.c".}
{.compile: libPath & "netinet/sctp_cc_functions.c".}
{.compile: libPath & "netinet/sctp_indata.c".}
{.compile: libPath & "netinet/sctp_ss_functions.c".}
{.compile: libPath & "netinet/sctp_peeloff.c".}
{.compile: libPath & "netinet/sctputil.c".}
{.compile: libPath & "netinet/sctp_timer.c".}
{.compile: libPath & "netinet/sctp_pcb.c".}
{.compile: libPath & "netinet/sctp_usrreq.c".}
{.compile: libPath & "netinet/sctp_input.c".}
{.compile: libPath & "netinet/sctp_callout.c".}
{.compile: libPath & "netinet/sctp_sysctl.c".}
{.compile: libPath & "netinet/sctp_userspace.c".}
{.compile: libPath & "netinet/sctp_output.c".}
{.compile: libPath & "netinet/sctp_sha1.c".}
{.compile: libPath & "netinet/sctp_auth.c".}
{.compile: libPath & "netinet/sctp_asconf.c".}
{.compile: libPath & "user_environment.c".}
