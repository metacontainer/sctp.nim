import sctp/lowlevel, reactor, collections/views, collections, posix

proc debug*(x: varargs[string]) =
  stderr.writeLine(join(x, " "))

type

  SctpReliabilityKind* = enum
    sctpReliable,
    sctpUnreliable,
    sctpTimedReliability
    sctpRtxReliability
    sctpBufferReliability

  SctpReliabilityPolicy* = object
    unordered*: bool

    case reliability*: SctpReliabilityKind
    of sctpReliable, sctpUnreliable:
      discard
    of sctpBufferReliability:
      maxBufferSize*: int # in bytes
    of sctpTimedReliability:
      deadline*: reactor.Time
    of sctpRtxReliability:
      maxRtx*: int

  SctpPacket* = object
    data*: Buffer
    streamId*: int
    reliabilityPolicy*: SctpReliabilityPolicy

  SctpConn* = ref object
    sock: ptr sctp_socket
    rawPackets: Pipe[Buffer]
    mySctpPackets: Pipe[SctpPacket]
    sctpPackets*: Pipe[SctpPacket]
    closed: bool

  SctpError* = object of IOError

# sctp_init()

const safeMtu* = 1200
const sendThresholdValue = 64 * 1024 # ?
const maxStreams = 1024

const IPPROTO_SCTP = 132

proc trySendAll(self: SctpConn)
proc tryRecvAll(self: SctpConn)

proc receiveCbInLoop(address: pointer) =
  let self = cast[SctpConn](address)
  self.tryRecvAll()

proc sendRawCbInLoop(packet: tuple[address: pointer, data: pointer, length: int]) =
  doAssert packet.address != nil
  let self = cast[SctpConn](packet.address)
  let view = initViewWithMallocMemory(cast[ptr byte](packet.data), packet.length)
  discard self.rawPackets.output.maybeSend(view)

proc getConnFromSocket(sock: ptr sctp_socket): SctpConn =
  var addrs: ptr SockAddr = nil
  if usrsctp_getladdrs(sock, 0, addr addrs) <= 0:
    return nil

  if addrs[].sa_family != AF_CONN:
    return nil

  var sconn: sockaddr_conn
  copyMem(addr sconn, addrs, sizeof(sockaddr_conn))
  result = cast[SctpConn](sconn.sconn_addr)
  usrsctp_freeladdrs(addrs)

proc sendThresholdCbInLoop(sock: ptr sctp_socket) =
  let self = getConnFromSocket(sock)
  doAssert self != nil

  self.trySendAll

let receiveQueue = newThreadsafeQueue[pointer](receiveCbInLoop)
let sendRawQueue = newThreadsafeQueue[tuple[address: pointer, data: pointer, length: int]](sendRawCbInLoop)
let sendThresholdQueue = newThreadsafeQueue[ptr sctp_socket](sendThresholdCbInLoop)

proc sendThresholdCb(sock: ptr sctp_socket, sb_free: uint32): cint {.cdecl.} =
  sendThresholdQueue.sendThreadsafe(sock)
  return 0

proc receiveCb(sock: ptr sctp_socket, `addr`: sctp_sockstore, data: pointer, datalen: csize,
               info: sctp_rcvinfo, flags: cint, ulp_info: pointer): cint {.cdecl.} =
  # we use modified usrsctp that doesn't do reads on receive - we do this using sctp_recvv
  receiveQueue.sendThreadsafe(ulp_info)
  return 1

proc c_malloc(m: csize): pointer {.importc: "malloc", header: "<string.h>".}

proc sendRawPacketCb(address: pointer, buffer: pointer,
                     length: csize, tos: uint8, set_df: uint8): cint {.cdecl.} =
  let copied = c_malloc(csize(length))
  unsafeInitView(cast[ptr byte](copied), length).copyFrom(unsafeInitView(cast[ptr byte](buffer), length))
  sendRawQueue.sendThreadsafe((address, copied, length.int))

proc printf(format: cstring) {.importc, cdecl, varargs, header: "<stdio.h>".}

proc init*() =
  var initialized {.global.} = false

  if not initialized:
    initialized = true
    usrsctp_init(0, sendRawPacketCb, printf)

    usrsctp_sysctl_set_sctp_auto_asconf(0)
    usrsctp_sysctl_set_sctp_nr_outgoing_streams_default(maxStreams)

    when defined(sctpDebug):
      usrsctp_sysctl_set_sctp_logging_level(10)
      usrsctp_sysctl_set_sctp_debug_on(0xffffffff'u32)

proc doClose(self: SctpConn) =
  debug "shutdown"
  usrsctp_close(self.sock)
  self.sock = nil
  usrsctp_deregister_address(cast[pointer](self))
  # TODO: GC references

proc close*(self: SctpConn) =
  if not self.closed:
    self.closed = true
    self.mySctpPackets.close
    self.rawPackets.close
    self.doClose

proc getAddress(self: SctpConn, port: int): sockaddr_conn =
  var sconn: sockaddr_conn
  sconn.sconn_family = AF_CONN
  sconn.sconn_port = htons(port.uint16)
  sconn.sconn_addr = cast[pointer](self)
  return sconn

proc `|=`(a: var SomeInteger, b: SomeInteger) =
  a = a or b

proc trySend(self: SctpConn, packet: SctpPacket): bool =
  var spa: sctp_sendv_spa
  spa.sendv_flags = SCTP_SEND_SNDINFO_VALID
  doAssert packet.streamId >= 0 and packet.streamId < maxStreams
  spa.sendv_sndinfo.snd_sid = uint16(packet.streamId)
  spa.sendv_sndinfo.snd_flags = 0
  let policy = packet.reliabilityPolicy
  if policy.unordered:
    spa.sendv_sndinfo.snd_flags |= SCTP_UNORDERED

  case policy.reliability:
  of sctpReliable:
    discard
  of sctpUnreliable:
    spa.sendv_flags |= SCTP_SEND_PRINFO_VALID
    spa.sendv_prinfo.pr_policy = SCTP_PR_SCTP_RTX
    spa.sendv_prinfo.pr_value = 0
  of sctpTimedReliability:
    spa.sendv_flags |= SCTP_SEND_PRINFO_VALID
    spa.sendv_prinfo.pr_policy = SCTP_PR_SCTP_TTL
    let delta = policy.deadline - currentTime()
    if delta < 0:
      return # already after deadline :(
    spa.sendv_prinfo.pr_value = uint32(delta)
  of sctpRtxReliability:
    spa.sendv_flags |= SCTP_SEND_PRINFO_VALID
    spa.sendv_prinfo.pr_policy = SCTP_PR_SCTP_RTX
    spa.sendv_prinfo.pr_value = uint32(policy.maxRtx)
  of sctpBufferReliability:
    spa.sendv_flags |= SCTP_SEND_PRINFO_VALID
    spa.sendv_prinfo.pr_policy = SCTP_PR_SCTP_BUF
    spa.sendv_prinfo.pr_value = uint32(policy.maxBufferSize)

  let res = usrsctp_sendv(self.sock, addr packet.data[0], csize(packet.data.len),
                          nil, 0, addr spa, sizeof(spa).Socklen, SCTP_SENDV_SPA, 0)
  if res < 0:
    if errno == EWOULDBLOCK:
      return false

    raise newException(SctpError, "sendv returned error ($1)" % $errno)

  return true

proc shutdownSend(self: SctpConn) =
  let res = usrsctp_shutdown(self.sock, SHUT_WR)
  if res < 0:
    stderr.writeLine "usrscrp: shutdown failed (?)"

proc trySendAll(self: SctpConn) =
  # TODO: enable Nagle and then disable before sending last packet
  let inp = self.mySctpPackets.input

  while inp.dataAvailable > 0:
    let packet = inp.peekMany[0]
    if self.trySend(packet):
      inp.discardItems 1
    else:
      break

  if inp.dataAvailable == 0 and inp.isSendClosed:
    self.shutdownSend
    return

proc tryRecv(self: SctpConn): Option[SctpPacket] =
  if self.sock == nil:
    return none(SctpPacket)

  let buf = newView(byte, 16 * 1024)
  var flags: cint
  var infotype: cuint = SCTP_RECVV_RCVINFO
  var info: sctp_rcvinfo
  var infolen = sizeof(sctp_rcvinfo).Socklen

  let ret = usrsctp_recvv(self.sock,
                          addr buf[0],
                          buf.len,
                          nil,
                          nil,
                          addr info,
                          addr infolen,
                          addr infotype,
                          addr flags)

  # TODO: we should really handle messages > 16k
  if ret < 0:
    if errno == EWOULDBLOCK:
      return none(SctpPacket)

    raise newException(SctpError, "recvv returned error")

  let data = buf.slice(0, ret)
  return some(SctpPacket(
    data: data,
    streamId: info.rcv_sid.int
  ))

proc tryRecvAll(self: SctpConn) =
  let output = self.mySctpPackets.output
  while output.freeBufferSize > 0:
    let packet = self.tryRecv
    if packet.isNone:
      break

    if packet.get.data.len == 0:
      # eof
      output.sendClose(JustClose)
      break
    else:
      doAssert output.maybeSend(packet.get) == true

proc pipe*(input: ByteInput, self: SctpConn, close=false) {.async.} =
  while true:
    # read a big chunk, SCTP will split it into packets for us
    let data = tryAwait input.readSome(12 * 1024)

    if data.isError:
      break

    await self.sctpPackets.output.send(
      SctpPacket(data: newView(data.get))
    )

  if close:
    self.sctpPackets.output.sendClose

proc dataOutput*(self: SctpConn): ByteOutput =
  let (input, output) = newInputOutputPair[byte]()

  pipe(input, self).onFinishClose(output)

  return output

proc pipe*(self: SctpConn, output: ByteOutput, close=false) {.async.} =
  asyncFor pkt in self.sctpPackets.input:
    if pkt.streamId == 0:
      await output.write(pkt.data)

  if close:
    output.sendClose

proc dataInput*(self: SctpConn): ByteInput =
  let (input, output) = newInputOutputPair[byte]()

  pipe(self, output).onFinishClose(output)

  return input

proc dataPipe*(self: SctpConn): BytePipe =
  return BytePipe(input: self.dataInput, output: self.dataOutput)

proc pipe*(self: SctpConn, stream: BytePipe) {.async.} =
  await zipVoid(@[
    pipe(self, stream.output),
    pipe(stream.input, self)
  ])

proc newSctpConn*(packets: Pipe[Buffer], sport=1, dport=1): SctpConn =
  init()
  let self = SctpConn()
  GC_ref(self)

  self.rawPackets = packets
  self.sock = usrsctp_socket(
    AF_CONN, SOCK_STREAM, IPPROTO_SCTP, receiveCb,
    sendThresholdCb, sendThresholdValue, cast[pointer](self))

  (self.mySctpPackets, self.sctpPackets) = newPipe(SctpPacket)

  self.mySctpPackets.input.onRecvReady.addListener(proc() = self.trySendAll)
  self.mySctpPackets.output.onSendReady.addListener(proc() = self.tryRecvAll)

  # disable linger (avoid getting calls after the object is destructed, but also prevents queued packets from being sent after!)
  var linger_opt = TLinger(l_onoff: 1, l_linger: 0)
  doAssert 0 == usrsctp_setsockopt(self.sock, SOL_SOCKET, SO_LINGER, addr linger_opt, sizeof(linger_opt).Socklen)
  doAssert 0 == usrsctp_set_non_blocking(self.sock, 1)

  var stream_rst = sctp_assoc_value(assoc_id: SCTP_ALL_ASSOC, assoc_value: 1);
  doAssert 0 == usrsctp_setsockopt(self.sock, IPPROTO_SCTP, SCTP_ENABLE_STREAM_RESET,
                                   addr stream_rst, sizeof(stream_rst).Socklen)

  var nodelay: uint32 = 1;
  doAssert 0 == usrsctp_setsockopt(self.sock, IPPROTO_SCTP, SCTP_NODELAY, addr nodelay,
                                   sizeof(nodelay).Socklen)

  usrsctp_register_address(cast[pointer](self))

  var address = self.getAddress(sport)
  let err = usrsctp_bind(self.sock, cast[ptr SockAddr](addr address), sizeof(address).Socklen)
  doAssert err == 0, ($errno)

  var remoteAddress = self.getAddress(dport)
  let connErr = usrsctp_connect(self.sock, cast[ptr SockAddr](addr remoteAddress), sizeof(remoteAddress).Socklen)
  doAssert 0 == connErr or errno == EINPROGRESS, ($errno)

  var params: sctp_paddrparams
  copyMem(cast[ptr sockaddr_conn](addr params.spp_address), addr remoteAddress,
          sizeof(sockaddr_conn))
  params.spp_flags = SPP_PMTUD_DISABLE # disable path mtu discovery, this might be a bad idea
  params.spp_pathmtu = safeMtu
  doAssert 0 == usrsctp_setsockopt(self.sock, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS, addr params,
                                   sizeof(params).Socklen)

  packets.input.forEach(proc(data: Buffer) =
    usrsctp_conninput(cast[pointer](self), addr data[0], data.len, 0)
  ).onFinishClose(self.mySctpPackets.output)

  self.trySendAll
  self.tryRecvAll

  return self
