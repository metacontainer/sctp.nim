import sctp, reactor, reactor/testpipe, collections

proc main() {.async.} =
  let (pipe1, pipe2, packetsA, packetsB) = newTwoWayTestPipe(mtu=1300, bandwidth=800)
  let connA = newSctpConn(packetsA)
  let connB = newSctpConn(packetsB)

  let startTime = currentTime()
  var recvCount = 0
  let allRecv = newCompleter[void]()
  connB.sctpPackets.input.forEach(proc(p: SctpPacket) =
    recvCount += 1
    if recvCount == 100: allRecv.complete
  ).ignore

  for i in 0..100:
    let p1 = "X".repeat(10000)
    await connA.sctpPackets.output.send(SctpPacket(data: newView(p1)))

  await allRecv.getFuture

  let delta = currentTime() - startTime
  doAssert delta > 900 and delta < 2000

  echo "ok"

when isMainModule:
  main().runMain
