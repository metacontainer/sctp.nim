import sctp, reactor, reactor/testpipe, collections

proc main() {.async.} =
  let (pipe1, pipe2, packetsA, packetsB) = newTwoWayTestPipe(mtu=1300)
  let connA = newSctpConn(packetsA)

  #connA.printPackets("A")
  #connB.printPackets("B")

  for i in 0..2:
    let p1 = "abcd".repeat(1000)
    await connA.sctpPackets.output.send(SctpPacket(data: newView(p1)))

  await asyncSleep(800)
  let connB = newSctpConn(packetsB)

  for i in 0..2:
    let p1 = "abcd".repeat(1000)
    let m = await connB.sctpPackets.input.receive()
    assert m.data == p1

  echo "ok"

when isMainModule:
  main().runMain
