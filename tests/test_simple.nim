import sctp, reactor, reactor/testpipe, collections

proc main() {.async.} =
  let (pipe1, pipe2, packetsA, packetsB) = newTwoWayTestPipe(mtu=1300)
  let connA = newSctpConn(packetsA)
  let connB = newSctpConn(packetsB)

  #connA.printPackets("A")
  #connB.printPackets("B")

  for i in 0..2:
    let p1 = "abcdefghijklmnoprstu".repeat(100)
    let p2 = "abcdefghijklmnoprstu".repeat(10)
    await connA.sctpPackets.output.send(SctpPacket(data: newView(p1)))
    await connA.sctpPackets.output.send(SctpPacket(data: newView(p2)))

    let r1 = await connB.sctpPackets.input.receive
    doAssert p1 == r1.data.copyAsString

    let r2 = await connB.sctpPackets.input.receive
    doAssert p2 == r2.data.copyAsString

  connB.sctpPackets.close
  let f = tryAwait connA.sctpPackets.input.receive
  assert f.isError

  # await connA.sctpPackets.output.send(SctpPacket(data: newView("aa")))
  # let r3 = await connB.sctpPackets.input.receive
  # assert r3.data.copyAsString == "aa"

  echo "ok"

when isMainModule:
  main().runMain
