#
#                 Ethereum P2P
#              (c) Copyright 2018
#       Status Research & Development GmbH
#
#    See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#

{.used.}

import
  std/sequtils,
  chronos, stew/byteutils, nimcrypto, testutils/unittests,
  ../../eth/keys, ../../eth/p2p/[discovery, kademlia, enode, node],
  chronicles

proc localAddress(port: int): Address =
  let port = Port(port)
  result = Address(udpPort: port, tcpPort: port,
                   ip: parseIpAddress("127.0.0.1"))

proc initDiscoveryNode(privKey: PrivateKey, address: Address,
                        bootnodes: seq[ENode]): DiscoveryProtocol =
  let node = newDiscoveryProtocol(privKey, address, bootnodes)
  node.open()

  return node

proc packData(payload: openArray[byte], pk: PrivateKey): seq[byte] =
  let
    payloadSeq = @payload
    signature = @(pk.sign(payload).toRaw())
    msgHash = keccak256.digest(signature & payloadSeq)
  result = @(msgHash.data) & signature & payloadSeq

procSuite "Discovery Tests":
  let
    bootNodeKey = PrivateKey.fromHex(
      "a2b50376a79b1a8c8a3296485572bdfbf54708bb46d3c25d73d2723aaaf6a617")[]
    bootNodeAddr = localAddress(20301)
    bootENode = ENode(pubkey: bootNodeKey.toPublicKey(), address: bootNodeAddr)
    bootNode = initDiscoveryNode(bootNodeKey, bootNodeAddr, @[]) # just a shortcut for new and open
  waitFor bootNode.bootstrap()  # immediate, since no bootnodes are defined above

  proc discoverNodes(nodecount: int) {.async.} =
    let
      rng = keys.newRng()

    var nodes: seq[DiscoveryProtocol]
    for i in 0..<nodecount:
      let bootnodes = @[bootENode]
      let node = initDiscoveryNode(PrivateKey.random(rng[]), localAddress(20302 + i),
        bootnodes)
      nodes.add(node)
    info "---- STARTING BOOSTRAPS ---"

    await allFutures(nodes.mapIt(it.bootstrap())) # this waits for bootstrap based on bootENode, which includes bonding with all its ping pongs
    nodes.add(bootNode)

    info "---- STARTING CHECKS ---"

    # for i in nodes:
    #   for j in nodes:
    #     if j != i:
    #       check(nodeIdInNodes(i.thisNode.id, j.randomNodes(nodes.len - 1)))

    info "---- STARTING LOOKUP ---"

    let targetId = toNodeId(PrivateKey.random(rng[]).toPublicKey) 
    let nodesFound = await nodes[0].kademlia.lookup(targetId)
    echo "nodes found: ", nodesFound.deduplicate()

    let addedTo = await nodes[0].addProvider(targetId)
    echo "Provider added to: ", addedTo
    let providers = await nodes[0].getProviders(targetId)
    await sleepAsync(5.seconds)

  asyncTest "Discover nodes UDP":
    await discoverNodes(nodecount=2)
