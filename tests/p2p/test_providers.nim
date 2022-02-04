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
  ../../eth/keys, ../../dht/[discovery, kademlia, enode, node],
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

proc bootstrapNodes(nodecount: int, bootnodes: seq[ENode], rng = keys.newRng()) : Future[seq[DiscoveryProtocol]] {.async.} =

    for i in 0..<nodecount:
      let node = initDiscoveryNode(PrivateKey.random(rng[]), localAddress(20302 + i), bootnodes)
      result.add(node)
    
    debug "---- STARTING BOOSTRAPS ---"

    await allFutures(result.mapIt(it.bootstrap())) # this waits for bootstrap based on bootENode, which includes bonding with all its ping pongs

proc bootstrapNetwork(nodecount: int, rng = keys.newRng()) : Future[seq[DiscoveryProtocol]] {.async.} =
  let
    bootNodeKey = PrivateKey.fromHex(
      "a2b50376a79b1a8c8a3296485572bdfbf54708bb46d3c25d73d2723aaaf6a617")[]
    bootNodeAddr = localAddress(20301)
    bootENode = ENode(pubkey: bootNodeKey.toPublicKey(), address: bootNodeAddr)
    bootNode = initDiscoveryNode(bootNodeKey, bootNodeAddr, @[]) # just a shortcut for new and open

  waitFor bootNode.bootstrap()  # immediate, since no bootnodes are defined above
  
  result = await bootstrapNodes(nodecount - 1, @[bootENode], rng = rng)
  result.insert(bootNode, 0)


suite "Providers Tests: node alone":

  asyncTest "node alone":
    let
      rng = keys.newRng()
      nodes = await bootstrapNetwork(nodecount=1)

    asyncTest "Node in isolation should store and retrieve":

      info "---- STARTING LOOKUP ---"

      let targetId = toNodeId(PrivateKey.random(rng[]).toPublicKey) 
      let nodesFound = await nodes[0].kademlia.lookup(targetId)
      info "nodes found: ", nodesFound

      info "---- ADDING PROVIDERS ---"

      let addedTo = await nodes[0].addProvider(targetId)
      info "Provider added to: ", addedTo

      info "---- STARTING PROVIDERS LOOKUP ---"

      let providers = await nodes[0].getProviders(targetId)
      info "Providers:", providers

      info "---- STARTING CHECKS ---"

      check (providers.len > 0 and providers[0].id == nodes[0].thisNode.id)

    nodes[0].close()
    await sleepAsync(chronos.seconds(3))

  asyncTest "Providers Tests: two nodes":
    let
      rng = keys.newRng()
      nodes = await bootstrapNetwork(nodecount=2)

    asyncTest "2 nodes, store and retieve":

      info "---- STARTING LOOKUP ---"

      let targetId = toNodeId(PrivateKey.random(rng[]).toPublicKey) 
      let nodesFound = await nodes[0].kademlia.lookup(targetId)
      info "nodes found: ", nodesFound

      info "---- ADDING PROVIDERS ---"

      let addedTo = await nodes[0].addProvider(targetId)
      info "Provider added to: ", addedTo

      info "---- STARTING PROVIDERS LOOKUP ---"

      let providers = await nodes[0].getProviders(targetId)
      info "Providers:", providers

      info "---- STARTING CHECKS ---"

      check (providers.len > 0 and providers[0].id == nodes[0].thisNode.id)

    nodes[0].close
    nodes[1].close
