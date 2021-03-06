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
      targetId = toNodeId(PrivateKey.random(rng[]).toPublicKey)

    asyncTest "Node in isolation should store":

      debug "---- ADDING PROVIDERS ---"
      let addedTo = await nodes[0].addProvider(targetId)
      debug "Provider added to: ", addedTo

      debug "---- STARTING CHECKS ---"
      check (addedTo.len == 1)
      check (addedTo[0].id == nodes[0].thisNode.id)
      check (nodes[0].getProvidersLocal(targetId)[0].id == nodes[0].thisNode.id)

    asyncTest "Node in isolation should retrieve":

      debug "---- STARTING PROVIDERS LOOKUP ---"
      let providers = await nodes[0].getProviders(targetId)
      debug "Providers:", providers

      debug "---- STARTING CHECKS ---"
      check (providers.len > 0 and providers[0].id == nodes[0].thisNode.id)

    asyncTest "Should not retrieve bogus":

      let bogusId = toNodeId(PrivateKey.random(rng[]).toPublicKey)
 
      debug "---- STARTING PROVIDERS LOOKUP ---"
      let providers = await nodes[0].getProviders(bogusId)
      debug "Providers:", providers

      debug "---- STARTING CHECKS ---"
      check (providers.len == 0)

    for n in nodes:
      n.close()
    await sleepAsync(chronos.seconds(3))

  asyncTest "Providers Tests: two nodes":
    let
      rng = keys.newRng()
      nodes = await bootstrapNetwork(nodecount=2)
      targetId = toNodeId(PrivateKey.random(rng[]).toPublicKey) 

    asyncTest "2 nodes, store and retieve from same":

      debug "---- ADDING PROVIDERS ---"
      let addedTo = await nodes[0].addProvider(targetId)
      debug "Provider added to: ", addedTo

      debug "---- STARTING PROVIDERS LOOKUP ---"
      let providers = await nodes[0].getProviders(targetId)
      debug "Providers:", providers

      debug "---- STARTING CHECKS ---"
      check (providers.len == 1 and providers[0].id == nodes[0].thisNode.id)

    asyncTest "2 nodes, retieve from other":
      debug "---- STARTING PROVIDERS LOOKUP ---"
      let providers = await nodes[1].getProviders(targetId)
      debug "Providers:", providers

      debug "---- STARTING CHECKS ---"
      check (providers.len == 1 and providers[0].id == nodes[0].thisNode.id)

    for n in nodes:
      n.close()
    await sleepAsync(chronos.seconds(3))

  asyncTest "Providers Tests: 20 nodes":
    let
      rng = keys.newRng()
      nodes = await bootstrapNetwork(nodecount=20)
      targetId = toNodeId(PrivateKey.random(rng[]).toPublicKey) 
    await sleepAsync(chronos.seconds(30))

    asyncTest "20 nodes, store and retieve from same":

      debug "---- ADDING PROVIDERS ---"
      let addedTo = await nodes[0].addProvider(targetId)
      debug "Provider added to: ", addedTo

      debug "---- STARTING PROVIDERS LOOKUP ---"
      let providers = await nodes[0].getProviders(targetId)
      debug "Providers:", providers

      debug "---- STARTING CHECKS ---"
      check (providers.len == 1 and providers[0].id == nodes[0].thisNode.id)

    asyncTest "20 nodes, retieve from other":
      debug "---- STARTING PROVIDERS LOOKUP ---"
      let providers = await nodes[^1].getProviders(targetId)
      debug "Providers:", providers

      debug "---- STARTING CHECKS ---"
      check (providers.len == 1 and providers[0].id == nodes[0].thisNode.id)

    asyncTest "20 nodes, retieve after bootnode dies":
      debug "---- KILLING BOOTSTRAP NODE ---"
      nodes[0].close

      debug "---- STARTING PROVIDERS LOOKUP ---"
      let providers = await nodes[^2].getProviders(targetId)
      debug "Providers:", providers

      debug "---- STARTING CHECKS ---"
      check (providers.len == 1 and providers[0].id == nodes[0].thisNode.id)

    for n in nodes:
      n.close()
