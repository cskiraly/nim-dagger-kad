# nim-eth
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# wire interface is implicit
# - sendPing(Node)
# - sendPong(Node, any)
# - sendFindNode(Node, NodeId)
# - sendNeighbour(Node, seq[Node])
# handles kademlia routing tables
# handles FindNode and Neighbour messaging and timeouts

{.push raises: [Defect].}

import
  std/[tables, hashes, times, algorithm, sets, sequtils, random],
  chronos, bearssl, chronicles, stint, nimcrypto/keccak,
  chronos/timer, # needed for doSleep parameter definition timer.Duration
  ../keys,
  ./node,
  ./helpers,
  ./routingtable,
  ./bond

export sets # TODO: This should not be needed, but compilation fails otherwise

logScope:
  topics = "kademlia"

type
  KademliaProtocol* [Wire] = ref object
    wire: Wire
    thisNode: Node
    routing: RoutingTable
    bond: BondProtocol[Wire]
    neighboursCallbacks: Table[Node, proc(n: seq[Node]) {.gcsafe, raises: [Defect].}]
    rng: ref BrHmacDrbgContext

const
  BUCKET_SIZE = 16
  BITS_PER_HOP = 8
  REQUEST_TIMEOUT = chronos.milliseconds(5000) # timeout of message round trips
  FIND_CONCURRENCY = 3                  # parallel find node lookups
  ID_SIZE = 256



proc newKademliaProtocol*[Wire](
    thisNode: Node, wire: Wire, rng = newRng()): KademliaProtocol[Wire] =
  if rng == nil: raiseAssert "Need an RNG" # doAssert gives compile error on mac

  result.new()
  result.thisNode = thisNode
  result.wire = wire
  result.routing.init(thisNode)
  result.rng = rng
  result.bond = newBondProtocol(thisNode, wire, result.routing)

proc waitNeighbours(k: KademliaProtocol, remote: Node):
    Future[seq[Node]] {.raises: [Defect].} =
  doAssert(remote notin k.neighboursCallbacks)
  result = newFuture[seq[Node]]("waitNeighbours")
  let fut = result
  var neighbours = newSeqOfCap[Node](BUCKET_SIZE)
  k.neighboursCallbacks[remote] = proc(n: seq[Node]) {.gcsafe, raises: [Defect].} =
    # This callback is expected to be called multiple times because nodes usually
    # split the neighbours replies into multiple packets, so we only complete the
    # future event.set() we've received enough neighbours.

    for i in n:
      if i != k.thisNode:
        neighbours.add(i)
        if neighbours.len == BUCKET_SIZE:
          k.neighboursCallbacks.del(remote)
          doAssert(not fut.finished)
          fut.complete(neighbours)

  onTimeout(REQUEST_TIMEOUT):
    if not fut.finished:
      k.neighboursCallbacks.del(remote)
      fut.complete(neighbours)

# Exported for test.
proc findNode*(k: KademliaProtocol, nodesSeen: ref HashSet[Node],
               nodeId: NodeId, remote: Node): Future[seq[Node]] {.async.} =
  # used in lookup only
  # sends a (1-hop) findNode, waits responses and bonds to them, finally sends back bonded ones
  if remote in k.neighboursCallbacks:
    # Sometimes findNode is called while another findNode is already in flight.
    # It's a bug when this happens, and the logic should probably be fixed
    # elsewhere.  However, this small fix has been tested and proven adequate.
    debug "Ignoring peer already in k.neighboursCallbacks", peer = remote
    result = newSeq[Node]()
    return
  k.wire.sendFindNode(remote, nodeId)
  var candidates = await k.waitNeighbours(remote)
  if candidates.len == 0:
    trace "Got no candidates from peer, returning", peer = remote
    result = candidates
  else:
    # The following line:
    # 1. Add new candidates to nodesSeen so that we don't attempt to bond with failing ones
    # in the future
    # 2. Removes all previously seen nodes from candidates
    # 3. Deduplicates candidates
    candidates.keepItIf(not nodesSeen[].containsOrIncl(it))
    trace "Got new candidates", count = candidates.len

    var bondedNodes: seq[Future[bool]] = @[]
    for node in candidates:
      bondedNodes.add(k.bond.bond(node)) # TODO: it would be enough to bond with those that we select for next round ...

    await allFutures(bondedNodes)

    for i in 0..<bondedNodes.len:
      let b = bondedNodes[i]
      # `bond` will not raise so there should be no failures,
      # and for cancellation this should be fine to raise for now.
      doAssert(b.finished() and not(b.failed()))
      let bonded = b.read()
      if not bonded: candidates[i] = nil

    candidates.keepItIf(not it.isNil)
    trace "Bonded with candidates", count = candidates.len
    result = candidates

proc populateNotFullBuckets(k: KademliaProtocol) =
  ## Go through all buckets that are not full and try to fill them.
  ##
  ## For every node in the replacement cache of every non-full bucket, try to bond.
  ## When the bonding succeeds the node is automatically added to the bucket.
  for bucket in k.routing.notFullBuckets:
    for node in bucket.replacementCache:
      asyncSpawn k.bond.bondDiscard(node)

proc sortByDistance(nodes: var seq[Node], nodeId: NodeId, maxResults = 0) =
  nodes = nodes.sortedByIt(it.distanceTo(nodeId))
  if maxResults != 0 and nodes.len > maxResults:
    nodes.setLen(maxResults)

proc lookup*(k: KademliaProtocol, nodeId: NodeId): Future[seq[Node]] {.async.} =
  ## Lookup performs a network search for nodes close to the given target.

  ## It approaches the target by querying nodes that are closer to it on each iteration.  The
  ## given target does not need to be an actual node identifier.
  var nodesAsked = initHashSet[Node]()
  let nodesSeen = new(HashSet[Node])

  proc excludeIfAsked(nodes: seq[Node]): seq[Node] =
    # Returns at most FIND_CONCURRENCY nodes, not yet asked, closest to NodeId
    result = toSeq(items(nodes.toHashSet() - nodesAsked))
    sortByDistance(result, nodeId, FIND_CONCURRENCY)

  var closest = k.routing.neighbours(nodeId)
  trace "Starting lookup; initial neighbours: ", closest
  var nodesToAsk = excludeIfAsked(closest)
  while nodesToAsk.len != 0:
    trace "Node lookup; querying ", nodesToAsk
    nodesAsked.incl(nodesToAsk.toHashSet())

    var findNodeRequests: seq[Future[seq[Node]]] = @[]
    for node in nodesToAsk:
      findNodeRequests.add(k.findNode(nodesSeen, nodeId, node))

    # waits for all FIND_CONCURRENCY requests to return or timeout. TODO: k out of n suffice?
    await allFutures(findNodeRequests)

    for candidates in findNodeRequests:
      # `findNode` will not raise so there should be no failures,
      # and for cancellation this should be fine to raise for now.
      doAssert(candidates.finished() and not(candidates.failed()))
      closest.add(candidates.read())

    sortByDistance(closest, nodeId, BUCKET_SIZE) # TODO: why BUCKET_SIZE here, and not FIND_CONCURRENCY?
    # TODO: We also need Unique here
    nodesToAsk = excludeIfAsked(closest)

  trace "Kademlia lookup finished", target = nodeId.toHex, closest
  result = closest

proc lookupRandom*(k: KademliaProtocol): Future[seq[Node]] =
  # lookup a randomly generated ID
  # used in bootstrap to populate the rooting table as a sideeffect of the lookup
  # Returns: same as lookup
  var id: NodeId
  var buf: array[sizeof(id), byte]
  brHmacDrbgGenerate(k.rng[], buf)
  copyMem(addr id, addr buf[0], sizeof(id))

  k.lookup(id)

proc resolve*(k: KademliaProtocol, id: NodeId): Future[Node] {.async.} =
  let closest = await k.lookup(id)
  for n in closest:
    if n.id == id: return n

proc bootstrap*(k: KademliaProtocol, bootstrapNodes: seq[Node], retries = 0) {.async.} =
  ## Bond with bootstrap nodes and do initial lookup. Retry `retries` times
  ## in case of failure, or indefinitely if `retries` is 0.
  var retryInterval = chronos.milliseconds(2)
  var numTries = 0
  if bootstrapNodes.len != 0:
    while true:
      var bondedNodes: seq[Future[bool]] = @[]
      for node in bootstrapNodes:
        bondedNodes.add(k.bond.bond(node))
      await allFutures(bondedNodes)

      # `bond` will not raise so there should be no failures,
      # and for cancellation this should be fine to raise for now.
      let bonded = bondedNodes.mapIt(it.read())

      if true notin bonded:
        inc numTries
        if retries == 0 or numTries < retries:
          info "Failed to bond with bootstrap nodes, retrying", k=k.thisNode
          retryInterval = min(chronos.seconds(10), retryInterval * 2)
          await sleepAsync(retryInterval)
        else:
          info "Failed to bond with bootstrap nodes"
          return
      else:
        break
    discard await k.lookupRandom() # Prepopulate the routing table
  else:
    info "Skipping discovery bootstrap, no bootnodes provided"

proc recvPong*(k: KademliaProtocol, n: Node, token: seq[byte]) =
  k.bond.recvPong(n, token)

proc recvPing*(k: KademliaProtocol, n: Node, msgHash: any)
    {.raises: [ValueError, Defect].} =
  k.bond.recvPing(n, msgHash)

proc recvNeighbours*(k: KademliaProtocol, remote: Node, neighbours: seq[Node]) =
  ## Process a neighbours response.
  ##
  ## Neighbours responses should only be received as a reply to a find_node, and that is only
  ## done as part of node lookup, so the actual processing is left to the callback from
  ## neighbours_callbacks, which is added (and removed after it's done or timed out) in
  ## wait_neighbours().
  trace "Received neighbours", remote, neighbours
  let cb = k.neighboursCallbacks.getOrDefault(remote)
  if not cb.isNil:
    cb(neighbours)
  else:
    trace "Unexpected neighbours, probably came too late", remote

proc recvFindNode*(k: KademliaProtocol, remote: Node, nodeId: NodeId)
    {.raises: [ValueError, Defect].} =
  if remote notin k.routing:
    # FIXME: This is not correct; a node we've bonded before may have become unavailable
    # and thus removed from self.routing, but once it's back online we should accept
    # find_nodes from them.
    # TODO: this also blocks until the bonding is finalized, which includes an extra ping timeout. Is it needed?
    # TODO: is this also blocking when the node does not make it to the routing table? E.g. while it is in the replacementCache.
    # TODO: seems we are sending back itself to the node as part of the list. Should this be excluded? 
    trace "Ignoring find_node request from unknown node ", remote
    return
  k.bond.updateRoutingTable(remote)
  var found = k.routing.neighbours(nodeId)
  found.sort() do(x, y: Node) -> int: cmp(x.id, y.id)
  k.wire.sendNeighbours(remote, found)

proc randomNodes*(k: KademliaProtocol, count: int): seq[Node] =
  k.routing.randomNodes(count)

proc nodesDiscovered*(k: KademliaProtocol): int = k.routing.len

when isMainModule:
  proc randomNode(): Node =
    newNode("enode://aa36fdf33dd030378a0168efe6ed7d5cc587fafa3cdd375854fe735a2e11ea3650ba29644e2db48368c46e1f60e716300ba49396cd63778bf8a818c09bded46f@13.93.211.84:30303")

  var nodes = @[randomNode()]
  doAssert(computeSharedPrefixBits(nodes) == ID_SIZE)
  nodes.add(randomNode())
  nodes[0].id = 0b1.u256
  nodes[1].id = 0b0.u256
  doAssert(computeSharedPrefixBits(nodes) == ID_SIZE - 1)

  nodes[0].id = 0b010.u256
  nodes[1].id = 0b110.u256
  doAssert(computeSharedPrefixBits(nodes) == ID_SIZE - 3)
