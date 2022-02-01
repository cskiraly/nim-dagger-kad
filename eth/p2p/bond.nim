# nim-eth
# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  std/[tables, hashes, times, algorithm, sets, sequtils, random],
  chronos, bearssl, chronicles, stint, nimcrypto/keccak,
  chronos/timer, # needed for doSleep parameter definition timer.Duration
  ../keys,
  ./node,
  ./routingtable,
  ./helpers

export sets # TODO: This should not be needed, but compilation fails otherwise

logScope:
  topics = "bond"

type
  BondProtocol* [Wire] = ref object
    wire: Wire
    routing: RoutingTable
    thisNode: Node
    pongFutures: Table[seq[byte], Future[bool]]
    pingFutures: Table[Node, Future[bool]]

const
  REQUEST_TIMEOUT = chronos.milliseconds(5000) # timeout of message round trips

proc updateRoutingTable*(k: BondProtocol, n: Node) : void
    {.raises: [ValueError, Defect], gcsafe.}

proc newBondProtocol*[Wire](
    thisNode: Node, wire: Wire, routing: RoutingTable): BondProtocol[Wire] =

  result.new()
  result.thisNode = thisNode
  result.wire = wire
  result.routing = routing #TODO: check if this needs ref

proc pingId(n: Node, token: seq[byte]): seq[byte] =
  result = token & @(n.node.pubkey.toRaw)

proc waitPong(k: BondProtocol, n: Node, pingid: seq[byte]): Future[bool] =
  doAssert(pingid notin k.pongFutures, "Already waiting for pong from " & $n)
  result = newFuture[bool]("waitPong")
  let fut = result
  k.pongFutures[pingid] = result
  onTimeout(REQUEST_TIMEOUT):
    if not fut.finished:
      k.pongFutures.del(pingid)
      fut.complete(false)

proc ping(k: BondProtocol, n: Node): seq[byte] =
  doAssert(n != k.thisNode)
  result = k.wire.sendPing(n)

proc waitPing(k: BondProtocol, n: Node): Future[bool] =
  result = newFuture[bool]("waitPing")
  doAssert(n notin k.pingFutures)
  k.pingFutures[n] = result
  let fut = result
  onTimeout(REQUEST_TIMEOUT):
    if not fut.finished:
      k.pingFutures.del(n)
      fut.complete(false)

proc bond*(k: BondProtocol, n: Node): Future[bool] {.async.} =
  ## Bond with the given node.
  ##
  ## Bonding consists of pinging the node, waiting for a pong and maybe a ping as well.
  ## It is necessary to do this at least once before we send findNode requests to a node.
  trace "Bonding to peer", n, this=k.thisNode
  if n in k.routing:
    return true

  let pid = pingId(n, k.ping(n))
  if pid in k.pongFutures:
    debug "Bonding failed, already waiting for pong", n, this=k.thisNode
    return false

  let gotPong = await k.waitPong(n, pid)
  if not gotPong:
    trace "Bonding failed, didn't receive pong from", n, this=k.thisNode
    # Drop the failing node and schedule a populateNotFullBuckets() call to try and
    # fill its spot.
    k.routing.removeNode(n)
    #TODO k.populateNotFullBuckets() #this calles 'bond'
    return false

  # Give the remote node a chance to ping us before we move on and start sending findNode
  # requests. It is ok for waitPing() to timeout and return false here as that just means
  # the remote remembers us.
  if n in k.pingFutures:
    debug "Bonding failed, already waiting for ping", n, this=k.thisNode
    return false

  discard await k.waitPing(n) #TODO: why is this needed here, seems like a useless timeout

  trace "Bonding completed successfully", n, this=k.thisNode
  k.updateRoutingTable(n)
  return true

proc bondDiscard*(k: BondProtocol, n: Node) {.async.} =
  discard (await k.bond(n))

proc recvPong*(k: BondProtocol, n: Node, token: seq[byte]) =
  trace "<<< pong from ", dst = k.thisNode, src = n
  let pingid = pingId(n, token)
  var future: Future[bool]
  if k.pongFutures.take(pingid, future):
    future.complete(true)

proc recvPing*(k: BondProtocol, n: Node, msgHash: any)
    {.raises: [ValueError, Defect].} =
  trace "<<< ping from ", dst = k.thisNode, src = n
  k.updateRoutingTable(n)
  k.wire.sendPong(n, msgHash)

  var future: Future[bool]
  if k.pingFutures.take(n, future):
    future.complete(true)

proc updateRoutingTable*(k: BondProtocol, n: Node)
    {.raises: [ValueError, Defect], gcsafe.} =
  ## Update the routing table entry for the given node.
  let evictionCandidate = k.routing.addNode(n)
  if not evictionCandidate.isNil:
      # This means we couldn't add the node because its bucket is full, so schedule a bond()
      # with the least recently seen node on that bucket. If the bonding fails the node will
      # be removed from the bucket and a new one will be picked from the bucket's
      # replacement cache.
      asyncSpawn k.bondDiscard(evictionCandidate)
