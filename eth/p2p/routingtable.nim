
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
  ./enode,
  ./helpers,
  ./node

const
  BUCKET_SIZE = 16
  BITS_PER_HOP = 8
  ID_SIZE = 256

type
  RoutingTable* = object #TODO: check if better ref
    thisNode: Node
    buckets: seq[KBucket]

  KBucket = ref object
    istart, iend: UInt256
    nodes: seq[Node]
    replacementCache: seq[Node]
    lastUpdated: float # epochTime

proc newKBucket(istart, iend: NodeId): KBucket =
  result.new()
  result.istart = istart
  result.iend = iend
  result.nodes = @[]
  result.replacementCache = @[]

proc midpoint(k: KBucket): NodeId =
  k.istart + (k.iend - k.istart) div 2.u256

proc distanceTo(k: KBucket, id: NodeId): UInt256 = k.midpoint xor id
proc nodesByDistanceTo(k: KBucket, id: NodeId): seq[Node] =
  sortedByIt(k.nodes, it.distanceTo(id))

proc len(k: KBucket): int = k.nodes.len
proc head(k: KBucket): Node = k.nodes[0]

proc add(k: KBucket, n: Node): Node =
  ## Try to add the given node to this bucket.

  ## If the node is already present, it is moved to the tail of the list, and we return None.

  ## If the node is not already present and the bucket has fewer than k entries, it is inserted
  ## at the tail of the list, and we return None.

  ## If the bucket is full, we add the node to the bucket's replacement cache and return the
  ## node at the head of the list (i.e. the least recently seen), which should be evicted if it
  ## fails to respond to a ping.
  k.lastUpdated = epochTime()
  let nodeIdx = k.nodes.find(n)
  if nodeIdx != -1:
      k.nodes.delete(nodeIdx)
      k.nodes.add(n)
  elif k.len < BUCKET_SIZE:
      k.nodes.add(n)
  else:
      k.replacementCache.add(n)
      return k.head
  return nil

proc removeNode(k: KBucket, n: Node) =
  let i = k.nodes.find(n)
  if i != -1: k.nodes.delete(i)

proc split(k: KBucket): tuple[lower, upper: KBucket] =
  ## Split at the median id
  let splitid = k.midpoint
  result.lower = newKBucket(k.istart, splitid)
  result.upper = newKBucket(splitid + 1.u256, k.iend)
  for node in k.nodes:
    let bucket = if node.id <= splitid: result.lower else: result.upper
    discard bucket.add(node)
  for node in k.replacementCache:
    let bucket = if node.id <= splitid: result.lower else: result.upper
    bucket.replacementCache.add(node)

proc inRange(k: KBucket, n: Node): bool =
  k.istart <= n.id and n.id <= k.iend

proc isFull(k: KBucket): bool = k.len == BUCKET_SIZE

proc contains(k: KBucket, n: Node): bool = n in k.nodes

proc binaryGetBucketForNode(buckets: openArray[KBucket], n: Node):
    KBucket {.raises: [ValueError, Defect].} =
  ## Given a list of ordered buckets, returns the bucket for a given node.
  let bucketPos = lowerBound(buckets, n.id) do(a: KBucket, b: NodeId) -> int:
    cmp(a.iend, b)
  # Prevents edge cases where bisect_left returns an out of range index
  if bucketPos < buckets.len:
    let bucket = buckets[bucketPos]
    if bucket.istart <= n.id and n.id <= bucket.iend:
      result = bucket

  if result.isNil:
    raise newException(ValueError, "No bucket found for node with id " & $n.id)

proc computeSharedPrefixBits(nodes: openArray[Node]): int =
  ## Count the number of prefix bits shared by all nodes.
  if nodes.len < 2:
    return ID_SIZE

  var mask = zero(UInt256)
  let one = one(UInt256)

  for i in 1 .. ID_SIZE:
    mask = mask or (one shl (ID_SIZE - i))
    let reference = nodes[0].id and mask
    for j in 1 .. nodes.high:
      if (nodes[j].id and mask) != reference: return i - 1

  doAssert(false, "Unable to calculate number of shared prefix bits")

proc init*(r: var RoutingTable, thisNode: Node) =
  r.thisNode = thisNode
  r.buckets = @[newKBucket(0.u256, high(UInt256))]
  randomize() # for later `randomNodes` selection

proc splitBucket(r: var RoutingTable, index: int) =
  let bucket = r.buckets[index]
  let (a, b) = bucket.split()
  r.buckets[index] = a
  r.buckets.insert(b, index + 1)

proc bucketForNode(r: RoutingTable, n: Node): KBucket
    {.raises: [ValueError, Defect].} =
  binaryGetBucketForNode(r.buckets, n)

proc removeNode*(r: var RoutingTable, n: Node) {.raises: [ValueError, Defect].} =
  r.bucketForNode(n).removeNode(n)

proc addNode*(r: var RoutingTable, n: Node): Node
    {.raises: [ValueError, Defect].} =
  if n == r.thisNode:
    warn "Trying to add ourselves to the routing table", node = n
    return
  let bucket = r.bucketForNode(n)
  let evictionCandidate = bucket.add(n)
  if not evictionCandidate.isNil:
    # Split if the bucket has the local node in its range or if the depth is not congruent
    # to 0 mod BITS_PER_HOP

    let depth = computeSharedPrefixBits(bucket.nodes)
    if bucket.inRange(r.thisNode) or (depth mod BITS_PER_HOP != 0 and depth != ID_SIZE):
      r.splitBucket(r.buckets.find(bucket))
      return r.addNode(n) # retry

    # Nothing added, ping evictionCandidate
    return evictionCandidate

proc contains*(r: RoutingTable, n: Node): bool {.raises: [ValueError, Defect].} =
  n in r.bucketForNode(n)

proc bucketsByDistanceTo(r: RoutingTable, id: NodeId): seq[KBucket] =
  sortedByIt(r.buckets, it.distanceTo(id))

proc notFullBuckets(r: RoutingTable): seq[KBucket] =
  r.buckets.filterIt(not it.isFull)

proc neighbours*(r: RoutingTable, id: NodeId, k: int = BUCKET_SIZE): seq[Node] =
  ## Return up to k neighbours of the given node.
  result = newSeqOfCap[Node](k * 2)
  for bucket in r.bucketsByDistanceTo(id):
    for n in bucket.nodesByDistanceTo(id):
      if n.id != id:
        result.add(n)
        if result.len == k * 2:
          break
  result = sortedByIt(result, it.distanceTo(id))
  if result.len > k:
    result.setLen(k)

proc len*(r: RoutingTable): int =
  for b in r.buckets: result += b.len

proc randomNodes*(r: RoutingTable, count: int): seq[Node] =
  var count = count
  let sz = r.len
  if count > sz:
    debug  "Looking for peers", requested = count, present = sz
    count = sz

  result = newSeqOfCap[Node](count)
  var seen = initHashSet[Node]()

  # This is a rather inneficient way of randomizing nodes from all buckets, but even if we
  # iterate over all nodes in the routing table, the time it takes would still be
  # insignificant compared to the time it takes for the network roundtrips when connecting
  # to nodes.
  while len(seen) < count:
    let bucket = r.buckets.sample()
    if bucket.nodes.len != 0:
      let node = bucket.nodes.sample()
      if node notin seen:
        result.add(node)
        seen.incl(node)
