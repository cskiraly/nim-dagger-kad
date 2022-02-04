# nim-eth
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  std/times,
  std/tables,
  std/sequtils,
  chronos, stint, nimcrypto/keccak, chronicles, bearssl,
  chronos/timer, # needed for doSleep parameter definition timer.Duration
  stew/[objects, results],
  "../eth"/[keys, rlp],
  "."/[kademlia, enode, node, helpers]

export
  Node, results

logScope:
  topics = "discovery"

const
  # UDP packet constants.
  MAC_SIZE = 256 div 8  # 32
  SIG_SIZE = 520 div 8  # 65
  HEAD_SIZE = MAC_SIZE + SIG_SIZE  # 97
  EXPIRATION = 60  # let messages expire after N secondes
  PROTO_VERSION = 4

type
  DiscoveryProtocol* = ref object
    privKey: PrivateKey # uses keys.nim which uses nimcrypto
    address: Address  # uses enode.nim
    bootstrapNodes*: seq[Node]
    thisNode*: Node
    kademlia*: KademliaProtocol[DiscoveryProtocol]
    transp: DatagramTransport # uses chronos
    providers*: Table[NodeId, seq[Node]]
    providersCallbacks: Table[NodeId, proc(n: seq[Node]) {.gcsafe, raises: [Defect].}]

  CommandId = enum
    cmdPing = 1
    cmdPong = 2
    cmdFindNode = 3
    cmdNeighbours = 4
    cmdAddProvider = 5
    cmdGetProviders = 6
    cmdProviders = 7

  DiscProtocolError* = object of CatchableError

  DiscResult*[T] = Result[T, cstring]

# number of mandatory fields, also used to get the index of expiration
const MinListLen: array[CommandId, int] = [4, 3, 2, 3, 3, 2, 3]

# --- constructor ---

proc newDiscoveryProtocol*(privKey: PrivateKey, address: Address,
                           bootstrapNodes: openArray[ENode], rng = newRng()
                           ): DiscoveryProtocol =
  result.new()
  result.privKey = privKey
  result.address = address
  result.bootstrapNodes = newSeqOfCap[Node](bootstrapNodes.len)
  for n in bootstrapNodes: result.bootstrapNodes.add(newNode(n))
  result.thisNode = newNode(privKey.toPublicKey(), address)
  result.kademlia = newKademliaProtocol(result.thisNode, result, rng = rng)

# --- message TX ----
proc append(w: var RlpWriter, a: IpAddress) =
  case a.family
  of IpAddressFamily.IPv6:
    w.append(a.address_v6)
  of IpAddressFamily.IPv4:
    w.append(a.address_v4)

proc append(w: var RlpWriter, p: Port) = w.append(p.int)
proc append(w: var RlpWriter, pk: PublicKey) = w.append(pk.toRaw())
proc append(w: var RlpWriter, h: MDigest[256]) = w.append(h.data)
proc append(w: var RlpWriter, x: UInt256) = w.append(x.toBytesBE)

proc pack(cmdId: CommandId, payload: openArray[byte], pk: PrivateKey): seq[byte] =
  ## Create and sign a UDP message to be sent to a remote node.
  ##
  ## See https://github.com/ethereum/devp2p/blob/master/rlpx.md#node-discovery for information on
  ## how UDP packets are structured.

  # TODO: There is a lot of unneeded allocations here
  let encodedData = @[cmdId.byte] & @payload
  let signature = @(pk.sign(encodedData).toRaw())
  let msgHash = keccak256.digest(signature & encodedData)
  result = @(msgHash.data) & signature & encodedData

proc expiration(): uint32 =
  result = uint32(epochTime() + EXPIRATION)

proc send(d: DiscoveryProtocol, dst: Node, data: seq[byte]) {.raises: [Defect].} =
  let n = dst.node
  trace "sendig to:", dst = n

  let ta = initTAddress(n.address.ip, n.address.udpPort)
  let f = d.transp.sendTo(ta, data)
  f.callback = proc(data: pointer) {.gcsafe.} =
    if f.failed:
      debug "Discovery send failed", msg = f.readError.msg

# --- Wire protocol encoders ---
# - defines message structure per message type
# - uses RLP binary encoding on the above structure
# - packs using common external format as:  hash | signature | rlp-encoded-data
# - outputs to common "send" function

proc sendPing*(d: DiscoveryProtocol, n: Node): seq[byte] {.raises: [Defect].} =
  # TODO: check why PROTO_VERSION, d.address, n.node.address are not used in recvPing
  let payload = rlp.encode((PROTO_VERSION, d.address, n.node.address,
                            expiration()))
  let msg = pack(cmdPing, payload, d.privKey)
  result = msg[0 ..< MAC_SIZE]
  trace ">>> ping ", src = d.thisNode, dst = n
  d.send(n, msg)

proc sendPong*(d: DiscoveryProtocol, n: Node, token: MDigest[256]) =
  let payload = rlp.encode((n.node.address, token, expiration()))
  let msg = pack(cmdPong, payload, d.privKey)
  trace ">>> pong ", src = d.thisNode, dst = n
  d.send(n, msg)

proc sendFindNode*(d: DiscoveryProtocol, n: Node, targetNodeId: NodeId) =
  ## The specification asks for the Public key to be sent, which is 64-bytes in its uncompressed form.
  ## However, this implementation is sending the Kad ID, which is the hash of the public key,
  ## and thus uses only the last 32 bytes.
  ## TODO: how this realtes to various specs?
  var data: array[64, byte]
  data[32 .. ^1] = targetNodeId.toByteArrayBE()
  let payload = rlp.encode((data, expiration()))
  let msg = pack(cmdFindNode, payload, d.privKey)
  trace ">>> find_node to ", src = d.thisNode, dst = n
  d.send(n, msg)

proc sendNodes(d: DiscoveryProtocol, node: Node, cmdId: CommandId, qId: NodeId, neighbours: seq[Node]) =
  const MAX_NEIGHBOURS_PER_PACKET = 12 # TODO: Implement a smarter way to compute it
  type AddressEnc = tuple[ip: IpAddress, udpPort, tcpPort: Port]
  type Neighbour = tuple[a: AddressEnc, pk: PublicKey]
  var nodes = newSeqOfCap[Neighbour](MAX_NEIGHBOURS_PER_PACKET)
  shallow(nodes)

  template flush() =
    block:
      let payload = rlp.encode((qId, nodes, expiration()))
      let msg = pack(cmdId, payload, d.privKey)
      trace ">>> Nodes to", cmdId, src = d.thisNode, dst = node, nodes
      d.send(node, msg)
      nodes.setLen(0)

  for i, n in neighbours:
    nodes.add(((n.node.address.ip, n.node.address.udpPort,
               n.node.address.tcpPort), n.node.pubkey))
    if nodes.len == MAX_NEIGHBOURS_PER_PACKET:
      flush()

  if nodes.len != 0: flush()

proc sendNeighbours*(d: DiscoveryProtocol, node: Node, qId: NodeId, neighbours: seq[Node]) =
  sendNodes(d, node, cmdNeighbours, qId, neighbours)

proc sendAddProvider*(d: DiscoveryProtocol, dst: Node, cId: NodeId) =
  type NodeDesc = tuple[ip: IpAddress, udpPort, tcpPort: Port, pk: PublicKey]
  let cIdEnc = cId.toByteArrayBE()
  let provider = d.thisNode.node
  let providerEnc = (provider.address.ip, provider.address.udpPort,
               provider.address.tcpPort, provider.pubkey)
  let payload = rlp.encode((cIdEnc, providerEnc, expiration()))
  let msg = pack(cmdAddProvider, payload, d.privKey)
  trace ">>> add_provider to ", src = d.thisNode, dst, cId
  d.send(dst, msg)

proc sendGetProviders*(d: DiscoveryProtocol, dst: Node, cId: NodeId) =
  let cIdEnc = cId.toByteArrayBE()
  let payload = rlp.encode((cIdEnc, expiration()))
  let msg = pack(cmdGetProviders, payload, d.privKey)
  trace ">>> get_providers to ", src = d.thisNode, dst, cId
  d.send(dst, msg)

proc sendProviders*(d: DiscoveryProtocol, node: Node, qId: NodeId, neighbours: seq[Node]) =
  sendNodes(d, node, cmdProviders, qId, neighbours)

# --- rlp message decoders ---

# --- Wire protocol decoders ---
# - uses common external format as:  hash | signature | rlp-encoded-data
# - uses RLP binary encoding inside
# - defines message structure per message
# - outputs to common "send" function

proc recvPing(d: DiscoveryProtocol, node: Node, msgHash: MDigest[256])
    {.raises: [ValueError, Defect].} =
  d.kademlia.recvPing(node, msgHash)

proc recvPong(d: DiscoveryProtocol, node: Node, payload: seq[byte])
    {.raises: [RlpError, Defect].} =
  let rlp = rlpFromBytes(payload)
  let tok = rlp.listElem(1).toBytes()
  d.kademlia.recvPong(node, tok)

proc decodeAddress(rlp: Rlp) : Address
    {.raises: [RlpError, Defect].} =
  let ipBlob = rlp.listElem(0).toBytes
  var ip: IpAddress
  case ipBlob.len
  of 4:
    ip = IpAddress(
      family: IpAddressFamily.IPv4, address_v4: toArray(4, ipBlob))
  of 16:
    ip = IpAddress(
      family: IpAddressFamily.IPv6, address_v6: toArray(16, ipBlob))
  else:
    error "Wrong ip address length!"
    #return nil #TODO: we need some optional here

  let udpPort = rlp.listElem(1).toInt(uint16).Port
  let tcpPort = rlp.listElem(2).toInt(uint16).Port

  return Address(ip: ip, udpPort: udpPort, tcpPort: tcpPort)

proc decodePublicKey(rlp: Rlp) : auto
    {.raises: [RlpError, Defect].} =

  result = PublicKey.fromRaw(rlp.toBytes)
  if result.isErr:
    warn "Could not parse public key"

proc decodeNode(rlp: Rlp) : Node
    {.raises: [RlpError, Defect].} =

    let address = decodeAddress(rlp.listElem(0))

    let pk = decodePublicKey(rlp.listElem(1))
    if pk.isErr:
      warn "Could not parse public key"
      #return nil #TODO: we need some optional here

    return newNode(pk[], address)

proc decodeNodes(neighboursList: Rlp) : seq[Node]
    {.raises: [RlpError, Defect].} =
  let sz = neighboursList.listLen()
  for i in 0 ..< sz:
    let n = decodeNode(neighboursList.listElem(i))
    result.add(n)

proc recvNeighbours(d: DiscoveryProtocol, node: Node, payload: seq[byte])
    {.raises: [RlpError, Defect].} =
  trace "<<< neighbours from ", dst = d.thisNode, src = node
  let rlp = rlpFromBytes(payload)
  let neighboursList = rlp.listElem(1)
  let neighbours = decodeNodes(neighboursList)
  d.kademlia.recvNeighbours(node, neighbours)

proc recvFindNode(d: DiscoveryProtocol, node: Node, payload: openArray[byte])
    {.raises: [RlpError, ValueError, Defect].} =
  ## Uses only last 32 bytes of 64 bytes sent
  let rlp = rlpFromBytes(payload)
  trace "<<< find_node from ", dst = d.thisNode, src = node
  let rng = rlp.listElem(0).toBytes
  # Check for pubkey len
  if rng.len == 64:
    let nodeId = readUintBE[256](rng[32 .. ^1])
    d.kademlia.recvFindNode(node, nodeId)
  else:
    trace "Invalid target public key received"

proc addProviderLocal(d: DiscoveryProtocol, cId: NodeId, prov: Node) = 
  d.providers.mgetOrPut(cId, @[]).add(prov)

proc recvAddProvider(d: DiscoveryProtocol, node: Node, payload: openArray[byte])
    {.raises: [RlpError, Defect].} =
  let rlp = rlpFromBytes(payload)
  trace "<<< add_provider from ", dst = d.thisNode, src = node
  let cId = readUintBE[256](rlp.listElem(0).toBytes)

  let n = rlp.listElem(1)
  let ipBlob = n.listElem(0).toBytes
  var ip: IpAddress
  case ipBlob.len
  of 4:
    ip = IpAddress(
      family: IpAddressFamily.IPv4, address_v4: toArray(4, ipBlob))
  of 16:
    ip = IpAddress(
      family: IpAddressFamily.IPv6, address_v6: toArray(16, ipBlob))
  else:
    error "Wrong ip address length!"
    return

  let udpPort = n.listElem(1).toInt(uint16).Port
  let tcpPort = n.listElem(2).toInt(uint16).Port
  let pk = PublicKey.fromRaw(n.listElem(3).toBytes)
  if pk.isErr:
    warn "Could not parse public key"
    return

  #TODO: add checks, add signed version
  let prov = newNode(pk[], Address(ip: ip, udpPort: udpPort, tcpPort: tcpPort))
  d.addProviderLocal(cId, prov)

  #TODO: check that CID is reasonably close to our NodeID

proc recvGetProviders(d: DiscoveryProtocol, node: Node, payload: openArray[byte])
    {.raises: [RlpError, Defect].} =
  let rlp = rlpFromBytes(payload)
  trace "<<< get_providers from ", dst = d.thisNode, src = node
  let cId = readUintBE[256](rlp.listElem(0).toBytes)

  #TODO: add checks, add signed version
  let provs = d.providers.getOrDefault(cId)
  trace "providers:", provs
  d.sendProviders(node, cId, provs)

proc recvProviders(d: DiscoveryProtocol, node: Node, payload: seq[byte])
    {.raises: [RlpError, Defect].} =
  trace "<<< providers from ", dst = d.thisNode, src = node

  let rlp = rlpFromBytes(payload)
  let qId = UInt256.fromBytesBE(rlp.listElem(0).toBytes)
  let neighboursList = rlp.listElem(1)
  let providers = decodeNodes(neighboursList)

  warn "recvProviders adding ", this=d.thisNode, providers
  let cb = d.providersCallbacks.getOrDefault(qId)
  if not cb.isNil:
    cb(providers)
  else:
    warn "Unexpected neighbours, probably came too late", node

# --- kademlia proxy ---

proc lookupRandom*(d: DiscoveryProtocol): Future[seq[Node]] =
  d.kademlia.lookupRandom()

proc resolve*(d: DiscoveryProtocol, n: NodeId): Future[Node] =
  d.kademlia.resolve(n)

proc randomNodes*(d: DiscoveryProtocol, count: int): seq[Node] =
  d.kademlia.randomNodes(count)

# --- message reception ---

# Receive and its helpers

proc validateMsgHash(msg: openArray[byte]): DiscResult[MDigest[256]] =
  if msg.len > HEAD_SIZE:
    var ret: MDigest[256]
    ret.data[0 .. ^1] = msg.toOpenArray(0, ret.data.high)
    if ret == keccak256.digest(msg.toOpenArray(MAC_SIZE, msg.high)):
      ok(ret)
    else:
      err("disc: invalid message hash")
  else:
    err("disc: msg missing hash")

proc recoverMsgPublicKey(msg: openArray[byte]): DiscResult[PublicKey] =
  if msg.len <= HEAD_SIZE:
    return err("disc: can't get public key")
  let sig = ? Signature.fromRaw(msg.toOpenArray(MAC_SIZE, HEAD_SIZE))
  recover(sig, msg.toOpenArray(HEAD_SIZE, msg.high))

proc unpack(msg: openArray[byte]): tuple[cmdId: CommandId, payload: seq[byte]]
    {.raises: [DiscProtocolError, Defect].} =
  # Check against possible RangeError
  if msg[HEAD_SIZE].int < CommandId.low.ord or
     msg[HEAD_SIZE].int > CommandId.high.ord:
    raise newException(DiscProtocolError, "Unsupported packet id")

  result = (cmdId: msg[HEAD_SIZE].CommandId, payload: msg[HEAD_SIZE + 1 .. ^1])

proc expirationValid(cmdId: CommandId, rlpEncodedPayload: openArray[byte]):
    bool {.raises: [DiscProtocolError, RlpError].} =
  ## Can only raise `DiscProtocolError` and all of `RlpError`
  # Check if there is a payload
  if rlpEncodedPayload.len <= 0:
    raise newException(DiscProtocolError, "RLP stream is empty")
  let rlp = rlpFromBytes(rlpEncodedPayload)
  # Check payload is an RLP list and if the list has the minimum items required
  # for this packet type
  if rlp.isList and rlp.listLen >= MinListLen[cmdId]:
    # Expiration is always the last mandatory item of the list
    let expiration = rlp.listElem(MinListLen[cmdId] - 1).toInt(uint32)
    result = epochTime() <= expiration.float
  else:
    raise newException(DiscProtocolError, "Invalid RLP list for this packet id")

# exported only for tests
proc receive*[srcT](d: DiscoveryProtocol, src: srcT, msg: openArray[byte])
    {.raises: [DiscProtocolError, RlpError, ValueError, Defect].} =
  # Receive and if needed create Kademlia Node before passing message up
  # Note: export only needed for testing
  let msgHash = validateMsgHash(msg)
  if msgHash.isOk():
    let remotePubkey = recoverMsgPublicKey(msg)
    if remotePubkey.isOk:
      let (cmdId, payload) = unpack(msg)

      if expirationValid(cmdId, payload):
        let node = newNode(remotePubkey[], src)
        case cmdId
        of cmdPing:
          d.recvPing(node, msgHash[])
        of cmdPong:
          d.recvPong(node, payload)
        of cmdNeighbours:
          d.recvNeighbours(node, payload)
        of cmdFindNode:
          d.recvFindNode(node, payload)
        of cmdAddProvider:
          d.recvAddProvider(node, payload)
        of cmdGetProviders:
          d.recvGetProviders(node, payload)
        of cmdProviders:
          d.recvProviders(node, payload)
      else:
        trace "Received msg already expired", cmdId, src
    else:
      notice "Wrong public key from ", src, err = remotePubkey.error
  else:
    notice "Wrong msg mac from ", src

# Open and its helpers, including RX callback binding

proc processClient(transp: DatagramTransport, raddr: TransportAddress):
    Future[void] {.async, raises: [Defect].} =
  # callback for undelying layer reception
  var proto = getUserData[DiscoveryProtocol](transp)
  let buf = try: transp.getMessage()
            except TransportOsError as e:
              # This is likely to be local network connection issues.
              warn "Transport getMessage", exception = e.name, msg = e.msg
              return
  let a = Address(ip: raddr.address, udpPort: raddr.port, tcpPort: raddr.port)
  try:
    proto.receive(a, buf)
  except RlpError as e:
    debug "Receive failed", exc = e.name, err = e.msg
  except DiscProtocolError as e:
    debug "Receive failed", exc = e.name, err = e.msg
  except ValueError as e:
    debug "Receive failed", exc = e.name, err = e.msg

proc openUdp(d: DiscoveryProtocol) {.raises: [Defect, CatchableError].} =
  # TODO allow binding to specific IP / IPv6 / etc
  # registers "processClient" callback in undelying layer
  let ta = initTAddress(IPv4_any(), d.address.udpPort)
  # store DiscoveryProtocol as callback user data
  d.transp = newDatagramTransport(processClient, udata = d, local = ta)

proc open*(d: DiscoveryProtocol) {.raises: [Defect, CatchableError].} =
  d.openUdp()

# Bootstrap and its helpers

proc run(d: DiscoveryProtocol) {.async.} =
  while true:
    trace "Starting periodic random lookup", d = d.thisNode
    discard await d.lookupRandom()
    await sleepAsync(chronos.seconds(3)) # TODO: expose as const
    trace "Discovered nodes", d = d.thisNode, nodes = d.kademlia.nodesDiscovered

proc bootstrap*(d: DiscoveryProtocol) {.async.} =
  trace "kademlia bootstrap start", d = d.thisNode
  await d.kademlia.bootstrap(d.bootstrapNodes)
  trace "kademlia bootstrap finished", d = d.thisNode
  discard d.run()

# --- Providers ---

proc addProvider*(d: DiscoveryProtocol, cId: NodeId): Future[seq[Node]] {.async.} =
  result = await d.kademlia.lookup(cId)
  for n in result:
    if n != d.thisNode:
      d.sendAddProvider(n, cId)
    else:
      d.addProviderLocal(cId, d.thisNode)

proc waitProviders(d: DiscoveryProtocol, qId: NodeId, maxitems: int, timeout: timer.Duration):
    Future[seq[Node]] {.raises: [Defect].} =
  ## Process incoming cmdProviders messages waiting for enough providers, or timeout
  ##
  ## Incoming messages are matched with the original query based on the qId query ID.
  ## Since we limit the number of providers in the result, it is worth doing some filtering
  ## * we remove outselves, assuming the node already knows whether it is a provider. Note
  ## that this also means we can't use this call to check whther we are listed, actually, we
  ## could do this removal at the src of cmdProviders (TODO)
  ## * since a single call to this can capture cmdProviders messages from multiple nodes,
  ## we should also deduplicate the list
  ## TODO: generlalize (similar function  in kademlia.waitNeighbours)
  doAssert(qId notin d.providersCallbacks)
  result = newFuture[seq[Node]]("waitProviders")
  let fut = result
  var nodes = newSeqOfCap[Node](maxitems)
  d.providersCallbacks[qId] = proc(n: seq[Node]) {.gcsafe, raises: [Defect].} =
    # This callback is expected to be called multiple times because nodes usually
    # split the replies into multiple packets, so we only complete the
    # future event.set() we've received enough neighbours.

    for i in n:
      if i != d.thisNode and i notin nodes:
        nodes.add(i)
        if nodes.len == maxitems:
          d.providersCallbacks.del(qId)
          doAssert(not fut.finished)
          fut.complete(nodes)

  onTimeout(timeout):
    if not fut.finished:
      d.providersCallbacks.del(qId)
      fut.complete(nodes)

proc getProviders*(
    d: DiscoveryProtocol,
    cId: NodeId,
    maxitems: int = 5,
    timeout: timer.Duration = chronos.milliseconds(5000)
  ): Future[seq[Node]] {.async.} =
  ## Search for providers of the given cId.
  ##
  ## Providers are not (by default) bonded, so they are not verified.
  ## Search until maxitems providers are found or the timeout expires.
  ## There is no one-to-one correspondance between cmdGetProviders messages and cmdProviders responses,
  ## and it is useless to try to wait for all the responses here with a simple await. What we need is enough
  ## responses or a timeout. An accumulator of responses that is fireing on condition.
  ## For this, we better have a a query ID that is included in all responses.
  ## We collect responses as they come it, and create a conditional waitProviders future that whatches these condotions.
  ## like kademlia.waitNeigbours
  
  # What providers do we know about?
  let provs =
    if cId in d.providers:
      d.providers[cId]
    else:
      @[]
  warn "provs:", provs

  let nodesNearby = await d.kademlia.lookup(cId)
  for n in nodesNearby:
    d.sendGetProviders(n, cId)

  result = provs.concat(await d.waitProviders(cId, maxitems, timeout)).deduplicate
  info "getProviders collected: ", result
