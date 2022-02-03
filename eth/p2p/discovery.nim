# nim-eth
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  std/times,
  chronos, stint, nimcrypto/keccak, chronicles, bearssl,
  stew/[objects, results],
  ".."/[keys, rlp],
  "."/[kademlia, enode, node]

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

  CommandId = enum
    cmdPing = 1
    cmdPong = 2
    cmdFindNode = 3
    cmdNeighbours = 4

  DiscProtocolError* = object of CatchableError

  DiscResult*[T] = Result[T, cstring]

# number of mandatory fields, also used to get the index of expiration
const MinListLen: array[CommandId, int] = [4, 3, 2, 2]

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

proc sendNodes(d: DiscoveryProtocol, node: Node, cmdId: CommandId, neighbours: seq[Node]) =
  const MAX_NEIGHBOURS_PER_PACKET = 12 # TODO: Implement a smarter way to compute it
  type Neighbour = tuple[ip: IpAddress, udpPort, tcpPort: Port, pk: PublicKey]
  var nodes = newSeqOfCap[Neighbour](MAX_NEIGHBOURS_PER_PACKET)
  shallow(nodes)

  template flush() =
    block:
      let payload = rlp.encode((nodes, expiration()))
      let msg = pack(cmdId, payload, d.privKey)
      trace ">>> Nodes to", cmdId, src = d.thisNode, dst = node, nodes
      d.send(node, msg)
      nodes.setLen(0)

  for i, n in neighbours:
    nodes.add((n.node.address.ip, n.node.address.udpPort,
               n.node.address.tcpPort, n.node.pubkey))
    if nodes.len == MAX_NEIGHBOURS_PER_PACKET:
      flush()

  if nodes.len != 0: flush()

proc sendNeighbours*(d: DiscoveryProtocol, node: Node, neighbours: seq[Node]) =
  sendNodes(d, node, cmdNeighbours, neighbours)
# ---- rlp message decoders ---

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

proc recvNeighbours(d: DiscoveryProtocol, node: Node, payload: seq[byte])
    {.raises: [RlpError, Defect].} =
  let rlp = rlpFromBytes(payload)
  let neighboursList = rlp.listElem(0)
  let sz = neighboursList.listLen()

  var neighbours = newSeqOfCap[Node](16)
  for i in 0 ..< sz:
    let n = neighboursList.listElem(i)
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
      continue

    let udpPort = n.listElem(1).toInt(uint16).Port
    let tcpPort = n.listElem(2).toInt(uint16).Port
    let pk = PublicKey.fromRaw(n.listElem(3).toBytes)
    if pk.isErr:
      warn "Could not parse public key"
      continue

    neighbours.add(newNode(pk[], Address(ip: ip, udpPort: udpPort, tcpPort: tcpPort)))
  d.kademlia.recvNeighbours(node, neighbours)

proc recvFindNode(d: DiscoveryProtocol, node: Node, payload: openArray[byte])
    {.raises: [RlpError, ValueError, Defect].} =
  let rlp = rlpFromBytes(payload)
  trace "<<< find_node from ", node
  let rng = rlp.listElem(0).toBytes
  # Check for pubkey len
  if rng.len == 64:
    let nodeId = readUintBE[256](rng[32 .. ^1])
    d.kademlia.recvFindNode(node, nodeId)
  else:
    trace "Invalid target public key received"

# ---- kademlia proxy ---

proc lookupRandom*(d: DiscoveryProtocol): Future[seq[Node]] =
  d.kademlia.lookupRandom()

proc resolve*(d: DiscoveryProtocol, n: NodeId): Future[Node] =
  d.kademlia.resolve(n)

proc randomNodes*(d: DiscoveryProtocol, count: int): seq[Node] =
  d.kademlia.randomNodes(count)

# --- message reception ----

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

proc receive[srcT](d: DiscoveryProtocol, src: srcT, msg: openArray[byte])
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

#Bootstrap and its helpers

proc run(d: DiscoveryProtocol) {.async.} =
  while true:
    discard await d.lookupRandom()
    await sleepAsync(chronos.seconds(3))
    trace "Discovered nodes", d = d.thisNode, nodes = d.kademlia.nodesDiscovered

proc bootstrap*(d: DiscoveryProtocol) {.async.} =
  await d.kademlia.bootstrap(d.bootstrapNodes)
  trace "kademlia bootstrap finished", d = d.thisNode
  discard d.run()
