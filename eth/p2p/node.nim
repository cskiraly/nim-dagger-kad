# nim-eth
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  std/[hashes],
  nimcrypto/keccak,
  stint,
  chronos, # only for $ on UdpPort
  ./enode

type
  NodeId* = UInt256

  Node* = ref object
    node*: ENode
    id*: NodeId

proc toNodeId*(pk: PublicKey): NodeId =
  readUintBE[256](keccak256.digest(pk.toRaw()).data)

proc newNode*(pk: PublicKey, address: Address): Node =
  result.new()
  result.node = ENode(pubkey: pk, address: address)
  result.id = pk.toNodeId()

proc newNode*(uriString: string): Node =
  result.new()
  result.node = ENode.fromString(uriString)[]
  result.id = result.node.pubkey.toNodeId()

proc newNode*(enode: ENode): Node =
  result.new()
  result.node = enode
  result.id = result.node.pubkey.toNodeId()

proc distanceTo*(n: Node, id: NodeId): UInt256 = n.id xor id

proc `$`*(n: Node): string =
  if n == nil:
    "Node[local]"
  else:
    "Node:" & $(n.id mod 1000) & "[" & $n.node.address.ip & ":" & $n.node.address.udpPort & "]"

proc hash*(n: Node): hashes.Hash = hash(n.node.pubkey.toRaw)
proc `==`*(a, b: Node): bool = (a.isNil and b.isNil) or
  (not a.isNil and not b.isNil and a.node.pubkey == b.node.pubkey)
