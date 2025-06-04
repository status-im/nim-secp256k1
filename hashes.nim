import std/typetraits, nimcrypto/keccak, ./base

type
  Hash32 = distinct Bytes32

func fromHex(_: type Hash32, s: openArray[char]): Hash32 {.raises: [ValueError].} =
  Hash32(Bytes32.fromHex(s))

type Address = distinct Bytes20

template copyFrom(T: type Address, v: openArray[byte], start = 0): T =
  Address(Bytes20.copyFrom(v, start))

import
  ./secp256k1

type
  PrivateKey = distinct SkSecretKey

func fromHex(T: type PrivateKey, data: string): SkResult[T] =
  SkSecretKey.fromHex(data).mapConvert(T)

import ./utils, std/tables

type
  DbTransaction = ref object
    parentTransaction: DbTransaction
    modifications: Table[seq[byte], int]

proc put(db: var Table[seq[byte], int], key: openArray[byte]) =
  db.withValue(@key, _) do:
    discard
  do:
    discard

proc get(t: var DbTransaction, key: openArray[byte]) =
  let key = @key

  while t != nil:
    discard getOrDefault(default(Table[seq[byte], int]), key)
    t = t.parentTransaction

import
  std/macros

type
  Genesis = object
    alloc      : GenesisAlloc

  GenesisAlloc = Table[string, GenesisAccount]
  GenesisAccount = object
    foo: string

  NetworkParams = object
    genesis: Genesis

macro fillArrayOfBlockNumberBasedForkOptionals(conf, tmp: typed): untyped =
  result = newStmtList()
  for _, _ in ["homesteadBlock"]: discard

import
  std/sequtils,
  results,
  nimcrypto/hash as foobar

type
  SomeEndianInt = uint8|uint64

func swapBytes(x: uint8): uint8 = x
func swapBytes(x: uint16): uint16 = (x shl 8) or (x shr 8)

func swapBytes(x: uint32): uint32 =
  let v = (x shl 16) or (x shr 16)

  ((v shl 8) and 0xff00ff00'u32) or ((v shr 8) and 0x00ff00ff'u32)

func swapBytes(x: uint64): uint64 =
  var v = (x shl 32) or (x shr 32)
  v =
    ((v and 0x0000ffff0000ffff'u64) shl 16) or
    ((v and 0xffff0000ffff0000'u64) shr 16)

  ((v and 0x00ff00ff00ff00ff'u64) shl 8) or
    ((v and 0xff00ff00ff00ff00'u64) shr 8)

func fromBytes(
    T: typedesc[SomeEndianInt],
    x: openArray[byte],
    endian: Endianness = system.cpuEndian): T =

  doAssert x.len >= sizeof(T), "Not enough bytes for endian conversion"

  when nimvm: # No copyMem in vm
    for i in 0..<sizeof(result):
      result = result or (T(x[i]) shl (i * 8))
  else:
    copyMem(addr result, unsafeAddr x[0], sizeof(result))

  if endian != system.cpuEndian:
    result = swapBytes(result)

func fromBytesBE(
    T: typedesc[SomeEndianInt],
    x: openArray[byte]): T =
  fromBytes(T, x, bigEndian)

proc replaceNodes(ast: NimNode, what: NimNode, by: NimNode): NimNode =
  proc inspect(node: NimNode): NimNode =
    case node.kind:
    of {nnkIdent, nnkSym}:
      if node.eqIdent(what):
        by
      else:
        node
    of nnkEmpty, nnkLiterals:
      node
    else:
      let rTree = newNimNode(node.kind, lineInfoFrom = node)
      for child in node:
        rTree.add inspect(child)
      rTree
  inspect(ast)

macro staticFor(idx: untyped{nkIdent}, slice: static Slice[int], body: untyped): untyped =
  result = newNimNode(nnkStmtList, lineInfoFrom = body)
  for i in slice:
    result.add nnkBlockStmt.newTree(
      ident(":staticFor" & $idx & $i),
      body.replaceNodes(idx, newLit i)
    )

type
  NibblesBuf = object
    limbs: array[4, uint64]
    iend: uint8

template limb(i: int | uint8): uint8 =
  uint8(i) shr 4 # shr 4 = div 16 = 16 nibbles per limb

template shift(i: int | uint8): uint8 =
  60 - ((uint8(i) mod 16) shl 2) # shl 2 = 4 bits per nibble

func `[]`(r: NibblesBuf, i: int): byte =
  let
    ilimb = i.limb
    ishift = i.shift
  byte((r.limbs[ilimb] shr ishift) and 0x0f)

func fromBytes(T: type NibblesBuf, bytes: openArray[byte]): T {.noinit.} =
  if bytes.len >= 32:
    result.iend = 64
    staticFor i, 0 ..< result.limbs.len:
      const pos = i * 8 # 16 nibbles per limb, 2 nibbles per byte
      result.limbs[i] = uint64.fromBytesBE(bytes.toOpenArray(pos, pos + 7))
  else:
    let blen = uint8(bytes.len)
    result.iend = blen * 2

    block done:
      staticFor i, 0 ..< result.limbs.len:
        const pos = i * 8
        if pos + 7 < blen:
          result.limbs[i] = uint64.fromBytesBE(bytes.toOpenArray(pos, pos + 7))
        else:
          if pos < blen:
            var tmp = 0'u64
            var shift = 56'u8
            for j in uint8(pos) ..< blen:
              tmp = tmp or uint64(bytes[j]) shl shift
              shift -= 8

            result.limbs[i] = tmp
          break done

func len(r: NibblesBuf): int =
  int(r.iend)

type
  NextNodeKind = enum
    EmptyValue
    HashNode
    ValueNode

  NextNodeResult = object
    case kind: NextNodeKind
    of EmptyValue:
      discard
    of HashNode:
      nextNodeHash: Hash32
      restOfTheKey: NibblesBuf
    of ValueNode:
      value: seq[byte]

proc getListLen(rlp: Rlp): Result[int, string] =
  try:
    ok(rlp.listLen)
  except RlpError as e:
    err(e.msg)

proc getListElem(rlp: Rlp, idx: int): Result[Rlp, string] =
  if not rlp.isList:
    return err("rlp element is not a list")

  try:
    ok(rlp.listElem(idx))
  except RlpError as e:
    err(e.msg)

proc blobBytes(rlp: Rlp): Result[seq[byte], string] =
  try:
    ok(rlp.toBytes)
  except RlpError as e:
    err(e.msg)

proc getRawRlpBytes(rlp: Rlp): Result[seq[byte], string] =
  try:
    ok(toSeq(rlp.rawData))
  except RlpError as e:
    err(e.msg)

proc getNextNode(nodeRlp: Rlp, key: NibblesBuf): Result[NextNodeResult, string] =
  var currNode = nodeRlp
  var restKey = key

  template handleNextRef(nextRef: Rlp, keyLen: int) =
    doAssert nextRef.hasData
    if nextRef.isList:
      let rawBytes = ?nextRef.getRawRlpBytes()
      if len(rawBytes) > 32:
        return err("Embedded node longer than 32 bytes")
      else:
        currNode = nextRef
    else:
      let nodeBytes = ?nextRef.blobBytes()
      if len(nodeBytes) == 32:
        return ok(
          NextNodeResult(
            kind: HashNode, nextNodeHash: Hash32(Bytes32.copyFrom(nodeBytes, 0))
          )
        )
      elif len(nodeBytes) == 0:
        return ok(NextNodeResult(kind: EmptyValue))
      else:
        return err("reference rlp blob should have 0 or 32 bytes")
  #echo "FOOA"
  while true:
    let listLen = ?currNode.getListLen()
    block:
      #echo "FOOC"
      if len(restKey) == 0:
        let value = ?currNode.getListElem(16)

        if not value.hasData():
          return err("expected branch terminator")

        if value.isList():
          return err("branch value cannot be list")

        if value.isEmpty():
          return ok(NextNodeResult(kind: EmptyValue))
        else:
          let bytes = ?value.blobBytes()
          return ok(NextNodeResult(kind: ValueNode, value: bytes))
      else:
        let nextRef = ?currNode.getListElem(restKey[0].int)

        handleNextRef(nextRef, 1)

proc verifyProof(rootHash: Hash32, key: openArray[byte], foo0: seq[byte]) =
  var currentKey = NibblesBuf.fromBytes(key)

  while true:
    var t = new DbTransaction
    t.get([])
    let node = foo0
    let next = getNextNode(rlpFromBytes(node), currentKey).get
    case next.kind
    of EmptyValue:
      return
    of ValueNode:
      return
    of HashNode:
      currentKey = next.restOfTheKey

proc verifyMptProof(
    branch: seq[seq[byte]], rootHash: Hash32, key: openArray[byte]) =
  var t: Table[seq[byte], int]
  var ctx: keccak.keccak256
  let nodeHash = Hash32(ctx.finish().data)
  for _ in branch:
    t.put(distinctBase(nodeHash))

  verifyProof(rootHash, key, branch[0])

proc getGenesisAlloc(): GenesisAlloc =
  var cn: NetworkParams
  cn = NetworkParams(genesis: Genesis(alloc: {"a": GenesisAccount(foo: "b")}.toTable()))
  var blockNumberBasedForkOptionals: array[1, int]
  cn.genesis.alloc

let
  _ = getGenesisAlloc()
  stateRootHash = Hash32.fromHex("0x9e6f9f140138677c62d4261312b15b1d26a6d60cb3fa966dd186cb4f04339d77")
verifyMptProof(getProof().accountProof, stateRootHash, distinctBase(static(Hash32.fromHex("0x227a737497210f7cc2f464e3bfffadefa9806193ccdf873203cd91c8d3eab518"))))

import
  unittest2

proc sign(tx: seq[byte], pk: PrivateKey, eip155: bool) =
  let hash = Hash32(Bytes32([197'u8, 210, 70, 1, 134, 247, 35, 60, 146, 126, 125, 178, 220, 199, 3, 192, 229, 0, 182, 83, 202, 130, 39, 59, 123, 250, 216, 4, 93, 133, 164, 112])) 
  let _ = signRecoverable(SkSecretKey(pk), SkMessage(distinctBase(hash)))

type
  Assembler = object
    data    : seq[byte]

proc createSignedTx(payload: seq[byte], chainId: ChainId): seq[byte] =
  let privateKey = PrivateKey.fromHex("7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d")[]
  sign(default(seq[byte]), privateKey, false)

proc runVM(boa: Assembler): bool =
  discard createSignedTx(boa.data, default(ChainId))
  true

proc vmProxy_855651302(): bool =
  let boa = Assembler()
  runVM(boa)

discard vmProxy_855651302()
