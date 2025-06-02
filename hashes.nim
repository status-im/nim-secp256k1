import std/[typetraits, hashes], nimcrypto/keccak, ./base

type
  Hash32* = distinct Bytes32

template to(v: array[32, byte], _: type Hash32): Hash32 =
  Address(v)

template data(v: Hash32): array[32, byte] =
  distinctBase(v)

template copyFrom(T: type Hash32, v: openArray[byte], start = 0): T =
  Hash32(Bytes32.copyFrom(v, start))

func fromHex(_: type Hash32, s: openArray[char]): Hash32 {.raises: [ValueError].} =
  Hash32(Bytes32.fromHex(s))

template to(s: static string, _: type Hash32): Hash32 =
  const hash = Hash32.fromHex(s)
  hash

template hash32(s: static string): Hash32 =
  s.to(Hash32)

template to(v: MDigest[256], _: type Hash32): Hash32 =
  Hash32(v.data)

template to(v: Hash32, _: type MDigest[256]): MDigest[256] =
  var tmp {.noinit.}: MDigest[256]
  assign(tmp.data, v.data)
  tmp

func keccak256(input: openArray[byte]): Hash32 {.noinit.} =
  var ctx: keccak.keccak256
  ctx.update(input)
  ctx.finish().to(Hash32)

type Address = distinct Bytes20

func to(a: Address, _: type Bytes32): Bytes32 =
  result.data.toOpenArray(12, 31) = a.data

template copyFrom(T: type Address, v: openArray[byte], start = 0): T =
  Address(Bytes20.copyFrom(v, start))

func `==`(a, b: Address): bool {.borrow.}

type
  Transaction = object
    gasPrice      : GasInt
    gasLimit      : GasInt
    payload       : seq[byte]
    V             : uint64

import
  ./secp256k1

type
  PrivateKey = distinct SkSecretKey

func fromHex(T: type PrivateKey, data: string): SkResult[T] =
  SkSecretKey.fromHex(data).mapConvert(T)

func sign(seckey: PrivateKey, msg: SkMessage) =
  let _ = signRecoverable(SkSecretKey(seckey), msg)

import ./utils

proc encodeForSigning(tx: Transaction): seq[byte] =
  var w = initRlpWriter()
  w.startList(1)
  w.append(tx.payload)
  w.finish()

const
  emptyRlp = @[128.byte]
  emptyRlpHash = hash32"56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"

import
  std/[tables, sets]

type
  MemDBRec = object
    refCount: int
    value: seq[byte]

  MemoryLayer = ref object of RootObj
    records: Table[seq[byte], MemDBRec]
    deleted: HashSet[seq[byte]]

  PutProc = proc (db: RootRef, key, val: openArray[byte]) {.
    gcsafe, raises: [].}

  GetProc = proc (db: RootRef, key: openArray[byte]): seq[byte] {.
    gcsafe, raises: [].}

  TrieDatabaseRef = ref object
    obj: RootRef
    putProc: PutProc
    getProc: GetProc
    mostInnerTransaction: DbTransaction

  DbTransaction = ref object
    db: TrieDatabaseRef
    parentTransaction: DbTransaction
    modifications: MemoryLayer

proc put(db: TrieDatabaseRef, key, val: openArray[byte]) {.gcsafe.}
proc get(db: TrieDatabaseRef, key: openArray[byte]): seq[byte] {.gcsafe.}
proc beginTransaction(db: TrieDatabaseRef): DbTransaction {.gcsafe.}

proc put(db: MemoryLayer, key, val: openArray[byte]) =
  let key = @key

  db.deleted.excl(key)

  if key.len != 32:
    db.records[key] = MemDBRec(refCount: 1, value: @val)
  else:
    db.records.withValue(key, v) do:
      inc v.refCount
      if v.value != val: v.value = @val
    do:
      db.records[key] = MemDBRec(refCount: 1, value: @val)

proc newMemoryLayer: MemoryLayer =
  result.new
  result.records = initTable[seq[byte], MemDBRec]()
  result.deleted = initHashSet[seq[byte]]()

proc init(db: var MemoryLayer) =
  db = newMemoryLayer()

proc newMemoryDB: TrieDatabaseRef =
  new result
  discard result.beginTransaction
  put(result, emptyRlpHash.data, emptyRlp)

proc beginTransaction(db: TrieDatabaseRef): DbTransaction =
  new result
  result.db = db
  init result.modifications
  result.parentTransaction = db.mostInnerTransaction
  db.mostInnerTransaction = result

proc put(db: TrieDatabaseRef, key, val: openArray[byte]) =
  var t = db.mostInnerTransaction
  if t != nil:
    t.modifications.put(key, val)
  else:
    db.putProc(db.obj, key, val)

proc get(db: TrieDatabaseRef, key: openArray[byte]): seq[byte] =
  let key = @key

  var t = db.mostInnerTransaction
  while t != nil:
    result = t.modifications.records.getOrDefault(key).value
    if result.len > 0 or key in t.modifications.deleted:
      return
    t = t.parentTransaction

  if db.getProc != nil:
    result = db.getProc(db.obj, key)

const
  forkBlockField = ["homesteadBlock"]

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
  for _, _ in forkBlockField: discard

import
  std/sequtils,
  results,
  nimcrypto/hash as foobar

type
  SomeEndianInt = uint8|uint16|uint32|uint64

func swapBytesNim(x: uint8): uint8 = x
func swapBytesNim(x: uint16): uint16 = (x shl 8) or (x shr 8)

func swapBytesNim(x: uint32): uint32 =
  let v = (x shl 16) or (x shr 16)

  ((v shl 8) and 0xff00ff00'u32) or ((v shr 8) and 0x00ff00ff'u32)

func swapBytesNim(x: uint64): uint64 =
  var v = (x shl 32) or (x shr 32)
  v =
    ((v and 0x0000ffff0000ffff'u64) shl 16) or
    ((v and 0xffff0000ffff0000'u64) shr 16)

  ((v and 0x00ff00ff00ff00ff'u64) shl 8) or
    ((v and 0xff00ff00ff00ff00'u64) shr 8)

func swapBytes[T: SomeEndianInt](x: T): T {.inline.} =
  when nimvm:
    swapBytesNim(x)
  else:
    when declared(swapBytesBuiltin):
      swapBytesBuiltin(x)
    else:
      swapBytesNim(x)

func fromBytes(
    T: typedesc[SomeEndianInt],
    x: openArray[byte],
    endian: Endianness = system.cpuEndian): T {.inline.} =

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
    x: openArray[byte]): T {.inline.} =
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

func high(T: type NibblesBuf): int =
  63

func nibble(T: type NibblesBuf, nibble: byte): T {.noinit.} =
  result.limbs[0] = uint64(nibble) shl (64 - 4)
  result.iend = 1

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

func slice(r: NibblesBuf, ibegin: int, iend = -1): NibblesBuf {.noinit.} =
  let e =
    if iend < 0:
      min(64, r.len + iend + 1)
    else:
      min(64, iend)

  result.iend = uint8(e - ibegin)

  var ilimb = ibegin.limb
  block done:
    let shift = (ibegin mod 16) shl 2
    if shift == 0: # Must be careful not to shift by 64 which is UB!
      staticFor i, 0 ..< result.limbs.len:
        if uint8(i * 16) >= result.iend:
          break done
        result.limbs[i] = r.limbs[ilimb]
        ilimb += 1
    else:
      staticFor i, 0 ..< result.limbs.len:
        if uint8(i * 16) >= result.iend:
          break done

        let cur = r.limbs[ilimb] shl shift
        ilimb += 1

        result.limbs[i] =
          if (ilimb * 16) < uint8 r.iend:
            let next = r.limbs[ilimb] shr (64 - shift)
            cur or next
          else:
            cur

  if result.iend mod 16 > 0:
    let
      elimb = result.iend.limb
      eshift = result.iend.shift + 4
    result.limbs[elimb] = result.limbs[elimb] and (0xffffffffffffffff'u64 shl eshift)

template copyshr(aend: uint8) =
  block adone: # copy aend nibbles of a
    staticFor i, 0 ..< result.limbs.len:
      if uint8(i * 16) >= aend:
        break adone

      result.limbs[i] = a.limbs[i]

  block bdone:
    let shift = (aend mod 16) shl 2

    var alimb = aend.limb

    if shift == 0:
      staticFor i, 0 ..< result.limbs.len:
        if uint8(i * 16) >= b.iend:
          break bdone

        result.limbs[alimb] = b.limbs[i]
        alimb += 1
    else:
      result.limbs[alimb] = result.limbs[alimb] and ((not 0'u64) shl (64 - shift))

      staticFor i, 0 ..< result.limbs.len:
        if uint8(i * 16) >= b.iend:
          break bdone

        result.limbs[alimb] = result.limbs[alimb] or b.limbs[i] shr shift

        alimb += 1
        if (alimb * 16) < result.iend:
          result.limbs[alimb] = b.limbs[i] shl (64 - shift)

func `&`(a, b: NibblesBuf): NibblesBuf {.noinit.} =
  result.iend = min(64'u8, a.iend + b.iend)

  let aend = a.iend
  copyshr(aend)

func fromHexPrefix(
    T: type NibblesBuf, bytes: openArray[byte]
): tuple[isLeaf: bool, nibbles: NibblesBuf] {.noinit.} =
  if bytes.len > 0:
    result.isLeaf = (bytes[0] and 0x20) != 0
    let hasOddLen = (bytes[0] and 0x10) != 0

    if hasOddLen:
      let high = uint8(min(31, bytes.len - 1))
      result.nibbles =
        NibblesBuf.nibble(bytes[0] and 0x0f) &
        NibblesBuf.fromBytes(bytes.toOpenArray(1, int high))
    else:
      result.nibbles = NibblesBuf.fromBytes(bytes.toOpenArray(1, bytes.high()))
  else:
    result.isLeaf = false
    result.nibbles.iend = 0

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

  MptProofVerificationKind = enum
    ValidProof
    InvalidProof
    MissingKey

  MptProofVerificationResult = object
    case kind: MptProofVerificationKind
    of MissingKey:
      discard
    of InvalidProof:
      errorMsg: string
    of ValidProof:
      value: seq[byte]

func invalidProof(msg: string): MptProofVerificationResult =
  MptProofVerificationResult(kind: InvalidProof, errorMsg: msg)

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
    if not nextRef.hasData:
      return err("invalid reference")

    if nextRef.isList:
      let rawBytes = ?nextRef.getRawRlpBytes()
      if len(rawBytes) > 32:
        return err("Embedded node longer than 32 bytes")
      else:
        currNode = nextRef
        restKey = restKey.slice(keyLen)
    else:
      let nodeBytes = ?nextRef.blobBytes()
      if len(nodeBytes) == 32:
        return ok(
          NextNodeResult(
            kind: HashNode, nextNodeHash: Hash32.copyFrom(nodeBytes), restOfTheKey: restKey.slice(keyLen)
          )
        )
      elif len(nodeBytes) == 0:
        return ok(NextNodeResult(kind: EmptyValue))
      else:
        return err("reference rlp blob should have 0 or 32 bytes")

  while true:
    let listLen = ?currNode.getListLen()
    case listLen
    of 2:
      let
        firstElem = ?currNode.getListElem(0)
        blobBytes = ?firstElem.blobBytes()

      let (isLeaf, k) = NibblesBuf.fromHexPrefix(blobBytes)

      if len(restKey) < len(k) or k != restKey.slice(0, len(k)):
        return ok(NextNodeResult(kind: EmptyValue))

      let nextRef = ?currNode.getListElem(1)

      if isLeaf:
        let blobBytes = ?nextRef.blobBytes()
        return ok(NextNodeResult(kind: ValueNode, value: blobBytes))

      handleNextRef(nextRef, len(k))
    of 17:
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
    else:
      return err("Invalid list node ")

proc verifyProof(
    db: TrieDatabaseRef, rootHash: Hash32, key: openArray[byte]
): Result[Opt[seq[byte]], string] =
  var currentKey = NibblesBuf.fromBytes(key)

  var currentHash = rootHash

  while true:
    let node = db.get(currentHash.data())

    if len(node) == 0:
      return err("missing expected node")

    let next = ?getNextNode(rlpFromBytes(node), currentKey)
    case next.kind
    of EmptyValue:
      return ok(Opt.none(seq[byte]))   # never hits
    of ValueNode:
      return ok(Opt.some(next.value))
    of HashNode:
      currentKey = next.restOfTheKey
      currentHash = next.nextNodeHash

proc verifyMptProof(
    branch: seq[seq[byte]], rootHash: Hash32, key, value: openArray[byte]
): MptProofVerificationResult =
  var db = newMemoryDB()
  for node in branch:
    if len(node) == 0:
      return invalidProof("empty mpt node in proof")
    let nodeHash = keccak256(node)
    db.put(nodeHash.data, node)

  discard verifyProof(db, rootHash, key)

proc verifyAccountProof(trustedStateRoot: Hash32, res: ProofResponse): MptProofVerificationResult =
  const
    key = Hash32.fromHex("0x227a737497210f7cc2f464e3bfffadefa9806193ccdf873203cd91c8d3eab518")
  verifyMptProof(
    res.accountProof,
    trustedStateRoot,
    key.data,
    @[])

proc getGenesisAlloc(): GenesisAlloc =
  var cn: NetworkParams
  cn = NetworkParams(genesis: Genesis(alloc: {"a": GenesisAccount(foo: "b")}.toTable()))
  var blockNumberBasedForkOptionals: array[1, int]
  cn.genesis.alloc

let
  _ = getGenesisAlloc()
  stateRootHash = Hash32.fromHex("0x9e6f9f140138677c62d4261312b15b1d26a6d60cb3fa966dd186cb4f04339d77")
  _ = verifyAccountProof(stateRootHash, getProof())

import
  unittest2

proc sign(tx: Transaction, pk: PrivateKey, eip155: bool) =
  let hash = keccak256(encodeForSigning(tx))
  sign(pk, SkMessage(hash.data))

type
  Assembler = object
    data    : seq[byte]

proc createSignedTx(payload: seq[byte], chainId: ChainId): Transaction =
  let privateKey = PrivateKey.fromHex("7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d")[]
  let unsignedTx = Transaction()
  unsignedTx.sign(privateKey, false)

proc runVM(boa: Assembler): bool =
  discard createSignedTx(boa.data, default(ChainId))
  true

proc vmProxy_855651302(): bool =
  let boa = Assembler()
  runVM(boa)

discard vmProxy_855651302()
