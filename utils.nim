template bitsof(T: typedesc[SomeInteger]): int = 8 * sizeof(T)
template bitsof(x: SomeInteger): int = 8 * sizeof(x)

func firstOneNim(x: uint32): int =
  const lookup = [0'u8, 1, 28, 2, 29, 14, 24, 3, 30, 22, 20, 15,
    25, 17, 4, 8, 31, 27, 13, 23, 21, 19, 16, 7, 26, 12, 18, 6, 11, 5, 10, 9]
  if x == 0:
    0
  else:
    let k = not x + 1 # get two's complement
    cast[int](uint(1 + lookup[((x and k) * 0x077CB531'u32) shr 27]))

func firstOneNim(x: uint8|uint16): int = firstOneNim(x.uint32)

func log2truncNim(x: uint8|uint16|uint32): int =
  const lookup: array[32, uint8] = [0'u8, 9, 1, 10, 13, 21, 2, 29, 11, 14, 16, 18,
    22, 25, 3, 30, 8, 12, 20, 28, 15, 17, 24, 7, 19, 27, 23, 6, 26, 5, 4, 31]
  var v = x.uint32
  v = v or v shr 1 # first round down to one less than a power of 2
  v = v or v shr 2
  v = v or v shr 4
  v = v or v shr 8
  v = v or v shr 16
  int(lookup[uint32(v * 0x07C4ACDD'u32) shr 27])

func log2truncNim(x: uint64): int =
  const lookup: array[64, uint8] = [0'u8, 58, 1, 59, 47, 53, 2, 60, 39, 48, 27, 54,
    33, 42, 3, 61, 51, 37, 40, 49, 18, 28, 20, 55, 30, 34, 11, 43, 14, 22, 4, 62,
    57, 46, 52, 38, 26, 32, 41, 50, 36, 17, 19, 29, 10, 13, 21, 56, 45, 25, 31,
    35, 16, 9, 12, 44, 24, 15, 8, 23, 7, 6, 5, 63]
  var v = x
  v = v or v shr 1 # first round down to one less than a power of 2
  v = v or v shr 2
  v = v or v shr 4
  v = v or v shr 8
  v = v or v shr 16
  v = v or v shr 32
  int(lookup[(v * 0x03F6EAF2CD271461'u64) shr 58])

func log2trunc(x: SomeUnsignedInt): int {.inline.} =
  if x == 0: -1
  else:
    when nimvm:
      log2truncNim(x)
    else:
      when declared(log2truncBuiltin):
        log2truncBuiltin(x)
      else:
        log2truncNim(x)

func leadingZeros(x: SomeInteger): int {.inline.} =
  bitsof(x) - 1 - log2trunc(x)

func bytesNeeded(num: SomeUnsignedInt): int =
  sizeof(num) - (num.leadingZeros() shr 3)

func writeBigEndian(
    outStream: var auto, number: SomeUnsignedInt, lastByteIdx: int, numberOfBytes: int
) =
  var n = number
  for i in countdown(lastByteIdx, lastByteIdx - numberOfBytes + 1):
    outStream[i] = byte(n and 0xff)
    n = n shr 8

const
  BLOB_START_MARKER = byte(0x80)
  LIST_START_MARKER = byte(0xc0)
  THRESHOLD_LIST_LEN = 56
  LEN_PREFIXED_LIST_MARKER = byte(LIST_START_MARKER + THRESHOLD_LIST_LEN - 1) # 247

type RlpDefaultWriter = object
  pendingLists: seq[tuple[remainingItems, startPos: int]]
  output: seq[byte]

func writeCount(writer: var RlpDefaultWriter, count: int, baseMarker: byte) =
  if count < THRESHOLD_LIST_LEN:
    writer.output.add(baseMarker + byte(count))
  else:
    let lenPrefixBytes = uint64(count).bytesNeeded

    writer.output.add baseMarker + (THRESHOLD_LIST_LEN - 1) + byte(lenPrefixBytes)

    writer.output.setLen(writer.output.len + lenPrefixBytes)
    writer.output.writeBigEndian(uint64(count), writer.output.len - 1, lenPrefixBytes)

proc maybeClosePendingLists(self: var RlpDefaultWriter) =
  while self.pendingLists.len > 0:
    let lastListIdx = self.pendingLists.len - 1
    doAssert self.pendingLists[lastListIdx].remainingItems > 0

    self.pendingLists[lastListIdx].remainingItems -= 1
    if self.pendingLists[lastListIdx].remainingItems == 0:
      let listStartPos = self.pendingLists[lastListIdx].startPos
      self.pendingLists.setLen lastListIdx

      let
        listLen = self.output.len - listStartPos
        totalPrefixBytes =
          if listLen < int(THRESHOLD_LIST_LEN):
            1
          else:
            int(uint64(listLen).bytesNeeded) + 1

      self.output.setLen(self.output.len + totalPrefixBytes)

      moveMem(
        addr self.output[listStartPos + totalPrefixBytes],
        unsafeAddr self.output[listStartPos],
        listLen,
      )

      if listLen < THRESHOLD_LIST_LEN:
        self.output[listStartPos] = LIST_START_MARKER + byte(listLen)
      else:
        let listLenBytes = totalPrefixBytes - 1
        self.output[listStartPos] = LEN_PREFIXED_LIST_MARKER + byte(listLenBytes)

        self.output.writeBigEndian(
          uint64(listLen), listStartPos + listLenBytes, listLenBytes
        )
    else:
      return

func assign[T](tgt: var openArray[T], src: openArray[T]) =
  for i in 0..<tgt.len:
    tgt[i] = src[i]
func appendRawBytes(self: var RlpDefaultWriter, bytes: openArray[byte]) =
  self.output.setLen(self.output.len + bytes.len)
  assign(
    self.output.toOpenArray(self.output.len - bytes.len, self.output.len - 1), bytes
  )
  self.maybeClosePendingLists()

proc writeBlob(self: var RlpDefaultWriter, bytes: openArray[byte]) =
  if bytes.len == 1 and byte(bytes[0]) < BLOB_START_MARKER:
    self.output.add byte(bytes[0])
    self.maybeClosePendingLists()
  else:
    self.writeCount(bytes.len, BLOB_START_MARKER)
    self.appendRawBytes(bytes)

proc startList*(self: var RlpDefaultWriter, listSize: int) =
  if listSize == 0:
    self.writeCount(0, LIST_START_MARKER)
    self.maybeClosePendingLists()
  else:
    self.pendingLists.add((listSize, self.output.len))

template finish*(self: RlpDefaultWriter): seq[byte] =
  doAssert self.pendingLists.len == 0,
    "Insufficient number of elements written to a started list"
  self.output

import
  std/macros

type
  RlpWriter* = RlpDefaultWriter

const wrapObjsInList* = true

proc initRlpWriter*(): RlpDefaultWriter =
  result

template appendBlob(self: var RlpWriter, data: openArray[byte]) =
  self.writeBlob(data)

template appendImpl(self: var RlpWriter, data: openArray[byte]) =
  self.appendBlob(data)

template appendImpl(self: var RlpWriter, data: openArray[char]) =
  self.appendBlob(data.toOpenArrayByte(0, data.high))

template appendImpl(self: var RlpWriter, data: string) =
  self.appendBlob(data.toOpenArrayByte(0, data.high))

proc appendImpl[T](self: var RlpWriter, list: openArray[T]) =
  mixin append

  self.startList list.len
  for i in 0 ..< list.len:
    self.append list[i]

template append*[T](w: var RlpWriter, data: T) =
  appendImpl(w, data)

template append*(w: var RlpWriter, data: SomeSignedInt) =
  {.error: "Signed integer encoding is not defined for rlp".}

proc initRlpList*(listSize: int): RlpDefaultWriter =
  result = initRlpWriter()
  startList(result, listSize)

macro encodeList*(args: varargs[untyped]): seq[byte] =
  var
    listLen = args.len
    writer = genSym(nskVar, "rlpWriter")
    body = newStmtList()
    append = bindSym("append", brForceOpen)

  for arg in args:
    body.add quote do:
      `append`(`writer`, `arg`)

  result = quote:
    var `writer` = initRlpList(`listLen`)
    `body`
    move(finish(`writer`))

type
  Rlp* = object
    bytes: seq[byte]
    position*: int

  RlpNodeType* = enum
    rlpBlob
    rlpList

  RlpError* = object of CatchableError
  MalformedRlpError* = object of RlpError
  UnsupportedRlpError* = object of RlpError
  RlpTypeMismatch* = object of RlpError

  RlpItem = tuple[payload: Slice[int], typ: RlpNodeType]

func raiseOutOfBounds() {.noreturn, noinline.} =
  raise (ref MalformedRlpError)(msg: "out-of-bounds payload access")

func raiseExpectedBlob() {.noreturn, noinline.} =
  raise (ref RlpTypeMismatch)(msg: "expected blob")

func raiseNonCanonical() {.noreturn, noinline.} =
  raise (ref MalformedRlpError)(msg: "non-canonical encoding")

func raiseIntOutOfBounds() {.noreturn, noinline.} =
  raise (ref UnsupportedRlpError)(msg: "integer out of bounds")

template view(input: openArray[byte], position: int): openArray[byte] =
  if position >= input.len:
    raiseOutOfBounds()

  toOpenArray(input, position, input.high())

template view(input: openArray[byte], slice: Slice[int]): openArray[byte] =
  if slice.b >= input.len:
    raiseOutOfBounds()

  toOpenArray(input, slice.a, slice.b)

func decodeInteger(input: openArray[byte]): uint64 =
  if input.len > sizeof(uint64):
    raiseIntOutOfBounds()

  if input.len == 0:
    0
  else:
    if input[0] == 0:
      raiseNonCanonical()

    var v: uint64
    for b in input:
      v = (v shl 8) or uint64(b)
    v

func rlpItem(input: openArray[byte], start = 0): RlpItem =
  if start >= len(input):
    raiseOutOfBounds()

  let
    length = len(input) - start # >= 1
    prefix = input[start]

  if prefix <= 0x7f:
    (start .. start, rlpBlob)
  elif prefix <= 0xb7:
    let strLen = int(prefix - 0x80)
    if strLen >= length:
      raiseOutOfBounds()
    if strLen == 1 and input[start + 1] <= 0x7f:
      raiseNonCanonical()

    (start + 1 .. start + strLen, rlpBlob)
  elif prefix <= 0xbf:

    let
      lenOfStrLen = int(prefix - 0xb7)
      strLen = decodeInteger(input.view(start + 1 .. start + lenOfStrLen))

    if strLen < THRESHOLD_LIST_LEN:
      raiseNonCanonical()

    if strLen >= uint64(length - lenOfStrLen):
      raiseOutOfBounds()

    (start + 1 + lenOfStrLen .. start + lenOfStrLen + int(strLen), rlpBlob)
  elif prefix <= 0xf7:
    let listLen = int(prefix - 0xc0)
    if listLen >= length:
      raiseOutOfBounds()

    (start + 1 .. start + listLen, rlpList)
  else:
    let
      lenOfListLen = int(prefix - 0xf7)
      listLen = decodeInteger(input.view(start + 1 .. start + lenOfListLen))

    if listLen < THRESHOLD_LIST_LEN:
      raiseNonCanonical()

    if listLen >= uint64(length - lenOfListLen):
      raiseOutOfBounds()

    (start + 1 + lenOfListLen .. start + lenOfListLen + int(listLen), rlpList)

func item(self: Rlp, position: int): RlpItem =
  rlpItem(self.bytes, position)

func item(self: Rlp): RlpItem =
  self.item(self.position)

func rlpFromBytes*(data: openArray[byte]): Rlp =
  Rlp(bytes: @data, position: 0)

func rlpFromBytes*(data: sink seq[byte]): Rlp =
  Rlp(bytes: move(data), position: 0)

const zeroBytesRlp* = Rlp()

func hasData*(self: Rlp, position: int): bool =
  position < self.bytes.len

func hasData*(self: Rlp): bool =
  self.hasData(self.position)

func isEmpty*(self: Rlp): bool =
  self.hasData() and (
    self.bytes[self.position] == BLOB_START_MARKER or
    self.bytes[self.position] == LIST_START_MARKER
  )

func isList*(self: Rlp, position: int): bool =
  self.hasData(position) and self.bytes[position] >= LIST_START_MARKER

func isList*(self: Rlp): bool =
  self.isList(self.position)

template maxBytes(o: type[Ordinal | uint64 | uint]): int =
  sizeof(o)

func toInt(self: Rlp, item: RlpItem, IntType: type): IntType =
  mixin maxBytes, to
  if item.typ != rlpBlob:
    raiseExpectedBlob()

  if item.payload.len > maxBytes(IntType):
    raiseIntOutOfBounds()

  for b in self.bytes.view(item.payload):
    result = (result shl 8) or IntType(b)

func toInt(self: Rlp, IntType: type): IntType =
  self.toInt(self.item(), IntType)

func toBytes*(self: Rlp, item: RlpItem): seq[byte] =
  if item.typ != rlpBlob:
    raiseExpectedBlob()

  @(self.bytes.view(item.payload))

func toBytes*(self: Rlp): seq[byte] =
  self.toBytes(self.item())

func currentElemEnd(self: Rlp, position: int): int =
  let item = self.item(position).payload
  item.b + 1

func currentElemEnd(self: Rlp): int =
  self.currentElemEnd(self.position)

template iterateIt(self: Rlp, position: int, body: untyped) =
  let item = self.item(position)
  doAssert item.typ == rlpList
  var it {.inject.} = item.payload.a
  let last = item.payload.b
  while it <= last:
    let subItem = rlpItem(self.bytes.view(it .. last)).payload
    body
    it += subItem.b + 1

func listElem*(self: Rlp, i: int): Rlp =
  let item = self.item()
  doAssert item.typ == rlpList

  var
    i = i
    start = item.payload.a
    payload = rlpItem(self.bytes.view(start .. item.payload.b)).payload

  while i > 0:
    start += payload.b + 1
    payload = rlpItem(self.bytes.view(start .. item.payload.b)).payload
    dec i

  rlpFromBytes self.bytes.view(start .. start + payload.b)

func listLen*(self: Rlp): int =
  if not self.isList():
    return 0

  self.iterateIt(self.position):
    inc result

template rawData*(self: Rlp): openArray[byte] =
  self.bytes.toOpenArray(self.position, self.currentElemEnd - 1)



