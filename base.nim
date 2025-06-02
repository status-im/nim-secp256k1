import
  std/[macros, typetraits],
  results,
  std/algorithm

{.pragma: hexRaises, raises: [ValueError].}
func assign[T](tgt: var openArray[T], src: openArray[T]) =
  for i in 0..<tgt.len:
    tgt[i] = src[i]

proc readHexChar(c: char): byte
                 {.hexRaises, noSideEffect, inline.} =
  case c
  of '0'..'9': result = byte(ord(c) - ord('0'))
  of 'a'..'f': result = byte(ord(c) - ord('a') + 10)
  of 'A'..'F': result = byte(ord(c) - ord('A') + 10)
  else:
    raise newException(ValueError, $c & " is not a hexadecimal character")

template skip0xPrefix(hexStr: openArray[char]): int =
  if hexStr.len > 1 and hexStr[0] == '0' and hexStr[1] in {'x', 'X'}: 2
  else: 0

func hexToByteArrayImpl(
    hexStr: openArray[char], output: var openArray[byte], fromIdx, toIdx: int):
    int {.hexRaises.} =
  var sIdx = skip0xPrefix(hexStr)
  doAssert fromIdx >= 0 and
    toIdx <= output.high and
    fromIdx <= (toIdx + 1)

  let sz = toIdx + 1 - fromIdx

  if hexStr.len - sIdx < 2*sz:
    raise (ref ValueError)(msg: "hex string too short")

  sIdx += fromIdx * 2
  for bIdx in fromIdx ..< sz + fromIdx:
    output[bIdx] =
      (hexStr[sIdx].readHexChar shl 4) or
      hexStr[sIdx + 1].readHexChar
    inc(sIdx, 2)

  sIdx

func hexToByteArrayStrict(hexStr: openArray[char], output: var openArray[byte])
                          {.hexRaises.} =
  if hexToByteArrayImpl(hexStr, output, 0, output.high) != hexStr.len:
    raise (ref ValueError)(msg: "hex string too long")

func hexToByteArrayStrict[N: static[int]](hexStr: openArray[char]): array[N, byte]
                          {.hexRaises, noinit, inline.}=
  hexToByteArrayStrict(hexStr, result)

func hexToByteArrayStrict(hexStr: openArray[char], N: static int): array[N, byte]
                          {.hexRaises, noinit, inline.}=
  hexToByteArrayStrict(hexStr, result)

func toHexAux(ba: openArray[byte], with0x: static bool): string =
  const hexChars = "0123456789abcdef"

  let extra = when with0x: 2 else: 0
  result = newStringOfCap(2 * ba.len + extra)
  when with0x:
    result.add("0x")

  for b in ba:
    result.add(hexChars[int(b shr 4 and 0x0f'u8)])
    result.add(hexChars[int(b and 0x0f'u8)])

func toHex(ba: openArray[byte]): string {.inline.} =
  toHexAux(ba, false)

func toHex[N: static[int]](ba: array[N, byte]): string {.inline.} =
  toHexAux(ba, false)

func to0xHex(ba: openArray[byte]): string {.inline.} =
  toHexAux(ba, true)

func to0xHex[N: static[int]](ba: array[N, byte]): string {.inline.} =
  toHexAux(ba, true)

type
  FixedBytes*[N: static int] = distinct array[N, byte]

  ChainId* = uint64

  GasInt* = uint64

template data[N: static int](v: FixedBytes[N]): array[N, byte] =
  distinctBase(v)

func copyFrom*[N: static int](T: type FixedBytes[N], v: openArray[byte], start = 0): T =
  if v.len > start:
    let n = min(N, v.len - start)
    assign(result.data.toOpenArray(0, n - 1), v.toOpenArray(start, start + n - 1))

func `==`*(a, b: FixedBytes): bool {.inline.} =
  equalMem(addr a.data[0], addr b.data[0], a.N)

func toHex*(v: FixedBytes): string =
  toHex(v.data)

func to0xHex*(v: FixedBytes): string =
  to0xHex(v.data)

func `$`*(v: FixedBytes): string =
  to0xHex(v)

func fromHex*(T: type FixedBytes, c: openArray[char]): T {.raises: [ValueError].} =
  T(hexToByteArrayStrict(c, T.N))

template makeFixedBytesN(N: static int) =
  type `Bytes N`* = FixedBytes[N]

makeFixedBytesN(20)
makeFixedBytesN(32)

type
  AccountNonce* = uint64
  ProofResponse* = object
    accountProof*: seq[seq[byte]]

import
  std/tables

proc makeProof(
      ): Result[(seq[seq[byte]],bool), int] =
  result = ok((@[@[248'u8, 177, 160, 129, 136, 149, 159, 31, 252, 215, 147, 250, 28, 74, 127, 243, 250, 52, 43, 117, 253, 206, 185, 136, 179, 23, 70, 75, 37, 169, 40, 81, 139, 29, 85, 128, 160, 166, 92, 64, 107, 103, 166, 196, 94, 147, 183, 129, 212, 225, 123, 145, 5, 105, 226, 248, 243, 193, 9, 179, 25, 169, 168, 252, 112, 223, 115, 37, 41, 128, 160, 212, 49, 8, 53, 235, 82, 204, 21, 4, 254, 38, 152, 121, 245, 19, 127, 137, 243, 84, 79, 146, 233, 16, 10, 222, 19, 147, 71, 196, 38, 5, 6, 128, 128, 128, 128, 128, 160, 194, 171, 71, 247, 21, 130, 2, 59, 51, 27, 110, 162, 104, 73, 163, 174, 229, 43, 72, 28, 43, 246, 103, 5, 27, 137, 130, 21, 106, 1, 201, 49, 128, 128, 128, 128, 160, 198, 39, 225, 154, 149, 227, 112, 175, 149, 233, 24, 177, 216, 49, 194, 32, 227, 116, 223, 82, 202, 202, 87, 37, 129, 92, 198, 14, 198, 134, 161, 216, 128], @[248, 105, 160, 50, 122, 115, 116, 151, 33, 15, 124, 194, 244, 100, 227, 191, 255, 173, 239, 169, 128, 97, 147, 204, 223, 135, 50, 3, 205, 145, 200, 211, 234, 181, 24, 184, 70, 248, 68, 128, 128, 160, 86, 232, 31, 23, 27, 204, 85, 166, 255, 131, 69, 230, 146, 192, 248, 110, 91, 72, 224, 27, 153, 108, 173, 192, 1, 98, 47, 181, 227, 99, 180, 33, 160, 197, 210, 70, 1, 134, 247, 35, 60, 146, 126, 125, 178, 220, 199, 3, 192, 229, 0, 182, 83, 202, 130, 39, 59, 123, 250, 216, 4, 93, 133, 164, 112]], true))

proc makeAccountProof(): Result[(seq[seq[byte]],bool), int] =
  makeProof()

proc proof(
      ): Result[(seq[seq[byte]],bool), int] =
  let rc = makeAccountProof().valueOr:
    return err(0)

  ok(rc)

type
  LedgerRef* = ref object
    savePoint: LedgerSpRef

  LedgerSpRef = ref object
    dirty: Table[int, int]

proc beginSavepoint(ac: LedgerRef): LedgerSpRef =
  new result
  ac.savePoint = result

proc init*(x: typedesc[LedgerRef]): LedgerRef =
  new result
  discard result.beginSavepoint

proc persist*(ac: LedgerRef) =
  doAssert not ac.isNil
  doAssert not ac.savePoint.isNil
  for _ in ac.savePoint.dirty.pairs():
    doAssert false

proc getAccountProof(): seq[seq[byte]] =
  let accProof = proof().valueOr:
    raiseAssert "Failed to get account proof: " & $error

  accProof[0]

proc getProof*(): ProofResponse = ProofResponse(accountProof: getAccountProof())
