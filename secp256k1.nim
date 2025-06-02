import
  results,
  ./secp256k1/abi,
  std/[typetraits]

{.pragma: hexRaises, raises: [ValueError].}

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

func hexToByteArray(
    hexStr: openArray[char], output: var openArray[byte], fromIdx, toIdx: int)
    {.hexRaises.} =
  discard hexToByteArrayImpl(hexStr, output, fromIdx, toIdx)

func hexToByteArray(hexStr: openArray[char], output: var openArray[byte])
                    {.hexRaises.} =
  hexToByteArray(hexStr, output, 0, output.high)

func hexToByteArray[N: static[int]](hexStr: openArray[char]): array[N, byte]
                    {.hexRaises, noinit.}=
  hexToByteArray(hexStr, result)

func hexToByteArray(hexStr: openArray[char], N: static int): array[N, byte]
                    {.hexRaises, noinit.}=
  hexToByteArray(hexStr, result)

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

func fromHex[N](A: type array[N, byte], hexStr: string): A
             {.hexRaises, noinit, inline.}=
  hexToByteArray(hexStr, result)

func hexToSeqByte(hexStr: string): seq[byte]
                  {.hexRaises.} =
  if (hexStr.len and 1) == 1:
    raise (ref ValueError)(msg: "hex string must have even length")

  let skip = skip0xPrefix(hexStr)
  let N = (hexStr.len - skip) div 2

  result = newSeq[byte](N)
  for i in 0 ..< N:
    result[i] = hexStr[2*i + skip].readHexChar shl 4 or hexStr[2*i + 1 + skip].readHexChar

func baseAddr[T](x: openArray[T]): ptr T =
  if x.len == 0: nil else: cast[ptr T](x)

func toArray[T](N: static int, data: openArray[T]): array[N, T] =
  doAssert data.len == N
  copyMem(addr result[0], unsafeAddr data[0], N)

export results

const
  SkRawSecretKeySize* = 32 # 256 div 8
  SkMessageSize = 32

type
  SkSecretKey* {.requiresInit.} = object
    data: array[SkRawSecretKeySize, byte]

  SkRecoverableSignature {.requiresInit.} = object
    data: secp256k1_ecdsa_recoverable_signature

  SkContext = object
    context: ptr secp256k1_context

  SkMessage* = distinct array[SkMessageSize, byte]

  SkResult*[T] = Result[T, cstring]

var secpContext {.threadvar.}: SkContext

template baseAddr(v: SkMessage): ptr byte =
  baseAddr(array[SkMessageSize, byte](v))

proc init(T: type SkContext): T =
  let flags = cuint(SECP256K1_CONTEXT_VERIFY or SECP256K1_CONTEXT_SIGN)
  result.context = secp256k1_context_create(flags)

func getContext(): ptr secp256k1_context =
  {.noSideEffect.}:
    if isNil(secpContext.context):
      secpContext = SkContext.init()
    secpContext.context

func fromHex*(T: type seq[byte], s: string): SkResult[T] =
  try:
    ok(hexToSeqByte(s))
  except CatchableError:
    err("secp: cannot parse hex string")

func fromRaw*(T: type SkSecretKey, data: openArray[byte]): SkResult[T] =
  if secp256k1_ec_seckey_verify(secp256k1_context_no_precomp, data.baseAddr) != 1:
    return err("secp: invalid private key")

  ok(T(data: toArray(32, data.toOpenArray(0, SkRawSecretKeySize - 1))))

func fromHex*(T: type SkSecretKey, data: string): SkResult[T] =
  T.fromRaw(? seq[byte].fromHex(data))

func signRecoverable*(key: SkSecretKey, msg: SkMessage): SkRecoverableSignature =
  var data {.noinit.}: secp256k1_ecdsa_recoverable_signature
  let res = secp256k1_ecdsa_sign_recoverable(
      getContext(), addr data, msg.baseAddr, key.data.baseAddr, nil, nil)
  doAssert res == 1, "cannot create recoverable signature, key invalid?"
  SkRecoverableSignature(data: data)
