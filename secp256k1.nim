## Copyright (c) 2018-2020 Status Research & Development GmbH
## Licensed under either of
##  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
##  * MIT license ([LICENSE-MIT](LICENSE-MIT))
## at your option.
## This file may not be copied, modified, or distributed except according to
## those terms.
##

{.push raises: [Defect].}

import
  strformat,
  stew/[byteutils, objects, results],
  nimcrypto/[hash, sysrand],
  ./secp256k1_abi

from nimcrypto/utils import burnMem

export results

# Implementation notes
#
# The goal of this wrapper is to create a thin layer on top of the API presented
# in secp256k1_abi, exploiting some of its regulatities to make it slightly more
# convenient to use from Nim
#
# * Types like keys and signatures are guaranteed to hold valid values which
#   simplifies reasoning about errors
#   * An exception is keys that have been cleared - these are no longer valid
#     to be passed as arguments to functions
#   * TODO a sink that makes the compiler guarantee that `clear` is the last
#     thing called on the instance
# * We hide raw pointer accesses and lengths behind nim types
# * We guarantee certain parameter properties, like not null and proper length,
#   on the Nim side - in turn, we can rely on certain errors never happening in
#   libsecp256k1, so we can skip checking for them
# * Functions like "fromRaw/toRaw" are balanced and will always rountrip
# * Functions like `fromRaw` are not called `init` because they may fail
# * No CatchableErrors

const
  SkRawSecretKeySize* = 32 # 256 div 8
    ## Size of private key in octets (bytes)
  SkRawSignatureSize* = 64
    ## Compact serialized non-recoverable signature
  SkDerSignatureMaxSize* = 72
    ## Max bytes in DER encoding

  SkRawRecoverableSignatureSize* = 65
    ## Size of recoverable signature in octets (bytes)

  SkRawPublicKeySize* = 65
    ## Size of uncompressed public key in octets (bytes)

  SkRawCompressedPublicKeySize* = 33
    ## Size of compressed public key in octets (bytes)

  SkMessageSize* = 32
    ## Size of message that can be signed

  SkEdchSecretSize* = 32
    ## ECDH-agreed key size

  SkEcdhRawSecretSize* = 33
    ## ECDH-agreed raw key size

type
  SkPublicKey* {.requiresInit.} = object
    ## Representation of public key.
    data: secp256k1_pubkey

  SkSecretKey* {.requiresInit.} = object
    ## Representation of secret key.
    data: array[SkRawSecretKeySize, byte]

  SkKeyPair* = object
    ## Representation of private/public keys pair.
    seckey*: SkSecretKey
    pubkey*: SkPublicKey

  SkSignature* {.requiresInit.} = object
    ## Representation of non-recoverable signature.
    data: secp256k1_ecdsa_signature

  SkRecoverableSignature* {.requiresInit.} = object
    ## Representation of recoverable signature.
    data: secp256k1_ecdsa_recoverable_signature

  SkContext* = ref object
    ## Representation of Secp256k1 context object.
    context: ptr secp256k1_context

  SkMessage* = MDigest[SkMessageSize * 8]
    ## Message that can be signed or verified

  SkEcdhSecret* {.requiresInit.} = object
    ## Representation of ECDH shared secret
    data*: array[SkEdchSecretSize, byte]

  SkEcdhRawSecret* {.requiresInit.} = object
    ## Representation of ECDH shared secret, with leading `y` byte
    # (`y` is 0x02 when pubkey.y is even or 0x03 when odd)
    data*: array[SkEcdhRawSecretSize, byte]

  SkResult*[T] = Result[T, cstring]

##
## Private procedures interface
##

var secpContext {.threadvar.}: SkContext
  ## Thread local variable which holds current context

proc illegalCallback(message: cstring, data: pointer) {.cdecl, raises: [].} =
  # Internal panic - should never happen - all objects we pass into functions
  # are guaranteed valid per their type
  echo message
  echo getStackTrace()
  quit 1

proc errorCallback(message: cstring, data: pointer) {.cdecl, raises: [].} =
  # Internal panic - should never happen
  echo message
  echo getStackTrace()
  quit 1

template ptr0(v: array|openArray): ptr cuchar =
  cast[ptr cuchar](unsafeAddr v[0])

func shutdownLibsecp256k1(ctx: SkContext) =
  # TODO: use destructor when finalizer are deprecated for destructors
  if not(isNil(ctx.context)):
    secp256k1_context_destroy(ctx.context)

proc newSkContext(): SkContext =
  ## Create new Secp256k1 context object.
  new(result, shutdownLibsecp256k1)
  let flags = cuint(SECP256K1_CONTEXT_VERIFY or SECP256K1_CONTEXT_SIGN)
  result.context = secp256k1_context_create(flags)
  secp256k1_context_set_illegal_callback(
    result.context, illegalCallback, cast[pointer](result))
  secp256k1_context_set_error_callback(
    result.context, errorCallback, cast[pointer](result))

func getContext(): ptr secp256k1_context =
  ## Get current `EccContext`
  {.noSideEffect.}: # TODO what problems will this cause?
    if isNil(secpContext):
      secpContext = newSkContext()
    secpContext.context

func fromHex*(T: type seq[byte], s: string): SkResult[T] =
  # TODO move this to some common location and return a general error?
  try:
    ok(hexToSeqByte(s))
  except CatchableError:
    err("secp: cannot parse hex string")

proc random*(T: type SkSecretKey): SkResult[T] =
  ## Generates new random private key.
  var data{.noinit.}: array[SkRawSecretKeySize, byte]

  while randomBytes(data) == SkRawSecretKeySize:
    if secp256k1_ec_seckey_verify(secp256k1_context_no_precomp, data.ptr0) == 1:
      return ok(T(data: data))

  return err("secp: cannot get random bytes for key")

func fromRaw*(T: type SkSecretKey, data: openArray[byte]): SkResult[T] =
  ## Load a valid private key, as created by `toRaw`
  if len(data) < SkRawSecretKeySize:
    return err(static(&"secp: raw private key should be {SkRawSecretKeySize} bytes"))

  {.noSideEffect.}:
    if secp256k1_ec_seckey_verify(secp256k1_context_no_precomp, data.ptr0) != 1:
      return err("secp: invalid private key")

  ok(T(data: toArray(32, data.toOpenArray(0, SkRawSecretKeySize - 1))))

func fromHex*(T: type SkSecretKey, data: string): SkResult[T] =
  ## Initialize Secp256k1 `private key` ``key`` from hexadecimal string
  ## representation ``data``.
  T.fromRaw(? seq[byte].fromHex(data))

func toRaw*(seckey: SkSecretKey): array[SkRawSecretKeySize, byte] =
  ## Serialize Secp256k1 `private key` ``key`` to raw binary form
  seckey.data

func toHex*(seckey: SkSecretKey): string =
  toHex(toRaw(seckey))

func toPublicKey*(key: SkSecretKey): SkPublicKey =
  ## Calculate and return Secp256k1 `public key` from `private key` ``key``.
  var pubkey {.noinit.}: secp256k1_pubkey
  let res = secp256k1_ec_pubkey_create(
    getContext(), addr pubkey, key.data.ptr0)
  doAssert res == 1, "Valid private keys should always have a corresponding pub"

  SkPublicKey(data: pubkey)

func fromRaw*(T: type SkPublicKey, data: openArray[byte]): SkResult[T] =
  ## Initialize Secp256k1 `public key` ``key`` from raw binary
  ## representation ``data``, which may be compressed, uncompressed or hybrid
  if len(data) < SkRawCompressedPublicKeySize:
    return err(static(
      &"secp: public key must be {SkRawCompressedPublicKeySize} or {SkRawPublicKeySize} bytes"))

  var length: int
  if data[0] == 0x02'u8 or data[0] == 0x03'u8:
    length = min(len(data), SkRawCompressedPublicKeySize)
  elif data[0] == 0x04'u8 or data[0] == 0x06'u8 or data[0] == 0x07'u8:
    length = min(len(data), SkRawPublicKeySize)
  else:
    return err("secp: public key format not recognised")

  var key {.noinit.}: secp256k1_pubkey
  {.noSideEffect.}:
    if secp256k1_ec_pubkey_parse(
        secp256k1_context_no_precomp, addr key, data.ptr0, csize_t(length)) != 1:
      return err("secp: cannot parse public key")

  ok(SkPublicKey(data: key))

func fromHex*(T: type SkPublicKey, data: string): SkResult[T] =
  ## Initialize Secp256k1 `public key` ``key`` from hexadecimal string
  ## representation ``data``.
  T.fromRaw(? seq[byte].fromHex(data))

func toRaw*(pubkey: SkPublicKey): array[SkRawPublicKeySize, byte] =
  ## Serialize Secp256k1 `public key` ``key`` to raw uncompressed form
  var length = csize_t(len(result))

  {.noSideEffect.}:
    let res = secp256k1_ec_pubkey_serialize(
      secp256k1_context_no_precomp, result.ptr0, addr length,
      unsafeAddr pubkey.data, SECP256K1_EC_UNCOMPRESSED)
  doAssert res == 1, "Can't fail, per documentation"

func toHex*(pubkey: SkPublicKey): string =
  toHex(toRaw(pubkey))

func toRawCompressed*(pubkey: SkPublicKey): array[SkRawCompressedPublicKeySize, byte] =
  ## Serialize Secp256k1 `public key` ``key`` to raw compressed form
  var length = csize_t(len(result))
  {.noSideEffect.}:
    let res = secp256k1_ec_pubkey_serialize(
      secp256k1_context_no_precomp, result.ptr0, addr length,
      unsafeAddr pubkey.data, SECP256K1_EC_COMPRESSED)
  doAssert res == 1, "Can't fail, per documentation"

func toHexCompressed*(pubkey: SkPublicKey): string =
  toHex(toRawCompressed(pubkey))

func fromRaw*(T: type SkSignature, data: openArray[byte]): SkResult[T] =
  ## Load compact signature from data
  if data.len() < SkRawSignatureSize:
    return err(static(&"secp: signature must be {SkRawSignatureSize} bytes"))

  var sig {.noinit.}: secp256k1_ecdsa_signature
  {.noSideEffect.}:
    if secp256k1_ecdsa_signature_parse_compact(
        secp256k1_context_no_precomp, addr sig, data.ptr0) != 1:
      return err("secp: cannot parse signaure")

  ok(T(data: sig))

func fromDer*(T: type SkSignature, data: openarray[byte]): SkResult[T] =
  ## Initialize Secp256k1 `signature` ``sig`` from DER
  ## representation ``data``.
  if len(data) < 1:
    return err("secp: DER signature too short")

  var sig {.noinit.}: secp256k1_ecdsa_signature
  {.noSideEffect.}:
    if secp256k1_ecdsa_signature_parse_der(
        secp256k1_context_no_precomp, addr sig, data.ptr0, csize_t(len(data))) != 1:
      return err("secp: cannot parse DER signature")

  ok(T(data: sig))

func fromHex*(T: type SkSignature, data: string): SkResult[T] =
  ## Initialize Secp256k1 `signature` ``sig`` from hexadecimal string
  ## representation ``data``.
  T.fromRaw(? seq[byte].fromHex(data))

func toRaw*(sig: SkSignature): array[SkRawSignatureSize, byte] =
  ## Serialize signature to compact binary form
  {.noSideEffect.}:
    let res = secp256k1_ecdsa_signature_serialize_compact(
      secp256k1_context_no_precomp, result.ptr0, unsafeAddr sig.data)
    doAssert res == 1, "Can't fail, per documentation"

func toDer*(sig: SkSignature, data: var openarray[byte]): int =
  ## Serialize Secp256k1 `signature` ``sig`` to raw binary form and store it
  ## to ``data``.
  ##
  ## funcedure returns number of bytes (octets) needed to store
  ## Secp256k1 signature.
  var buffer: array[SkDerSignatureMaxSize, byte]
  var plength = csize_t(len(buffer))
  {.noSideEffect.}:
    let res = secp256k1_ecdsa_signature_serialize_der(
      secp256k1_context_no_precomp, buffer.ptr0, addr plength,
      unsafeAddr sig.data)
    doAssert res == 1, "Can't fail, per documentation"
  result = int(plength)
  if len(data) >= result:
    copyMem(addr data[0], addr buffer[0], result)

func toDer*(sig: SkSignature): seq[byte] =
  ## Serialize Secp256k1 `signature` and return it.
  result = newSeq[byte](72)
  let length = toDer(sig, result)
  result.setLen(length)

func toHex*(sig: SkSignature): string =
  toHex(toRaw(sig))

func fromRaw*(T: type SkRecoverableSignature, data: openArray[byte]): SkResult[T] =
  if data.len() < SkRawRecoverableSignatureSize:
    return err(
      static(&"secp: recoverable signature must be {SkRawRecoverableSignatureSize} bytes"))

  let recid = cint(data[64])
  var sig {.noinit.}: secp256k1_ecdsa_recoverable_signature
  {.noSideEffect.}:
    if secp256k1_ecdsa_recoverable_signature_parse_compact(
        secp256k1_context_no_precomp, addr sig, data.ptr0, recid) != 1:
      return err("secp: invalid recoverable signature")

  ok(T(data: sig))

func fromHex*(T: type SkRecoverableSignature, data: string): SkResult[T] =
  ## Initialize Secp256k1 `signature` ``sig`` from hexadecimal string
  ## representation ``data``.
  T.fromRaw(? seq[byte].fromHex(data))

func toRaw*(sig: SkRecoverableSignature): array[SkRawRecoverableSignatureSize, byte] =
  ## Converts recoverable signature to compact binary form
  var recid = cint(0)
  {.noSideEffect.}:
    let res = secp256k1_ecdsa_recoverable_signature_serialize_compact(
        secp256k1_context_no_precomp, result.ptr0, addr recid, unsafeAddr sig.data)
    doAssert res == 1, "can't fail, per documentation"

  result[64] = byte(recid)

func toHex*(sig: SkRecoverableSignature): string =
  toHex(toRaw(sig))

proc random*(T: type SkKeyPair): SkResult[T] =
  ## Generates new random key pair.
  let seckey = ? SkSecretKey.random()
  ok(T(
    seckey: seckey,
    pubkey: seckey.toPublicKey()
  ))

func `==`*(lhs, rhs: SkPublicKey): bool =
  ## Compare Secp256k1 `public key` objects for equality.
  lhs.toRaw() == rhs.toRaw()

func `==`*(lhs, rhs: SkSignature): bool =
  ## Compare Secp256k1 `signature` objects for equality.
  lhs.toRaw() == rhs.toRaw()

func `==`*(lhs, rhs: SkRecoverableSignature): bool =
  ## Compare Secp256k1 `recoverable signature` objects for equality.
  lhs.toRaw() == rhs.toRaw()

func sign*(key: SkSecretKey, msg: SkMessage): SkSignature =
  ## Sign message `msg` using private key `key` and return signature object.
  var data {.noinit.}: secp256k1_ecdsa_signature
  let res = secp256k1_ecdsa_sign(
    getContext(), addr data, msg.data.ptr0, key.data.ptr0, nil, nil)
  doAssert res == 1, "cannot create signature, key invalid?"
  SkSignature(data: data)

func signRecoverable*(key: SkSecretKey, msg: SkMessage): SkRecoverableSignature =
  ## Sign message `msg` using private key `key` and return signature object.
  var data {.noinit.}: secp256k1_ecdsa_recoverable_signature
  let res = secp256k1_ecdsa_sign_recoverable(
      getContext(), addr data, msg.data.ptr0, key.data.ptr0, nil, nil)
  doAssert res == 1, "cannot create recoverable signature, key invalid?"
  SkRecoverableSignature(data: data)

func verify*(sig: SkSignature, msg: SkMessage, key: SkPublicKey): bool =
  secp256k1_ecdsa_verify(
    getContext(), unsafeAddr sig.data, msg.data.ptr0, unsafeAddr key.data) == 1

func recover*(sig: SkRecoverableSignature, msg: SkMessage): SkResult[SkPublicKey] =
  var data {.noinit.}: secp256k1_pubkey
  if secp256k1_ecdsa_recover(
      getContext(), addr data, unsafeAddr sig.data, msg.data.ptr0) != 1:
    return err("secp: cannot recover public key from signature")

  ok(SkPublicKey(data: data))

func ecdh*(seckey: SkSecretKey, pubkey: SkPublicKey): SkEcdhSecret =
  ## Calculate ECDH shared secret.
  var secret {.noinit.}: array[SkEdchSecretSize, byte]
  {.noSideEffect.}:
    let res = secp256k1_ecdh(
        secp256k1_context_no_precomp, secret.ptr0, unsafeAddr pubkey.data,
        seckey.data.ptr0)
    doAssert res == 1, "cannot compute ECDH secret, keys invalid?"

  SkEcdhSecret(data: secret)

func ecdhRaw*(seckey: SkSecretKey, pubkey: SkPublicKey): SkEcdhRawSecret =
  ## Calculate ECDH shared secret, ethereum style
  # TODO - deprecate: https://github.com/status-im/nim-eth/issues/222
  var secret {.noinit.}: array[SkEcdhRawSecretSize, byte]
  {.noSideEffect.}:
    let res = secp256k1_ecdh_raw(
        secp256k1_context_no_precomp, secret.ptr0, unsafeAddr pubkey.data,
        seckey.data.ptr0)
    doAssert res == 1, "cannot compute raw ECDH secret, keys invalid?"

  SkEcdhRawSecret(data: secret)

func clear*(v: var SkSecretKey) =
  ## Wipe and clear memory of Secp256k1 `private key`.
  ## After calling this function, the key is invalid and using it elsewhere will
  ## result in undefined behaviour or Defect
  burnMem(v.data)

func clear*(v: var SkEcdhSecret) =
  ## Wipe and clear memory of ECDH `shared secret`.
  ## After calling this function, the key is invalid and using it elsewhere will
  ## result in undefined behaviour or Defect
  burnMem(v.data)

func clear*(v: var SkEcdhRawSecret) =
  ## Wipe and clear memory of ECDH `shared secret`.
  ## After calling this function, the key is invalid and using it elsewhere will
  ## result in undefined behaviour or Defect
  burnMem(v.data)

func `$`*(
    v: SkPublicKey | SkSecretKey | SkSignature | SkRecoverableSignature): string =
  toHex(v)

func fromBytes*(T: type SkMessage, data: openArray[byte]): SkResult[SkMessage] =
  if data.len() != SkMessageSize:
    return err("Message must be 32 bytes")

  ok(SkMessage(data: toArray(SkMessageSize, data)))

# Close `requiresInit` loophole
# TODO replace `requiresInit` with a pragma that does the expected thing
proc default*(T: type SkPublicKey): T {.error: "loophole".}
proc default*(T: type SkSecretKey): T {.error: "loophole".}
proc default*(T: type SkSignature): T {.error: "loophole".}
proc default*(T: type SkRecoverableSignature): T {.error: "loophole".}
proc default*(T: type SkEcdhSecret): T {.error: "loophole".}
proc default*(T: type SkEcdhRawSecret): T {.error: "loophole".}
