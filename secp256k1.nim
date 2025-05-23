## Copyright (c) 2018-2023 Status Research & Development GmbH
## Licensed under either of
##  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
##  * MIT license ([LICENSE-MIT](LICENSE-MIT))
## at your option.
## This file may not be copied, modified, or distributed except according to
## those terms.
##

{.push raises: [].}

import
  strformat, typetraits,
  results,
  stew/[byteutils, objects, ctops, ptrops],
  ./secp256k1/abi

from nimcrypto/utils import burnMem

export results

# Implementation notes
#
# The goal of this wrapper is to create a thin layer on top of the API presented
# in secp256k1/abi, exploiting some of its regulatities to make it slightly more
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
# * Where `secp256k1_context_no_precomp`, we surround the code with
#   `{.noSideEffect.}` as the compiler cannot deduce that this is a constant

const
  SkRawSecretKeySize* = 32 # 256 div 8
    ## Size of private key in octets (bytes)
  SkRawSignatureSize* = 64
    ## Compact serialized non-recoverable signature
  SkDerSignatureMaxSize* = 72
    ## Max bytes in DER encoding

  SkRawRecoverableSignatureSize* = 65
    ## Size of recoverable signature in octets (bytes)

  SkRawSchnorrSignatureSize* = 64
    ## Size of Schnorr signature in octets (bytes)

  SkRawPublicKeySize* = 65
    ## Size of uncompressed public key in octets (bytes)

  SkRawCompressedPublicKeySize* = 33
    ## Size of compressed public key in octets (bytes)

  SkRawXOnlyPublicKeySize* = 32
    ## Size of x-only public key in octets (bytes)

  SkMessageSize* = 32
    ## Size of message that can be signed

  SkEcdhSecretSize* = 32
    ## ECDH-agreed key size

type
  SkPublicKey* {.requiresInit.} = object
    ## Representation of public key.
    data: secp256k1_pubkey

  SkXOnlyPublicKey* {.requiresInit.} = object
    ## Representation of public key that only reveals the x-coordinate.
    data: secp256k1_xonly_pubkey

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

  SkSchnorrSignature* {.requiresInit.} = object
    ## Representation of a Schnorr signature.
    data: array[SkRawSchnorrSignatureSize, byte]

  SkContext = object
    ## Representation of Secp256k1 context object.
    context: ptr secp256k1_context

  SkMessage* = distinct array[SkMessageSize, byte]
    ## Message that can be signed or verified

  SkEcdhSecret* {.requiresInit.} = object
    ## Representation of ECDH shared secret
    data*: array[SkEcdhSecretSize, byte]

  SkEcdhHashFunc* = secp256k1_ecdh_hash_function

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

template baseAddr(v: SkMessage): ptr byte =
  baseAddr(distinctBase(v))

proc releaseThread*(T: type SkContext): T =
  if not isNil(secpContext.context):
    secp256k1_context_destroy(secpContext.context)
    secpContext.context = nil

proc init(T: type SkContext): T =
  ## Create new Secp256k1 context object - when no longer needed, it should be
  ## destroyed

  # TODO We _should_ release the context on thread shutdown but there's no
  #      reliable way to do that short of doing it manually, which the code is
  #      not really prepared for - unfortunately, nim finalizers are broken:
  #      https://github.com/nim-lang/Nim/issues/4851
  #      A workaround is to call SkContext.releaseThread() on thread end - this
  #      will become a no-op when the issue is fixed
  let flags = cuint(SECP256K1_CONTEXT_VERIFY or SECP256K1_CONTEXT_SIGN)
  result.context = secp256k1_context_create(flags)
  secp256k1_context_set_illegal_callback(
    result.context, illegalCallback, nil)
  secp256k1_context_set_error_callback(
    result.context, errorCallback, nil)

func getContext(): ptr secp256k1_context =
  ## Get current `EccContext`
  {.noSideEffect.}:
    # TODO modifying the secp context here is a side effect, but not
    #      necessarily an observable one, since the modification is done to
    #      a thread-local variable that is only  updated from within here.
    #      Technically, it should be possible to precompute a static context
    #      at compile time and use that instead, which would turn this into
    #      a truly side-effect-free function, instead of an as-if-free one.
    if isNil(secpContext.context):
      secpContext = SkContext.init()
    secpContext.context

func fromHex*(T: type seq[byte], s: string): SkResult[T] =
  # TODO move this to some common location and return a general error?
  try:
    ok(hexToSeqByte(s))
  except CatchableError:
    err("secp: cannot parse hex string")

type
  Rng* = proc(data: var openArray[byte]): bool {.raises: [Defect], gcsafe.}
    ## A function that fills data with random bytes from a cryptographically
    ## secure source or returns false

  FoolproofRng* = proc(data: var openArray[byte]) {.raises: [Defect], gcsafe.}
    ## The world will run out of fools before this RNG fails!

proc random*(T: type SkSecretKey, rng: Rng): SkResult[T] =
  ## Generates new random private key - a cryptographically secure RNG should be
  ## used - see nimcrypto or bearssl for good RNG's.
  ##
  ## The random number generator in the Nim standard library `random` module is
  ## not cryptographically secure.
  ##
  ## This function may fail to generate a valid key if the RNG fails. In the
  ## current version, the random number generation will be called in a loop
  ## which may be vulnerable to timing attacks. Generate your keys elsewhere
  ## if this is a issue.
  var data{.noinit.}: array[SkRawSecretKeySize, byte]

  while rng(data):
    if secp256k1_ec_seckey_verify(secp256k1_context_no_precomp, data.baseAddr) == 1:
      return ok(T(data: data))

  return err("secp: cannot get random bytes for key")

proc random*(T: type SkSecretKey, rng: FoolproofRng): T =
  ## Generates new random private key - a cryptographically secure RNG should be
  ## used - see nimcrypto or bearssl for good RNG's.
  ##
  ## The random number generator in the Nim standard library `random` module is
  ## not cryptographically secure.
  ##
  ## This function may fail to generate a valid key if the RNG fails, in which
  ## case it will raise a Defect.
  ##
  ## In the current version, the random number generation will be called in a
  ## loop which may be vulnerable to timing attacks. Generate your keys
  ## elsewhere if this is a issue.
  var data{.noinit.}: array[SkRawSecretKeySize, byte]

  for _ in 0..1000*1000:
    rng(data)
    if secp256k1_ec_seckey_verify(secp256k1_context_no_precomp, data.baseAddr) == 1:
      return T(data: data)

  result = T(data: default(array[32, byte])) # Silence compiler
  # All-zeroes all the time for example will break this function
  raiseAssert "RNG not giving random enough bytes, can't create valid key"

func fromRaw*(T: type SkSecretKey, data: openArray[byte]): SkResult[T] =
  ## Load a valid private key, as created by `toRaw`
  if len(data) < SkRawSecretKeySize:
    return err(static(&"secp: raw private key should be {SkRawSecretKeySize} bytes"))

  if secp256k1_ec_seckey_verify(secp256k1_context_no_precomp, data.baseAddr) != 1:
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
    getContext(), addr pubkey, key.data.baseAddr)
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
  if secp256k1_ec_pubkey_parse(
      secp256k1_context_no_precomp, addr key, data.baseAddr, csize_t(length)) != 1:
    return err("secp: cannot parse public key")

  ok(SkPublicKey(data: key))

func fromHex*(T: type SkPublicKey, data: string): SkResult[T] =
  ## Initialize Secp256k1 `public key` ``key`` from hexadecimal string
  ## representation ``data``.
  T.fromRaw(? seq[byte].fromHex(data))

func toRaw*(pubkey: SkPublicKey): array[SkRawPublicKeySize, byte] =
  ## Serialize Secp256k1 `public key` ``key`` to raw uncompressed form
  var length = csize_t(len(result))
  let res = secp256k1_ec_pubkey_serialize(
    secp256k1_context_no_precomp, result.baseAddr, addr length,
    unsafeAddr pubkey.data, SECP256K1_EC_UNCOMPRESSED)
  doAssert res == 1, "Can't fail, per documentation"

func toHex*(pubkey: SkPublicKey): string =
  toHex(toRaw(pubkey))

func toRawCompressed*(pubkey: SkPublicKey): array[SkRawCompressedPublicKeySize, byte] =
  ## Serialize Secp256k1 `public key` ``key`` to raw compressed form
  var length = csize_t(len(result))
  let res = secp256k1_ec_pubkey_serialize(
    secp256k1_context_no_precomp, result.baseAddr, addr length,
    unsafeAddr pubkey.data, SECP256K1_EC_COMPRESSED)
  doAssert res == 1, "Can't fail, per documentation"

func toHexCompressed*(pubkey: SkPublicKey): string =
  toHex(toRawCompressed(pubkey))

func toXOnly*(pk: SkPublicKey): SkXOnlyPublicKey =
  ## Gets a pubkey that reveals only the x-coordinate on the curve.
  var data {.noinit.}: secp256k1_xonly_pubkey
  let res = secp256k1_xonly_pubkey_from_pubkey(
    secp256k1_context_no_precomp, addr data, nil, unsafeAddr pk.data)
  doAssert res == 1, "cannot get xonly pubkey from pubkey, key invalid?"

  SkXOnlyPublicKey(data: data)

func fromRaw*(T: type SkXOnlyPublicKey, data: openArray[byte]): SkResult[T] =
  ## Initialize Secp256k1 `x-only public key` ``key`` from raw binary
  ## representation ``data``.
  if len(data) != SkRawXOnlyPublicKeySize:
    return err(static(
      &"secp: x-only public key must be {SkRawXOnlyPublicKeySize} bytes"))

  var key {.noinit.}: secp256k1_xonly_pubkey
  if secp256k1_xonly_pubkey_parse(
      secp256k1_context_no_precomp, addr key, data.baseAddr) != 1:
    return err("secp: cannot parse x-only public key")

  ok(SkXOnlyPublicKey(data: key))

func fromHex*(T: type SkXOnlyPublicKey, data: string): SkResult[T] =
  ## Initialize Secp256k1 `x-only public key` ``key`` from hexadecimal string
  ## representation ``data``.
  T.fromRaw(? seq[byte].fromHex(data))

func toRaw*(pubkey: SkXOnlyPublicKey): array[SkRawXOnlyPublicKeySize, byte] =
  ## Serialize Secp256k1 `x-only public key` ``key`` to raw form.
  let res = secp256k1_xonly_pubkey_serialize(
    secp256k1_context_no_precomp, result.baseAddr, unsafeAddr pubkey.data)
  doAssert res == 1, "Can't fail, per documentation"

func toHex*(pubkey: SkXOnlyPublicKey): string =
  toHex(toRaw(pubkey))

func fromRaw*(T: type SkSignature, data: openArray[byte]): SkResult[T] =
  ## Load compact signature from data
  if data.len() < SkRawSignatureSize:
    return err(static(&"secp: signature must be {SkRawSignatureSize} bytes"))

  var sig {.noinit.}: secp256k1_ecdsa_signature
  if secp256k1_ecdsa_signature_parse_compact(
      secp256k1_context_no_precomp, addr sig, data.baseAddr) != 1:
    return err("secp: cannot parse signaure")

  ok(T(data: sig))

func fromDer*(T: type SkSignature, data: openArray[byte]): SkResult[T] =
  ## Initialize Secp256k1 `signature` ``sig`` from DER
  ## representation ``data``.
  if len(data) < 1:
    return err("secp: DER signature too short")

  var sig {.noinit.}: secp256k1_ecdsa_signature
  if secp256k1_ecdsa_signature_parse_der(
      secp256k1_context_no_precomp, addr sig, data.baseAddr, csize_t(len(data))) != 1:
    return err("secp: cannot parse DER signature")

  ok(T(data: sig))

func fromHex*(T: type SkSignature, data: string): SkResult[T] =
  ## Initialize Secp256k1 `signature` ``sig`` from hexadecimal string
  ## representation ``data``.
  T.fromRaw(? seq[byte].fromHex(data))

func toRaw*(sig: SkSignature): array[SkRawSignatureSize, byte] =
  ## Serialize signature to compact binary form
  let res = secp256k1_ecdsa_signature_serialize_compact(
    secp256k1_context_no_precomp, result.baseAddr, unsafeAddr sig.data)
  doAssert res == 1, "Can't fail, per documentation"

func toDer*(sig: SkSignature, data: var openArray[byte]): int =
  ## Serialize Secp256k1 `signature` ``sig`` to raw binary form and store it
  ## to ``data``.
  ##
  ## Returns number of bytes (octets) needed to store secp256k1 signature - if
  ## this is more than `data.len`, `data` is not written to.
  var buffer: array[SkDerSignatureMaxSize, byte]
  var plength = csize_t(len(buffer))
  let res = secp256k1_ecdsa_signature_serialize_der(
    secp256k1_context_no_precomp, buffer.baseAddr, addr plength,
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
  if recid < 0 or recid > 3:
    return err("secp: recoverable signature's recid must be >= 0 and <= 3")

  var sig {.noinit.}: secp256k1_ecdsa_recoverable_signature
  if secp256k1_ecdsa_recoverable_signature_parse_compact(
      secp256k1_context_no_precomp, addr sig, data.baseAddr, recid) != 1:
    return err("secp: invalid recoverable signature")

  ok(T(data: sig))

func fromHex*(T: type SkRecoverableSignature, data: string): SkResult[T] =
  ## Initialize Secp256k1 `signature` ``sig`` from hexadecimal string
  ## representation ``data``.
  T.fromRaw(? seq[byte].fromHex(data))

func toRaw*(sig: SkRecoverableSignature): array[SkRawRecoverableSignatureSize, byte] =
  ## Converts recoverable signature to compact binary form
  var recid = cint(0)
  let res = secp256k1_ecdsa_recoverable_signature_serialize_compact(
      secp256k1_context_no_precomp, result.baseAddr, addr recid, unsafeAddr sig.data)
  doAssert res == 1, "Can't fail, per documentation"

  result[64] = byte(recid)

func toHex*(sig: SkRecoverableSignature): string =
  toHex(toRaw(sig))

func fromRaw*(T: type SkSchnorrSignature, data: openArray[byte]): SkResult[T] =
  ## Load Schnorr `signature` from data as created by `toRaw`.
  if len(data) < SkRawSchnorrSignatureSize:
    return err(static(&"secp: raw schnorr signature should be {SkRawSchnorrSignatureSize} bytes"))

  ok(T(data: toArray(64, data.toOpenArray(0, SkRawSchnorrSignatureSize - 1))))

func fromHex*(T: type SkSchnorrSignature, data: string): SkResult[T] =
  ## Initialize Schnorr `signature` from hexadecimal string representation ``data``.
  T.fromRaw(? seq[byte].fromHex(data))

func toRaw*(sig: SkSchnorrSignature): array[SkRawSchnorrSignatureSize, byte] =
  ## Serialize Schnorr `signature` ``sig`` to raw binary form.
  sig.data

func toHex*(sig: SkSchnorrSignature): string =
  toHex(toRaw(sig))

proc random*(T: type SkKeyPair, rng: Rng): SkResult[T] =
  ## Generates new random key pair.
  let seckey = ? SkSecretKey.random(rng)
  ok(T(
    seckey: seckey,
    pubkey: seckey.toPublicKey()
  ))

proc random*(T: type SkKeyPair, rng: FoolproofRng): T =
  ## Generates new random key pair.
  let seckey = SkSecretKey.random(rng)
  T(
    seckey: seckey,
    pubkey: seckey.toPublicKey()
  )

func `==`*(lhs, rhs: SkPublicKey): bool =
  ## Compare Secp256k1 `public key` objects for equality.
  CT.isEqual(lhs.toRaw(), rhs.toRaw())

func `==`*(lhs, rhs: SkSignature): bool =
  ## Compare Secp256k1 `signature` objects for equality.
  CT.isEqual(lhs.toRaw(), rhs.toRaw())

func `==`*(lhs, rhs: SkXOnlyPublicKey): bool =
  ## Compare Secp256k1 `x-only public key` objects for equality.
  CT.isEqual(lhs.toRaw(), rhs.toRaw())

func `==`*(lhs, rhs: SkRecoverableSignature): bool =
  ## Compare Secp256k1 `recoverable signature` objects for equality.
  CT.isEqual(lhs.toRaw(), rhs.toRaw())

func `==`*(lhs, rhs: SkSchnorrSignature): bool =
  ## Compare Schnorr signature objects for equality.
  CT.isEqual(lhs.toRaw(), rhs.toRaw())

func sign*(key: SkSecretKey, msg: SkMessage): SkSignature =
  ## Sign message `msg` using private key `key` and return signature object.
  ## It is recommended that `msg` is produced by hashing the input data to
  ## a 32-byte hash, like sha256.
  var data {.noinit.}: secp256k1_ecdsa_signature
  let res = secp256k1_ecdsa_sign(
    getContext(), addr data, msg.baseAddr, key.data.baseAddr, nil, nil)
  doAssert res == 1, "cannot create signature, key invalid?"
  SkSignature(data: data)

func signRecoverable*(key: SkSecretKey, msg: SkMessage): SkRecoverableSignature =
  ## Sign message `msg` using private key `key` and return signature object.
  var data {.noinit.}: secp256k1_ecdsa_recoverable_signature
  let res = secp256k1_ecdsa_sign_recoverable(
      getContext(), addr data, msg.baseAddr, key.data.baseAddr, nil, nil)
  doAssert res == 1, "cannot create recoverable signature, key invalid?"
  SkRecoverableSignature(data: data)

template signSchnorrImpl(signMsg: untyped): untyped =
  var kp {.noinit, inject.}: secp256k1_keypair
  let res = secp256k1_keypair_create(
    getContext(), addr kp, key.data.baseAddr)
  doAssert res == 1, "cannot create keypair, key invalid?"

  var data {.noinit, inject.}: array[SkRawSchnorrSignatureSize, byte]
  let res2 = signMsg
  doAssert res2 == 1, "cannot create signature, key invalid?"
  SkSchnorrSignature(data: data)

func signSchnorr*(key: SkSecretKey, msg: SkMessage, randbytes: Opt[array[32, byte]]): SkSchnorrSignature =
  ## Sign message `msg` using private key `key` with the Schnorr signature algorithm and return signature object.
  ## `randbytes` should be an array of 32 freshly generated random bytes.
  let aux_rand32 = if randbytes.isSome: randbytes[].baseAddr else: nil
  signSchnorrImpl(
    secp256k1_schnorrsig_sign32(
      getContext(), data.baseAddr, msg.baseAddr, addr kp, aux_rand32))

func signSchnorr*(key: SkSecretKey, msg: openArray[byte], randbytes: Opt[array[32, byte]]): SkSchnorrSignature =
  ## Sign message `msg` using private key `key` with the Schnorr signature algorithm and return signature object.
  ## `randbytes` should be an array of 32 freshly generated random bytes.
  let aux_rand32 = if randbytes.isSome: randbytes[].baseAddr else: nil
  let extraparams = secp256k1_schnorrsig_extraparams(magic: SECP256K1_SCHNORRSIG_EXTRAPARAMS_MAGIC, noncefp: nil, ndata: aux_rand32)
  signSchnorrImpl(
    secp256k1_schnorrsig_sign_custom(
      getContext(), data.baseAddr, msg.baseAddr, csize_t msg.len, addr kp, unsafeAddr extraparams))

template signSchnorrRngImpl(): untyped =
  var randbytes: array[32, byte]
  if rng(randbytes):
    return ok(signSchnorr(key, msg, Opt.some randbytes))
  return err("secp: cannot get random bytes for signature")

proc signSchnorr*(key: SkSecretKey, msg: SkMessage, rng: Rng): SkResult[SkSchnorrSignature] {.inline.} =
  ## Sign message `msg` using private key `key` with the Schnorr signature algorithm and return signature object.
  ## Uses ``rng`` to generate 32-bytes of random data for signature generation.
  signSchnorrRngImpl()

proc signSchnorr*(key: SkSecretKey, msg: openArray[byte], rng: Rng): SkResult[SkSchnorrSignature] {.inline.} =
  ## Sign message `msg` using private key `key` with the Schnorr signature algorithm and return signature object.
  ## Uses ``rng`` to generate 32-bytes of random data for signature generation.
  signSchnorrRngImpl()

template signSchnorrFoolproofRngImpl(): untyped =
  var randbytes: array[32, byte]
  rng(randbytes)
  return signSchnorr(key, msg, Opt.some randbytes)

proc signSchnorr*(key: SkSecretKey, msg: SkMessage, rng: FoolproofRng): SkSchnorrSignature {.inline.} =
  ## Sign message `msg` using private key `key` with the Schnorr signature algorithm and return signature object.
  ## Uses ``rng`` to generate 32-bytes of random data for signature generation.
  signSchnorrFoolproofRngImpl()

proc signSchnorr*(key: SkSecretKey, msg: openArray[byte], rng: FoolproofRng): SkSchnorrSignature {.inline.} =
  ## Sign message `msg` using private key `key` with the Schnorr signature algorithm and return signature object.
  ## Uses ``rng`` to generate 32-bytes of random data for signature generation.
  signSchnorrFoolproofRngImpl()

func verify*(sig: SkSignature, msg: SkMessage, key: SkPublicKey): bool =
  secp256k1_ecdsa_verify(
    getContext(), unsafeAddr sig.data, msg.baseAddr, unsafeAddr key.data) == 1

func verify*(sig: SkSchnorrSignature, msg: SkMessage, pubkey: SkXOnlyPublicKey): bool =
  secp256k1_schnorrsig_verify(
    getContext(), unsafeAddr sig.data[0], msg.baseAddr, csize_t SkMessageSize, unsafeAddr pubkey.data) == 1

func verify*(sig: SkSchnorrSignature, msg: openArray[byte], pubkey: SkXOnlyPublicKey): bool =
  secp256k1_schnorrsig_verify(
    getContext(), unsafeAddr sig.data[0], msg.baseAddr, csize_t msg.len, unsafeAddr pubkey.data) == 1

template verify*(sig: SkSchnorrSignature, msg: SkMessage, pubkey: SkPublicKey): bool =
  verify(sig, msg, pubkey.toXOnly)

template verify*(sig: SkSchnorrSignature, msg: openArray[byte], pubkey: SkPublicKey): bool =
  verify(sig, msg, pubkey.toXOnly)

func recover*(sig: SkRecoverableSignature, msg: SkMessage): SkResult[SkPublicKey] =
  var data {.noinit.}: secp256k1_pubkey
  if secp256k1_ecdsa_recover(
      getContext(), addr data, unsafeAddr sig.data, msg.baseAddr) != 1:
    return err("secp: cannot recover public key from signature")

  ok(SkPublicKey(data: data))

func ecdh*(seckey: SkSecretKey, pubkey: SkPublicKey): SkEcdhSecret =
  ## Calculate ECDH shared secret.
  ## Default hash function and `requiresInit` should prevent this function
  ## from failing.
  var secret {.noinit.}: array[SkEcdhSecretSize, byte]
  let res = secp256k1_ecdh(
      secp256k1_context_no_precomp, secret.baseAddr, unsafeAddr pubkey.data,
      seckey.data.baseAddr)
  doAssert res == 1, "cannot compute ECDH secret, keys invalid?"

  SkEcdhSecret(data: secret)

func ecdh*[N: static[int]](seckey: SkSecretKey, pubkey: SkPublicKey,
           hashfn: SkEcdhHashFunc, data: pointer): SkResult[array[N, byte]] =
  ## Calculate ECDH shared secret using custom hash function.
  ## This function may fail if the custom hash function return zero
  ## although other inputs have been initialized properly.
  var secret {.noinit.}: array[N, byte]
  if secp256k1_ecdh(
      secp256k1_context_no_precomp, secret.baseAddr, unsafeAddr pubkey.data,
      seckey.data.baseAddr, hashfn, data) != 1:
    return err("cannot compute ECDH secret, keys invalid?")

  ok(secret)

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

func `$`*(
    v: SkPublicKey | SkSecretKey | SkXOnlyPublicKey | SkSignature | SkRecoverableSignature | SkSchnorrSignature): string =
  toHex(v)

func fromBytes*(T: type SkMessage, data: openArray[byte]): SkResult[SkMessage] =
  if data.len() != SkMessageSize:
    return err("Message must be 32 bytes")

  ok(SkMessage(toArray(SkMessageSize, data)))

# Close `requiresInit` loophole
# TODO replace `requiresInit` with a pragma that does the expected thing
proc default*(T: type SkPublicKey): T {.error: "loophole".}
proc default*(T: type SkSecretKey): T {.error: "loophole".}
proc default*(T: type SkXOnlyPublicKey): T {.error: "loophole".}
proc default*(T: type SkSignature): T {.error: "loophole".}
proc default*(T: type SkRecoverableSignature): T {.error: "loophole".}
proc default*(T: type SkSchnorrSignature): T {.error: "loophole".}
proc default*(T: type SkEcdhSecret): T {.error: "loophole".}

func tweakAdd*(secretKey: var SkSecretKey, tweak: openArray[byte]): SkResult[void] =
  let res = secp256k1_ec_privkey_tweak_add(
    secp256k1_context_no_precomp, secretKey.data.baseAddr, tweak.baseAddr)
  if res != 1:
    err("Tweak out of range, or invalid private key")
  else:
    ok()

func tweakMul*(secretKey: var SkSecretKey, tweak: openArray[byte]): SkResult[void] =
  let res = secp256k1_ec_privkey_tweak_mul(
    secp256k1_context_no_precomp, secretKey.data.baseAddr, tweak.baseAddr)
  if res != 1:
    err("Tweak out of range, or equal to zero")
  else:
    ok()

