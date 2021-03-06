import ../secp256k1, unittest

{.used.}

const
  msg0 = SkMessage([
    0'u8, 0, 0, 0, 0, 0, 0, 0,
    0'u8, 0, 0, 0, 0, 0, 0, 0,
    0'u8, 0, 0, 0, 0, 0, 0, 0,
    0'u8, 0, 0, 0, 0, 0, 0, 0,
  ])
  msg1 = SkMessage([
    1'u8, 0, 0, 0, 0, 0, 0, 0,
    1'u8, 0, 0, 0, 0, 0, 0, 0,
    1'u8, 0, 0, 0, 0, 0, 0, 0,
    1'u8, 0, 0, 0, 0, 0, 0, 0,
  ])

proc workingRng(data: var openArray[byte]): bool =
  data[0] += 1
  true

proc brokenRng(data: var openArray[byte]): bool = false

suite "secp256k1":
  test "Key ops":
    let
      sk = SkSecretKey.random(workingRng).expect("should get a key")
      pk = sk.toPublicKey()

    check:
      SkSecretKey.fromRaw(sk.toRaw())[].toHex() == sk.toHex()
      SkSecretKey.fromHex(sk.toHex())[].toHex() == sk.toHex()
      SkPublicKey.fromRaw(pk.toRaw())[].toHex() == pk.toHex()
      SkPublicKey.fromRaw(pk.toRawCompressed())[].toHex() == pk.toHex()
      SkPublicKey.fromHex(pk.toHex())[].toHex() == pk.toHex()
      SkSecretKey.random(brokenRng).isErr

  test "Signatures":
    let
      sk = SkSecretKey.random(workingRng)[]
      pk = sk.toPublicKey()
      otherPk = SkSecretKey.random(workingRng)[].toPublicKey()
      sig = sign(sk, msg0)
      sig2 = signRecoverable(sk, msg0)

    check:
      verify(sig, msg0, pk)
      not verify(sig, msg0, otherPk)
      not verify(sig, msg1, pk)
      recover(sig2, msg0)[] == pk
      recover(sig2, msg1)[] != pk
      SkSignature.fromDer(sig.toDer())[].toHex() == sig.toHex()

  test "Message":
    check:
      SkMessage.fromBytes([]).isErr()
      SkMessage.fromBytes([0'u8]).isErr()
      SkMessage.fromBytes(array[32, byte](msg0)).isOk()
