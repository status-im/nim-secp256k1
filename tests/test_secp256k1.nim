import
  ../secp256k1,
  unittest,
  stew/ptrops

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
  msg2: array[40, byte] = [
    0'u8, 0, 0, 0, 0, 0, 0, 0,
    0'u8, 0, 0, 0, 0, 0, 0, 0,
    0'u8, 0, 0, 0, 0, 0, 0, 0,
    0'u8, 0, 0, 0, 0, 0, 0, 0,
    0'u8, 0, 0, 0, 0, 0, 0, 0,
  ]

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
      SkXOnlyPublicKey.fromRaw(pk.toXOnly.toRaw())[].toHex() == pk.toXOnly.toHex()
      SkXOnlyPublicKey.fromHex(pk.toXOnly.toHex())[].toHex() == pk.toXOnly.toHex()
      SkSecretKey.random(brokenRng).isErr

  test "Signatures":
    let
      sk = SkSecretKey.random(workingRng)[]
      pk = sk.toPublicKey()
      otherPk = SkSecretKey.random(workingRng)[].toPublicKey()
      sig = sign(sk, msg0)
      sig2 = signRecoverable(sk, msg0)
      sig3 = signSchnorr(sk, msg0, workingRng)[]
      sig4 = signSchnorr(sk, cast[array[SkMessageSize, byte]](msg0), workingRng)[]
      sig5 = signSchnorr(sk, msg2, workingRng)[]

    check:
      verify(sig, msg0, pk)
      not verify(sig, msg0, otherPk)
      not verify(sig, msg1, pk)
      recover(sig2, msg0)[] == pk
      recover(sig2, msg1)[] != pk
      SkSignature.fromDer(sig.toDer())[].toHex() == sig.toHex()
      verify(sig3, msg0, pk)
      sig3 == sig4
      verify(sig5, msg2, pk)

  test "Message":
    check:
      SkMessage.fromBytes([]).isErr()
      SkMessage.fromBytes([0'u8]).isErr()
      SkMessage.fromBytes(array[32, byte](msg0)).isOk()

  test "Custom hash function":
    proc customHash(output: ptr byte, x32, y32: ptr byte, data: pointer): cint
                    {.cdecl, raises: [].} =
      # Save x and y as uncompressed public key
      output[] = 0x04
      copyMem(output.offset(1), x32, 32)
      copyMem(output.offset(33), y32, 32)
      return 1

    proc skone(_: type SkSecretKey): SkSecretKey =
      # silence noisy warning: Cannot prove that 'result' is initialized.
      result = SkSecretKey.random(workingRng)[]
      var data: array[SkRawSecretKeySize, byte]
      zeroMem(data[0].addr, data.len)
      data[31] = 1
      copyMem(result.addr, data[0].addr, data.len)

    let
      sone = SkSecretKey.skone()
      sb32 = SkSecretKey.random(workingRng)[]
      pk0  = sone.toPublicKey
      pk1  = sb32.toPublicKey

    var
      # compute using ECDH function with custom hash function
      outputEcdh = ecdh[65](sb32, pk0, customHash, nil).get
      # compute "explicitly"
      pointSer = pk1.toRaw

    check equalMem(outputEcdh.addr, pointSer.addr, 65)
