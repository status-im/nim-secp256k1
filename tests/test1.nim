import secp256k1, unittest

suite "Test1":
  test "Context should be created and destroyed":
    let ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN or SECP256K1_CONTEXT_VERIFY)
    check ctx != nil
    secp256k1_context_destroy(ctx)

  test "ECDHE data should be equal":
    var aSecretKey: array[32, uint8]
    var bSecretKey: array[32, uint8]
    var aPublicKey: secp256k1_pubkey
    var bPublicKey: secp256k1_pubkey
    var data1: array[32, cuchar]
    var data2: array[32, cuchar]
    aSecretKey[31] = 1'u8
    bSecretKey[31] = 2'u8
    let ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN)
    check ctx != nil
    check secp256k1_ec_pubkey_create(ctx, addr aPublicKey,
                                     cast[ptr cuchar](addr aSecretKey[0])) == 1
    check secp256k1_ec_pubkey_create(ctx, addr bPublicKey,
                                     cast[ptr cuchar](addr bSecretKey[0])) == 1
    check secp256k1_ecdh(ctx, addr data1[0],
                         addr bPublicKey,
                         cast[ptr cuchar](addr aSecretKey[0])) == 1
    check secp256k1_ecdh(ctx, addr data2[0],
                         addr aPublicKey,
                         cast[ptr cuchar](addr bSecretKey[0])) == 1
    check(data1 == data2)
