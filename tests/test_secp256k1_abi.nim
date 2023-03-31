import ../secp256k1/abi, unittest

{.used.}

suite "ABI tests":
  test "Context should be created and destroyed":
    let ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN or SECP256K1_CONTEXT_VERIFY)
    check ctx != nil
    secp256k1_context_destroy(ctx)

  test "ECDHE data should be equal":
    var aSecretKey: array[32, uint8]
    var bSecretKey: array[32, uint8]
    var aPublicKey: secp256k1_pubkey
    var bPublicKey: secp256k1_pubkey
    var data1: array[32, byte]
    var data2: array[32, byte]
    aSecretKey[31] = 1'u8
    bSecretKey[31] = 2'u8
    let ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN)
    check ctx != nil
    check secp256k1_ec_pubkey_create(ctx, addr aPublicKey,
                                     cast[ptr byte](addr aSecretKey[0])) == 1
    check secp256k1_ec_pubkey_create(ctx, addr bPublicKey,
                                     cast[ptr byte](addr bSecretKey[0])) == 1
    check secp256k1_ecdh(ctx, addr data1[0],
                         addr bPublicKey,
                         cast[ptr byte](addr aSecretKey[0])) == 1
    check secp256k1_ecdh(ctx, addr data2[0],
                         addr aPublicKey,
                         cast[ptr byte](addr bSecretKey[0])) == 1
    check(data1 == data2)

  test "Schnorr signatures":
    var keypair: secp256k1_keypair
    var secretKey: array[32, uint8]
    var publicKey: secp256k1_xonly_pubkey
    var data: array[32, byte]
    var sig: array[64, byte]
    var sig2: array[64, byte]
    secretKey[31] = 1'u8
    let ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN or SECP256K1_CONTEXT_VERIFY)
    check secp256k1_keypair_create(ctx, addr keypair, cast[ptr byte](addr secretKey[0])) == 1
    check secp256k1_keypair_xonly_pub(ctx, addr publicKey, nil, addr keypair) == 1
    check secp256k1_schnorrsig_sign32(ctx, addr sig[0], addr data[0], addr keypair, nil) == 1
    check secp256k1_schnorrsig_sign_custom(ctx, addr sig2[0], addr data[0], csize_t data.len, addr keypair, nil) == 1
    check sig == sig2
    check secp256k1_schnorrsig_verify(ctx, addr sig[0], addr data[0], csize_t data.len, addr publicKey) == 1

  test "Multikeys should be unchanged when serialized":
    var keypair: secp256k1_keypair
    var secretKey: array[32, uint8]
    var publicKey: secp256k1_xonly_pubkey
    var parsed: array[32, byte]
    var reflectedPublicKey: secp256k1_xonly_pubkey
    secretKey[31] = 1'u8
    let ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN or SECP256K1_CONTEXT_VERIFY)
    check secp256k1_keypair_create(ctx, addr keypair, cast[ptr byte](addr secretKey[0])) == 1
    check secp256k1_keypair_xonly_pub(ctx, addr publicKey, nil, addr keypair) == 1
    check secp256k1_xonly_pubkey_serialize(ctx, addr parsed[0], addr publicKey) == 1
    check secp256k1_xonly_pubkey_parse(ctx, addr reflectedPublicKey, addr parsed[0]) == 1
    check publicKey == reflectedPublicKey
