import secp256k1, unittest

suite "Test1":
    test "Context should be created and destroyed":
        let ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN or SECP256K1_CONTEXT_VERIFY)
        check ctx != nil
        secp256k1_context_destroy(ctx)
