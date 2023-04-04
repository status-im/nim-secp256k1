import strutils
from os import DirSep, AltSep, quoteShell

const
  wrapperPath = currentSourcePath.rsplit({DirSep, AltSep}, 1)[0] &
                "/../secp256k1_wrapper"
  internalPath = wrapperPath & "/secp256k1"
  srcPath = internalPath & "/src"

{.passc: "-I" & quoteShell(wrapperPath).}
{.passc: "-I" & quoteShell(internalPath).}
{.passc: "-I" & quoteShell(srcPath).}
{.passc: "-DHAVE_CONFIG_H".}

when defined(amd64) and (defined(gcc) or defined(clang)):
  {.passc: "-DUSE_ASM_X86_64"}

{.compile: srcPath & "/secp256k1.c".}
{.compile: srcPath & "/precomputed_ecmult.c".}
{.compile: srcPath & "/precomputed_ecmult_gen.c".}

{.pragma: secp, importc, cdecl, raises: [].}

type
  secp256k1_pubkey* = object
    data*: array[64, uint8]

  secp256k1_ecdsa_signature* = object
    data*: array[64, uint8]

  secp256k1_nonce_function* = proc (nonce32: ptr byte; msg32: ptr byte;
                                    key32: ptr byte; algo16: ptr byte; data: pointer;
                                    attempt: cuint): cint {.cdecl, raises: [].}
  secp256k1_error_function* = proc (message: cstring; data: pointer) {.cdecl, raises: [].}

  secp256k1_ecdh_hash_function* = proc (output: ptr byte,
                                        x32, y32: ptr byte,
                                        data: pointer) {.cdecl, raises: [].}

  secp256k1_context* = object
  secp256k1_scratch_space* = object

const
  SECP256K1_FLAGS_TYPE_MASK* = ((1 shl 8) - 1)
  SECP256K1_FLAGS_TYPE_CONTEXT* = (1 shl 0)
  SECP256K1_FLAGS_TYPE_COMPRESSION* = (1 shl 1)

  ## * The higher bits contain the actual data. Do not use directly.
  SECP256K1_FLAGS_BIT_CONTEXT_VERIFY* = (1 shl 8)
  SECP256K1_FLAGS_BIT_CONTEXT_SIGN* = (1 shl 9)
  SECP256K1_FLAGS_BIT_CONTEXT_DECLASSIFY* = (1 shl 10)
  SECP256K1_FLAGS_BIT_COMPRESSION* = (1 shl 8)

  ## * Flags to pass to secp256k1_context_create.
  SECP256K1_CONTEXT_VERIFY* = (
    SECP256K1_FLAGS_TYPE_CONTEXT or SECP256K1_FLAGS_BIT_CONTEXT_VERIFY)
  SECP256K1_CONTEXT_SIGN* = (
    SECP256K1_FLAGS_TYPE_CONTEXT or SECP256K1_FLAGS_BIT_CONTEXT_SIGN)
  SECP256K1_CONTEXT_DECLASSIFY* = (
    SECP256K1_FLAGS_TYPE_CONTEXT or SECP256K1_FLAGS_BIT_CONTEXT_DECLASSIFY
  )
  SECP256K1_CONTEXT_NONE* = (SECP256K1_FLAGS_TYPE_CONTEXT)

  ## * Flag to pass to secp256k1_ec_pubkey_serialize and secp256k1_ec_privkey_export.
  SECP256K1_EC_COMPRESSED* = (
    SECP256K1_FLAGS_TYPE_COMPRESSION or SECP256K1_FLAGS_BIT_COMPRESSION)
  SECP256K1_EC_UNCOMPRESSED* = (SECP256K1_FLAGS_TYPE_COMPRESSION)

  ## * Prefix byte used to tag various encoded curvepoints for specific purposes
  SECP256K1_TAG_PUBKEY_EVEN* = 0x00000002
  SECP256K1_TAG_PUBKEY_ODD* = 0x00000003
  SECP256K1_TAG_PUBKEY_UNCOMPRESSED* = 0x00000004
  SECP256K1_TAG_PUBKEY_HYBRID_EVEN* = 0x00000006
  SECP256K1_TAG_PUBKEY_HYBRID_ODD* = 0x00000007

var secp256k1_context_no_precomp_imp {.
  importc: "secp256k1_context_no_precomp".}: ptr secp256k1_context

var secp256k1_ecdh_hash_function_default_imp {.
  importc: "secp256k1_ecdh_hash_function_default".}: secp256k1_ecdh_hash_function

template secp256k1_context_no_precomp*: ptr secp256k1_context =
  # This is really a constant
  {.noSideEffect.}:
    secp256k1_context_no_precomp_imp

template secp256k1_ecdh_hash_function_default*: secp256k1_ecdh_hash_function =
  # This is really a constant
  {.noSideEffect.}:
    secp256k1_ecdh_hash_function_default_imp

proc secp256k1_context_create*(
  flags: cuint): ptr secp256k1_context {.secp.}

proc secp256k1_context_clone*(
  ctx: ptr secp256k1_context): ptr secp256k1_context {.secp.}

proc secp256k1_context_destroy*(
  ctx: ptr secp256k1_context) {.secp.}

proc secp256k1_context_set_illegal_callback*(
  ctx: ptr secp256k1_context;
  fun: secp256k1_error_function;
  data: pointer) {.secp.}

proc secp256k1_context_set_error_callback*(
  ctx: ptr secp256k1_context;
  fun: secp256k1_error_function;
  data: pointer) {.secp.}

proc secp256k1_scratch_space_create*(
  ctx: ptr secp256k1_context;
  size: csize_t): ptr secp256k1_scratch_space {.secp.}

proc secp256k1_scratch_space_destroy*(
  ctx: ptr secp256k1_context;
  scratch: ptr secp256k1_scratch_space) {.secp.}

proc secp256k1_ec_pubkey_parse*(
  ctx: ptr secp256k1_context;
  pubkey: ptr secp256k1_pubkey;
  input: ptr byte;
  inputlen: csize_t): cint {.secp.}

proc secp256k1_ec_pubkey_serialize*(
  ctx: ptr secp256k1_context;
  output: ptr byte;
  outputlen: ptr csize_t;
  pubkey: ptr secp256k1_pubkey;
  flags: cuint): cint {.secp.}

proc secp256k1_ecdsa_signature_parse_compact*(
  ctx: ptr secp256k1_context;
  sig: ptr secp256k1_ecdsa_signature;
  input64: ptr byte): cint {.secp.}

proc secp256k1_ecdsa_signature_parse_der*(
  ctx: ptr secp256k1_context;
  sig: ptr secp256k1_ecdsa_signature;
  input: ptr byte;
  inputlen: csize_t): cint {.secp.}

proc secp256k1_ecdsa_signature_serialize_der*(
  ctx: ptr secp256k1_context;
  output: ptr byte;
  outputlen: ptr csize_t;
  sig: ptr secp256k1_ecdsa_signature): cint {.secp.}

proc secp256k1_ecdsa_signature_serialize_compact*(
  ctx: ptr secp256k1_context;
  output64: ptr byte;
  sig: ptr secp256k1_ecdsa_signature): cint {.secp.}

proc secp256k1_ecdsa_verify*(
  ctx: ptr secp256k1_context;
  sig: ptr secp256k1_ecdsa_signature;
  msg32: ptr byte;
  pubkey: ptr secp256k1_pubkey): cint {.secp.}

proc secp256k1_ecdsa_signature_normalize*(
  ctx: ptr secp256k1_context;
  sigout: ptr secp256k1_ecdsa_signature;
  sigin: ptr secp256k1_ecdsa_signature): cint {.secp.}

proc secp256k1_ecdsa_sign*(
  ctx: ptr secp256k1_context;
  sig: ptr secp256k1_ecdsa_signature;
  msg32: ptr byte;
  seckey: ptr byte;
  noncefp: secp256k1_nonce_function;
  ndata: pointer): cint {.secp.}

proc secp256k1_ec_seckey_verify*(
  ctx: ptr secp256k1_context;
  seckey: ptr byte): cint {.secp.}

proc secp256k1_ec_pubkey_create*(
  ctx: ptr secp256k1_context;
  pubkey: ptr secp256k1_pubkey;
  seckey: ptr byte): cint {.secp.}

proc secp256k1_ec_privkey_negate*(
  ctx: ptr secp256k1_context;
  seckey: ptr byte): cint {.secp.}

proc secp256k1_ec_pubkey_negate*(
  ctx: ptr secp256k1_context;
  pubkey: ptr secp256k1_pubkey): cint {.secp.}

proc secp256k1_ec_privkey_tweak_add*(
  ctx: ptr secp256k1_context;
  seckey: ptr byte;
  tweak: ptr byte): cint {.secp.}

proc secp256k1_ec_pubkey_tweak_add*(
  ctx: ptr secp256k1_context;
  pubkey: ptr secp256k1_pubkey;
  tweak: ptr byte): cint {.secp.}

proc secp256k1_ec_privkey_tweak_mul*(
  ctx: ptr secp256k1_context;
  seckey: ptr byte;
  tweak: ptr byte): cint {.secp.}

proc secp256k1_ec_pubkey_tweak_mul*(
  ctx: ptr secp256k1_context;
  pubkey: ptr secp256k1_pubkey;
  tweak: ptr byte): cint {.secp.}

proc secp256k1_context_randomize*(
  ctx: ptr secp256k1_context;
  seed32: ptr byte): cint {.secp.}

proc secp256k1_ec_pubkey_combine*(
  ctx: ptr secp256k1_context;
  output: ptr secp256k1_pubkey;
  ins: ptr ptr secp256k1_pubkey;
  n: csize_t): cint {.secp.}

var secp256k1_nonce_function_rfc6979*: secp256k1_nonce_function
var secp256k1_nonce_function_default*: secp256k1_nonce_function

## Recovery interface follows

type
  secp256k1_ecdsa_recoverable_signature* = object
    ## Opaque data structured that holds a parsed ECDSA signature,
    ## supporting pubkey recovery.
    ## The exact representation of data inside is implementation defined and not
    ## guaranteed to be portable between different platforms or versions. It is
    ## however guaranteed to be 65 bytes in size, and can be safely copied/moved.
    ## If you need to convert to a format suitable for storage or transmission, use
    ## the secp256k1_ecdsa_signature_serialize_* and
    ## secp256k1_ecdsa_signature_parse_* functions.
    ## Furthermore, it is guaranteed that identical signatures (including their
    ## recoverability) will have identical representation, so they can be
    ## memcmp'ed.
    data*: array[65, uint8]

proc secp256k1_ecdsa_sign_recoverable*(
  ctx: ptr secp256k1_context;
  sig: ptr secp256k1_ecdsa_recoverable_signature;
  msg32: ptr byte;
  seckey: ptr byte;
  noncefp: secp256k1_nonce_function;
  ndata: pointer): cint {.secp.}
  ##  Create a recoverable ECDSA signature.
  ##
  ##  Returns: 1: signature created
  ##           0: the nonce generation function failed, or the private key was invalid.
  ##  Args:    ctx:    pointer to a context object, initialized for signing (cannot be NULL)
  ##  Out:     sig:    pointer to an array where the signature will be placed (cannot be NULL)
  ##  In:      msg32:  the 32-byte message hash being signed (cannot be NULL)
  ##           seckey: pointer to a 32-byte secret key (cannot be NULL)
  ##           noncefp:pointer to a nonce generation function. If NULL, secp256k1_nonce_function_default is used
  ##           ndata:  pointer to arbitrary data used by the nonce generation function (can be NULL)
  ##

proc secp256k1_ecdsa_recover*(
  ctx: ptr secp256k1_context;
  pubkey: ptr secp256k1_pubkey;
  sig: ptr secp256k1_ecdsa_recoverable_signature;
  msg32: ptr byte): cint {.secp.}
  ##  Recover an ECDSA public key from a signature.
  ##
  ##  Returns: 1: public key successfully recovered (which guarantees a correct signature).
  ##           0: otherwise.
  ##  Args:    ctx:        pointer to a context object, initialized for verification (cannot be NULL)
  ##  Out:     pubkey:     pointer to the recovered public key (cannot be NULL)
  ##  In:      sig:        pointer to initialized signature that supports pubkey recovery (cannot be NULL)
  ##           msg32:      the 32-byte message hash assumed to be signed (cannot be NULL)
  ##

proc secp256k1_ecdsa_recoverable_signature_serialize_compact*(
  ctx: ptr secp256k1_context;
  output64: ptr byte;
  recid: ptr cint;
  sig: ptr secp256k1_ecdsa_recoverable_signature): cint {.secp.}
  ##  Serialize an ECDSA signature in compact format (64 bytes + recovery id).
  ##
  ##  Returns: 1
  ##  Args: ctx:      a secp256k1 context object
  ##  Out:  output64: a pointer to a 64-byte array of the compact signature (cannot be NULL)
  ##        recid:    a pointer to an integer to hold the recovery id (can be NULL).
  ##  In:   sig:      a pointer to an initialized signature object (cannot be NULL)
  ##

proc secp256k1_ecdsa_recoverable_signature_parse_compact*(
  ctx: ptr secp256k1_context;
  sig: ptr secp256k1_ecdsa_recoverable_signature;
  input64: ptr byte, recid: cint): cint {.secp.}

func secp256k1_ecdh*(ctx: ptr secp256k1_context; output32: ptr byte;
                     pubkey: ptr secp256k1_pubkey;
                     privkey: ptr byte,
                     hashfp: secp256k1_ecdh_hash_function,
                     data: pointer): cint {.secp.}
  ## Compute an EC Diffie-Hellman secret in constant time
  ## Returns: 1: exponentiation was successful
  ##          0: scalar was invalid (zero or overflow)
  ## Args:    ctx:        pointer to a context object (cannot be NULL)
  ## Out:     result:     a 32-byte array which will be populated by an ECDH
  ##                      secret computed from the point and scalar
  ## In:      pubkey:     a pointer to a secp256k1_pubkey containing an
  ##                      initialized public key
  ##          privkey:    a 32-byte scalar with which to multiply the point
  ##

template secp256k1_ecdh*(ctx: ptr secp256k1_context; output32: ptr byte;
                         pubkey: ptr secp256k1_pubkey;
                         privkey: ptr byte): cint =
  secp256k1_ecdh(ctx, output32, pubkey, privkey,
    secp256k1_ecdh_hash_function_default(), nil)

proc secp256k1_ecdh_raw*(ctx: ptr secp256k1_context; output32: ptr byte;
                         pubkey: ptr secp256k1_pubkey;
                         input32: ptr byte): cint {.secp.}
  ## Compute an EC Diffie-Hellman secret in constant time
  ## Returns: 1: exponentiation was successful
  ##         0: scalar was invalid (zero or overflow)
  ## Args:    ctx:        pointer to a context object (cannot be NULL)
  ## Out:     result:     a 33-byte array which will be populated by an ECDH
  ##                      secret computed from the point and scalar in form
  ##                      of compressed point
  ## In:      pubkey:     a pointer to a secp256k1_pubkey containing an
  ##                      initialized public key
  ##          privkey:    a 32-byte scalar with which to multiply the point
  ##

## Multikey interface follows

type
  secp256k1_xonly_pubkey* = object
    ## Opaque data structure that holds a parsed and valid "x-only" public key.
    ## An x-only pubkey encodes a point whose Y coordinate is even. It is
    ## serialized using only its X coordinate (32 bytes). See BIP-340 for more
    ## information about x-only pubkeys.
    ##
    ## The exact representation of data inside is implementation defined and not
    ## guaranteed to be portable between different platforms or versions. It is
    ## however guaranteed to be 64 bytes in size, and can be safely copied/moved.
    ## If you need to convert to a format suitable for storage, transmission, use
    ## use secp256k1_xonly_pubkey_serialize and secp256k1_xonly_pubkey_parse. To
    ## compare keys, use secp256k1_xonly_pubkey_cmp.
    ##
    data*: array[64, uint8]

  secp256k1_keypair* = object
    ## Opaque data structure that holds a keypair consisting of a secret and a
    ## public key.
    ##
    ## The exact representation of data inside is implementation defined and not
    ## guaranteed to be portable between different platforms or versions. It is
    ## however guaranteed to be 96 bytes in size, and can be safely copied/moved.
    ##
    data*: array[96, uint8]

proc secp256k1_xonly_pubkey_parse*(ctx: ptr secp256k1_context;
                                   pubkey: ptr secp256k1_xonly_pubkey;
                                   input32: ptr byte): cint {.secp.}

proc secp256k1_xonly_pubkey_serialize*(ctx: ptr secp256k1_context;
                                       output32: ptr byte;
                                       pubkey: ptr secp256k1_xonly_pubkey): cint {.secp.}

proc secp256k1_xonly_pubkey_from_pubkey*(ctx: ptr secp256k1_context;
                                         xonly_pubkey: ptr secp256k1_xonly_pubkey;
                                         pk_parity: ptr cint;
                                         pubkey: ptr secp256k1_pubkey): cint {.secp.}
  ## Converts a secp256k1_pubkey into a secp256k1_xonly_pubkey.
  ##
  ## Returns: 1 always.
  ##
  ## Args:         ctx: pointer to a context object.
  ## Out: xonly_pubkey: pointer to an x-only public key object for placing the converted public key.
  ##         pk_parity: Ignored if NULL. Otherwise, pointer to an integer that
  ##                    will be set to 1 if the point encoded by xonly_pubkey is
  ##                    the negation of the pubkey and set to 0 otherwise.
  ## In:        pubkey: pointer to a public key that is converted.
  ##

proc secp256k1_xonly_pubkey_tweak_add*(ctx: ptr secp256k1_context;
                                       output_pubkey: ptr secp256k1_pubkey;
                                       internal_pubkey: ptr secp256k1_xonly_pubkey;
                                       tweak32: ptr byte): cint {.secp.}

proc secp256k1_xonly_pubkey_tweak_add_check*(ctx: ptr secp256k1_context;
                                             tweaked_pubkey32: ptr byte;
                                             tweaked_pk_parity: cint;
                                             internal_pubkey: ptr secp256k1_xonly_pubkey;
                                             tweak32: ptr byte): cint {.secp.}

proc secp256k1_keypair_create*(ctx: ptr secp256k1_context;
                               keypair: ptr secp256k1_keypair;
                               seckey: ptr byte): cint {.secp.}
  ## Compute the keypair for a secret key.
  ##
  ## Returns: 1: secret was valid, keypair is ready to use
  ##          0: secret was invalid, try again with a different secret
  ## Args:    ctx: pointer to a context object, initialized for signing.
  ## Out: keypair: pointer to the created keypair.
  ## In:   seckey: pointer to a 32-byte secret key.
  ##

proc secp256k1_keypair_sec*(ctx: ptr secp256k1_context;
                            seckey: ptr byte;
                            keypair: ptr secp256k1_keypair): cint {.secp.}

proc secp256k1_keypair_pub*(ctx: ptr secp256k1_context;
                            pubkey: ptr secp256k1_pubkey;
                            keypair: ptr secp256k1_keypair): cint {.secp.}

proc secp256k1_keypair_xonly_pub*(ctx: ptr secp256k1_context;
                                  pubkey: ptr secp256k1_xonly_pubkey;
                                  pk_parity: ptr cint;
                                  keypair: ptr secp256k1_keypair): cint {.secp.}

proc secp256k1_keypair_xonly_tweak_add*(ctx: ptr secp256k1_context;
                                        keypair: ptr secp256k1_keypair;
                                        tweak32: ptr byte): cint {.secp.}

## Schnorrsig interface follows

type
  secp256k1_nonce_function_hardened* {.bycopy.} = object
    nonce32*: ptr byte
    msg*: ptr byte
    msglen*: csize_t
    key32*: ptr byte
    xonly_pk32*: ptr byte
    algo*: ptr byte
    algolen*: csize_t
    data*: pointer

const
  SECP256K1_SCHNORRSIG_EXTRAPARAMS_MAGIC* = [ 0xda'u8 , 0x6f, 0xb3, 0x8c ]

type
  secp256k1_schnorrsig_extraparams* = object
    magic*: array[4, uint8]
    noncefp*: secp256k1_nonce_function_hardened
    ndata*: pointer

proc secp256k1_schnorrsig_sign32*(ctx: ptr secp256k1_context;
                                  sig64: ptr byte;
                                  msg32: ptr byte;
                                  keypair: ptr secp256k1_keypair;
                                  aux_rand32: ptr byte): cint {.secp.}
  ## Create a Schnorr signature.
  ##
  ## Does _not_ strictly follow BIP-340 because it does not verify the resulting
  ## signature. Instead, you can manually use secp256k1_schnorrsig_verify and
  ## abort if it fails.
  ##
  ## This function only signs 32-byte messages. If you have messages of a
  ## different size (or the same size but without a context-specific tag
  ## prefix), it is recommended to create a 32-byte message hash with
  ## secp256k1_tagged_sha256 and then sign the hash. Tagged hashing allows
  ## providing an context-specific tag for domain separation. This prevents
  ## signatures from being valid in multiple contexts by accident.
  ##
  ## Returns 1 on success, 0 on failure.
  ## Args:    ctx: pointer to a context object, initialized for signing.
  ## Out:   sig64: pointer to a 64-byte array to store the serialized signature.
  ## In:    msg32: the 32-byte message being signed.
  ##      keypair: pointer to an initialized keypair.
  ##   aux_rand32: 32 bytes of fresh randomness. While recommended to provide
  ##               this, it is only supplemental to security and can be NULL. A
  ##               NULL argument is treated the same as an all-zero one. See
  ##               BIP-340 "Default Signing" for a full explanation of this
  ##               argument and for guidance if randomness is expensive.
  ##

proc secp256k1_schnorrsig_sign_custom*(
  ctx: ptr secp256k1_context;
  sig64: ptr byte;
  msg: ptr byte;
  msglen: csize_t;
  keypair: ptr secp256k1_keypair;
  extraparams: ptr secp256k1_schnorrsig_extraparams): cint {.secp.}
  ## Create a Schnorr signature with a more flexible API.
  ##
  ## Same arguments as secp256k1_schnorrsig_sign except that it allows signing
  ## variable length messages and accepts a pointer to an extraparams object that
  ## allows customizing signing by passing additional arguments.
  ##
  ## Creates the same signatures as schnorrsig_sign if msglen is 32 and the
  ## extraparams.ndata is the same as aux_rand32.
  ##
  ## In:     msg: the message being signed. Can only be NULL if msglen is 0.
  ##      msglen: length of the message
  ## extraparams: pointer to a extraparams object (can be NULL)
  ##

proc secp256k1_schnorrsig_verify*(
  ctx: ptr secp256k1_context;
  sig64: ptr byte;
  msg: ptr byte;
  msglen: csize_t;
  pubkey: ptr secp256k1_xonly_pubkey): cint {.secp.}
  ## Verify a Schnorr signature.
  ##
  ## Returns: 1: correct signature
  ##          0: incorrect signature
  ## Args:    ctx: a secp256k1 context object, initialized for verification.
  ## In:    sig64: pointer to the 64-byte signature to verify.
  ##          msg: the message being verified. Can only be NULL if msglen is 0.
  ##       msglen: length of the message
  ##       pubkey: pointer to an x-only public key to verify with (cannot be NULL)
  ##

var secp256k1_nonce_function_bip340*: secp256k1_nonce_function_hardened
