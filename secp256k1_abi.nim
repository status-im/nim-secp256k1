import strutils
from os import DirSep, AltSep, quoteShell

const
  wrapperPath = currentSourcePath.rsplit({DirSep, AltSep}, 1)[0] &
                "/secp256k1_wrapper"
  internalPath = wrapperPath & "/secp256k1"
  srcPath = internalPath & "/src"
  secpSrc = srcPath & "/secp256k1.c"

{.passC: "-I" & quoteShell(wrapperPath).}
{.passC: "-I" & quoteShell(internalPath).}
{.passC: "-I" & quoteShell(srcPath).}
{.passC: "-DHAVE_CONFIG_H".}

when defined(gcc) or defined(clang):
  {.passC: "-DHAVE_BUILTIN_EXPECT"}

{.compile: secpSrc.}

{.pragma: secp, importc, cdecl, raises: [].}

type
  secp256k1_pubkey* = object
    data*: array[64, uint8]

  secp256k1_ecdsa_signature* = object
    data*: array[64, uint8]

  secp256k1_nonce_function* = proc (nonce32: ptr cuchar; msg32: ptr cuchar;
                                    key32: ptr cuchar; algo16: ptr cuchar; data: pointer;
                                    attempt: cuint): cint {.cdecl, raises: [].}
  secp256k1_error_function* = proc (message: cstring; data: pointer) {.cdecl, raises: [].}

  secp256k1_ecdh_hash_function* = proc (output: ptr cuchar,
                                        x32, y32: ptr cuchar,
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
  input: ptr cuchar;
  inputlen: csize_t): cint {.secp.}

proc secp256k1_ec_pubkey_serialize*(
  ctx: ptr secp256k1_context;
  output: ptr cuchar;
  outputlen: ptr csize_t;
  pubkey: ptr secp256k1_pubkey;
  flags: cuint): cint {.secp.}

proc secp256k1_ecdsa_signature_parse_compact*(
  ctx: ptr secp256k1_context;
  sig: ptr secp256k1_ecdsa_signature;
  input64: ptr cuchar): cint {.secp.}

proc secp256k1_ecdsa_signature_parse_der*(
  ctx: ptr secp256k1_context;
  sig: ptr secp256k1_ecdsa_signature;
  input: ptr cuchar;
  inputlen: csize_t): cint {.secp.}

proc secp256k1_ecdsa_signature_serialize_der*(
  ctx: ptr secp256k1_context;
  output: ptr cuchar;
  outputlen: ptr csize_t;
  sig: ptr secp256k1_ecdsa_signature): cint {.secp.}

proc secp256k1_ecdsa_signature_serialize_compact*(
  ctx: ptr secp256k1_context;
  output64: ptr cuchar;
  sig: ptr secp256k1_ecdsa_signature): cint {.secp.}

proc secp256k1_ecdsa_verify*(
  ctx: ptr secp256k1_context;
  sig: ptr secp256k1_ecdsa_signature;
  msg32: ptr cuchar;
  pubkey: ptr secp256k1_pubkey): cint {.secp.}

proc secp256k1_ecdsa_signature_normalize*(
  ctx: ptr secp256k1_context;
  sigout: ptr secp256k1_ecdsa_signature;
  sigin: ptr secp256k1_ecdsa_signature): cint {.secp.}

proc secp256k1_ecdsa_sign*(
  ctx: ptr secp256k1_context;
  sig: ptr secp256k1_ecdsa_signature;
  msg32: ptr cuchar;
  seckey: ptr cuchar;
  noncefp: secp256k1_nonce_function;
  ndata: pointer): cint {.secp.}

proc secp256k1_ec_seckey_verify*(
  ctx: ptr secp256k1_context;
  seckey: ptr cuchar): cint {.secp.}

proc secp256k1_ec_pubkey_create*(
  ctx: ptr secp256k1_context;
  pubkey: ptr secp256k1_pubkey;
  seckey: ptr cuchar): cint {.secp.}

proc secp256k1_ec_privkey_negate*(
  ctx: ptr secp256k1_context;
  seckey: ptr cuchar): cint {.secp.}

proc secp256k1_ec_pubkey_negate*(
  ctx: ptr secp256k1_context;
  pubkey: ptr secp256k1_pubkey): cint {.secp.}

proc secp256k1_ec_privkey_tweak_add*(
  ctx: ptr secp256k1_context;
  seckey: ptr cuchar;
  tweak: ptr cuchar): cint {.secp.}

proc secp256k1_ec_pubkey_tweak_add*(
  ctx: ptr secp256k1_context;
  pubkey: ptr secp256k1_pubkey;
  tweak: ptr cuchar): cint {.secp.}

proc secp256k1_ec_privkey_tweak_mul*(
  ctx: ptr secp256k1_context;
  seckey: ptr cuchar;
  tweak: ptr cuchar): cint {.secp.}

proc secp256k1_ec_pubkey_tweak_mul*(
  ctx: ptr secp256k1_context;
  pubkey: ptr secp256k1_pubkey;
  tweak: ptr cuchar): cint {.secp.}

proc secp256k1_context_randomize*(
  ctx: ptr secp256k1_context;
  seed32: ptr cuchar): cint {.secp.}

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
  msg32: ptr cuchar;
  seckey: ptr cuchar;
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
  msg32: ptr cuchar): cint {.secp.}
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
  output64: ptr cuchar;
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
  input64: ptr cuchar, recid: cint): cint {.secp.}

func secp256k1_ecdh*(ctx: ptr secp256k1_context; output32: ptr cuchar;
                     pubkey: ptr secp256k1_pubkey;
                     privkey: ptr cuchar,
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

template secp256k1_ecdh*(ctx: ptr secp256k1_context; output32: ptr cuchar;
                         pubkey: ptr secp256k1_pubkey;
                         privkey: ptr cuchar): cint =
  secp256k1_ecdh(ctx, output32, pubkey, privkey,
    secp256k1_ecdh_hash_function_default(), nil)

proc secp256k1_ecdh_raw*(ctx: ptr secp256k1_context; output32: ptr cuchar;
                         pubkey: ptr secp256k1_pubkey;
                         input32: ptr cuchar): cint {.secp.}
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
