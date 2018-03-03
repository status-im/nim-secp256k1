import strutils
from os import DirSep

const wrapperPath = currentSourcePath.rsplit(DirSep, 1)[0] & "/secp256k1_wrapper"
{.passC: "-I" & wrapperPath .}
{.passC: "-I" & wrapperPath & "/secp256k1".}
{.passC: "-DHAVE_CONFIG_H".}

const secpSrc = wrapperPath & "/secp256k1/src/secp256k1.c"

{.compile: secpSrc.}

{.deadCodeElim: on.}

{.pragma: secp, importc, cdecl.}

type
  secp256k1_pubkey* = object
    data*: array[64, uint8]

  secp256k1_ecdsa_signature* = object
    data*: array[64, uint8]

  secp256k1_nonce_function* = proc (nonce32: ptr cuchar; msg32: ptr cuchar;
                                    key32: ptr cuchar; algo16: ptr cuchar; data: pointer;
                                    attempt: cuint): cint

  secp256k1_context* = object
  secp256k1_scratch_space* = object

const
  SECP256K1_FLAGS_TYPE_MASK* = ((1 shl 8) - 1)
  SECP256K1_FLAGS_TYPE_CONTEXT* = (1 shl 0)
  SECP256K1_FLAGS_TYPE_COMPRESSION* = (1 shl 1)

  ## * The higher bits contain the actual data. Do not use directly.
  SECP256K1_FLAGS_BIT_CONTEXT_VERIFY* = (1 shl 8)
  SECP256K1_FLAGS_BIT_CONTEXT_SIGN* = (1 shl 9)
  SECP256K1_FLAGS_BIT_COMPRESSION* = (1 shl 8)

  ## * Flags to pass to secp256k1_context_create.
  SECP256K1_CONTEXT_VERIFY* = (
    SECP256K1_FLAGS_TYPE_CONTEXT or SECP256K1_FLAGS_BIT_CONTEXT_VERIFY)
  SECP256K1_CONTEXT_SIGN* = (
    SECP256K1_FLAGS_TYPE_CONTEXT or SECP256K1_FLAGS_BIT_CONTEXT_SIGN)
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

proc secp256k1_context_create*(
  flags: cuint): ptr secp256k1_context {.secp.}

proc secp256k1_context_clone*(
  ctx: ptr secp256k1_context): ptr secp256k1_context {.secp.}

proc secp256k1_context_destroy*(
  ctx: ptr secp256k1_context) {.secp.}

proc secp256k1_context_set_illegal_callback*(
  ctx: ptr secp256k1_context;
  fun: proc (message: cstring; data: pointer);
  data: pointer) {.secp.}

proc secp256k1_context_set_error_callback*(
  ctx: ptr secp256k1_context;
  fun: proc (message: cstring; data: pointer);
  data: pointer) {.secp.}

proc secp256k1_scratch_space_create*(
  ctx: ptr secp256k1_context;
  init_size: csize;
  max_size: csize): ptr secp256k1_scratch_space {.secp.}

proc secp256k1_scratch_space_destroy*(
  scratch: ptr secp256k1_scratch_space) {.secp.}

proc secp256k1_ec_pubkey_parse*(
  ctx: ptr secp256k1_context;
  pubkey: ptr secp256k1_pubkey;
  input: ptr cuchar;
  inputlen: csize): cint {.secp.}

proc secp256k1_ec_pubkey_serialize*(
  ctx: ptr secp256k1_context;
  output: ptr cuchar;
  outputlen: ptr csize;
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
  inputlen: csize): cint {.secp.}

proc secp256k1_ecdsa_signature_serialize_der*(
  ctx: ptr secp256k1_context;
  output: ptr cuchar;
  outputlen: ptr csize;
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
  n: csize): cint {.secp.}

var secp256k1_nonce_function_rfc6979*: secp256k1_nonce_function
var secp256k1_nonce_function_default*: secp256k1_nonce_function

