import strutils
from os import DirSep, AltSep, quoteShell

const
  vendorPath = currentSourcePath.rsplit({DirSep, AltSep}, 1)[0] &
                "/../vendor"
  internalPath = vendorPath & "/secp256k1"
  srcPath = internalPath & "/src"

const compileFlags =
  "-DENABLE_MODULE_ECDH=1 -DENABLE_MODULE_RECOVERY=1 -DENABLE_MODULE_EXTRAKEYS=1" &
  " -I" & quoteShell(internalPath) &
  " -I" & quoteShell(srcPath)

{.compile(srcPath & "/secp256k1.c", compileFlags).}
{.compile: srcPath & "/precomputed_ecmult.c".}
{.compile: srcPath & "/precomputed_ecmult_gen.c".}

{.pragma: secp, importc, cdecl, raises: [].}

type
  secp256k1_nonce_function = proc (nonce32: ptr byte; msg32: ptr byte;
                                    key32: ptr byte; algo16: ptr byte; data: pointer;
                                    attempt: cuint): cint {.cdecl, raises: [].}

  secp256k1_context* = object

const
  SECP256K1_FLAGS_TYPE_CONTEXT = (1 shl 0)
  SECP256K1_FLAGS_BIT_CONTEXT_VERIFY = (1 shl 8)
  SECP256K1_FLAGS_BIT_CONTEXT_SIGN = (1 shl 9)

  SECP256K1_CONTEXT_VERIFY* = (
    SECP256K1_FLAGS_TYPE_CONTEXT or SECP256K1_FLAGS_BIT_CONTEXT_VERIFY)
  SECP256K1_CONTEXT_SIGN* = (
    SECP256K1_FLAGS_TYPE_CONTEXT or SECP256K1_FLAGS_BIT_CONTEXT_SIGN)

var secp256k1_context_no_precomp_imp {.
  importc: "secp256k1_context_no_precomp".}: ptr secp256k1_context

template secp256k1_context_no_precomp*: ptr secp256k1_context =
  {.noSideEffect.}:
    secp256k1_context_no_precomp_imp

proc secp256k1_context_create*(
  flags: cuint): ptr secp256k1_context {.secp.}
proc secp256k1_ec_seckey_verify*(
  ctx: ptr secp256k1_context;
  seckey: ptr byte): cint {.secp.}

type
  secp256k1_ecdsa_recoverable_signature* = object
    data: array[65, uint8]

proc secp256k1_ecdsa_sign_recoverable*(
  ctx: ptr secp256k1_context;
  sig: ptr secp256k1_ecdsa_recoverable_signature;
  msg32: ptr byte;
  seckey: ptr byte;
  noncefp: secp256k1_nonce_function;
  ndata: pointer): cint {.secp.}
