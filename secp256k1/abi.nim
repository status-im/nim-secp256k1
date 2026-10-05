import std/[strutils, os]

const
  vendorPath = currentSourcePath.rsplit({DirSep, AltSep}, 1)[0] &
                "/../vendor"
  internalPath = vendorPath & "/secp256k1"
  srcPath = internalPath & "/src"

when defined(amd64) and (defined(gcc) or defined(clang)):
  const asmFlags = " -DUSE_ASM_X86_64"
else:
  const asmFlags = ""

# quoteShell is not defined when compiling to bare metal
when not defined(`any`) and not defined(standalone):
  const compileFlags =
    "-DENABLE_MODULE_ECDH=1 -DENABLE_MODULE_RECOVERY=1 -DENABLE_MODULE_SCHNORRSIG=1 -DENABLE_MODULE_EXTRAKEYS=1" &
    " -I" & quoteShell(internalPath) &
    " -I" & quoteShell(srcPath) &
    asmFlags
else:
  const compileFlags =
    "-DENABLE_MODULE_ECDH=1 -DENABLE_MODULE_RECOVERY=1 -DENABLE_MODULE_SCHNORRSIG=1 -DENABLE_MODULE_EXTRAKEYS=1" &
    " -I\"" & internalPath & "\"" &
    " -I\"" & srcPath & "\"" &
    asmFlags

{.compile(srcPath & "/secp256k1.c", compileFlags).}
{.compile: srcPath & "/precomputed_ecmult.c".}
{.compile: srcPath & "/precomputed_ecmult_gen.c".}

{.pragma: secp, cdecl, raises: [].}

type
  ConstPtrByte* {.importc: "const unsigned char *".} = pointer
  ConstCstring* {.importc: "const char *".} = cstring

  secp256k1_error_function* = proc (message: ConstCstring; data: pointer) {.secp.}

  secp256k1_scratch_space* = object

const
  SECP256K1_SCHNORRSIG_EXTRAPARAMS_MAGIC* = [0xda'u8, 0x6f, 0xb3, 0x8c]
## * Unless explicitly stated all pointer arguments must not be NULL.
##
##  The following rules specify the order of arguments in API calls:
##
##  1. Context pointers go first, followed by output arguments, combined
##     output/input arguments, and finally input-only arguments.
##  2. Array lengths always immediately follow the argument whose length
##     they describe, even if this violates rule 1.
##  3. Within the OUT/OUTIN/IN groups, pointers to data that is typically generated
##     later go first. This means: signatures, public nonces, secret nonces,
##     messages, public keys, secret keys, tweaks.
##  4. Arguments that are not data pointers go last, from more complex to less
##     complex: function pointers, algorithm names, messages, void pointers,
##     counts, flags, booleans.
##  5. Opaque data pointers follow the function pointer they are to be passed to.
##
## * Opaque data structure that holds context information
##
##   The primary purpose of context objects is to store randomization data for
##   enhanced protection against side-channel leakage. This protection is only
##   effective if the context is randomized after its creation. See
##   secp256k1_context_create for creation of contexts and
##   secp256k1_context_randomize for randomization.
##
##   A secondary purpose of context objects is to store pointers to callback
##   functions that the library will call when certain error states arise. See
##   secp256k1_context_set_error_callback as well as
##   secp256k1_context_set_illegal_callback for details. Future library versions
##   may use context objects for additional purposes.
##
##   A constructed context can safely be used from multiple threads
##   simultaneously, but API calls that take a non-const pointer to a context
##   need exclusive access to it. In particular this is the case for
##   secp256k1_context_destroy, secp256k1_context_preallocated_destroy,
##   and secp256k1_context_randomize.
##
##   Regarding randomization, either do it once at creation time (in which case
##   you do not need any locking for the other calls), or use a read-write lock.
##

type
  secp256k1_context* = object

## * Opaque data structure that holds a parsed and valid public key.
##
##   The exact representation of data inside is implementation defined and not
##   guaranteed to be portable between different platforms or versions. It is
##   however guaranteed to be 64 bytes in size, and can be safely copied/moved.
##   If you need to convert to a format suitable for storage or transmission,
##   use secp256k1_ec_pubkey_serialize and secp256k1_ec_pubkey_parse. To
##   compare keys, use secp256k1_ec_pubkey_cmp.
##

type
  secp256k1_pubkey* {.bycopy.} = object
    data*: array[64, byte]


## * Opaque data structure that holds a parsed ECDSA signature.
##
##   The exact representation of data inside is implementation defined and not
##   guaranteed to be portable between different platforms or versions. It is
##   however guaranteed to be 64 bytes in size, and can be safely copied/moved.
##   If you need to convert to a format suitable for storage, transmission, or
##   comparison, use the secp256k1_ecdsa_signature_serialize_* and
##   secp256k1_ecdsa_signature_parse_* functions.
##

type
  secp256k1_ecdsa_signature* {.bycopy.} = object
    data*: array[64, byte]


## * A pointer to a function to deterministically generate a nonce.
##
##  Returns: 1 if a nonce was successfully generated. 0 will cause signing to fail.
##  Out:     nonce32:   pointer to a 32-byte array to be filled by the function.
##  In:      msg32:     the 32-byte message hash being verified (will not be NULL)
##           key32:     pointer to a 32-byte secret key (will not be NULL)
##           algo16:    pointer to a 16-byte array describing the signature
##                      algorithm (will be NULL for ECDSA for compatibility).
##           data:      Arbitrary data pointer that is passed through.
##           attempt:   how many iterations we have tried to find a nonce.
##                      This will almost always be 0, but different attempt values
##                      are required to result in a different nonce.
##
##  Except for test cases, this function should compute some cryptographic hash of
##  the message, the algorithm, the key and the attempt.
##

type
  secp256k1_nonce_function* = proc (nonce32: ptr byte; msg32: ConstPtrByte;
                                 key32: ConstPtrByte; algo16: ConstPtrByte;
                                 data: pointer; attempt: cuint): cint {.secp.}

##   When this header is used at build-time the SECP256K1_BUILD define needs to be set
##   to correctly setup export attributes and nullness checks.  This is normally done
##   by secp256k1.c but to guard against this header being included before secp256k1.c
##   has had a chance to set the define (e.g. via test harnesses that just includes
##   secp256k1.c) we set SECP256K1_NO_BUILD when this header is processed without the
##   BUILD define so this condition can be caught.
##
##  Symbol visibility.
##  On Windows, SECP256K1_STATIC must be defined when consuming
##  libsecp256k1 as a static library. Note that SECP256K1_STATIC is a
##  "consumer-only" macro, and it has no meaning when building
##  libsecp256k1.
##  Warning attributes
##  NONNULL is not used if SECP256K1_BUILD is set to avoid the compiler optimizing out
##  some paranoid null checks.
##  Attribute for marking functions, types, and variables as deprecated
##  All flags' lower 8 bits indicate what they're for. Do not use directly.

const
  SECP256K1_FLAGS_TYPE_MASK* = ((1 shl 8) - 1)
  SECP256K1_FLAGS_TYPE_CONTEXT* = (1 shl 0)
  SECP256K1_FLAGS_TYPE_COMPRESSION* = (1 shl 1)

##  The higher bits contain the actual data. Do not use directly.

const
  SECP256K1_FLAGS_BIT_CONTEXT_VERIFY* = (1 shl 8)
  SECP256K1_FLAGS_BIT_CONTEXT_SIGN* = (1 shl 9)
  SECP256K1_FLAGS_BIT_CONTEXT_DECLASSIFY* = (1 shl 10)
  SECP256K1_FLAGS_BIT_COMPRESSION* = (1 shl 8)

## * Context flags to pass to secp256k1_context_create, secp256k1_context_preallocated_size, and
##   secp256k1_context_preallocated_create.

const
  SECP256K1_CONTEXT_NONE* = (SECP256K1_FLAGS_TYPE_CONTEXT)

## * Deprecated context flags. These flags are treated equivalent to SECP256K1_CONTEXT_NONE.

const
  SECP256K1_CONTEXT_VERIFY* = (
    SECP256K1_FLAGS_TYPE_CONTEXT or SECP256K1_FLAGS_BIT_CONTEXT_VERIFY)
  SECP256K1_CONTEXT_SIGN* = (
    SECP256K1_FLAGS_TYPE_CONTEXT or SECP256K1_FLAGS_BIT_CONTEXT_SIGN)

##  Testing flag. Do not use.

const
  SECP256K1_CONTEXT_DECLASSIFY* = (
    SECP256K1_FLAGS_TYPE_CONTEXT or SECP256K1_FLAGS_BIT_CONTEXT_DECLASSIFY)

## * Flag to pass to secp256k1_ec_pubkey_serialize.

const
  SECP256K1_EC_COMPRESSED* = (
    SECP256K1_FLAGS_TYPE_COMPRESSION or SECP256K1_FLAGS_BIT_COMPRESSION)
  SECP256K1_EC_UNCOMPRESSED* = (SECP256K1_FLAGS_TYPE_COMPRESSION)

## * Prefix byte used to tag various encoded curvepoints for specific purposes

const
  SECP256K1_TAG_PUBKEY_EVEN* = 0x02
  SECP256K1_TAG_PUBKEY_ODD* = 0x03
  SECP256K1_TAG_PUBKEY_UNCOMPRESSED* = 0x04
  SECP256K1_TAG_PUBKEY_HYBRID_EVEN* = 0x06
  SECP256K1_TAG_PUBKEY_HYBRID_ODD* = 0x07

## * A built-in constant secp256k1 context object with static storage duration, to be
##   used in conjunction with secp256k1_selftest.
##
##   This context object offers *only limited functionality* , i.e., it cannot be used
##   for API functions that perform computations involving secret keys, e.g., signing
##   and public key generation. If this restriction applies to a specific API function,
##   it is mentioned in its documentation. See secp256k1_context_create if you need a
##   full context object that supports all functionality offered by the library.
##
##   It is highly recommended to call secp256k1_selftest before using this context.
##

var secp256k1_context_static_imp {.importc: "secp256k1_context_static".}: ptr secp256k1_context

template secp256k1_context_static*: ptr secp256k1_context =
  {.noSideEffect.}:
    secp256k1_context_static_imp

## * Perform basic self tests (to be used in conjunction with secp256k1_context_static)
##
##   This function performs self tests that detect some serious usage errors and
##   similar conditions, e.g., when the library is compiled for the wrong endianness.
##   This is a last resort measure to be used in production. The performed tests are
##   very rudimentary and are not intended as a replacement for running the test
##   binaries.
##
##   It is highly recommended to call this before using secp256k1_context_static.
##   It is not necessary to call this function before using a context created with
##   secp256k1_context_create (or secp256k1_context_preallocated_create), which will
##   take care of performing the self tests.
##
##   If the tests fail, this function will call the default error callback to abort the
##   program (see secp256k1_context_set_error_callback).
##

proc secp256k1_selftest*() {.secp, importc: "secp256k1_selftest".}
## * Create a secp256k1 context object (in dynamically allocated memory).
##
##   This function uses malloc to allocate memory. It is guaranteed that malloc is
##   called at most once for every call of this function. If you need to avoid dynamic
##   memory allocation entirely, see secp256k1_context_static and the functions in
##   secp256k1_preallocated.h.
##
##   Returns: pointer to a newly created context object.
##   In:      flags: Always set to SECP256K1_CONTEXT_NONE (see below).
##
##   The only valid non-deprecated flag in recent library versions is
##   SECP256K1_CONTEXT_NONE, which will create a context sufficient for all functionality
##   offered by the library. All other (deprecated) flags will be treated as equivalent
##   to the SECP256K1_CONTEXT_NONE flag. Though the flags parameter primarily exists for
##   historical reasons, future versions of the library may introduce new flags.
##
##   If the context is intended to be used for API functions that perform computations
##   involving secret keys, e.g., signing and public key generation, then it is highly
##   recommended to call secp256k1_context_randomize on the context before calling
##   those API functions. This will provide enhanced protection against side-channel
##   leakage, see secp256k1_context_randomize for details.
##
##   Do not create a new context object for each operation, as construction and
##   randomization can take non-negligible time.
##

proc secp256k1_context_create*(flags: cuint): ptr secp256k1_context {.secp,
    importc: "secp256k1_context_create".}
## * Copy a secp256k1 context object (into dynamically allocated memory).
##
##   This function uses malloc to allocate memory. It is guaranteed that malloc is
##   called at most once for every call of this function. If you need to avoid dynamic
##   memory allocation entirely, see the functions in secp256k1_preallocated.h.
##
##   Cloning secp256k1_context_static is not possible, and should not be emulated by
##   the caller (e.g., using memcpy). Create a new context instead.
##
##   Returns: pointer to a newly created context object.
##   Args:    ctx: pointer to a context to copy (not secp256k1_context_static).
##

proc secp256k1_context_clone*(ctx: ptr secp256k1_context): ptr secp256k1_context {.
    secp, importc: "secp256k1_context_clone".}
## * Destroy a secp256k1 context object (created in dynamically allocated memory).
##
##   The context pointer may not be used afterwards.
##
##   The context to destroy must have been created using secp256k1_context_create
##   or secp256k1_context_clone. If the context has instead been created using
##   secp256k1_context_preallocated_create or secp256k1_context_preallocated_clone, the
##   behaviour is undefined. In that case, secp256k1_context_preallocated_destroy must
##   be used instead.
##
##   Args:   ctx: pointer to a context to destroy, constructed using
##                secp256k1_context_create or secp256k1_context_clone
##                (i.e., not secp256k1_context_static).
##

proc secp256k1_context_destroy*(ctx: ptr secp256k1_context) {.secp,
    importc: "secp256k1_context_destroy".}
## * Set a callback function to be called when an illegal argument is passed to
##   an API call. It will only trigger for violations that are mentioned
##   explicitly in the header.
##
##   The philosophy is that these shouldn't be dealt with through a specific
##   return value, as calling code should not have branches to deal with the case
##   that this code itself is broken.
##
##   On the other hand, during debug stage, one would want to be informed about
##   such mistakes, and the default (crashing) may be inadvisable. Should this
##   callback return instead of crashing, the return value and output arguments
##   of the API function call are undefined. Moreover, the same API call may
##   trigger the callback again in this case.
##
##   When this function has not been called (or called with fun==NULL), then the
##   default callback will be used. The library provides a default callback which
##   writes the message to stderr and calls abort. This default callback can be
##   replaced at link time if the preprocessor macro
##   USE_EXTERNAL_DEFAULT_CALLBACKS is defined, which is the case if the build
##   has been configured with --enable-external-default-callbacks (GNU Autotools) or
##   -DSECP256K1_USE_EXTERNAL_DEFAULT_CALLBACKS=ON (CMake). Then the
##   following two symbols must be provided to link against:
##    - void secp256k1_default_illegal_callback_fn(const char *message, void *data);
##    - void secp256k1_default_error_callback_fn(const char *message, void *data);
##   The library may call a default callback even before a proper callback data
##   pointer could have been set using secp256k1_context_set_illegal_callback or
##   secp256k1_context_set_error_callback, e.g., when the creation of a context
##   fails. In this case, the corresponding default callback will be called with
##   the data pointer argument set to NULL.
##
##   Args: ctx:  pointer to a context object.
##   In:   fun:  pointer to a function to call when an illegal argument is
##               passed to the API, taking a message and an opaque pointer.
##               (NULL restores the default callback.)
##         data: the opaque pointer to pass to fun above, must be NULL for the
##               default callback.
##
##   See also secp256k1_context_set_error_callback.
##

proc secp256k1_context_set_illegal_callback*(ctx: ptr secp256k1_context;
    fun: proc (message: ConstCstring; data: pointer) {.secp.}; data: pointer) {.secp,
    importc: "secp256k1_context_set_illegal_callback".}
## * Set a callback function to be called when an internal consistency check
##   fails.
##
##   The default callback writes an error message to stderr and calls abort
##   to abort the program.
##
##   This can only trigger in case of a hardware failure, miscompilation,
##   memory corruption, serious bug in the library, or other error that would
##   result in undefined behaviour. It will not trigger due to mere
##   incorrect usage of the API (see secp256k1_context_set_illegal_callback
##   for that). After this callback returns, anything may happen, including
##   crashing.
##
##   Args: ctx:  pointer to a context object.
##   In:   fun:  pointer to a function to call when an internal error occurs,
##               taking a message and an opaque pointer (NULL restores the
##               default callback, see secp256k1_context_set_illegal_callback
##               for details).
##         data: the opaque pointer to pass to fun above, must be NULL for the
##               default callback.
##
##   See also secp256k1_context_set_illegal_callback.
##

proc secp256k1_context_set_error_callback*(ctx: ptr secp256k1_context;
    fun: proc (message: ConstCstring; data: pointer) {.secp.}; data: pointer) {.secp,
    importc: "secp256k1_context_set_error_callback".}
## * A pointer to a function implementing SHA256's internal compression function.
##
##  This function processes one or more contiguous 64-byte message blocks and
##  updates the internal SHA256 state accordingly. The function is not responsible
##  for counting consumed blocks or bytes, nor for performing padding.
##
##  In/Out:  state:     pointer to eight 32-bit words representing the current internal state;
##                      the state is updated in place.
##  In:      blocks64:  pointer to concatenation of n_blocks blocks, of 64 bytes each.
##                      no alignment guarantees are made for this pointer.
##           n_blocks:  number of contiguous 64-byte blocks to process.
##

type
  secp256k1_sha256_compression_function* = proc (state: ptr uint32;
      blocks64: ConstPtrByte; n_blocks: csize_t) {.secp.}

## *
##  Set a callback function to override the internal SHA256 compression function.
##
##  This installs a callback to replace the built-in block-compression
##  step used by the library's internal SHA256 implementation.
##  The provided callback must exactly implement the effect of n_blocks
##  repeated applications of the SHA256 compression function.
##
##  This API exists to support environments that wish to route the
##  SHA256 compression step through a hardware-accelerated or otherwise
##  specialized implementation. It is NOT meant for replacing SHA256
##  with a different hash function.
##
##  Since auxiliary functions exposed by the library via a function
##  pointer such as secp256k1_nonce_function_default do not take a
##  context object, they will not use the callback when called directly
##  from user code. (But they will use the callback when called from
##  other library functions that do take a context object, e.g., when
##  noncefp==NULL or noncefp==secp256k1_nonce_function_default is passed
##  as an argument to secp256k1_ecdsa_sign.)
##
##  Note: The provided function is tested against a set of known SHA256
##  digests; invokes the context's illegal callback on any mismatch
##  (which aborts by default), in order to catch basic misbehavior early.
##  It takes well under 2.5 ms on a desktop machine.
##  This is NOT a substitute for having proper test coverage of the
##  supplied function outside this library.
##
##  Args:    ctx:             pointer to a context object.
##  In:      fn_compression:  pointer to a function implementing the compression function;
##                            passing NULL restores the default implementation.
##

proc secp256k1_context_set_sha256_compression*(ctx: ptr secp256k1_context;
    fn_compression: secp256k1_sha256_compression_function) {.secp,
    importc: "secp256k1_context_set_sha256_compression".}
## * Parse a variable-length public key into the pubkey object.
##
##   Returns: 1 if the public key was fully valid.
##            0 if the public key could not be parsed or is invalid.
##   Args: ctx:      pointer to a context object.
##   Out:  pubkey:   pointer to a pubkey object. If 1 is returned, it is set to a
##                   parsed version of input. If not, its value is undefined.
##   In:   input:    pointer to a serialized public key
##         inputlen: length of the array pointed to by input
##
##   This function supports parsing compressed (33 bytes, header byte 0x02 or
##   0x03), uncompressed (65 bytes, header byte 0x04), or hybrid (65 bytes, header
##   byte 0x06 or 0x07) format public keys.
##

proc secp256k1_ec_pubkey_parse*(ctx: ptr secp256k1_context;
                               pubkey: ptr secp256k1_pubkey; input: ConstPtrByte;
                               inputlen: csize_t): cint {.secp,
    importc: "secp256k1_ec_pubkey_parse".}
## * Serialize a pubkey object into a serialized byte sequence.
##
##   Returns: 1 always.
##   Args:   ctx:        pointer to a context object.
##   Out:    output:     pointer to a 65-byte (if compressed==0) or 33-byte (if
##                       compressed==1) byte array to place the serialized key
##                       in.
##   In/Out: outputlen:  pointer to an integer which is initially set to the
##                       size of output, and is overwritten with the written
##                       size.
##   In:     pubkey:     pointer to a secp256k1_pubkey containing an
##                       initialized public key.
##           flags:      SECP256K1_EC_COMPRESSED if serialization should be in
##                       compressed format, otherwise SECP256K1_EC_UNCOMPRESSED.
##

proc secp256k1_ec_pubkey_serialize*(ctx: ptr secp256k1_context; output: ptr byte;
                                   outputlen: ptr csize_t;
                                   pubkey: ptr secp256k1_pubkey; flags: cuint): cint {.
    secp, importc: "secp256k1_ec_pubkey_serialize".}
## * Compare two public keys using lexicographic (of compressed serialization) order
##
##   Returns: <0 if the first public key is less than the second
##            >0 if the first public key is greater than the second
##            0 if the two public keys are equal
##   Args: ctx:      pointer to a context object
##   In:   pubkey1:  first public key to compare
##         pubkey2:  second public key to compare
##

proc secp256k1_ec_pubkey_cmp*(ctx: ptr secp256k1_context;
                             pubkey1: ptr secp256k1_pubkey;
                             pubkey2: ptr secp256k1_pubkey): cint {.secp,
    importc: "secp256k1_ec_pubkey_cmp".}
## * Sort public keys using lexicographic (of compressed serialization) order
##
##   Returns: 0 if the arguments are invalid. 1 otherwise.
##
##   Args:     ctx: pointer to a context object
##   In:   pubkeys: array of pointers to pubkeys to sort
##       n_pubkeys: number of elements in the pubkeys array
##

proc secp256k1_ec_pubkey_sort*(ctx: ptr secp256k1_context;
                              pubkeys: ptr ptr secp256k1_pubkey; n_pubkeys: csize_t): cint {.
    secp, importc: "secp256k1_ec_pubkey_sort".}
## * Parse an ECDSA signature in compact (64 bytes) format.
##
##   Returns: 1 when the signature could be parsed, 0 otherwise.
##   Args: ctx:      pointer to a context object
##   Out:  sig:      pointer to a signature object
##   In:   input64:  pointer to the 64-byte array to parse
##
##   The signature must consist of a 32-byte big endian R value, followed by a
##   32-byte big endian S value. If R or S fall outside of [0..order-1], the
##   encoding is invalid. R and S with value 0 are allowed in the encoding.
##
##   After the call, sig will always be initialized. If parsing failed or R or
##   S are zero, the resulting sig value is guaranteed to fail verification for
##   any message and public key.
##

proc secp256k1_ecdsa_signature_parse_compact*(ctx: ptr secp256k1_context;
    sig: ptr secp256k1_ecdsa_signature; input64: ConstPtrByte): cint {.secp,
    importc: "secp256k1_ecdsa_signature_parse_compact".}
## * Parse a DER ECDSA signature.
##
##   Returns: 1 when the signature could be parsed, 0 otherwise.
##   Args: ctx:      pointer to a context object
##   Out:  sig:      pointer to a signature object
##   In:   input:    pointer to the signature to be parsed
##         inputlen: the length of the array pointed to be input
##
##   This function will accept any valid DER encoded signature, even if the
##   encoded numbers are out of range.
##
##   After the call, sig will always be initialized. If parsing failed or the
##   encoded numbers are out of range, signature verification with it is
##   guaranteed to fail for every message and public key.
##

proc secp256k1_ecdsa_signature_parse_der*(ctx: ptr secp256k1_context;
    sig: ptr secp256k1_ecdsa_signature; input: ConstPtrByte; inputlen: csize_t): cint {.
    secp, importc: "secp256k1_ecdsa_signature_parse_der".}
## * Serialize an ECDSA signature in DER format.
##
##   Returns: 1 if enough space was available to serialize, 0 otherwise
##   Args:   ctx:       pointer to a context object
##   Out:    output:    pointer to an array to store the DER serialization
##   In/Out: outputlen: pointer to a length integer. Initially, this integer
##                      should be set to the length of output. After the call
##                      it will be set to the length of the serialization (even
##                      if 0 was returned).
##   In:     sig:       pointer to an initialized signature object
##

proc secp256k1_ecdsa_signature_serialize_der*(ctx: ptr secp256k1_context;
    output: ptr byte; outputlen: ptr csize_t; sig: ptr secp256k1_ecdsa_signature): cint {.
    secp, importc: "secp256k1_ecdsa_signature_serialize_der".}
## * Serialize an ECDSA signature in compact (64 byte) format.
##
##   Returns: 1
##   Args:   ctx:       pointer to a context object
##   Out:    output64:  pointer to a 64-byte array to store the compact serialization
##   In:     sig:       pointer to an initialized signature object
##
##   See secp256k1_ecdsa_signature_parse_compact for details about the encoding.
##

proc secp256k1_ecdsa_signature_serialize_compact*(ctx: ptr secp256k1_context;
    output64: ptr byte; sig: ptr secp256k1_ecdsa_signature): cint {.secp,
    importc: "secp256k1_ecdsa_signature_serialize_compact".}
## * Verify an ECDSA signature.
##
##   Returns: 1: correct signature
##            0: incorrect or unparseable signature
##   Args:    ctx:       pointer to a context object
##   In:      sig:       the signature being verified.
##            msghash32: the 32-byte message hash being verified.
##                       The verifier must make sure to apply a cryptographic
##                       hash function to the message by itself and not accept an
##                       msghash32 value directly. Otherwise, it would be easy to
##                       create a "valid" signature without knowledge of the
##                       secret key. See also
##                       https://bitcoin.stackexchange.com/a/81116/35586 for more
##                       background on this topic.
##            pubkey:    pointer to an initialized public key to verify with.
##
##  To avoid accepting malleable signatures, only ECDSA signatures in lower-S
##  form are accepted.
##
##  If you need to accept ECDSA signatures from sources that do not obey this
##  rule, apply secp256k1_ecdsa_signature_normalize to the signature prior to
##  verification, but be aware that doing so results in malleable signatures.
##
##  For details, see the comments for that function.
##

proc secp256k1_ecdsa_verify*(ctx: ptr secp256k1_context;
                            sig: ptr secp256k1_ecdsa_signature;
                            msghash32: ConstPtrByte; pubkey: ptr secp256k1_pubkey): cint {.
    secp, importc: "secp256k1_ecdsa_verify".}
## * Convert a signature to a normalized lower-S form.
##
##   Returns: 1 if sigin was not normalized, 0 if it already was.
##   Args: ctx:    pointer to a context object
##   Out:  sigout: pointer to a signature to fill with the normalized form,
##                 or copy if the input was already normalized. (can be NULL if
##                 you're only interested in whether the input was already
##                 normalized).
##   In:   sigin:  pointer to a signature to check/normalize (can be identical to sigout)
##
##   With ECDSA a third-party can forge a second distinct signature of the same
##   message, given a single initial signature, but without knowing the key. This
##   is done by negating the S value modulo the order of the curve, 'flipping'
##   the sign of the random point R which is not included in the signature.
##
##   Forgery of the same message isn't universally problematic, but in systems
##   where message malleability or uniqueness of signatures is important this can
##   cause issues. This forgery can be blocked by all verifiers forcing signers
##   to use a normalized form.
##
##   The lower-S form reduces the size of signatures slightly on average when
##   variable length encodings (such as DER) are used and is cheap to verify,
##   making it a good choice. Security of always using lower-S is assured because
##   anyone can trivially modify a signature after the fact to enforce this
##   property anyway.
##
##   The lower S value is always between 0x1 and
##   0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0,
##   inclusive.
##
##   No other forms of ECDSA malleability are known and none seem likely, but
##   there is no formal proof that ECDSA, even with this additional restriction,
##   is free of other malleability. Commonly used serialization schemes will also
##   accept various non-unique encodings, so care should be taken when this
##   property is required for an application.
##
##   The secp256k1_ecdsa_sign function will by default create signatures in the
##   lower-S form, and secp256k1_ecdsa_verify will not accept others. In case
##   signatures come from a system that cannot enforce this property,
##   secp256k1_ecdsa_signature_normalize must be called before verification.
##

proc secp256k1_ecdsa_signature_normalize*(ctx: ptr secp256k1_context;
    sigout: ptr secp256k1_ecdsa_signature; sigin: ptr secp256k1_ecdsa_signature): cint {.
    secp, importc: "secp256k1_ecdsa_signature_normalize".}
## * An implementation of RFC6979 (using HMAC-SHA256) as nonce generation function.
##  If a data pointer is passed, it is assumed to be a pointer to 32 bytes of
##  extra entropy.
##

var secp256k1_nonce_function_rfc6979_imp {.importc: "secp256k1_nonce_function_rfc6979".}: secp256k1_nonce_function

template secp256k1_nonce_function_rfc6979*: secp256k1_nonce_function =
  {.noSideEffect.}:
    secp256k1_nonce_function_rfc6979_imp

## * A default safe nonce generation function (currently equal to secp256k1_nonce_function_rfc6979).

var secp256k1_nonce_function_default_imp {.importc: "secp256k1_nonce_function_default".}: secp256k1_nonce_function

template secp256k1_nonce_function_default*: secp256k1_nonce_function =
  {.noSideEffect.}:
    secp256k1_nonce_function_default_imp

## * Create an ECDSA signature.
##
##   Returns: 1: signature created
##            0: the nonce generation function failed, or the secret key was invalid.
##   Args:    ctx:       pointer to a context object (not secp256k1_context_static).
##   Out:     sig:       pointer to a signature object.
##   In:      msghash32: the 32-byte message hash being signed.
##            seckey:    pointer to a 32-byte secret key.
##            noncefp:   pointer to a nonce generation function. If NULL,
##                       secp256k1_nonce_function_default is used.
##            ndata:     pointer to arbitrary data used by the nonce generation function
##                       (can be NULL). If it is non-NULL and
##                       secp256k1_nonce_function_default is used, then ndata must be a
##                       pointer to 32-bytes of additional data.
##
##  The created signature is always in lower-S form. See
##  secp256k1_ecdsa_signature_normalize for more details.
##

proc secp256k1_ecdsa_sign*(ctx: ptr secp256k1_context;
                          sig: ptr secp256k1_ecdsa_signature;
                          msghash32: ConstPtrByte; seckey: ConstPtrByte;
                          noncefp: secp256k1_nonce_function; ndata: pointer): cint {.
    secp, importc: "secp256k1_ecdsa_sign".}
## * Verify an elliptic curve secret key.
##
##   A secret key is valid if it is not 0 and less than the secp256k1 curve order
##   when interpreted as an integer (most significant byte first). The
##   probability of choosing a 32-byte string uniformly at random which is an
##   invalid secret key is negligible. However, if it does happen it should
##   be assumed that the randomness source is severely broken and there should
##   be no retry.
##
##   Returns: 1: secret key is valid
##            0: secret key is invalid
##   Args:    ctx: pointer to a context object.
##   In:      seckey: pointer to a 32-byte secret key.
##

proc secp256k1_ec_seckey_verify*(ctx: ptr secp256k1_context; seckey: ConstPtrByte): cint {.
    secp, importc: "secp256k1_ec_seckey_verify".}
## * Compute the public key for a secret key.
##
##   Returns: 1: secret was valid, public key stores.
##            0: secret was invalid, try again.
##   Args:    ctx:    pointer to a context object (not secp256k1_context_static).
##   Out:     pubkey: pointer to the created public key.
##   In:      seckey: pointer to a 32-byte secret key.
##

proc secp256k1_ec_pubkey_create*(ctx: ptr secp256k1_context;
                                pubkey: ptr secp256k1_pubkey; seckey: ConstPtrByte): cint {.
    secp, importc: "secp256k1_ec_pubkey_create".}
## * Negates a secret key in place.
##
##   Returns: 0 if the given secret key is invalid according to
##            secp256k1_ec_seckey_verify. 1 otherwise
##   Args:   ctx:    pointer to a context object
##   In/Out: seckey: pointer to the 32-byte secret key to be negated. If the
##                   secret key is invalid according to
##                   secp256k1_ec_seckey_verify, this function returns 0 and
##                   seckey will be set to some unspecified value.
##

proc secp256k1_ec_seckey_negate*(ctx: ptr secp256k1_context; seckey: ptr byte): cint {.
    secp, importc: "secp256k1_ec_seckey_negate".}
## * Negates a public key in place.
##
##   Returns: 1 always
##   Args:   ctx:        pointer to a context object
##   In/Out: pubkey:     pointer to the public key to be negated.
##

proc secp256k1_ec_pubkey_negate*(ctx: ptr secp256k1_context;
                                pubkey: ptr secp256k1_pubkey): cint {.secp,
    importc: "secp256k1_ec_pubkey_negate".}
## * Tweak a secret key by adding tweak to it.
##
##   Returns: 0 if the arguments are invalid or the resulting secret key would be
##            invalid (only when the tweak is the negation of the secret key). 1
##            otherwise.
##   Args:    ctx:   pointer to a context object.
##   In/Out: seckey: pointer to a 32-byte secret key. If the secret key is
##                   invalid according to secp256k1_ec_seckey_verify, this
##                   function returns 0. seckey will be set to some unspecified
##                   value if this function returns 0.
##   In:    tweak32: pointer to a 32-byte tweak, which must be valid according to
##                   secp256k1_ec_seckey_verify or 32 zero bytes. For uniformly
##                   random 32-byte tweaks, the chance of being invalid is
##                   negligible (around 1 in 2^128).
##

proc secp256k1_ec_seckey_tweak_add*(ctx: ptr secp256k1_context; seckey: ptr byte;
                                   tweak32: ConstPtrByte): cint {.secp,
    importc: "secp256k1_ec_seckey_tweak_add".}
## * Tweak a public key by adding tweak times the generator to it.
##
##   Returns: 0 if the arguments are invalid or the resulting public key would be
##            invalid (only when the tweak is the negation of the corresponding
##            secret key). 1 otherwise.
##   Args:    ctx:   pointer to a context object.
##   In/Out: pubkey: pointer to a public key object. pubkey will be set to an
##                   invalid value if this function returns 0.
##   In:    tweak32: pointer to a 32-byte tweak, which must be valid according to
##                   secp256k1_ec_seckey_verify or 32 zero bytes. For uniformly
##                   random 32-byte tweaks, the chance of being invalid is
##                   negligible (around 1 in 2^128).
##

proc secp256k1_ec_pubkey_tweak_add*(ctx: ptr secp256k1_context;
                                   pubkey: ptr secp256k1_pubkey;
                                   tweak32: ConstPtrByte): cint {.secp,
    importc: "secp256k1_ec_pubkey_tweak_add".}
## * Tweak a secret key by multiplying it by a tweak.
##
##   Returns: 0 if the arguments are invalid. 1 otherwise.
##   Args:   ctx:    pointer to a context object.
##   In/Out: seckey: pointer to a 32-byte secret key. If the secret key is
##                   invalid according to secp256k1_ec_seckey_verify, this
##                   function returns 0. seckey will be set to some unspecified
##                   value if this function returns 0.
##   In:    tweak32: pointer to a 32-byte tweak. If the tweak is invalid according to
##                   secp256k1_ec_seckey_verify, this function returns 0. For
##                   uniformly random 32-byte arrays the chance of being invalid
##                   is negligible (around 1 in 2^128).
##

proc secp256k1_ec_seckey_tweak_mul*(ctx: ptr secp256k1_context; seckey: ptr byte;
                                   tweak32: ConstPtrByte): cint {.secp,
    importc: "secp256k1_ec_seckey_tweak_mul".}
## * Tweak a public key by multiplying it by a tweak value.
##
##   Returns: 0 if the arguments are invalid. 1 otherwise.
##   Args:    ctx:   pointer to a context object.
##   In/Out: pubkey: pointer to a public key object. pubkey will be set to an
##                   invalid value if this function returns 0.
##   In:    tweak32: pointer to a 32-byte tweak. If the tweak is invalid according to
##                   secp256k1_ec_seckey_verify, this function returns 0. For
##                   uniformly random 32-byte arrays the chance of being invalid
##                   is negligible (around 1 in 2^128).
##

proc secp256k1_ec_pubkey_tweak_mul*(ctx: ptr secp256k1_context;
                                   pubkey: ptr secp256k1_pubkey;
                                   tweak32: ConstPtrByte): cint {.secp,
    importc: "secp256k1_ec_pubkey_tweak_mul".}
## * Randomizes the context to provide enhanced protection against side-channel leakage.
##
##   Returns: 1: randomization successful
##            0: error
##   Args:    ctx:       pointer to a context object (not secp256k1_context_static).
##   In:      seed32:    pointer to a 32-byte random seed (NULL resets to initial state).
##
##  While secp256k1 code is written and tested to be constant-time no matter what
##  secret values are, it is possible that a compiler may output code which is not,
##  and also that the CPU may not emit the same radio frequencies or draw the same
##  amount of power for all values. Randomization of the context shields against
##  side-channel observations which aim to exploit secret-dependent behaviour in
##  certain computations which involve secret keys.
##
##  It is highly recommended to call this function on contexts returned from
##  secp256k1_context_create or secp256k1_context_clone (or from the corresponding
##  functions in secp256k1_preallocated.h) before using these contexts to call API
##  functions that perform computations involving secret keys, e.g., signing and
##  public key generation. It is possible to call this function more than once on
##  the same context, and doing so before every few computations involving secret
##  keys is recommended as a defense-in-depth measure. Randomization of the static
##  context secp256k1_context_static is not supported.
##
##  Currently, the random seed is mainly used for blinding multiplications of a
##  secret scalar with the elliptic curve base point. Multiplications of this
##  kind are performed by exactly those API functions which are documented to
##  require a context that is not secp256k1_context_static. As a rule of thumb,
##  these are all functions which take a secret key (or a keypair) as an input.
##  A notable exception to that rule is the ECDH module, which relies on a different
##  kind of elliptic curve point multiplication and thus does not benefit from
##  enhanced protection against side-channel leakage currently.
##

proc secp256k1_context_randomize*(ctx: ptr secp256k1_context; seed32: ConstPtrByte): cint {.
    secp, importc: "secp256k1_context_randomize".}
## * Add a number of public keys together.
##
##   Returns: 1: the sum of the public keys is valid.
##            0: the sum of the public keys is not valid.
##   Args:   ctx:        pointer to a context object.
##   Out:    out:        pointer to a public key object for placing the resulting public key.
##   In:     ins:        pointer to array of pointers to public keys.
##           n:          the number of public keys to add together (must be at least 1).
##

proc secp256k1_ec_pubkey_combine*(ctx: ptr secp256k1_context;
                                 `out`: ptr secp256k1_pubkey;
                                 ins: ptr ptr secp256k1_pubkey; n: csize_t): cint {.
    secp, importc: "secp256k1_ec_pubkey_combine".}
## * Compute a tagged hash as defined in BIP-340.
##
##   This is useful for creating a message hash and achieving domain separation
##   through an application-specific tag. This function returns
##   SHA256(SHA256(tag)||SHA256(tag)||msg). Therefore, tagged hash
##   implementations optimized for a specific tag can precompute the SHA256 state
##   after hashing the tag hashes.
##
##   Returns: 1 always.
##   Args:    ctx: pointer to a context object
##   Out:  hash32: pointer to a 32-byte array to store the resulting hash
##   In:      tag: pointer to an array containing the tag
##         taglen: length of the tag array
##            msg: pointer to an array containing the message
##         msglen: length of the message array
##

proc secp256k1_tagged_sha256*(ctx: ptr secp256k1_context; hash32: ptr byte;
                             tag: ConstPtrByte; taglen: csize_t; msg: ConstPtrByte;
                             msglen: csize_t): cint {.secp,
    importc: "secp256k1_tagged_sha256".}
## * A pointer to a function that hashes an EC point to obtain an ECDH secret
##
##   Returns: 1 if the point was successfully hashed.
##            0 will cause secp256k1_ecdh to fail and return 0.
##            Other return values are not allowed, and the behaviour of
##            secp256k1_ecdh is undefined for other return values.
##   Out:     output:     pointer to an array to be filled by the function
##   In:      x32:        pointer to a 32-byte x coordinate
##            y32:        pointer to a 32-byte y coordinate
##            data:       arbitrary data pointer that is passed through
##

type
  secp256k1_ecdh_hash_function* = proc (output: ptr byte; x32: ConstPtrByte;
                                     y32: ConstPtrByte; data: pointer): cint {.secp.}

## * An implementation of SHA256 hash function that applies to compressed public key.
##  Populates the output parameter with 32 bytes.

var secp256k1_ecdh_hash_function_sha256_imp {.importc: "secp256k1_ecdh_hash_function_sha256".}: secp256k1_ecdh_hash_function

template secp256k1_ecdh_hash_function_sha256*: secp256k1_ecdh_hash_function =
  {.noSideEffect.}:
    secp256k1_ecdh_hash_function_sha256_imp

## * A default ECDH hash function (currently equal to secp256k1_ecdh_hash_function_sha256).
##  Populates the output parameter with 32 bytes.

var secp256k1_ecdh_hash_function_default_imp {.importc: "secp256k1_ecdh_hash_function_default".}: secp256k1_ecdh_hash_function

template secp256k1_ecdh_hash_function_default*: secp256k1_ecdh_hash_function =
  {.noSideEffect.}:
    secp256k1_ecdh_hash_function_default_imp

## * Compute an EC Diffie-Hellman secret in constant time
##
##   Returns: 1: exponentiation was successful
##            0: scalar was invalid (zero or overflow) or hashfp returned 0
##   Args:    ctx:        pointer to a context object.
##   Out:     output:     pointer to an array to be filled by hashfp.
##   In:      pubkey:     pointer to a secp256k1_pubkey containing an initialized public key.
##            seckey:     a 32-byte scalar with which to multiply the point.
##            hashfp:     pointer to a hash function. If NULL,
##                        secp256k1_ecdh_hash_function_sha256 is used
##                        (in which case, 32 bytes will be written to output).
##            data:       arbitrary data pointer that is passed through to hashfp
##                        (can be NULL for secp256k1_ecdh_hash_function_sha256).
##

proc secp256k1_ecdh*(ctx: ptr secp256k1_context; output: ptr byte;
                    pubkey: ptr secp256k1_pubkey; seckey: ConstPtrByte;
                    hashfp: secp256k1_ecdh_hash_function; data: pointer): cint {.
    secp, importc: "secp256k1_ecdh".}
## * Opaque data structure that holds a parsed ECDSA signature,
##   supporting pubkey recovery.
##
##   The exact representation of data inside is implementation defined and not
##   guaranteed to be portable between different platforms or versions. It is
##   however guaranteed to be 65 bytes in size, and can be safely copied/moved.
##   If you need to convert to a format suitable for storage or transmission, use
##   the secp256k1_ecdsa_signature_serialize_* and
##   secp256k1_ecdsa_signature_parse_* functions.
##
##   Furthermore, it is guaranteed that identical signatures (including their
##   recoverability) will have identical representation, so they can be
##   memcmp'ed.
##

type
  secp256k1_ecdsa_recoverable_signature* {.bycopy.} = object
    data*: array[65, byte]


## * Parse a compact ECDSA signature (64 bytes + recovery id).
##
##   Returns: 1 when the signature could be parsed, 0 otherwise
##   Args: ctx:     pointer to a context object
##   Out:  sig:     pointer to a signature object
##   In:   input64: pointer to a 64-byte compact signature
##         recid:   the recovery id (0, 1, 2 or 3)
##

proc secp256k1_ecdsa_recoverable_signature_parse_compact*(
    ctx: ptr secp256k1_context; sig: ptr secp256k1_ecdsa_recoverable_signature;
    input64: ConstPtrByte; recid: cint): cint {.secp,
    importc: "secp256k1_ecdsa_recoverable_signature_parse_compact".}
## * Convert a recoverable signature into a normal signature.
##
##   Returns: 1
##   Args: ctx:    pointer to a context object.
##   Out:  sig:    pointer to a normal signature.
##   In:   sigin:  pointer to a recoverable signature.
##

proc secp256k1_ecdsa_recoverable_signature_convert*(ctx: ptr secp256k1_context;
    sig: ptr secp256k1_ecdsa_signature;
    sigin: ptr secp256k1_ecdsa_recoverable_signature): cint {.secp,
    importc: "secp256k1_ecdsa_recoverable_signature_convert".}
## * Serialize an ECDSA signature in compact format (64 bytes + recovery id).
##
##   Returns: 1
##   Args: ctx:      pointer to a context object.
##   Out:  output64: pointer to a 64-byte array of the compact signature.
##         recid:    pointer to an integer to hold the recovery id.
##   In:   sig:      pointer to an initialized signature object.
##

proc secp256k1_ecdsa_recoverable_signature_serialize_compact*(
    ctx: ptr secp256k1_context; output64: ptr byte; recid: ptr cint;
    sig: ptr secp256k1_ecdsa_recoverable_signature): cint {.secp,
    importc: "secp256k1_ecdsa_recoverable_signature_serialize_compact".}
## * Create a recoverable ECDSA signature.
##
##   Returns: 1: signature created
##            0: the nonce generation function failed, or the secret key was invalid.
##   Args:    ctx:       pointer to a context object (not secp256k1_context_static).
##   Out:     sig:       pointer to a signature object.
##   In:      msghash32: the 32-byte message hash being signed.
##            seckey:    pointer to a 32-byte secret key.
##            noncefp:   pointer to a nonce generation function. If NULL,
##                       secp256k1_nonce_function_default is used.
##            ndata:     pointer to arbitrary data used by the nonce generation function
##                       (can be NULL for secp256k1_nonce_function_default).
##

proc secp256k1_ecdsa_sign_recoverable*(ctx: ptr secp256k1_context; sig: ptr secp256k1_ecdsa_recoverable_signature;
                                      msghash32: ConstPtrByte;
                                      seckey: ConstPtrByte;
                                      noncefp: secp256k1_nonce_function;
                                      ndata: pointer): cint {.secp,
    importc: "secp256k1_ecdsa_sign_recoverable".}
## * Recover an ECDSA public key from a signature.
##
##   Successful public key recovery guarantees that the signature, after normalization,
##   passes `secp256k1_ecdsa_verify`. Thus, explicit verification is not necessary.
##
##   However, a recoverable signature that successfully passes `secp256k1_ecdsa_recover`,
##   when converted to a non-recoverable signature (using
##   `secp256k1_ecdsa_recoverable_signature_convert`), is not guaranteed to be
##   normalized and thus not guaranteed to pass `secp256k1_ecdsa_verify`. If a
##   normalized signature is required, call `secp256k1_ecdsa_signature_normalize`
##   after `secp256k1_ecdsa_recoverable_signature_convert`.
##
##   Returns: 1: public key successfully recovered
##            0: otherwise.
##   Args:    ctx:       pointer to a context object.
##   Out:     pubkey:    pointer to the recovered public key.
##   In:      sig:       pointer to initialized signature that supports pubkey recovery.
##            msghash32: the 32-byte message hash assumed to be signed.
##

proc secp256k1_ecdsa_recover*(ctx: ptr secp256k1_context;
                             pubkey: ptr secp256k1_pubkey;
                             sig: ptr secp256k1_ecdsa_recoverable_signature;
                             msghash32: ConstPtrByte): cint {.secp,
    importc: "secp256k1_ecdsa_recover".}
## * Opaque data structure that holds a parsed and valid "x-only" public key.
##   An x-only pubkey encodes a point whose Y coordinate is even. It is
##   serialized using only its X coordinate (32 bytes). See BIP-340 for more
##   information about x-only pubkeys.
##
##   The exact representation of data inside is implementation defined and not
##   guaranteed to be portable between different platforms or versions. It is
##   however guaranteed to be 64 bytes in size, and can be safely copied/moved.
##   If you need to convert to a format suitable for storage, transmission, use
##   use secp256k1_xonly_pubkey_serialize and secp256k1_xonly_pubkey_parse. To
##   compare keys, use secp256k1_xonly_pubkey_cmp.
##

type
  secp256k1_xonly_pubkey* {.bycopy.} = object
    data*: array[64, byte]


## * Opaque data structure that holds a keypair consisting of a secret and a
##   public key.
##
##   The exact representation of data inside is implementation defined and not
##   guaranteed to be portable between different platforms or versions. It is
##   however guaranteed to be 96 bytes in size, and can be safely copied/moved.
##

type
  secp256k1_keypair* {.bycopy.} = object
    data*: array[96, byte]


## * Parse a 32-byte sequence into a xonly_pubkey object.
##
##   Returns: 1 if the public key was fully valid.
##            0 if the public key could not be parsed or is invalid.
##
##   Args:   ctx: pointer to a context object.
##   Out: pubkey: pointer to a pubkey object. If 1 is returned, it is set to a
##                parsed version of input. If not, it's set to an invalid value.
##   In: input32: pointer to a serialized xonly_pubkey.
##

proc secp256k1_xonly_pubkey_parse*(ctx: ptr secp256k1_context;
                                  pubkey: ptr secp256k1_xonly_pubkey;
                                  input32: ConstPtrByte): cint {.secp,
    importc: "secp256k1_xonly_pubkey_parse".}
## * Serialize an xonly_pubkey object into a 32-byte sequence.
##
##   Returns: 1 always.
##
##   Args:     ctx: pointer to a context object.
##   Out: output32: pointer to a 32-byte array to place the serialized key in.
##   In:    pubkey: pointer to a secp256k1_xonly_pubkey containing an initialized public key.
##

proc secp256k1_xonly_pubkey_serialize*(ctx: ptr secp256k1_context;
                                      output32: ptr byte;
                                      pubkey: ptr secp256k1_xonly_pubkey): cint {.
    secp, importc: "secp256k1_xonly_pubkey_serialize".}
## * Compare two x-only public keys using lexicographic order
##
##   Returns: <0 if the first public key is less than the second
##            >0 if the first public key is greater than the second
##            0 if the two public keys are equal
##   Args: ctx:      pointer to a context object.
##   In:   pubkey1:  first public key to compare
##         pubkey2:  second public key to compare
##

proc secp256k1_xonly_pubkey_cmp*(ctx: ptr secp256k1_context;
                                pk1: ptr secp256k1_xonly_pubkey;
                                pk2: ptr secp256k1_xonly_pubkey): cint {.secp,
    importc: "secp256k1_xonly_pubkey_cmp".}
## * Converts a secp256k1_pubkey into a secp256k1_xonly_pubkey.
##
##   Returns: 1 always.
##
##   Args:         ctx: pointer to a context object.
##   Out: xonly_pubkey: pointer to an x-only public key object for placing the converted public key.
##           pk_parity: Ignored if NULL. Otherwise, pointer to an integer that
##                      will be set to 1 if the point encoded by xonly_pubkey is
##                      the negation of the pubkey and set to 0 otherwise.
##   In:        pubkey: pointer to a public key that is converted.
##

proc secp256k1_xonly_pubkey_from_pubkey*(ctx: ptr secp256k1_context; xonly_pubkey: ptr secp256k1_xonly_pubkey;
                                        pk_parity: ptr cint;
                                        pubkey: ptr secp256k1_pubkey): cint {.secp,
    importc: "secp256k1_xonly_pubkey_from_pubkey".}
## * Tweak an x-only public key by adding the generator multiplied with tweak32
##   to it.
##
##   Note that the resulting point can not in general be represented by an x-only
##   pubkey because it may have an odd Y coordinate. Instead, the output_pubkey
##   is a normal secp256k1_pubkey.
##
##   Returns: 0 if the arguments are invalid or the resulting public key would be
##            invalid (only when the tweak is the negation of the corresponding
##            secret key). 1 otherwise.
##
##   Args:           ctx: pointer to a context object.
##   Out:  output_pubkey: pointer to a public key to store the result. Will be set
##                        to an invalid value if this function returns 0.
##   In: internal_pubkey: pointer to an x-only pubkey to apply the tweak to.
##               tweak32: pointer to a 32-byte tweak, which must be valid
##                        according to secp256k1_ec_seckey_verify or 32 zero
##                        bytes. For uniformly random 32-byte tweaks, the chance of
##                        being invalid is negligible (around 1 in 2^128).
##

proc secp256k1_xonly_pubkey_tweak_add*(ctx: ptr secp256k1_context;
                                      output_pubkey: ptr secp256k1_pubkey;
    internal_pubkey: ptr secp256k1_xonly_pubkey; tweak32: ConstPtrByte): cint {.secp,
    importc: "secp256k1_xonly_pubkey_tweak_add".}
## * Checks that a tweaked pubkey is the result of calling
##   secp256k1_xonly_pubkey_tweak_add with internal_pubkey and tweak32.
##
##   The tweaked pubkey is represented by its 32-byte x-only serialization and
##   its pk_parity, which can both be obtained by converting the result of
##   tweak_add to a secp256k1_xonly_pubkey.
##
##   Note that this alone does _not_ verify that the tweaked pubkey is a
##   commitment. If the tweak is not chosen in a specific way, the tweaked pubkey
##   can easily be the result of a different internal_pubkey and tweak.
##
##   Returns: 0 if the arguments are invalid or the tweaked pubkey is not the
##            result of tweaking the internal_pubkey with tweak32. 1 otherwise.
##   Args:            ctx: pointer to a context object.
##   In: tweaked_pubkey32: pointer to a serialized xonly_pubkey.
##      tweaked_pk_parity: the parity of the tweaked pubkey (whose serialization
##                         is passed in as tweaked_pubkey32). This must match the
##                         pk_parity value that is returned when calling
##                         secp256k1_xonly_pubkey with the tweaked pubkey, or
##                         this function will fail.
##        internal_pubkey: pointer to an x-only public key object to apply the tweak to.
##                tweak32: pointer to a 32-byte tweak.
##

proc secp256k1_xonly_pubkey_tweak_add_check*(ctx: ptr secp256k1_context;
    tweaked_pubkey32: ConstPtrByte; tweaked_pk_parity: cint;
    internal_pubkey: ptr secp256k1_xonly_pubkey; tweak32: ConstPtrByte): cint {.secp,
    importc: "secp256k1_xonly_pubkey_tweak_add_check".}
## * Compute the keypair for a valid secret key.
##
##   See the documentation of `secp256k1_ec_seckey_verify` for more information
##   about the validity of secret keys.
##
##   Returns: 1: secret key is valid
##            0: secret key is invalid
##   Args:    ctx: pointer to a context object (not secp256k1_context_static).
##   Out: keypair: pointer to the created keypair.
##   In:   seckey: pointer to a 32-byte secret key.
##

proc secp256k1_keypair_create*(ctx: ptr secp256k1_context;
                              keypair: ptr secp256k1_keypair; seckey: ConstPtrByte): cint {.
    secp, importc: "secp256k1_keypair_create".}
## * Get the secret key from a keypair.
##
##   Returns: 1 always.
##   Args:   ctx: pointer to a context object.
##   Out: seckey: pointer to a 32-byte buffer for the secret key.
##   In: keypair: pointer to a keypair.
##

proc secp256k1_keypair_sec*(ctx: ptr secp256k1_context; seckey: ptr byte;
                           keypair: ptr secp256k1_keypair): cint {.secp,
    importc: "secp256k1_keypair_sec".}
## * Get the public key from a keypair.
##
##   Returns: 1 always.
##   Args:   ctx: pointer to a context object.
##   Out: pubkey: pointer to a pubkey object, set to the keypair public key.
##   In: keypair: pointer to a keypair.
##

proc secp256k1_keypair_pub*(ctx: ptr secp256k1_context;
                           pubkey: ptr secp256k1_pubkey;
                           keypair: ptr secp256k1_keypair): cint {.secp,
    importc: "secp256k1_keypair_pub".}
## * Get the x-only public key from a keypair.
##
##   This is the same as calling secp256k1_keypair_pub and then
##   secp256k1_xonly_pubkey_from_pubkey.
##
##   Returns: 1 always.
##   Args:   ctx: pointer to a context object.
##   Out: pubkey: pointer to an xonly_pubkey object, set to the keypair
##                public key after converting it to an xonly_pubkey.
##     pk_parity: Ignored if NULL. Otherwise, pointer to an integer that will be set to the
##                pk_parity argument of secp256k1_xonly_pubkey_from_pubkey.
##   In: keypair: pointer to a keypair.
##

proc secp256k1_keypair_xonly_pub*(ctx: ptr secp256k1_context;
                                 pubkey: ptr secp256k1_xonly_pubkey;
                                 pk_parity: ptr cint;
                                 keypair: ptr secp256k1_keypair): cint {.secp,
    importc: "secp256k1_keypair_xonly_pub".}
## * Tweak a keypair by adding tweak32 to the secret key and updating the public
##   key accordingly.
##
##   Calling this function and then secp256k1_keypair_pub results in the same
##   public key as calling secp256k1_keypair_xonly_pub and then
##   secp256k1_xonly_pubkey_tweak_add.
##
##   Returns: 0 if the arguments are invalid or the resulting keypair would be
##            invalid (only when the tweak is the negation of the keypair's
##            secret key). 1 otherwise.
##
##   Args:       ctx: pointer to a context object.
##   In/Out: keypair: pointer to a keypair to apply the tweak to. Will be set to
##                    an invalid value if this function returns 0.
##   In:     tweak32: pointer to a 32-byte tweak, which must be valid according to
##                    secp256k1_ec_seckey_verify or 32 zero bytes. For uniformly
##                    random 32-byte tweaks, the chance of being invalid is
##                    negligible (around 1 in 2^128).
##

proc secp256k1_keypair_xonly_tweak_add*(ctx: ptr secp256k1_context;
                                       keypair: ptr secp256k1_keypair;
                                       tweak32: ConstPtrByte): cint {.secp,
    importc: "secp256k1_keypair_xonly_tweak_add".}
## * This module implements a variant of Schnorr signatures compliant with
##   Bitcoin Improvement Proposal 340 "Schnorr Signatures for secp256k1"
##   (https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki).
##
## * A pointer to a function to deterministically generate a nonce.
##
##   Same as secp256k1_nonce function with the exception of accepting an
##   additional pubkey argument and not requiring an attempt argument. The pubkey
##   argument can protect signature schemes with key-prefixed challenge hash
##   inputs against reusing the nonce when signing with the wrong precomputed
##   pubkey.
##
##   Returns: 1 if a nonce was successfully generated. 0 will cause signing to
##            return an error.
##   Out:  nonce32: pointer to a 32-byte array to be filled by the function
##   In:       msg: the message being verified. Is NULL if and only if msglen
##                  is 0.
##          msglen: the length of the message
##           key32: pointer to a 32-byte secret key (will not be NULL)
##      xonly_pk32: the 32-byte serialized xonly pubkey corresponding to key32
##                  (will not be NULL)
##            algo: pointer to an array describing the signature
##                  algorithm (will not be NULL)
##         algolen: the length of the algo array
##            data: arbitrary data pointer that is passed through
##
##   Except for test cases, this function should compute some cryptographic hash of
##   the message, the key, the pubkey, the algorithm description, and data.
##

type
  secp256k1_nonce_function_hardened* = proc (nonce32: ptr byte; msg: ConstPtrByte;
      msglen: csize_t; key32: ConstPtrByte; xonly_pk32: ConstPtrByte;
      algo: ConstPtrByte; algolen: csize_t; data: pointer): cint {.secp.}

## * An implementation of the nonce generation function as defined in Bitcoin
##   Improvement Proposal 340 "Schnorr Signatures for secp256k1"
##   (https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki).
##
##   If a data pointer is passed, it is assumed to be a pointer to 32 bytes of
##   auxiliary random data as defined in BIP-340. If the data pointer is NULL,
##   the nonce derivation procedure follows BIP-340 by setting the auxiliary
##   random data to zero. The algo argument must be non-NULL, otherwise the
##   function will fail and return 0. The hash will be tagged with algo.
##   Therefore, to create BIP-340 compliant signatures, algo must be set to
##   "BIP0340/nonce" and algolen to 13.
##

var secp256k1_nonce_function_bip340_imp {.importc: "secp256k1_nonce_function_bip340".}: secp256k1_nonce_function_hardened

template secp256k1_nonce_function_bip340*: secp256k1_nonce_function_hardened =
  {.noSideEffect.}:
    secp256k1_nonce_function_bip340_imp

## * Data structure that contains additional arguments for schnorrsig_sign_custom.
##
##   A schnorrsig_extraparams structure object can be initialized correctly by
##   setting it to SECP256K1_SCHNORRSIG_EXTRAPARAMS_INIT.
##
##   Members:
##       magic: set to SECP256K1_SCHNORRSIG_EXTRAPARAMS_MAGIC at initialization
##              and has no other function than making sure the object is
##              initialized.
##     noncefp: pointer to a nonce generation function. If NULL,
##              secp256k1_nonce_function_bip340 is used
##       ndata: pointer to arbitrary data used by the nonce generation function
##              (can be NULL). If it is non-NULL and
##              secp256k1_nonce_function_bip340 is used, then ndata must be a
##              pointer to 32-byte auxiliary randomness as per BIP-340.
##

type
  secp256k1_schnorrsig_extraparams* {.bycopy.} = object
    magic*: array[4, byte]
    noncefp*: secp256k1_nonce_function_hardened
    ndata*: pointer


## * Create a Schnorr signature.
##
##   Does _not_ strictly follow BIP-340 because it does not verify the resulting
##   signature. Instead, you can manually use secp256k1_schnorrsig_verify and
##   abort if it fails.
##
##   This function only signs 32-byte messages. If you have messages of a
##   different size (or the same size but without a context-specific tag
##   prefix), it is recommended to create a 32-byte message hash with
##   secp256k1_tagged_sha256 and then sign the hash. Tagged hashing allows
##   providing an context-specific tag for domain separation. This prevents
##   signatures from being valid in multiple contexts by accident.
##
##   Returns 1 on success, 0 on failure.
##   Args:    ctx: pointer to a context object (not secp256k1_context_static).
##   Out:   sig64: pointer to a 64-byte array to store the serialized signature.
##   In:    msg32: the 32-byte message being signed.
##        keypair: pointer to an initialized keypair.
##     aux_rand32: 32 bytes of fresh randomness. While recommended to provide
##                 this, it is only supplemental to security and can be NULL. A
##                 NULL argument is treated the same as an all-zero one. See
##                 BIP-340 "Default Signing" for a full explanation of this
##                 argument and for guidance if randomness is expensive.
##

proc secp256k1_schnorrsig_sign32*(ctx: ptr secp256k1_context; sig64: ptr byte;
                                 msg32: ConstPtrByte;
                                 keypair: ptr secp256k1_keypair;
                                 aux_rand32: ConstPtrByte): cint {.secp,
    importc: "secp256k1_schnorrsig_sign32".}
## * Create a Schnorr signature with a more flexible API.
##
##   Same arguments as secp256k1_schnorrsig_sign32 except that it allows signing
##   variable length messages and accepts a pointer to an extraparams object that
##   allows customizing signing by passing additional arguments.
##
##   Equivalent to secp256k1_schnorrsig_sign32(..., aux_rand32) if msglen is 32
##   and extraparams is initialized as follows:
##   ```
##   secp256k1_schnorrsig_extraparams extraparams = SECP256K1_SCHNORRSIG_EXTRAPARAMS_INIT;
##   extraparams.ndata = (unsigned char*)aux_rand32;
##   ```
##
##   Returns 1 on success, 0 on failure.
##   Args:   ctx: pointer to a context object (not secp256k1_context_static).
##   Out:  sig64: pointer to a 64-byte array to store the serialized signature.
##   In:     msg: the message being signed. Can only be NULL if msglen is 0.
##        msglen: length of the message.
##       keypair: pointer to an initialized keypair.
##   extraparams: pointer to an extraparams object (can be NULL).
##

proc secp256k1_schnorrsig_sign_custom*(ctx: ptr secp256k1_context;
                                      sig64: ptr byte; msg: ConstPtrByte;
                                      msglen: csize_t;
                                      keypair: ptr secp256k1_keypair; extraparams: ptr secp256k1_schnorrsig_extraparams): cint {.
    secp, importc: "secp256k1_schnorrsig_sign_custom".}
## * Verify a Schnorr signature.
##
##   Returns: 1: correct signature
##            0: incorrect signature
##   Args:    ctx: pointer to a context object.
##   In:    sig64: pointer to the 64-byte signature to verify.
##            msg: the message being verified. Can only be NULL if msglen is 0.
##         msglen: length of the message
##         pubkey: pointer to an x-only public key to verify with
##

proc secp256k1_schnorrsig_verify*(ctx: ptr secp256k1_context; sig64: ConstPtrByte;
                                 msg: ConstPtrByte; msglen: csize_t;
                                 pubkey: ptr secp256k1_xonly_pubkey): cint {.secp,
    importc: "secp256k1_schnorrsig_verify".}
template secp256k1_ecdh*(ctx: ptr secp256k1_context; output: ptr byte;
                         pubkey: ptr secp256k1_pubkey; seckey: ConstPtrByte): cint =
  secp256k1_ecdh(ctx, output, pubkey, seckey,
    secp256k1_ecdh_hash_function_default, nil)

proc secp256k1_scratch_space_create*(
  ctx: ptr secp256k1_context;
  size: csize_t): ptr secp256k1_scratch_space {.secp, importc,
    deprecated: "not part of the libsecp256k1 API".}

proc secp256k1_scratch_space_destroy*(
  ctx: ptr secp256k1_context;
  scratch: ptr secp256k1_scratch_space) {.secp, importc,
    deprecated: "not part of the libsecp256k1 API".}
