#!/usr/bin/env bash
set -eu -o pipefail
cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")"

git diff --exit-code -- . ':(exclude)update.sh' > /dev/null || { echo "Commit changes before updating!" ; exit 1 ; }

[[ $(c2nim -v) == "0.9.18" ]] || { echo "c2nim 0.9.18 required"; exit 1; }

# https://github.com/bitcoin-core/secp256k1/releases
VERSION="${1:-0.8.0}"

git -C vendor/secp256k1 fetch -q --tags origin
git -C vendor/secp256k1 checkout -q "v${VERSION}"

# Modules enabled by `-DENABLE_MODULE_...` in `secp256k1/abi.nim`, dependencies first
HEADERS=(secp256k1 secp256k1_ecdh secp256k1_recovery secp256k1_extrakeys secp256k1_schnorrsig)

mkdir -p gen
FILES=()
for h in "${HEADERS[@]}"; do
  cp "vendor/secp256k1/include/$h.h" gen
  FILES+=("gen/$h.h")
done

# c2nim gets confused by the attribute macros and struct initializers - drop them
sed -i.bak -E \
  -e '/^# *define SECP256K1_(API|NO_BUILD|WARN_UNUSED_RESULT|ARG_NONNULL|DEPRECATED)([ (]|$)/d' \
  -e 's/SECP256K1_API //' \
  -e 's/ ?SECP256K1_(WARN_UNUSED_RESULT|ARG_NONNULL\([0-9]+\)|DEPRECATED\("[^"]*"\))//g' \
  -e '/^#define SECP256K1_SCHNORRSIG_EXTRAPARAMS_MAGIC /d' \
  -e '/^#define SECP256K1_SCHNORRSIG_EXTRAPARAMS_INIT/,/^}/d' \
  gen/*.h
rm -f gen/*.h.bak  # Portable GNU/macOS `sed` needs backup

# c2nim gets confused by #if around the attribute macros
unifdef -m -U__cplusplus -U__GNUC__ -U__has_attribute -U_WIN32 \
  -USECP256K1_BUILD -USECP256K1_API -USECP256K1_NO_API_VISIBILITY_ATTRIBUTES \
  gen/*.h || [ $? -eq 1 ]  # Exit status 1: files changed

# c2nim drops `const` - replace const pointers with const-qualified aliases
# (`ConstPtrByte`, `ConstCstring`, defined further below) - outside of comments
sed -i.bak -E \
  -e '/^ *\/?\*/!s/const unsigned char \*/ConstPtrByte /g' \
  -e '/^ *\/?\*/!s/const char \*/ConstCstring /g' \
  gen/*.h
rm -f gen/*.h.bak  # Portable GNU/macOS `sed` needs backup

c2nim --importc --skipinclude --cdecl --concat --out:gen/abi.nim "${FILES[@]}"

# Fix cosmetic and ease-of-use issues
# - The context is opaque
# - The `const` globals are bound to their C symbols, wrapped in `{.noSideEffect.}`
#   templates as the compiler cannot deduce that they are constants
sed -i.bak -E \
  -e 's/cuchar/byte/g' \
  -e 's/uint([0-9]+)_t/uint\1/g' \
  -e 's/cdecl/secp/g' \
  -e 's/= secp256k1_context_struct$/= object/' \
  -e 's/^var ([a-z0-9_]+)\*: (.*)$/var \1_imp {.importc: "\1".}: \2\
\
template \1*: \2 =\
  {.noSideEffect.}:\
    \1_imp/' \
  gen/abi.nim
rm -f gen/abi.nim.bak  # Portable GNU/macOS `sed` needs backup

OUT=secp256k1/abi.nim

cat > "$OUT" <<'EOF'
import strutils, os

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
EOF

cat gen/abi.nim >> "$OUT"

cat >> "$OUT" <<'EOF'

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
EOF

rm -rf gen

# Wrapper version (`major.minor`) followed by the bundled libsecp256k1 version
sed -i.bak -E \
  -e "s/^(version *= *\"[0-9]+\.[0-9]+)\.[0-9]+\.[0-9]+\.[0-9]+\"/\1.${VERSION}\"/" \
  secp256k1.nimble
rm -f secp256k1.nimble.bak  # Portable GNU/macOS `sed` needs backup

! git diff --exit-code > /dev/null || { echo "This repository is already up to date" ; exit 0 ; }

git commit -a \
  -m "Update libsecp256k1 to ${VERSION}" \
  -m "- https://github.com/bitcoin-core/secp256k1/releases/tag/v${VERSION}"

echo "The repo has been updated with a commit recording the update."
echo "You can review the changes with 'git diff HEAD^' before pushing to a public repository."
