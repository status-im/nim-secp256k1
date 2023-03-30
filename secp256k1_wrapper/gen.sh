#!/bin/sh

set -e

THIS_DIR=$(dirname "$0")
cd $THIS_DIR/secp256k1
./autogen.sh
./configure --enable-module-ecdh --enable-module-recovery --enable-module-extrakeys --enable-module-schnorrsig --enable-experimental
make src/ecmult_static_context.h

cd -
cp secp256k1/src/ecmult_static_context.h "$THIS_DIR"
cp secp256k1/src/libsecp256k1-config.h "$THIS_DIR"
