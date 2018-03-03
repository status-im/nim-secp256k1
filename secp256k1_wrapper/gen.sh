#!/bin/sh

THIS_DIR=$(dirname "$0")
cd $THIS_DIR/secp256k1
./autogen.sh
./configure
make src/ecmult_static_context.h
cp src/ecmult_static_context.h "$THIS_DIR"
cp src/libsecp256k1-config.h "$THIS_DIR"
