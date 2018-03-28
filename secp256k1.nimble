mode = ScriptMode.Verbose

packageName   = "secp256k1"
version       = "0.1.0"
author        = "Status Research & Development GmbH"
description   = "A wrapper for the libsecp256k1 C library"
license       = "Apache License 2.0"
skipDirs      = @["tests"]

requires "nim >= 0.18.0"
