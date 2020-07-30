mode = ScriptMode.Verbose

packageName   = "secp256k1"
version       = "0.5.1"
author        = "Status Research & Development GmbH"
description   = "A wrapper for the libsecp256k1 C library"
license       = "Apache License 2.0"
installDirs   = @[".", "secp256k1_wrapper"]

requires "nim >= 1.2.0"
requires "stew"
requires "nimcrypto"

proc test(name: string, lang: string = "c") =
  if not dirExists "build":
    mkDir "build"
  --run
  --threads:on
  switch("out", ("./build/" & name))
  setCommand lang, "tests/" & name & ".nim"

task test, "Tests":
  test "all_tests"
