mode = ScriptMode.Verbose

packageName   = "secp256k1"
version       = "0.1.2"
author        = "Status Research & Development GmbH"
description   = "A wrapper for the libsecp256k1 C library"
license       = "Apache License 2.0"
installDirs   = @["secp256k1_wrapper"]

requires "nim >= 0.18.0"

proc test(name: string, lang: string = "c") =
  if not dirExists "build":
    mkDir "build"
  --run
  --threads:on
  switch("out", ("./build/" & name))
  setCommand lang, "tests/" & name & ".nim"

task test, "Run Proof-of-Work tests (without mining)":
  test "test1"
