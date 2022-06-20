mode = ScriptMode.Verbose

packageName   = "secp256k1"
version       = "0.5.2"
author        = "Status Research & Development GmbH"
description   = "A wrapper for the libsecp256k1 C library"
license       = "Apache License 2.0"
skipDirs      = @["tests"]
installDirs   = @["secp256k1_wrapper"]

requires "nim >= 1.2.0"
requires "stew"
requires "nimcrypto"

proc test(args, path: string) =
  # style checking can't generate errors, because nimcrypto mixes styles
  exec "nim " & getEnv("TEST_LANG", "c") & " " & getEnv("NIMFLAGS")  & " " & args &
    " -r -f --hints:off --styleCheck:usages --styleCheck:hint --skipParentCfg " & path

task test, "Tests":
  test "--threads:on", "tests/all_tests"
  test "--threads:off", "tests/all_tests"

