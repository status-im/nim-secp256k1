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

proc test(env, path: string) =
  # Compilation language is controlled by TEST_LANG
  var lang = "c"
  if existsEnv"TEST_LANG":
    lang = getEnv"TEST_LANG"

  exec "nim " & lang & " " & env &
    " -r -f --hints:off --skipParentCfg " & path

task test, "Tests":
  test "--threads:on", "tests/all_tests"
  test "--threads:off", "tests/all_tests"

