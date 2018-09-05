# secp256k1

[![Build Status (Travis)](https://img.shields.io/travis/status-im/nim-secp256k1/master.svg?label=Linux%20/%20macOS "Linux/macOS build status (Travis)")](https://travis-ci.org/status-im/nim-secp256k1)
[![Windows build status (Appveyor)](https://img.shields.io/appveyor/ci/nimbus/nim-secp256k1/master.svg?label=Windows "Windows build status (Appveyor)")](https://ci.appveyor.com/project/nimbus/nim-secp256k1)
[![License: Apache](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
![Stability: experimental](https://img.shields.io/badge/stability-experimental-orange.svg)

# Introduction
This library is a wrapper for Bitcoin's [secp256k1](https://github.com/bitcoin-core/secp256k1) library.

# Installation

Add to your `.nimble` file:
```
requires "secp256k1"
```

# Build and test

```
# Upstream secp256k1 c library is tracked with a submodule
git submodule update --init
nimble test
```
## License

Licensed under both of the following:

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license: [LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT
