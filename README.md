# secp256k1

[![License: Apache](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
![Stability: experimental](https://img.shields.io/badge/stability-experimental-orange.svg)
![Github action](https://github.com/status-im/nim-secp256k1/workflows/CI/badge.svg)

# Introduction

This library is a wrapper for Bitcoin's [secp256k1](https://github.com/bitcoin-core/secp256k1) library. Two interfaces are exposed - `secp256k1` which thinly wraps the raw C interface found in `secp256k1_abi`. The thin wrapper is recommended.

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

Licensed and distributed under either of

* MIT license: [LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT

or

* Apache License, Version 2.0, ([LICENSE-APACHEv2](LICENSE-APACHEv2) or http://www.apache.org/licenses/LICENSE-2.0)

at your option. This file may not be copied, modified, or distributed except according to those terms.
