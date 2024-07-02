# CryptKeyPer

CryptKeyPer is a Rust-based API for cryptographic key management, focusing on deterministic random bit generation (HMAC_DRBG), mnemonic seed handling, and XMSS (eXtended Merkle Signature Scheme) implementation. The goal is to create a modular, reusable, and secure library for projects requiring cryptographic functionalities.

this is a work in progress and will be changed as I learn more about post quantum encryption methods. 

may not work for everyone!! use at your own discretion!!

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [Features](#features)
- [License](#license)
- [Contact](#contact)

## Installation

Follow these steps to install CryptKeyPer:

```bash
# Clone the repository
git clone https://github.com/mluna030/CryptKeyPer.git

# Navigate to the project directory
cd CryptKeyPer

# Build the project using Cargo
cargo build
```
## Usage
Examples of how to use CryptKeyPer

```rust
extern crate cryptkeyper;

use cryptkeyper::{HMAC_DRBG, MnemonicSeed, XMSS};

fn main() {
    // Example usage of HMAC_DRBG
    let mut drbg = HMAC_DRBG::new();
    let random_bits = drbg.generate();

    // Example usage of MnemonicSeed
    let seed = MnemonicSeed::new("example mnemonic phrase");
    let seed_bytes = seed.to_bytes();

    // Example usage of XMSS
    let xmss = XMSS::new(seed_bytes);
    let signature = xmss.sign(b"message");
}
```

## Features

- Deterministic Random Bit Generation (HMAC_DRBG)
- Mnemonic Seed Handling
- eXtended Merkle Signature Scheme (XMSS)

## License
- Creative Commons Attribution-NonCommercial-NoDerivatives 4.0 International

## Contact

For any questions or suggestions, feel free to contact me:

Michael Luna - michael.angelo.luna1@gmail.com

Project Link: https://github.com/mluna030/CryptKeyPer
