[![CI](https://github.com/aleph-fbk/pet-crypto-primitives-rs/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/aleph-fbk/pet-crypto-primitives-rs/actions/workflows/ci.yml)
[![Docs](https://img.shields.io/badge/docs-GitHub%20Pages-blue)](https://aleph-fbk.github.io/pet-crypto-primitives-rs/)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-informational)](#license)

# Cryptographic Primitives for Privacy-Enhancing Technologies (PETs)

This repository hosts a collection of Rust libraries for building **privacy-enhancing protocols**. Think of these components as cryptographic PETs 🐕—reliable, well-behaved, and safe to keep around. It's organized as a Rust **workspace** with multiple crates:

- **`dlog-group`**: abstraction layer over prime-order groups.
- **`dlog-sigma-primitives`**: implementations of encryption schemes, commitments, and zero-knowledge proofs.

The goal of this project is to provide modular, composable, and group-agnostic building blocks for cryptographic applications such as **secure voting and anonymous credentials**.

## &#9888; Security Disclaimer

This project has not been independently audited. Correctness and resistance to side-channel attacks are not guaranteed. The software is not ready for production use. **Use at your own risk**.

## License

Licensed under either of [Apache License Version 2.0](LICENSE-APACHE), or [MIT license](LICENSE-MIT).

## Acknowledgments

This work has been supported by the joint laboratory between the Bruno Kessler Foundation (FBK) and the Italian Government Printing Office and Mint (IPZS).
