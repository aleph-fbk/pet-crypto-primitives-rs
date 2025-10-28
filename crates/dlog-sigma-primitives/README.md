# dlog-sigma-primitives

This library provides a collection of cryptographic primitives built on top of Elliptic Curve groups, taking advantage of the abstraction defined in `dlog-group`.

It includes support for the Modified ElGamal encryption scheme [JCJ02], in both its standard and exponential variants. Additionally, it implements Pedersen Commitments [TPP91] and a variety of Zero-Knowledge proofs (ZKPs) for discrete logarithm relations, made non-interactive using the Fiat-Shamir heuristic [FS86] with the help of the well known [`merlin`] crate to construct transcripts and derive challenge values.

The library offers a wide range of proofs, from simple building blocks such as proving that the plaintext in an ElGamal ciphertext is zero to more advanced constructions, like designated verifier proofs.

[JCJ02]: https://eprint.iacr.org/2002/165
[TPP91]: https://link.springer.com/chapter/10.1007/3-540-46766-1_9
[FS86]: https://link.springer.com/chapter/10.1007/3-540-47721-7_12
[`merlin`]: https://crates.io/crates/merlin

## &#9888; Security Disclaimer

This project has not been independently audited. Correctness and resistance to side-channel attacks are not guaranteed. The software is not ready for production use. **Use at your own risk**.

## License

Licensed under either of [Apache License Version 2.0](LICENSE-APACHE), or [MIT license](LICENSE-MIT).

## Acknowledgments

This work has been supported by the joint laboratory between the Bruno Kessler Foundation (FBK) and the Italian Government Printing Office and Mint (IPZS).