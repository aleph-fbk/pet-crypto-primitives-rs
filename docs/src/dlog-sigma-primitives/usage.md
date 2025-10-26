# User Guide
---
## Installation

`dlog-sigma-primitives` is published on crates.io. It depends on a cryptographic group implementation, typically provided by a backend like `dlog-group`, which the crate already uses internally, so you don't need to add it as a dependency yourself unless you want to use it directly.

Add via Cargo:

```bash
cargo add dlog-sigma-primitives --features p256
```

Or add entries manually to your `Cargo.toml` (replace the version with the latest on crates.io):

```toml
[dependencies]
dlog-sigma-primitives = { version = "x.y.z", features = ["p256"] }
```

Notes:

1. `serde` is a regular dependency of this crate. Types that are safe to serialize implement `Serialize` and `Deserialize` with no feature flag.
2. Select exactly one concrete group via a crate feature on `dlog-sigma-primitives` (for example `p256`). These features forward to the underlying `dlog-group` backend.
3. You only need a direct `dlog-group` dependency if you plan to call its APIs or need fine grained control over its own features beyond what this crate forwards.
4. Randomness is provided via `rand_core`; transcripts and Fiat-Shamir challenges use `merlin`. These are regular dependencies and require no special configuration.

API documentation are available online:
- Crate page on crates.io: https://crates.io/crates/dlog-sigma-primitives
- API docs on docs.rs: https://docs.rs/dlog-sigma-primitives

## Supported Algorithms

1. ElGamal encryption (modified and exponential).
   - Modified ElGamal: a rerandomizable ElGamal variant tailored to verifiable shuffles and mixnets. It exposes ciphertext and randomness structures convenient for proof composition. [[JCJ02]]
   - Exponential ElGamal: plaintexts are represented in the exponent, enabling linear relations on messages to be proven with compact Sigma protocols.

2. Pedersen commitments.
   - Additively homomorphic commitments of the form $C = g^m h^r$, with binding under DL in G and perfect hiding for uniformly random $r$. [[TPP91]]
   - Designed to compose with the proof system below.

3. Sigma protocols and non interactive zero knowledge proofs for DL relations.
   - Schnorr type proofs for knowledge of discrete logs and linear relations among logs. [[CS97]]
   - Relation specific statements used in the crate include:
     - Zero plaintext proofs for ElGamal ciphertexts, i.e., proofs that a ciphertext encrypts m = 0 without revealing the randomness.
     - Equality of discrete logs across independent bases.
     - Disjunctive (OR) proofs for alternative witnesses.
     - Designated verifier proofs that bind verification to a verifier secret. [[JSB96]]
   - All proofs are rendered non interactive via Fiat Shamir using `merlin` for transcript construction and challenge derivation. [[FS86]]


[JCJ02]: https://eprint.iacr.org/2002/165  
[TPP91]: https://link.springer.com/chapter/10.1007/3-540-46766-1_9  
[FS86]: https://link.springer.com/chapter/10.1007/3-540-47721-7_12  
[CS97]: https://crypto.ethz.ch/publications/files/CamSta97b.pdf  
[JSB96]: https://link.springer.com/chapter/10.1007/3-540-68339-9_13  
[`merlin`]: https://crates.io/crates/merlin