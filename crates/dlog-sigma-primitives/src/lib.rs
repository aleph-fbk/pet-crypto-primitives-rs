#![allow(non_snake_case)]
//! This library provides a collection of cryptographic primitives built on top
//! of Elliptic Curve groups, taking advantage of the abstraction defined in
//! `dlog-group`.

//!  It includes support for the Modified ElGamal encryption scheme [[JCJ02]],
//! in both its standard and exponential variants. Additionally, it implements
//! Pedersen Commitments [[TPP91]] and a variety of Zero-Knowledge proofs (ZKPs)
//! for discrete logarithm relations, made non-interactive using the Fiat-Shamir
//! heuristic [[FS86]] with the help of the well known [`merlin`] crate to
//! construct transcripts and derive challenge values.
//!  The library offers a wide range of proofs, from simple building blocks such
//! as proving that the plaintext in an ElGamal ciphertext is zero to more
//! advanced constructions, like designated verifier proofs.  
//!
//!
//!  [JCJ02]: https://eprint.iacr.org/2002/165
//!  [TPP91]: https://link.springer.com/chapter/10.1007/3-540-46766-1_9
//!  [FS86]: https://link.springer.com/chapter/10.1007/3-540-47721-7_12
//!  [`merlin`]: https://crates.io/crates/merlin

pub mod elgamal;
pub mod error;
pub mod pedersen;
pub mod proofs;
pub mod serde;

// Feature types derived from dlog-group

#[cfg(feature = "p256")]
pub type Curve = dlog_group::p256::P256Group;

#[cfg(feature = "k256")]
pub type Curve = dlog_group::k256::K256Group;

#[cfg(feature = "ristretto")]
pub type Curve = dlog_group::ristretto::RistrettoGroup;

#[cfg(feature = "p384")]
pub type Curve = dlog_group::p384::P384Group;

/// Convenience re-export module
pub mod prelude {
    pub use crate::elgamal::keys::{ElGamalParams, PublicKey};
    pub use crate::proofs::{Proof, SigmaProtocol, TranscriptForGroup};

    pub use crate::elgamal::keys::KeyPair;
    pub use crate::Curve;

    pub use dlog_group::group::{Group, GroupPoint, GroupScalar};
}
