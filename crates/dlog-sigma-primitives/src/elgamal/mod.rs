//! Modified ElGamal encryption scheme as described in
//! [JCJ02](https://eprint.iacr.org/2002/165).
//!
//! Definition.
//! Public parameters: two independent bases G1, G2 in a group G of prime order
//! p. Secret key: `sk = (sk1, sk2)` in `Z_q^2`.
//! Public key: `H = [sk1]G1 + [sk2]G2`.
//!
//! Encrypt a group element M in G with fresh randomness `r` in `Z_p`:
//! ```text
//!   CT = (R1, R2, C) where
//!     R1 = [r]G1
//!     R2 = [r]G2
//!     C  = [r]H + M
//! ```
//! Decrypt with sk:
//!   `M = C - ( [sk1]R1 + [sk2]R2 )`.
//!
//! Exponential mode.
//! Encode `x` in a small interval as `M = [x]G` and recover `x` by a discrete-log
//! lookup table.
//!
//! Points of interest.
//! - Homomorphism: component-wise addition of ciphertexts adds plaintexts;
//!   scalar mul scales plaintext.
//! - Re-randomization: adding an encryption of the identity re-randomizes
//!   without changing M.
//! - Security: IND-CPA under DDH in G assuming bases are independent.
//! - Serialization: compressed points via dlog_group::serde helpers.
//!
//! Example
//!
//! ```rust
//! # use dlog_sigma_primitives::{Curve, elgamal::keys::{ElGamalParams, KeyPair}};
//! # use dlog_group::{
//! #     group::{GroupPoint, GroupScalar},
//! # };
//! # use rand::thread_rng;
//! # pub type Scalar = <Curve as GroupScalar>::Scalar;
//!
//! # fn main() {
//! let mut rng = thread_rng();
//!
//! // Set up parameters and keypair
//! let params = ElGamalParams::<Curve>::new(&mut rng);
//! let (sk, pk) = KeyPair::new_from_params(&params, &mut rng).into_tuple();
//!
//! // Encrypt a random group point
//! let message = Curve::point_random(&mut rng);
//! let ext_ct = pk.encrypt(message, &params, &mut rng);
//! let ct = ext_ct.to_inner(); // strip randomness
//!
//! // Decrypt
//! let dec = sk.decrypt(&ct);
//! assert_eq!(message, dec);
//! # }
//! ```
//
pub mod ciphertext;
pub mod keys;
