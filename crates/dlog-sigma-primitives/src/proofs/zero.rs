//! Zero-plaintext proof for ElGamal-style ciphertexts.
//!
//! Statement.
//! Given ElGamal parameters and a public key `PK`, prove that a ciphertext
//! encrypts the group identity (i.e., the zero message) without revealing the
//! encryption randomness.
//!
//! Protocol.
//! 1) Commit phase.
//! - Pick random `t` and compute `I = [t]PK`.
//! 2) Challenge.
//! - Derive the challenge `c` from a transcript that absorbs `(params, PK,
//!   ciphertext, I)`.
//! 3) Response.
//! - Compute `z = t + r * c`, where `r` is the encryption randomness of the
//!   ciphertext.
//!
//! Verification.
//! Check that the verifier equation holds:
//! ```text
//! [z]PK == I + c * ciphertext
//! ```
//!
//! This proof demonstrates that the ciphertext encrypts the neutral group
//! element (zero plaintext) while keeping the randomness secret.
//!
//! ## Example
//!
//! ```rust
//! # use merlin::Transcript;
//! # use rand::thread_rng;
//! # use dlog_group::group::GroupPoint;
//! # use dlog_sigma_primitives::elgamal::keys::{ElGamalParams, KeyPair};
//! # use dlog_sigma_primitives::elgamal::ciphertext::ExtendedCiphertext;
//! # use dlog_sigma_primitives::proofs::{zero::{ZeroPublicBorrowed, ZeroProtocol}, SigmaProtocol};
//! # use dlog_sigma_primitives::Curve;
//!
//! # fn main() {
//! // Choose a concrete group.
//! type ZK = ZeroProtocol<Curve>;
//!
//! let mut rng = thread_rng();
//! let params: ElGamalParams<Curve> = ElGamalParams::new(&mut rng);
//! let (_sk, pk) = KeyPair::new_from_params(&params, &mut rng).into_tuple();
//! // Zero plaintext (group identity)
//! let ct = pk.encrypt(Curve::identity(), &params, &mut rng).into_tuple();
//!
//! let public = ZeroPublicBorrowed { pk: &pk, params: &params, ct: &ct.0 };
//!
//! // Prover
//! let mut tr_p = Transcript::new(b"example");
//! let proof = ZK::prove(public, &ct.1, &mut tr_p, &mut rng);
//!
//! // Verifier
//! let mut tr_v = Transcript::new(b"example");
//! ZK::verify(public, &proof, &mut tr_v).expect("verification");
//! # }
//! ```

use core::marker::PhantomData;

use dlog_group::group::Group;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use dlog_group::serde::ScalarHelper;
use serde::{Deserialize, Serialize};

use crate::proofs::Proof;
use crate::{
    elgamal::{
        ciphertext::Ciphertext,
        keys::{ElGamalParams, PublicKey, SecretScalar},
    },
    error::Error,
};

use crate::serde::CiphertextHelper;

use super::{SigmaProtocol, TranscriptForGroup};

/// Borrowed public inputs used by the protocol.
#[derive(Debug, Clone, Copy)]
pub struct ZeroPublicBorrowed<'a, G: Group> {
    /// ElGamal public key.
    pub pk: &'a PublicKey<G>,
    /// ElGamal bases g1 and g2.
    pub params: &'a ElGamalParams<G>,
    /// Ciphertext to prove as zero-plaintext.
    pub ct: &'a Ciphertext<G>,
}

impl<'a, G: Group> ZeroPublicBorrowed<'a, G> {
    pub fn new(pk: &'a PublicKey<G>, params: &'a ElGamalParams<G>, ct: &'a Ciphertext<G>) -> Self {
        Self { pk, params, ct }
    }
}

/// Zero-plaintext proof for ElGamal ciphertext.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Zero<G: Group> {
    /// Commitment `I = [t] PK`
    #[serde(with = "CiphertextHelper::<G>")]
    pub commitment: Ciphertext<G>,
    /// Response `z = t + r*c`, where r is the encryption randomness for ct.
    #[serde(with = "ScalarHelper::<G>")]
    pub response: G::Scalar,
}

/// Prover ephemeral state: holds `t` and the commitment computed during
/// `commit`.
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct ZeroState<G: Group> {
    pub(crate) t: SecretScalar<G>,
    pub(crate) commitment: Option<Ciphertext<G>>,
}

/// Marker type binding `Zero<G>` to the SigmaProtocol trait.
pub struct ZeroProtocol<G: Group>(PhantomData<G>);

impl<G: Group> SigmaProtocol for ZeroProtocol<G> {
    const DOMAIN: &'static [u8] = b"ELGAMAL-ZERO";

    type Public<'a> = ZeroPublicBorrowed<'a, G>;
    type Witness = SecretScalar<G>;
    type Proof = Zero<G>;
    type State = ZeroState<G>;

    /// Public absorption, called by prover and verifier.
    fn absorb_public(public: Self::Public<'_>, tr: &mut Transcript) {
        // Add the public parameters shared by prover and verifier, i.e.
        // public key, bases and the zero-ciphertext.
        tr.append_point::<G>(b"H", &public.pk.h);
        tr.append_point::<G>(b"G1", &public.params.g1);
        tr.append_point::<G>(b"G2", &public.params.g2);
        tr.append_ciphertext::<G>(b"CT", public.ct);
    }

    /// Initialize the randomness and the prover state.
    fn init<R: RngCore + CryptoRng>(_public: Self::Public<'_>, rng: &mut R) -> Self::State {
        ZeroState {
            t: SecretScalar::new(rng),
            commitment: None,
        }
    }

    /// Produce the commitment and append it to the transcript.
    /// NOTE: witness here is not used by it is required by the trait.
    fn commit(
        ref_public: Self::Public<'_>,
        st: &mut Self::State,
        _witness: &Self::Witness,
        tr: &mut Transcript,
    ) {
        // I = [t]PK expressed as a ciphertext in the same basis.
        let base = ref_public.pk.to_ciphertext(ref_public.params);
        let I = base * st.t.expose();

        // Commitment label must match verifier replay below.
        tr.append_ciphertext::<G>(b"[t]PK", &I);
        st.commitment = Some(I);
    }

    /// Consume the state and finilize a proof deriving the cjhallenge from the
    /// transcript.
    fn complete(st: Self::State, witness: &Self::Witness, tr: &mut Transcript) -> Self::Proof {
        // Derive challenge after all public and commitment data are absorbed.
        let c = tr.challenge_scalar::<G>(b"c");
        // z = t + c·r
        let z = c * witness.expose() + st.t.expose();

        Zero {
            commitment: st.commitment.expect("commit must run before complete"),
            response: z,
        }
    }

    /// Follows what is appended in commit.
    fn update_transcript(proof: &Self::Proof, tr: &mut Transcript) -> Result<(), Error> {
        // Replay commitment exactly as in `commit`.
        tr.append_ciphertext::<G>(b"[t]PK", &proof.commitment);
        Ok(())
    }

    /// Re-derive the challenge and check the algebraic relation.
    fn verify_relation(
        public: Self::Public<'_>,
        proof: &Self::Proof,
        tr: &mut Transcript,
    ) -> Result<(), Error> {
        let c = tr.challenge_scalar::<G>(b"c");

        // Check: [z]PK == I + [c]C
        let lhs = public.pk.to_ciphertext(public.params) * &proof.response;
        let rhs = proof.commitment + (*public.ct * &c);

        if lhs == rhs {
            Ok(())
        } else {
            Err(Error::CommitmentMismatch)
        }
    }
}

impl<G: dlog_group::group::Group> Proof for Zero<G> {
    type Protocol = ZeroProtocol<G>;
}

// region:    --- Tests

#[cfg(test)]
mod tests {

    use crate::proofs::{
        prelude::*,
        zero::{Zero, ZeroProtocol, ZeroPublicBorrowed},
    };

    #[test]
    fn verify_zero_proof_happy_path() {
        let (mut rng, params, pk) = setup();
        let ct = pk
            .encrypt(Curve::identity(), &params, &mut rng)
            .into_tuple();

        let public = ZeroPublicBorrowed {
            pk: &pk,
            params: &params,
            ct: &ct.0,
        };

        // Prover
        let proof = Zero::prove(public, &ct.1, &mut rng);

        // Verifier
        let res = proof.verify(public);
        assert!(res.is_ok(), "verification failed: {res:?}");
    }

    #[test]
    fn rejects_wrong_challenge() {
        let (mut rng, params, pk) = setup();
        let ct = pk
            .encrypt(Curve::identity(), &params, &mut rng)
            .into_tuple();
        let public = ZeroPublicBorrowed {
            pk: &pk,
            params: &params,
            ct: &ct.0,
        };

        // get two different challenges
        let mut t1 = Transcript::new(b"test");
        let proof = ZeroProtocol::prove(public, &ct.1, &mut t1, &mut rng);

        let mut t2 = Transcript::new(b"tset");
        let res = ZeroProtocol::verify(public, &proof, &mut t2);

        assert!(res.is_err(), "proof should reject a different challenge");
    }

    #[test]
    fn serde_roundtrip() {
        let (mut rng, params, pk) = setup();
        let ct = pk
            .encrypt(Curve::identity(), &params, &mut rng)
            .into_tuple();

        let public = ZeroPublicBorrowed {
            pk: &pk,
            params: &params,
            ct: &ct.0,
        };

        // Prover
        let proof = Zero::prove(public, &ct.1, &mut rng);

        // Serialization via serde (e.g. json)
        let json = serde_json::to_value(proof).unwrap();
        let de: Zero<Curve> = serde_json::from_value(json).unwrap();

        // Verifier
        let res = de.verify(public);
        assert!(res.is_ok(), "serde round-trip must preserve the proof");
    }
}
// endregion
