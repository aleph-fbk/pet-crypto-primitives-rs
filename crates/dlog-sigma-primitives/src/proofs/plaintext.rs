//! Plaintext-knowledge proof for ElGamal-style ciphertexts.
//!
//! Statement.
//! Prove knowledge of scalars `(r, m)` such that the ciphertext
//! satisfies the relation:
//! ```text
//! C = [r]PK + (0, 0, [m]G)
//! ```
//!
//! Protocol.
//! 1) Commit phase.
//! - Pick random values `t_r`, `t_m`.
//! - Compute the commitment `I = [t_r]PK + (0, 0, [t_m]G)`.
//! 2) Challenge.
//! - Derive challenge `c` from the transcript that absorbs `(params, PK, C,
//!   I)`.
//! 3) Response.
//! - Compute   `z_r = t_r + c * r`   `z_m = t_m + c * m`
//!
//! Verification.
//! Check that the verifier equation holds:
//! ```text
//! [z_r]PK + (0, 0, [z_m]G) == I + c * C
//! ```
//!
//! This proof demonstrates that the prover knows both the plaintext and the
//! randomness used in the ElGamal encryption, without revealing either.

use core::marker::PhantomData;

use dlog_group::group::Group;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{SigmaProtocol, TranscriptForGroup};
use crate::proofs::Proof;
use crate::{
    elgamal::{
        ciphertext::Ciphertext,
        keys::{ElGamalParams, PublicKey, SecretScalar},
    },
    error::Error,
};

use crate::serde::CiphertextHelper;
use dlog_group::serde::ScalarHelper;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy)]
pub struct PlaintextPublicBorrowed<'a, G: Group> {
    pub pk: &'a PublicKey<G>,
    pub params: &'a ElGamalParams<G>,
    pub ct: &'a Ciphertext<G>,
}

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct PlaintextWitness<G: Group> {
    pub r: SecretScalar<G>,
    pub m: SecretScalar<G>,
}

impl<G: Group> PlaintextWitness<G> {
    pub fn new(r: SecretScalar<G>, m: SecretScalar<G>) -> Self {
        Self { r, m }
    }
}

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct PlaintextState<G: Group> {
    t_r: SecretScalar<G>,
    t_m: SecretScalar<G>,
    I: Option<Ciphertext<G>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Plaintext<G: Group> {
    #[serde(with = "CiphertextHelper::<G>")]
    pub commitment: Ciphertext<G>,
    #[serde(with = "ScalarHelper::<G>")]
    pub z_r: G::Scalar,
    #[serde(with = "ScalarHelper::<G>")]
    pub z_m: G::Scalar,
}

#[derive(Debug, Clone)]
pub struct PlaintextProtocol<G: Group>(PhantomData<G>);

impl<G: Group> SigmaProtocol for PlaintextProtocol<G> {
    const DOMAIN: &'static [u8] = b"ELGAMAL-PLAINTEXT";

    type Public<'a> = PlaintextPublicBorrowed<'a, G>;
    type Witness = PlaintextWitness<G>;
    type Proof = Plaintext<G>;
    type State = PlaintextState<G>;

    fn absorb_public(public: Self::Public<'_>, tr: &mut Transcript) {
        tr.append_point::<G>(b"H", &public.pk.h);
        tr.append_point::<G>(b"G1", &public.params.g1);
        tr.append_point::<G>(b"G2", &public.params.g2);
        tr.append_ciphertext::<G>(b"ciphertext", public.ct);
    }

    fn init<R: RngCore + CryptoRng>(_public: Self::Public<'_>, rng: &mut R) -> Self::State {
        PlaintextState {
            t_r: SecretScalar::new(rng),
            t_m: SecretScalar::new(rng),
            I: None,
        }
    }

    fn commit(
        public: Self::Public<'_>,
        state: &mut Self::State,
        _wit: &Self::Witness,
        tr: &mut Transcript,
    ) {
        let mut I = public.pk.to_ciphertext(public.params) * state.t_r.expose();
        I.blinded_point += G::generator() * state.t_m.expose();
        tr.append_ciphertext::<G>(b"commitment", &I);
        state.I = Some(I);
    }

    fn complete(state: Self::State, witness: &Self::Witness, tr: &mut Transcript) -> Self::Proof {
        let c = tr.challenge_scalar::<G>(b"c");
        let z_r = c * witness.r.expose() + state.t_r.expose();
        let z_m = c * witness.m.expose() + state.t_m.expose();

        Plaintext {
            commitment: state.I.expect("commit must run before complete"),
            z_r,
            z_m,
        }
    }

    fn update_transcript(proof: &Self::Proof, tr: &mut Transcript) -> Result<(), Error> {
        tr.append_ciphertext::<G>(b"commitment", &proof.commitment);
        Ok(())
    }

    fn verify_relation(
        public: Self::Public<'_>,
        proof: &Self::Proof,
        tr: &mut Transcript,
    ) -> Result<(), Error> {
        let c = tr.challenge_scalar::<G>(b"c");

        let mut lhs = public.pk.to_ciphertext(public.params) * &proof.z_r;
        lhs.blinded_point += G::generator() * &proof.z_m;
        let rhs = proof.commitment + (*public.ct * &c);

        if lhs == rhs {
            Ok(())
        } else {
            Err(Error::CommitmentMismatch)
        }
    }
}

impl<G: Group> Proof for Plaintext<G> {
    type Protocol = PlaintextProtocol<G>;
}

// region:    --- Tests

#[cfg(test)]
mod tests {

    use crate::proofs::plaintext::SecretScalar;
    use crate::proofs::{
        plaintext::{Plaintext, PlaintextProtocol, PlaintextPublicBorrowed, PlaintextWitness},
        prelude::{Curve, *},
    };

    #[test]
    fn verify_plaintext_proof_happy_path() {
        let (mut rng, params, pk) = setup();

        let m_sec = SecretScalar::new(&mut rng);
        let M = Curve::generator() * m_sec.expose();
        let (ct, r_sec) = pk.encrypt(M, &params, &mut rng).into_tuple();

        let public = PlaintextPublicBorrowed::<Curve> {
            pk: &pk,
            params: &params,
            ct: &ct,
        };
        let wit = PlaintextWitness::new(r_sec, m_sec);

        // Prover
        let proof = Plaintext::prove(public, &wit, &mut rng);

        // Verifier
        let res = proof.verify(public);
        assert!(res.is_ok(), "verification failed: {res:?}");
    }

    #[test]
    fn rejects_wrong_challenge() {
        let (mut rng, params, pk) = setup();
        let m_sec = SecretScalar::new(&mut rng);
        let M = Curve::generator() * m_sec.expose();
        let (ct, r_sec) = pk.encrypt(M, &params, &mut rng).into_tuple();

        let public = PlaintextPublicBorrowed::<Curve> {
            pk: &pk,
            params: &params,
            ct: &ct,
        };
        let wit = PlaintextWitness::new(r_sec, m_sec);

        // get two different challenges
        let mut t1 = Transcript::new(b"test");
        let proof = PlaintextProtocol::prove(public, &wit, &mut t1, &mut rng);

        let mut t2 = Transcript::new(b"tset");
        let res = PlaintextProtocol::verify(public, &proof, &mut t2);

        assert!(res.is_err(), "proof should reject a different challenge");
    }

    #[test]
    fn serde_roundtrip() {
        let (mut rng, params, pk) = setup();

        let m_sec = SecretScalar::new(&mut rng);
        let M = Curve::generator() * m_sec.expose();
        let (ct, r_sec) = pk.encrypt(M, &params, &mut rng).into_tuple();

        let public = PlaintextPublicBorrowed::<Curve> {
            pk: &pk,
            params: &params,
            ct: &ct,
        };
        let wit = PlaintextWitness::new(r_sec, m_sec);

        // Prover
        let proof = Plaintext::prove(public, &wit, &mut rng);

        // Serialization via serde (e.g. json)
        let json = serde_json::to_value(proof).unwrap();
        let de: Plaintext<Curve> = serde_json::from_value(json).unwrap();

        // Verifier
        let res = de.verify(public);
        assert!(res.is_ok(), "serde round-trip must preserve the proof");
    }
}

// endregion
