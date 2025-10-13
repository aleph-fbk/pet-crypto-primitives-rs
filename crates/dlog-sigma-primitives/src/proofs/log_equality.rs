//! Logarithm-equality proof between two modified ElGamal ciphertexts.
//!
//! Statement.
//! Given parameters `(G1, G2)` and a public key `PK = (G, G2, H)`, consider two
//! ciphertexts:
//! ```text
//! C1 = (s1 * G, s1 * G2, s1 * H + m * G3)
//! C2 = (s2 * G, s2 * G2, s2 * H + m * O)
//! ```
//! The goal is to prove that both ciphertexts encrypt the same discrete-log
//! message `m` under the same public key, without revealing `m`.
//!
//! Protocol.
//! 1) Commit phase.
//! - Pick random scalar `t`.
//! - Compute the commitment: ` I = [t](PK with blinded_point shifted by
//!   (G3 - O)) `
//! 2) Challenge.
//! - Derive the challenge `c` from the transcript that absorbs all public data
//!   `(params, PK, C1, C2, I)`.
//! 3) Response.
//! - Compute the responses: ` z1 = t + c * (s1 - s2) z2 = t + c * m `
//!
//! Verification.
//! Check that the verifier equation holds:
//! ```text
//! [z1]PK + [z2](0, 0, G3 - O) == I + c * (C1 - C2)
//! ```
//!
//! This proof shows that two modified ElGamal ciphertexts encrypt values with
//! the same discrete logarithm, ensuring consistency without revealing the
//! underlying plaintext.
//!
//! ## Example
//! ```rust
//! # use dlog_sigma_primitives::proofs::{SigmaProtocol, Proof, log_equality::{LogEq, LogEqPublicBorrowed, LogEqWitness, LogEqProtocol}};
//! # use merlin::Transcript;
//! # use rand::thread_rng;
//! # use dlog_group::{group::{GroupPoint, GroupScalar}};
//! # use dlog_sigma_primitives::elgamal::keys::{ElGamalParams, KeyPair};
//! # use dlog_sigma_primitives::Curve;
//! # type Scalar = <Curve as GroupScalar>::Scalar;
//!
//! // Prove and verify a LogEq statement
//! # fn main() {
//! let mut rng = thread_rng();
//! let params = ElGamalParams::<Curve>::new(&mut rng);
//! let (_sk, pk) = KeyPair::<Curve>::new_from_params(&params, &mut rng).into_tuple();
//!
//! // Choose bases G3 and O and message m
//! let g3 = Curve::point_random(&mut rng);
//! let o  = Curve::point_random(&mut rng);
//! let m  = Curve::scalar_random(&mut rng);
//!
//! // Encrypt m under the two bases
//! let (ct1, r1) = pk.encrypt(g3 * m, &params, &mut rng).into_tuple();
//! let (ct2, r2) = pk.encrypt(o  * m, &params, &mut rng).into_tuple();
//!
//! // Public and witness
//! let public = LogEqPublicBorrowed::new(&pk, &params, &ct1, &ct2, &g3, &o);
//! let witness = LogEqWitness::from_r1_r2(m, r1, r2);
//!
//! // Prove
//! let mut tr_p = Transcript::new(b"logeq-doctest");
//! let proof = <LogEq<Curve> as Proof>::Protocol::prove(public, &witness, &mut tr_p, &mut rng);
//!
//! // Verify
//! let mut tr_v = Transcript::new(b"logeq-doctest");
//! <LogEq<Curve> as Proof>::Protocol::verify(public, &proof, &mut tr_v).unwrap();
//! # }
//! ```
use crate::serde::CiphertextHelper;
use dlog_group::serde::ScalarHelper;
use serde::{Deserialize, Serialize};

use core::marker::PhantomData;
use dlog_group::group::Group;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    elgamal::{
        ciphertext::Ciphertext,
        keys::{ElGamalParams, PublicKey, SecretScalar},
    },
    error::Error,
    proofs::{Proof, SigmaProtocol, TranscriptForGroup},
};

/// Borrowed public input for LogEq.
#[derive(Debug, Clone, Copy)]
pub struct LogEqPublicBorrowed<'a, G: Group> {
    pub pk: &'a PublicKey<G>,
    pub params: &'a ElGamalParams<G>,
    pub c1: &'a Ciphertext<G>,
    pub c2: &'a Ciphertext<G>,
    pub g3: &'a G::Point,
    pub o: &'a G::Point,
}

impl<'a, G: Group> LogEqPublicBorrowed<'a, G> {
    pub fn new(
        pk: &'a PublicKey<G>,
        params: &'a ElGamalParams<G>,
        c1: &'a Ciphertext<G>,
        c2: &'a Ciphertext<G>,
        g3: &'a G::Point,
        o: &'a G::Point,
    ) -> Self {
        Self {
            pk,
            params,
            c1,
            c2,
            g3,
            o,
        }
    }
}

/// Prover witness: message m and the randomness delta (s1 - s2).
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct LogEqWitness<G: Group> {
    pub m: G::Scalar,
    pub delta_r: SecretScalar<G>, // s1 - s2
}

impl<G: Group> LogEqWitness<G> {
    pub fn new(m: G::Scalar, delta_r: SecretScalar<G>) -> Self {
        Self { m, delta_r }
    }
    pub fn from_r1_r2(m: G::Scalar, r1: SecretScalar<G>, r2: SecretScalar<G>) -> Self {
        // delta = r1 - r2
        let d = r1 - r2;
        Self { m, delta_r: d }
    }
}

/// Final proof object: commitment I and responses (z1, z2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LogEq<G: Group> {
    #[serde(with = "CiphertextHelper::<G>")]
    pub commitment: Ciphertext<G>,
    #[serde(with = "ScalarHelper::<G>")]
    pub response_delta: G::Scalar, // z1
    #[serde(with = "ScalarHelper::<G>")]
    pub response_m: G::Scalar, // z2
}

/// Prover ephemeral state: holds t and the commitment computed at commit.
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct LogEqState<G: Group> {
    pub(crate) t: SecretScalar<G>,
    pub(crate) commitment: Option<Ciphertext<G>>,
}

/// Marker type to bind `LogEq<G>` to SigmaProtocol.
pub struct LogEqProtocol<G: Group>(PhantomData<G>);

impl<G: Group> SigmaProtocol for LogEqProtocol<G> {
    const DOMAIN: &'static [u8] = b"ELGAMAL-LOGEQ";

    type Public<'a> = LogEqPublicBorrowed<'a, G>;
    type Witness = LogEqWitness<G>;
    type Proof = LogEq<G>;
    type State = LogEqState<G>;

    fn absorb_public(p: Self::Public<'_>, tr: &mut Transcript) {
        tr.append_point::<G>(b"H", &p.pk.h);
        tr.append_point::<G>(b"G1", &p.params.g1);
        tr.append_point::<G>(b"G2", &p.params.g2);
        tr.append_ciphertext::<G>(b"C1", p.c1);
        tr.append_ciphertext::<G>(b"C2", p.c2);
        tr.append_point::<G>(b"G3", p.g3);
        tr.append_point::<G>(b"O", p.o);
    }

    fn init<R: RngCore + CryptoRng>(_: Self::Public<'_>, rng: &mut R) -> Self::State {
        LogEqState {
            t: SecretScalar::<G>::new(rng),
            commitment: None,
        }
    }

    fn commit(
        public: Self::Public<'_>,
        st: &mut Self::State,
        _: &Self::Witness,
        tr: &mut Transcript,
    ) {
        // I = [t](PK_ct with blinded_point shifted by (G3 - O))
        let mut base = public.pk.to_ciphertext(public.params);
        base.blinded_point += *public.g3 - public.o;
        let I = base * st.t.expose();
        tr.append_ciphertext::<G>(b"I", &I);
        st.commitment = Some(I);
    }

    fn complete(st: Self::State, w: &Self::Witness, tr: &mut Transcript) -> Self::Proof {
        // c, then z1 = t + c*(s1 - s2), z2 = t + c*m
        let c = tr.challenge_scalar::<G>(b"c");
        let z1 = c * w.delta_r.expose() + st.t.expose();
        let z2 = c * &w.m + st.t.expose();
        LogEq {
            commitment: st
                .commitment
                .expect("commit must be called before complete"),
            response_delta: z1,
            response_m: z2,
        }
    }

    fn update_transcript(proof: &Self::Proof, tr: &mut Transcript) -> Result<(), Error> {
        tr.append_ciphertext::<G>(b"I", &proof.commitment);
        Ok(())
    }

    fn verify_relation(
        public: Self::Public<'_>,
        proof: &Self::Proof,
        tr: &mut Transcript,
    ) -> Result<(), Error> {
        // c
        let c = tr.challenge_scalar::<G>(b"c");

        // LHS = [z1]PK + [z2](0,0,G3 - O)
        let mut lhs = public.pk.to_ciphertext(public.params) * &proof.response_delta;
        lhs.blinded_point += (*public.g3 - public.o) * &proof.response_m;

        // RHS = I + c*(C1 - C2)
        let rhs = proof.commitment + ((*public.c1 - *public.c2) * &c);

        if lhs == rhs {
            Ok(())
        } else {
            Err(Error::CommitmentMismatch)
        }
    }
}

impl<G: Group> Proof for LogEq<G> {
    type Protocol = LogEqProtocol<G>;
}

// region:    --- Tests

#[cfg(test)]
mod tests {

    use crate::proofs::{
        log_equality::{LogEq, LogEqProtocol, LogEqPublicBorrowed, LogEqWitness},
        prelude::*,
        Proof,
    };

    #[test]
    fn verify_logeq_proof_happy_path() {
        let (mut rng, params, pk) = setup();

        let g3 = Curve::point_random(&mut rng);
        let o = Curve::point_random(&mut rng);
        let m = Curve::scalar_random(&mut rng);

        let (c1, r1) = pk.encrypt(g3 * m, &params, &mut rng).into_tuple();
        let (c2, r2) = pk.encrypt(o * m, &params, &mut rng).into_tuple();

        let public = LogEqPublicBorrowed::new(&pk, &params, &c1, &c2, &g3, &o);
        let wit = LogEqWitness::from_r1_r2(m, r1, r2);

        // Prover
        let proof = LogEq::prove(public, &wit, &mut rng);

        // Verifier
        let res = proof.verify(public);
        assert!(res.is_ok(), "verification failed: {res:?}");
    }

    #[test]
    fn rejects_wrong_challenge() {
        let (mut rng, params, pk) = setup();

        let g3 = Curve::point_random(&mut rng);
        let o = Curve::point_random(&mut rng);
        let m = Curve::scalar_random(&mut rng);

        let (c1, r1) = pk.encrypt(g3 * m, &params, &mut rng).into_tuple();
        let (c2, r2) = pk.encrypt(o * m, &params, &mut rng).into_tuple();

        let public = LogEqPublicBorrowed::new(&pk, &params, &c1, &c2, &g3, &o);
        let wit = LogEqWitness::from_r1_r2(m, r1, r2);

        // get two different challenges
        let mut t1 = Transcript::new(b"test");
        let proof = LogEqProtocol::prove(public, &wit, &mut t1, &mut rng);

        let mut t2 = Transcript::new(b"tset");
        let res = LogEqProtocol::verify(public, &proof, &mut t2);

        assert!(res.is_err(), "proof should reject a different challenge");
    }

    #[test]
    fn serde_roundtrip() {
        let (mut rng, params, pk) = setup();

        let g3 = Curve::point_random(&mut rng);
        let o = Curve::point_random(&mut rng);
        let m = Curve::scalar_random(&mut rng);

        let (c1, r1) = pk.encrypt(g3 * m, &params, &mut rng).into_tuple();
        let (c2, r2) = pk.encrypt(o * m, &params, &mut rng).into_tuple();

        let public = LogEqPublicBorrowed::new(&pk, &params, &c1, &c2, &g3, &o);
        let wit = LogEqWitness::from_r1_r2(m, r1, r2);

        // Prover
        let proof = LogEq::prove(public, &wit, &mut rng);

        // Serialization via serde (e.g. json)
        let json = serde_json::to_value(proof).unwrap();
        let de: LogEq<Curve> = serde_json::from_value(json).unwrap();

        // Verifier
        let res = de.verify(public);
        assert!(res.is_ok(), "serde round-trip must preserve the proof");
    }
}
// endregion
