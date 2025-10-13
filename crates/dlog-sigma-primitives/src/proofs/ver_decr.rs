//! Verifiable ElGamal decryption: proof of correct plaintext recovery.
//!
//! Statement.
//! Given ElGamal parameters `(G1, G2)`, a public key `H = [x1]G1 + [x2]G2`,
//! a ciphertext `C = (R1, R2, B) = ([r]G1, [r]G2, [r]H + M)`, and a claimed
//! plaintext `M`, prove that `M = B - [r]H` where `(R1, R2) = ([r]G1, [r]G2)`.
//!
//! Relation.
//! Show knowledge of `(x1, x2)` such that:
//! ```text
//! H = [x1]G1 + [x2]G2
//! B - M = [x1]R1 + [x2]R2
//! ```
//!
//! Protocol.
//! 1) Commit phase.
//! - Pick random `t1`, `t2`
//! - Compute   `K = [t1]G1 + [t2]G2`   `T = [t1]R1 + [t2]R2`
//! 2) Challenge.
//! - Derive challenge `c = H(tr, ...)` from the transcript
//! 3) Response.
//! - Compute   `z1 = t1 + c * x1`   `z2 = t2 + c * x2`
//!
//! Verification.
//! - Check both equations:
//! ```text
//! [z1]G1 + [z2]G2 == K + [c]H
//! [z1]R1 + [z2]R2 == T + [c](B - M)
//! ```
//!
//! This protocol proves that the ciphertext decrypts correctly under the
//! claimed plaintext, without revealing the secret key.

use dlog_group::serde::{PointHelper, ScalarHelper};
use serde::{Deserialize, Serialize};

use dlog_group::group::Group;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    elgamal::{
        ciphertext::Ciphertext,
        keys::{ElGamalParams, PublicKey, SecretKey, SecretScalar},
    },
    error::Error,
    proofs::{Proof, SigmaProtocol, TranscriptForGroup},
};

/// Public instance (borrowed view).
#[derive(Debug, Copy, Clone)]
pub struct DecOkPublicBorrowed<'a, G: Group> {
    pub params: &'a ElGamalParams<G>,
    pub pk: &'a PublicKey<G>,
    pub ct: &'a Ciphertext<G>,
    pub plaintext: &'a G::Point,
}

impl<'a, G: Group> DecOkPublicBorrowed<'a, G> {
    pub fn new(
        params: &'a ElGamalParams<G>,
        pk: &'a PublicKey<G>,
        ct: &'a Ciphertext<G>,
        plaintext: &'a G::Point,
    ) -> Self {
        Self {
            params,
            pk,
            ct,
            plaintext,
        }
    }
}

/// Non-interactive proof object.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecOk<G: Group> {
    #[serde(with = "PointHelper::<G>")]
    commit_pk: G::Point, // K
    #[serde(with = "PointHelper::<G>")]
    commit_ct: G::Point, // T

    #[serde(with = "ScalarHelper::<G>")]
    z1: G::Scalar,
    #[serde(with = "ScalarHelper::<G>")]
    z2: G::Scalar,
}

impl<G: Group> Proof for DecOk<G> {
    type Protocol = DecOkProtocol<G>;
}

/// Ephemeral prover state.
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct DecOkState<G: Group> {
    t1: SecretScalar<G>,
    t2: SecretScalar<G>,
    K: Option<G::Point>,
    T: Option<G::Point>,
}

/// Protocol implementation.
pub struct DecOkProtocol<G: Group>(core::marker::PhantomData<G>);

impl<G: Group> SigmaProtocol for DecOkProtocol<G> {
    const DOMAIN: &'static [u8] = b"ELGAMAL-DEC";

    type Public<'a> = DecOkPublicBorrowed<'a, G>;
    type Witness = SecretKey<G>;
    type Proof = DecOk<G>;
    type State = DecOkState<G>;

    // Absorb public inputs in a fixed order.
    fn absorb_public(public: Self::Public<'_>, tr: &mut Transcript) {
        tr.append_point::<G>(b"G1", &public.params.g1);
        tr.append_point::<G>(b"G2", &public.params.g2);
        tr.append_point::<G>(b"H", &public.pk.h);
        tr.append_ciphertext::<G>(b"C", public.ct);
        tr.append_point::<G>(b"M", public.plaintext);
    }

    // Sample ephemeral randomness.
    fn init<R: RngCore + CryptoRng>(_: Self::Public<'_>, rng: &mut R) -> Self::State {
        DecOkState {
            t1: SecretScalar::new(rng),
            t2: SecretScalar::new(rng),
            K: None,
            T: None,
        }
    }

    // Compute commitments and absorb them.
    fn commit(
        public: Self::Public<'_>,
        st: &mut Self::State,
        _witness: &Self::Witness,
        tr: &mut Transcript,
    ) {
        // K = [t1]G1 + [t2]G2
        let K = (public.params.g1 * st.t1.expose()) + &(public.params.g2 * st.t2.expose());
        tr.append_point::<G>(b"K", &K);

        // T = [t1]R1 + [t2]R2
        let T =
            (public.ct.random_point * st.t1.expose()) + &(public.ct.random_point2 * st.t2.expose());
        tr.append_point::<G>(b"T", &T);

        st.K = Some(K);
        st.T = Some(T);
    }

    // Produce responses.
    fn complete(mut st: Self::State, sk: &Self::Witness, tr: &mut Transcript) -> Self::Proof {
        let c = tr.challenge_scalar::<G>(b"c");

        let (x1, x2) = sk.expose_scalars();
        let z1 = c * x1 + st.t1.expose();
        let z2 = c * x2 + st.t2.expose();

        DecOk {
            commit_pk: st.K.take().unwrap(),
            commit_ct: st.T.take().unwrap(),
            z1,
            z2,
        }
    }

    // Re-absorb commitments for the verifier with identical labels/order.
    fn update_transcript(proof: &Self::Proof, tr: &mut Transcript) -> Result<(), Error> {
        tr.append_point::<G>(b"K", &proof.commit_pk);
        tr.append_point::<G>(b"T", &proof.commit_ct);
        Ok(())
    }

    // Algebraic verification.
    fn verify_relation(
        public: Self::Public<'_>,
        proof: &Self::Proof,
        tr: &mut Transcript,
    ) -> Result<(), Error> {
        let c = tr.challenge_scalar::<G>(b"c");

        // Check 1: [z1]G1 + [z2]G2 == K + [c]H
        let lhs1 = (public.params.g1 * &proof.z1) + &(public.params.g2 * &proof.z2);
        let rhs1 = proof.commit_pk + &(public.pk.h * &c);
        if lhs1 != rhs1 {
            return Err(Error::CommitmentMismatch);
        }

        // Check 2: [z1]R1 + [z2]R2 == T + [c](B - M)
        let lhs2 = (public.ct.random_point * &proof.z1) + &(public.ct.random_point2 * &proof.z2);
        let rhs2 = proof.commit_ct + &((public.ct.blinded_point - public.plaintext) * &c);
        if lhs2 != rhs2 {
            return Err(Error::CommitmentMismatch);
        }

        Ok(())
    }
}

// region:    --- Tests

#[cfg(test)]
mod tests {

    use super::*;
    use crate::proofs::prelude::*;
    use crate::Curve;

    #[test]
    fn verify_zero_proof_happy_path() {
        let mut rng = test_rng();
        let params: ElGamalParams<Curve> = ElGamalParams::new(&mut rng);
        let (sk, pk) = KeyPair::<Curve>::new_from_params(&params, &mut rng).into_tuple();

        let m = Curve::point_random(&mut rng);
        let ct = pk.encrypt(m, &params, &mut rng).into_tuple();

        let public = DecOkPublicBorrowed::new(&params, &pk, &ct.0, &m);

        // Prover
        let proof = DecOk::prove(public, &sk, &mut rng);

        // Verifier
        let res = proof.verify(public);
        assert!(res.is_ok(), "verification failed: {res:?}");
    }

    #[test]
    fn rejects_wrong_challenge() {
        let mut rng = test_rng();
        let params: ElGamalParams<Curve> = ElGamalParams::new(&mut rng);
        let (sk, pk) = KeyPair::<Curve>::new_from_params(&params, &mut rng).into_tuple();

        let m = Curve::point_random(&mut rng);
        let ct = pk.encrypt(m, &params, &mut rng).into_tuple();

        let public = DecOkPublicBorrowed::new(&params, &pk, &ct.0, &m);

        // get two different challenges
        let mut t1 = Transcript::new(b"test");
        let proof = DecOkProtocol::prove(public, &sk, &mut t1, &mut rng);

        let mut t2 = Transcript::new(b"tset");
        let res = DecOkProtocol::verify(public, &proof, &mut t2);

        assert!(res.is_err(), "proof should reject a different challenge");
    }

    #[test]
    fn serde_roundtrip() {
        let mut rng = test_rng();
        let params: ElGamalParams<Curve> = ElGamalParams::new(&mut rng);
        let (sk, pk) = KeyPair::<Curve>::new_from_params(&params, &mut rng).into_tuple();

        let m = Curve::point_random(&mut rng);
        let ct = pk.encrypt(m, &params, &mut rng).into_tuple();

        let public = DecOkPublicBorrowed::new(&params, &pk, &ct.0, &m);

        // Prover
        let proof = DecOk::prove(public, &sk, &mut rng);

        // Serialization via serde (e.g. json)
        let json = serde_json::to_value(proof).unwrap();
        let de: DecOk<Curve> = serde_json::from_value(json).unwrap();

        // Verifier
        let res = de.verify(public);
        assert!(res.is_ok(), "serde round-trip must preserve the proof");
    }
}
// endregion
