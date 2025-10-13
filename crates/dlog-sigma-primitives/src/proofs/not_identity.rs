//! [`NotId`] proof: a modified ElGamal ciphertext `C` is not an encryption of
//! the group identity.
//!
//! Statement.
//! Let the ElGamal parameters be `(G1, G2)` and the public key `PK = H`.  
//! A ciphertext is defined as:
//! ```text
//! C = (r * G1, r * G2, r * H + M)
//! ```
//! for some message `M`. The goal is to prove that `M != 0` without revealing
//! either `M` or the encryption randomness `r`.
//!
//! Protocol.
//! 1) Commit phase.
//! - Define `PK_ct := PK` expressed as a ciphertext in the same basis.
//! - Pick random scalars `t`, `t1`, and `t2`.
//! - Compute the commitments: `I1 = [t1] PK_ct I2 = [t * r] PK_ct I3 =
//!   [t2] C I4 = [-t] C `
//! 2) Challenge.
//! - Derive the challenges `c1 = H(tr, ...)` and `c2 = H(tr, ...)` from the
//!   transcript that absorbs all public inputs and commitments.
//! 3) Response.
//! - Compute the responses: ` z1 = t1 + c1 * r * t z2 = t2 - c2 * t `
//!
//! The resulting proof is `(I1, I2, I3, I4, z1, z2)`.
//!
//! Verification.
//! The verifier checks:
//! ```text
//! [z1] PK_ct == I1 + [c1] I2
//! [z2] C     == I3 + [c2] I4
//! ```
//! and confirms that the element `I2 + I4` has zero first two components and
//! a non-zero third component, i.e. `(0, 0, != 0)`, ensuring that the
//! ciphertext cannot represent an encryption of the identity element.
//!
//! ## Example
//! ```rust
//! # use dlog_sigma_primitives::proofs::{Proof, TranscriptForGroup, SigmaProtocol, not_identity::{NotIdPublicBorrowed, NotIdProtocol}};
//! # use merlin::Transcript;
//! # use rand::thread_rng;
//! # use dlog_group::{group::{GroupPoint, GroupScalar}};
//! # use dlog_sigma_primitives::elgamal::keys::{ElGamalParams, KeyPair};
//! # use dlog_sigma_primitives::Curve;
//! # type Scalar = <Curve as GroupScalar>::Scalar;
//!
//! let mut rng = thread_rng();
//! let params: ElGamalParams<Curve> = ElGamalParams::new(&mut rng);
//! let (_sk, pk) = KeyPair::<Curve>::new_from_params(&params, &mut rng).into_tuple();
//!
//! // Encrypt a non-identity message
//! let m = Curve::point_random(&mut rng);
//! let ct = pk.encrypt(m, &params, &mut rng).into_tuple();
//!
//! // Public view
//! let public = NotIdPublicBorrowed::new(&pk, &params, &ct.0);
//!
//! // Prove
//! let mut tr_p = Transcript::new(b"example-notid");
//! let proof = NotIdProtocol::prove(public, &ct.1, &mut tr_p, &mut rng);
//!
//! // Verify
//! let mut tr_v = Transcript::new(b"example-notid");
//! NotIdProtocol::verify(public, &proof, &mut tr_v).unwrap();
//! ```
//!
//! Implementation notes.
//! - All labels and absorption order are stable and must not change.
//! - We derive two independent challenges `c1` and `c2` under labels `b"c1"`,
//!   `b"c2"` to bind the two linear relations independently.

use core::fmt::Debug;
use dlog_group::serde::{ScalarHelper, VecHelper};
use serde::{Deserialize, Serialize};

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
    proofs::{Proof as ProofTrait, SigmaProtocol, TranscriptForGroup},
};

#[derive(Debug, Copy, Clone)]
pub struct NotIdPublicBorrowed<'a, G: Group> {
    pub pk: &'a PublicKey<G>,
    pub params: &'a ElGamalParams<G>,
    pub ct: &'a Ciphertext<G>,
}

impl<'a, G: Group> NotIdPublicBorrowed<'a, G> {
    pub fn new(pk: &'a PublicKey<G>, params: &'a ElGamalParams<G>, ct: &'a Ciphertext<G>) -> Self {
        Self { pk, params, ct }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NotId<G: Group> {
    /// Commitments over the PK basis: [I1, I2].
    #[serde(with = "VecHelper::<crate::serde::CiphertextHelper<G>, 2>")]
    commitments_pk: Vec<Ciphertext<G>>,
    /// Commitments over the ciphertext: [I3, I4].
    #[serde(with = "VecHelper::<crate::serde::CiphertextHelper<G>, 2>")]
    commitments_ct: Vec<Ciphertext<G>>,
    /// Responses (z1, z2).
    #[serde(with = "VecHelper::<ScalarHelper<G>, 2>")]
    responses: Vec<G::Scalar>,
}

impl<G: Group> ProofTrait for NotId<G> {
    type Protocol = NotIdProtocol<G>;
}

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct NotIdState<G: Group> {
    /// Ephemeral scalars t, t1, t2.
    t: SecretScalar<G>,
    t1: SecretScalar<G>,
    t2: SecretScalar<G>,
    /// Commitments I1..I4.
    I1: Option<Ciphertext<G>>,
    I2: Option<Ciphertext<G>>,
    I3: Option<Ciphertext<G>>,
    I4: Option<Ciphertext<G>>,
}

pub struct NotIdProtocol<G: Group>(core::marker::PhantomData<G>);

impl<G: Group> SigmaProtocol for NotIdProtocol<G> {
    const DOMAIN: &'static [u8] = b"ELGAMAL-NOTID";

    type Public<'a> = NotIdPublicBorrowed<'a, G>;
    type Witness = SecretScalar<G>;
    type Proof = NotId<G>;
    type State = NotIdState<G>;

    // Absorb the public instance in a fixed, versioned order.
    fn absorb_public(public: Self::Public<'_>, tr: &mut Transcript) {
        tr.append_point::<G>(b"H", &public.pk.h);
        tr.append_point::<G>(b"G1", &public.params.g1);
        tr.append_point::<G>(b"G2", &public.params.g2);
        tr.append_ciphertext::<G>(b"C", public.ct);
    }

    // Sample ephemeral state.
    fn init<R: RngCore + CryptoRng>(_: Self::Public<'_>, rng: &mut R) -> Self::State {
        Self::State {
            t: SecretScalar::new(rng),
            t1: SecretScalar::new(rng),
            t2: SecretScalar::new(rng),
            I1: None,
            I2: None,
            I3: None,
            I4: None,
        }
    }

    // Compute commitments and absorb them into the transcript.
    fn commit(
        public: Self::Public<'_>,
        st: &mut Self::State,
        witness: &Self::Witness,
        tr: &mut Transcript,
    ) {
        let base = public.pk.to_ciphertext(public.params);

        // I1 = [t1] PK_ct
        let I1 = base * st.t1.expose();
        tr.append_ciphertext::<G>(b"[t1]PK", &I1);

        // I2 = [t*r] PK_ct
        let I2 = base * (witness * &st.t).expose();
        tr.append_ciphertext::<G>(b"[t*r]PK", &I2);

        // I3 = [t2] C
        let I3 = (*public.ct) * st.t2.expose();
        tr.append_ciphertext::<G>(b"[t2]C", &I3);

        // I4 = [-t] C
        let I4 = -(*public.ct) * st.t.expose();
        tr.append_ciphertext::<G>(b"[-t]C", &I4);

        st.I1 = Some(I1);
        st.I2 = Some(I2);
        st.I3 = Some(I3);
        st.I4 = Some(I4);
    }

    // Produce responses from challenges and consume the state.
    fn complete(mut st: Self::State, wit: &Self::Witness, tr: &mut Transcript) -> Self::Proof {
        // Two independent challenges.
        let c1 = tr.challenge_scalar::<G>(b"c1");
        let c2 = tr.challenge_scalar::<G>(b"c2");

        // Responses:
        // z1 = t1 + c1 * r * t  and  z2 = t2 - c2 * t
        let z1 = (c1 * st.t.expose() * wit.expose()) + st.t1.expose();
        let z2 = (G::Scalar::from(0) + st.t2.expose()) - &(c2 * st.t.expose());

        // Safe take of cached commitments.
        NotId {
            commitments_pk: vec![st.I1.take().unwrap(), st.I2.take().unwrap()],
            commitments_ct: vec![st.I3.take().unwrap(), st.I4.take().unwrap()],
            responses: vec![z1, z2],
        }
    }

    // Re-absorb commitments (verifier side) in the exact same order/labels.
    fn update_transcript(proof: &Self::Proof, tr: &mut Transcript) -> Result<(), Error> {
        tr.append_ciphertext::<G>(b"[t1]PK", &proof.commitments_pk[0]);
        tr.append_ciphertext::<G>(b"[t*r]PK", &proof.commitments_pk[1]);
        tr.append_ciphertext::<G>(b"[t2]C", &proof.commitments_ct[0]);
        tr.append_ciphertext::<G>(b"[-t]C", &proof.commitments_ct[1]);
        Ok(())
    }

    // Algebraic verification.
    fn verify_relation(
        public: Self::Public<'_>,
        proof: &Self::Proof,
        tr: &mut Transcript,
    ) -> Result<(), Error> {
        let c1 = tr.challenge_scalar::<G>(b"c1");
        let c2 = tr.challenge_scalar::<G>(b"c2");

        let base = public.pk.to_ciphertext(public.params);

        // [z1]PK_ct == I1 + [c1] I2
        let lhs1 = base * &proof.responses[0];
        let rhs1 = proof.commitments_pk[0] + (proof.commitments_pk[1] * &c1);
        if lhs1 != rhs1 {
            return Err(Error::CommitmentMismatch);
        }

        // [z2]C == I3 + [c2] I4
        let lhs2 = (*public.ct) * &proof.responses[1];
        let rhs2 = proof.commitments_ct[0] + (proof.commitments_ct[1] * &c2);
        if lhs2 != rhs2 {
            return Err(Error::CommitmentMismatch);
        }

        // Non-identity filter: I2 + I4 must have zero first two components and a
        // non-zero third component.
        let s = { proof.commitments_pk[1] + proof.commitments_ct[1] };
        let zero = G::identity();
        if s.random_point != zero || s.random_point2 != zero || s.blinded_point == zero {
            return Err(Error::CommitmentMismatch);
        }

        Ok(())
    }
}

// region:    --- Tests

#[cfg(test)]
mod tests {

    use crate::proofs::{
        not_identity::{NotId, NotIdProtocol, NotIdPublicBorrowed},
        prelude::*,
    };

    #[test]
    fn verify_notid_proof_happy_path() {
        let (mut rng, params, pk) = setup();
        // Non-identity message
        let m = Curve::point_random(&mut rng);
        let ct = pk.encrypt(m, &params, &mut rng).into_tuple();

        let public = NotIdPublicBorrowed::new(&pk, &params, &ct.0);

        // Prover
        let proof = NotId::prove(public, &ct.1, &mut rng);

        // Verifier
        let res = proof.verify(public);
        assert!(res.is_ok(), "verification failed: {res:?}");
    }

    #[test]
    fn rejects_wrong_challenge() {
        let (mut rng, params, pk) = setup();
        // Non-identity message
        let m = Curve::point_random(&mut rng);
        let ct = pk.encrypt(m, &params, &mut rng).into_tuple();

        let public = NotIdPublicBorrowed::new(&pk, &params, &ct.0);

        // get two different challenges
        let mut t1 = Transcript::new(b"test");
        let proof = NotIdProtocol::prove(public, &ct.1, &mut t1, &mut rng);

        let mut t2 = Transcript::new(b"tset");
        let res = NotIdProtocol::verify(public, &proof, &mut t2);

        assert!(res.is_err(), "proof should reject a different challenge");
    }

    #[test]
    fn serde_roundtrip() {
        let (mut rng, params, pk) = setup();
        // Non-identity message
        let m = Curve::point_random(&mut rng);
        let ct = pk.encrypt(m, &params, &mut rng).into_tuple();

        let public = NotIdPublicBorrowed::new(&pk, &params, &ct.0);

        // Prover
        let proof = NotId::prove(public, &ct.1, &mut rng);

        // Serialization via serde (e.g. json)
        let json = serde_json::to_value(proof).unwrap();
        let de: NotId<Curve> = serde_json::from_value(json).unwrap();

        // Verifier
        let res = de.verify(public);
        assert!(res.is_ok(), "serde round-trip must preserve the proof");
    }
}
// endregion
