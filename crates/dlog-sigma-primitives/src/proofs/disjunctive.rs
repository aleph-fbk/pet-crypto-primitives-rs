//! Disjunctive (OR) proof for ElGamal ciphertexts.
//!
//! Statement.
//! Given ElGamal parameters `(G1, G2)` and a public key `PK`, a ciphertext  
//! `C = (r * G1, r * G2, r * H + M)` encrypts one element from a fixed set  
//! `S = {M_0, ..., M_{k-1}}`, where each `M_i = v_i * G` for scalars `v_i`.
//!
//! The relation proved is that there exists an index `m` and randomness `r`
//! such that:
//! `C - (0, 0, M_m) = r * PK`
//!
//! Protocol.
//! 1) For all `i != m`:
//!    - Pick random `c_i`, `z_i`
//!    - Set   `I_i = [z_i]PK - c_i * (C - (0, 0, M_i))`
//! 2) For `i == m`:
//!    - Pick random `t`
//!    - Set `I_m = [t]PK`
//! 3) Absorb all `I_i` values into the transcript and derive a master challenge
//!    `c`.
//! 4) Compute   `c_m = c - sum_{i != m} c_i`   `z_m = t + r * c_m`
//!
//! Verification.
//! The verifier checks, for all `i`:
//! `
//! [z_i]PK == I_i + c_i * (C - (0, 0, M_i))
//! `
//! and ensures that `sum_i c_i == c`.
//!
//! This proof shows that an ElGamal ciphertext encrypts one value from a
//! predefined finite set without revealing which one.

//! ## Example
//! ```rust
//! # use dlog_sigma_primitives::proofs::{Proof, disjunctive::{Or, OrPublicBorrowed, OrWitness, OrProtocol}};
//! # use merlin::Transcript;
//! # use rand::thread_rng;
//! # use dlog_group::{group::{GroupPoint, GroupScalar}};
//! # use dlog_sigma_primitives::elgamal::keys::{ElGamalParams, KeyPair};
//! # use dlog_sigma_primitives::Curve;
//! # type Scalar = <Curve as GroupScalar>::Scalar;
//!
//! # fn main() {
//! let mut rng = thread_rng();
//! let params: ElGamalParams<Curve> = ElGamalParams::new(&mut rng);
//! let (_sk, pk) = KeyPair::new_from_params(&params, &mut rng).into_tuple();
//!
//! // Discrete set S = {v0, v1}. We prove that C encrypts v1.
//! let values = [0u64, 10u64].to_vec();
//! let (ct, r) = pk.encrypt(Curve::generator() * &<Curve as dlog_group::group::GroupScalar>::Scalar::from(values[1]), &params, &mut rng).into_tuple();
//!
//! let public = OrPublicBorrowed::<Curve>::new(&pk, &params, ct, &values);
//! let witness = OrWitness::new(1, r, values.len()).unwrap();
//!
//! // Prove (one-shot).
//! let proof = <Or<Curve> as Proof>::prove(public, &witness, &mut rng);
//!
//! // Verify.
//! proof.verify(public).expect("verify");
//! # }
//! ```
use core::marker::PhantomData;

use dlog_group::group::Group;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use dlog_group::serde::{ScalarHelper, VecHelper};
use serde::{Deserialize, Serialize};

use super::{SigmaProtocol, TranscriptForGroup};
use crate::proofs::Proof;
use crate::{
    elgamal::{
        ciphertext::Ciphertext,
        keys::{ElGamalParams, PublicKey, SecretScalar},
    },
    error::Error,
    serde::CiphertextHelper,
};

/// Borrowed public inputs for the OR proof.
#[derive(Debug, Clone, Copy)]
pub struct OrPublicBorrowed<'a, G: Group> {
    pub pk: &'a PublicKey<G>,
    pub params: &'a ElGamalParams<G>,
    pub ct: Ciphertext<G>,
    pub values: &'a [u64],
}

impl<'a, G: Group> OrPublicBorrowed<'a, G> {
    pub fn new(
        pk: &'a PublicKey<G>,
        params: &'a ElGamalParams<G>,
        ct: Ciphertext<G>,
        values: &'a [u64],
    ) -> Self {
        Self {
            pk,
            params,
            ct,
            values,
        }
    }
}

/// Prover's witness.
#[derive(Debug, Zeroize, ZeroizeOnDrop, Clone)]
pub struct OrWitness<G: Group> {
    /// Index related to the exact value encrypted.
    pub index: usize,
    /// Randomness used in the encryption.
    pub r: SecretScalar<G>,
}

impl<G: Group> OrWitness<G> {
    pub fn new(index: usize, r: SecretScalar<G>, values_len: usize) -> Result<Self, Error> {
        if values_len == 0 || index >= values_len {
            return Err(Error::InvalidInputShape);
        }
        Ok(Self { index, r })
    }
}

/// Final proof object.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Or<G: Group> {
    /// Commitments I_i
    #[serde(with = "VecHelper::<CiphertextHelper<G>, 2>")]
    pub commitments: Vec<Ciphertext<G>>,
    /// Responses z_i
    #[serde(with = "VecHelper::<ScalarHelper<G>, 2>")]
    pub responses: Vec<G::Scalar>,
    /// Per-branch challenges c_i that sum to the master challenge.
    #[serde(with = "VecHelper::<ScalarHelper<G>, 2>")]
    pub challenges: Vec<G::Scalar>,
}

/// Prover ephemeral state.
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct OrState<G: Group> {
    /// t for the real branch
    pub(crate) t: SecretScalar<G>,
    /// pre-sampled simulated challenges for all branches
    pub(crate) sim_c: Vec<G::Scalar>,
    /// pre-sampled simulated responses for all branches
    pub(crate) sim_z: Vec<G::Scalar>,
    /// commitments I_i (filled at commit)
    pub(crate) commitments: Vec<Ciphertext<G>>,
}

/// Marker type to bind `Or<G>` to SigmaProtocol.
pub struct OrProtocol<G: Group>(PhantomData<G>);

impl<G: Group> SigmaProtocol for OrProtocol<G> {
    const DOMAIN: &'static [u8] = b"ELGAMAL-OR";

    type Public<'a> = OrPublicBorrowed<'a, G>;
    type Witness = OrWitness<G>;
    type Proof = Or<G>;
    type State = OrState<G>;

    fn absorb_public(public: Self::Public<'_>, tr: &mut Transcript) {
        tr.append_point::<G>(b"H", &public.pk.h);
        tr.append_point::<G>(b"G1", &public.params.g1);
        tr.append_point::<G>(b"G2", &public.params.g2);
        tr.append_ciphertext::<G>(b"CT", &public.ct);
        // absorb values count and the list
        let n = public.values.len() as u64;
        tr.append_bytes(b"n", &n.to_le_bytes());
        for v in public.values.iter() {
            tr.append_scalar::<G>(b"", &G::Scalar::from(*v));
        }
    }

    fn init<R: RngCore + CryptoRng>(public: Self::Public<'_>, rng: &mut R) -> Self::State {
        let k = public.values.len();
        let mut sim_c = Vec::with_capacity(k);
        let mut sim_z = Vec::with_capacity(k);
        for _ in 0..k {
            sim_c.push(G::scalar_random(rng));
            sim_z.push(G::scalar_random(rng));
        }
        OrState {
            t: SecretScalar::new(rng),
            sim_c,
            sim_z,
            commitments: Vec::with_capacity(k),
        }
    }

    fn commit(
        public: Self::Public<'_>,
        st: &mut Self::State,
        witness: &Self::Witness,
        tr: &mut Transcript,
    ) {
        let k = public.values.len();
        let base = public.pk.to_ciphertext(public.params);

        for i in 0..k {
            if i == witness.index {
                // Real branch: I_m = [t]PK
                let I = base * st.t.expose();
                tr.append_ciphertext::<G>(b"I", &I);
                st.commitments.push(I);
            } else {
                // Simulated branch: I_i = [z_i]PK - c_i * (C - (0,0,M_i))
                let v_i = &public.values[i];
                let adjusted = Ciphertext::<G> {
                    random_point: public.ct.random_point,
                    random_point2: public.ct.random_point2,
                    blinded_point: public.ct.blinded_point - &(G::generator() * &G::Scalar::from(*v_i)),
                };
                let I_i = (base * &st.sim_z[i]) - (adjusted * &st.sim_c[i]);
                tr.append_ciphertext::<G>(b"I", &I_i);
                st.commitments.push(I_i);
            }
        }
    }

    fn complete(st: Self::State, witness: &Self::Witness, tr: &mut Transcript) -> Self::Proof {
        let k = st.commitments.len();
        let mut challenges = st.sim_c.clone();
        let mut responses = st.sim_z.clone();

        // Derive master challenge
        let c = tr.challenge_scalar::<G>(b"c");

        // Fold sum of simulated challenges excluding the real branch
        let mut sum = G::Scalar::from(0u64);
        for (i, challenge) in challenges.iter().enumerate().take(k) {
            if i != witness.index {
                sum = sum + challenge;
            }
        }
        let c_m = c - &sum;
        // z_m = t + r * c_m
        let z_m = c_m * witness.r.expose() + st.t.expose();

        challenges[witness.index] = c_m;
        responses[witness.index] = z_m;

        Or {
            commitments: st.commitments.clone(),
            responses,
            challenges,
        }
    }

    fn update_transcript(proof: &Self::Proof, tr: &mut Transcript) -> Result<(), Error> {
        for com in &proof.commitments {
            tr.append_ciphertext::<G>(b"I", com);
        }
        Ok(())
    }

    fn verify_relation(
        public: Self::Public<'_>,
        proof: &Self::Proof,
        tr: &mut Transcript,
    ) -> Result<(), Error> {
        // Derive master challenge
        let c = tr.challenge_scalar::<G>(b"c");

        // Check lengths
        let k = public.values.len();
        if proof.commitments.len() != k || proof.responses.len() != k || proof.challenges.len() != k
        {
            return Err(Error::InvalidInputShape);
        }

        // Check challenge sum
        let mut sum = G::Scalar::from(0u64);
        for c_i in &proof.challenges {
            sum = sum + c_i;
        }
        if sum != c {
            return Err(Error::ChallengeMismatch);
        }

        // Check commitments
        let base: Ciphertext<G> = public.pk.to_ciphertext(public.params);
        for i in 0..k {
            let v_i = &public.values[i];
            let adjusted = Ciphertext::<G> {
                random_point: public.ct.random_point,
                random_point2: public.ct.random_point2,
                blinded_point: public.ct.blinded_point - &(G::generator() * &G::Scalar::from(*v_i)),
            };
            let lhs = base * &proof.responses[i];
            let rhs = proof.commitments[i] + (adjusted * &proof.challenges[i]);
            if lhs != rhs {
                return Err(Error::CommitmentMismatch);
            }
        }
        Ok(())
    }
}

impl<G: Group> Proof for Or<G> {
    type Protocol = OrProtocol<G>;
}

// region:    --- Tests
#[cfg(test)]
mod tests {

    use crate::proofs::{
        disjunctive::{Or, OrPublicBorrowed, OrWitness},
        prelude::*,
    };

    #[test]
    fn verify_or_proof_happy_path() {
        let (mut rng, params, pk) = setup();
        let values = [0u64, 10u64].to_vec();
        // Encrypt the value 0
        let index = 0;
        let (ct, r) = pk
            .encrypt(Curve::generator() * &<Curve as dlog_group::group::GroupScalar>::Scalar::from(values[index]), &params, &mut rng)
            .into_tuple();
        // build public
        let public = OrPublicBorrowed::<Curve> {
            pk: &pk,
            params: &params,
            ct: ct,
            values: &values,
        };
        let wit = OrWitness { index, r };

        // Prove
        let proof = Or::prove(public, &wit, &mut rng);

        // Verify
        let res = proof.verify(public);
        assert!(res.is_ok(), "verification failed: {res:?}");
    }

    #[test]
    fn or_fails_on_values_permutation() {
        // Reordering the public value set changes the transcript and must fail.
        let (mut rng, params, pk) = setup();
        let values = [0u64, 10u64].to_vec();
        // Encrypt the value 0
        let index = 0;
        let (ct, r) = pk
            .encrypt(Curve::generator() * &<Curve as dlog_group::group::GroupScalar>::Scalar::from(values[index]), &params, &mut rng)
            .into_tuple();
        // build public
        let public = OrPublicBorrowed::<Curve> {
            pk: &pk,
            params: &params,
            ct: ct,
            values: &values,
        };
        let wit = OrWitness { index, r };

        let proof = Or::prove(public, &wit, &mut rng);

        // Permute values in the verifier's public input
        let mut values_perm = values.clone();
        values_perm.swap(0, 1);
        let public_bad = OrPublicBorrowed::<Curve> {
            pk: &pk,
            params: &params,
            ct: ct,
            values: &values_perm,
        };

        let res = proof.verify(public_bad);
        assert!(res.is_err(), "verifier with permuted values must fail");
    }

    #[test]
    fn serde_roundtrip() {
        let (mut rng, params, pk) = setup();
        let values = [0u64, 10u64].to_vec();
        let index = 0;
        let (ct, r) = pk
            .encrypt(Curve::generator() * &<Curve as dlog_group::group::GroupScalar>::Scalar::from(values[index]), &params, &mut rng)
            .into_tuple();
        // build public
        let public = OrPublicBorrowed::<Curve> {
            pk: &pk,
            params: &params,
            ct: ct,
            values: &values,
        };
        let wit = OrWitness { index, r };

        // Prove
        let proof = Or::prove(public, &wit, &mut rng);

        // Serialization via serde (e.g. json)
        let json = serde_json::to_value(proof).unwrap();
        let de: Or<Curve> = serde_json::from_value(json).unwrap();

        // Verifier
        let res = de.verify(public);
        assert!(res.is_ok(), "serde round-trip must preserve the proof");
    }
}
// endregion: --- Tests
