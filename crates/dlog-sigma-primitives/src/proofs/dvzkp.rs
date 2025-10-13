//! Designated-verifier NIZK proof.
//!
//! Setting. Let G be a group written additively on scalars and multiplicatively
//! on points. Public values:
//! ```text
//!   B0, B1A, B1B in G; P0, P1A, P1B in G.
//! ```
//! Statements:
//! ```text
//!   S0: P0 = [x] B0
//!   S1: P1A = [x] B1A and P1B = [x] B1B
//! ```
//! Goal: Prove knowledge of x for S0 OR S1 to a designated verifier only.
//! The designated verifier holds a trapdoor for a commitment that lets them
//! simulate transcripts. Hence proofs are non-transferable: any third party
//! cannot tell whether they were produced honestly or simulated.
//!
//! Construction sketch [JSB96](https://link.springer.com/chapter/10.1007/3-540-68339-9_13). One branch is proven honestly, the other is
//! simulated by fixing the challenge and programming the commitment so that
//! the verifier transcript is accepting. The designated verifier can simulate
//! either branch using their trapdoor. See tests for relations and checks.
//!
//! Points of interest:
//! - Honest-or-simulated OR proof: exactly one branch uses the real secret x.
//! - Non-transferability: the designated verifier can simulate
//!   indistinguishable proofs.
//! - Fiat-Shamir with Merlin transcript domain.
//! - Public API: DvProof::prove(..) and DvProof::verify(..).
//!
//! ## Example:
//! ```rust
//! # use dlog_sigma_primitives::proofs::{Proof, dvzkp::{DesignatedPair, DvPublicBorrowed, DvWitness, DvProof}};
//! # use merlin::Transcript;
//! # use rand::thread_rng;
//! # use dlog_group::{group::{GroupPoint, GroupScalar}};
//! # use dlog_sigma_primitives::elgamal::keys::{ElGamalParams, KeyPair};
//! # use dlog_sigma_primitives::Curve;
//! # type Scalar = <Curve as GroupScalar>::Scalar;
//!
//! # fn main() {
//! // Verifier designates itself (publishes base B0 and P0=[sv]B0, keeps sv).
//! let mut rng = thread_rng();
//! let b0 = Curve::point_random(&mut rng);
//! let (dv_pub, _dv_sec) = DesignatedPair::new(b0, &mut rng).into_tuple();
//!
//! // Prover chooses the second branch and prepares matching relation P1A=[x]B1A, P1B=[x]B1B.
//! let b1a = Curve::point_random(&mut rng);
//! let b1b = Curve::point_random(&mut rng);
//! let x = dlog_sigma_primitives::elgamal::keys::SecretScalar::<Curve>::new(&mut rng);
//! let p1a = b1a * x.expose();
//! let p1b = b1b * x.expose();
//!
//! // Assemble public instance and witness, then prove and verify.
//! let public = DvPublicBorrowed::<Curve>::new(&dv_pub, &b1a, &b1b, &p1a, &p1b);
//! let wit = DvWitness::new(x); // prove S1 honestly; S0 is simulated
//! let proof = DvProof::prove(public, &wit, &mut rng);
//! proof.verify(public).expect("proof must verify");
//! # }
//! ```
use core::fmt::Debug;
use core::marker::PhantomData;

use dlog_group::group::Group;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    elgamal::keys::SecretScalar,
    error::Error,
    proofs::{Proof, SigmaProtocol, TranscriptForGroup},
};

use dlog_group::serde::{PointHelper, ScalarHelper};
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub struct DesignatedSecret<G: Group> {
    pub sv: SecretScalar<G>,
}

impl<G: Group> DesignatedSecret<G> {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self {
            sv: SecretScalar::new(rng),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DesignatedPublic<G: Group> {
    pub base0: G::Point, // binds pv to this base
    pub pv: G::Point,    // pv = [sv] * base0
}

impl<G: Group> DesignatedPublic<G> {
    pub fn new(ds: &DesignatedSecret<G>, base0: G::Point) -> Self {
        Self {
            base0,
            pv: base0 * ds.sv.expose(),
        }
    }
}

#[derive(Debug)]
pub struct DesignatedPair<G: Group> {
    pub ds: DesignatedSecret<G>,
    pub dp: DesignatedPublic<G>,
}

impl<G: Group> DesignatedPair<G> {
    pub fn new<R: RngCore + CryptoRng>(base0: G::Point, rng: &mut R) -> Self {
        let ds = DesignatedSecret::new(rng);
        let dp = DesignatedPublic::new(&ds, base0);
        Self { ds, dp }
    }
    pub fn into_tuple(self) -> (DesignatedPublic<G>, DesignatedSecret<G>) {
        (self.dp, self.ds)
    }
}

/// Public inputs for the DV statement.
/// `S0: P0 = [x] B0`. Those are the values exposed Designated Verifier.
/// `S1: P1A = [x] B1A` and `P1B = [x] B1B`.
/// Constraint: B1A and B1B must be independent generators
#[derive(Debug, Clone, Copy)]
pub struct DvPublicBorrowed<'a, G: Group> {
    pub dv: &'a DesignatedPublic<G>,
    pub b1a: &'a G::Point,
    pub b1b: &'a G::Point,
    pub p1a: &'a G::Point,
    pub p1b: &'a G::Point,
}

impl<'a, G: Group> DvPublicBorrowed<'a, G> {
    pub fn new(
        dv: &'a DesignatedPublic<G>,
        b1a: &'a G::Point,
        b1b: &'a G::Point,
        p1a: &'a G::Point,
        p1b: &'a G::Point,
    ) -> Self {
        Self {
            dv,
            b1a,
            b1b,
            p1a,
            p1b,
        }
    }
}

/// Witness for the designated-verifier proof.
///
/// Let the two statements be:
/// ```text
///   S0: P0 = [x] B0
///   S1: P1A = [x] B1A  and  P1B = [x] B1B
/// ```
/// The protocol proves `S0` OR `S1`. Exactly one branch is proved honestly with the
/// real secret x; the other branch is simulated so that the verifier cannot
/// tell which branch was real. The chosen enum variant indicates which branch
/// is the honest one.
///
/// Guidance:
/// - Use `First { x }` to prove the first statement (`S0`) honestly.
/// - Use `Second  { x }` to prove the second statement (`S1`) honestly.
///
/// Designated-verifier context:
/// - Typically the verifier publishes `pv = [sv] B0` and keeps `sv` secret.
/// - Then `P0 := pv`. Since the prover does not know `sv`, they **cannot** honestly
///   prove `S0`. They should pick `Second { x }` and prove `S1` honestly, while the
///   `S0` branch is simulated.
/// - The verifier, knowing `sv`, can generate simulated transcripts that are
///   indistinguishable from real ones; hence non-transferability.
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub enum DvWitness<G: Group> {
    First { x: SecretScalar<G> },  // knows `x` for `P0 = [x] B0`
    Second { x: SecretScalar<G> }, // knows `x` for `P1A = [x] B1A` and `P1B = [x] B1B`
}

impl<G: Group> DvWitness<G> {
    pub fn new_simulate(x: SecretScalar<G>) -> Self {
        Self::First { x }
    }
    pub fn new(x: SecretScalar<G>) -> Self {
        Self::Second { x }
    }
}

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct DvState<G: Group> {
    t: SecretScalar<G>, // honest branch randomizer
    c_sim: G::Scalar,   // simulated challenge
    z_sim: G::Scalar,   // simulated response
    // cached commitments
    i0: Option<G::Point>,
    i1a: Option<G::Point>,
    i1b: Option<G::Point>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DvProof<G: Group> {
    // Commitments
    #[serde(with = "PointHelper::<G>")]
    pub i0: G::Point,
    #[serde(with = "PointHelper::<G>")]
    pub i1a: G::Point,
    #[serde(with = "PointHelper::<G>")]
    pub i1b: G::Point,
    // Challenge split
    #[serde(with = "ScalarHelper::<G>")]
    pub c0: G::Scalar,
    #[serde(with = "ScalarHelper::<G>")]
    pub c1: G::Scalar,
    // Responses
    #[serde(with = "ScalarHelper::<G>")]
    pub z0: G::Scalar,
    #[serde(with = "ScalarHelper::<G>")]
    pub z1: G::Scalar,
}

#[derive(Debug, Clone)]
pub struct DvProtocol<G: Group>(PhantomData<G>);

impl<G: Group> SigmaProtocol for DvProtocol<G> {
    const DOMAIN: &'static [u8] = b"DV-NIZKP";

    type Public<'a> = DvPublicBorrowed<'a, G>;
    type Witness = DvWitness<G>;
    type Proof = DvProof<G>;
    type State = DvState<G>;

    fn absorb_public(public: Self::Public<'_>, tr: &mut Transcript) {
        tr.append_point::<G>(b"B0", &public.dv.base0);
        tr.append_point::<G>(b"B1A", public.b1a);
        tr.append_point::<G>(b"B1B", public.b1b);
        tr.append_point::<G>(b"P0", &public.dv.pv);
        tr.append_point::<G>(b"P1A", public.p1a);
        tr.append_point::<G>(b"P1B", public.p1b);
    }

    fn init<R: RngCore + CryptoRng>(_public: Self::Public<'_>, rng: &mut R) -> Self::State {
        DvState {
            t: SecretScalar::new(rng),
            c_sim: G::scalar_random(rng),
            z_sim: G::scalar_random(rng),
            i0: None,
            i1a: None,
            i1b: None,
        }
    }

    fn commit(
        public: Self::Public<'_>,
        state: &mut Self::State,
        witness: &Self::Witness,
        tr: &mut Transcript,
    ) {
        match *witness {
            DvWitness::First { .. } => {
                // Honest branch 0
                let i0 = public.dv.base0 * state.t.expose();
                // Simulated branch 1
                let i1a = *public.b1a * &state.z_sim - &(*public.p1a * &state.c_sim);
                let i1b = *public.b1b * &state.z_sim - &(*public.p1b * &state.c_sim);

                tr.append_point::<G>(b"I0", &i0);
                tr.append_point::<G>(b"I1A", &i1a);
                tr.append_point::<G>(b"I1B", &i1b);

                state.i0 = Some(i0);
                state.i1a = Some(i1a);
                state.i1b = Some(i1b);
            }
            DvWitness::Second { .. } => {
                // Simulated branch 0
                let i0 = public.dv.base0 * &state.z_sim - &(public.dv.pv * &state.c_sim);
                // Honest branch 1
                let i1a = *public.b1a * state.t.expose();
                let i1b = *public.b1b * state.t.expose();

                tr.append_point::<G>(b"I0", &i0);
                tr.append_point::<G>(b"I1A", &i1a);
                tr.append_point::<G>(b"I1B", &i1b);

                state.i0 = Some(i0);
                state.i1a = Some(i1a);
                state.i1b = Some(i1b);
            }
        }
    }

    fn complete(state: Self::State, witness: &Self::Witness, tr: &mut Transcript) -> Self::Proof {
        let c = tr.challenge_scalar::<G>(b"c");
        match witness {
            DvWitness::First { x } => {
                let c1 = state.c_sim;
                let c0 = c - &c1;
                let z0 = (c0 * x.expose()) + state.t.expose();
                DvProof {
                    i0: state.i0.expect("I0"),
                    i1a: state.i1a.expect("I1A"),
                    i1b: state.i1b.expect("I1B"),
                    c0,
                    c1,
                    z0,
                    z1: state.z_sim,
                }
            }
            DvWitness::Second { x } => {
                let c0 = state.c_sim;
                let c1 = c - &c0;
                let z1 = (c1 * x.expose()) + state.t.expose();
                DvProof {
                    i0: state.i0.expect("I0"),
                    i1a: state.i1a.expect("I1A"),
                    i1b: state.i1b.expect("I1B"),
                    c0,
                    c1,
                    z0: state.z_sim,
                    z1,
                }
            }
        }
    }

    fn update_transcript(proof: &Self::Proof, tr: &mut Transcript) -> Result<(), Error> {
        tr.append_point::<G>(b"I0", &proof.i0);
        tr.append_point::<G>(b"I1A", &proof.i1a);
        tr.append_point::<G>(b"I1B", &proof.i1b);
        Ok(())
    }

    fn verify_relation(
        public: Self::Public<'_>,
        proof: &Self::Proof,
        tr: &mut Transcript,
    ) -> Result<(), Error> {
        let c = tr.challenge_scalar::<G>(b"c");
        if c != proof.c0 + &proof.c1 {
            return Err(Error::ChallengeMismatch);
        }
        // Check branch 0
        let lhs0 = public.dv.base0 * &proof.z0;
        let rhs0 = proof.i0 + &(public.dv.pv * &proof.c0);
        if lhs0 != rhs0 {
            return Err(Error::CommitmentMismatch);
        }
        // Check branch 1
        let lhs1a = *public.b1a * &proof.z1;
        let rhs1a = proof.i1a + &(*public.p1a * &proof.c1);
        if lhs1a != rhs1a {
            return Err(Error::CommitmentMismatch);
        }
        let lhs1b = *public.b1b * &proof.z1;
        let rhs1b = proof.i1b + &(*public.p1b * &proof.c1);
        if lhs1b != rhs1b {
            return Err(Error::CommitmentMismatch);
        }
        Ok(())
    }
}

// Bind proof to protocol
impl<G: Group> Proof for DvProof<G> {
    type Protocol = DvProtocol<G>;
}

// --- region: Tests

#[cfg(test)]
mod tests {
    use crate::{
        elgamal::keys::SecretScalar,
        proofs::{
            dvzkp::{DesignatedPair, DvProof, DvPublicBorrowed, DvWitness},
            prelude::*,
        },
    };

    #[test]
    fn dv_first_branch_happy_path() {
        let mut rng = test_rng();
        let b0 = Curve::point_random(&mut rng);
        let (dv, ds) = DesignatedPair::new(b0, &mut rng).into_tuple();

        // The other group generators. Since we are in the simulator branch we can pick
        // them randomly.
        let b1a = Curve::point_random(&mut rng);
        let b1b = Curve::point_random(&mut rng);

        let p1a = Curve::point_random(&mut rng);
        let p1b = Curve::point_random(&mut rng);

        let public = DvPublicBorrowed::<Curve>::new(&dv, &b1a, &b1b, &p1a, &p1b);
        let wit = DvWitness::new_simulate(ds.sv);

        let proof = DvProof::prove(public, &wit, &mut rng);
        proof.verify(public).expect("simulation failed");
    }

    #[test]
    fn dv_second_branch_happy_path() {
        let mut rng = test_rng();
        let b0 = Curve::point_random(&mut rng);
        let (dv, _ds) = DesignatedPair::new(b0, &mut rng).into_tuple();

        // The other group generators.
        let b1a = Curve::point_random(&mut rng);
        let b1b = Curve::point_random(&mut rng);

        // Since we are in the second branch here we need to make the relation hold.
        let x = SecretScalar::<Curve>::new(&mut rng);
        let p1a = b1a * x.expose();
        let p1b = b1b * x.expose();

        let public = DvPublicBorrowed::<Curve>::new(&dv, &b1a, &b1b, &p1a, &p1b);
        let wit = DvWitness::new(x);

        let proof = DvProof::prove(public, &wit, &mut rng);
        proof.verify(public).expect("verification failed");
    }

    #[test]
    fn dv_wrong_relation_fails() {
        let mut rng = test_rng();
        let b0 = Curve::point_random(&mut rng);
        let (dv, _ds) = DesignatedPair::new(b0, &mut rng).into_tuple();

        // The other group generators.
        let b1a = Curve::point_random(&mut rng);
        let b1b = Curve::point_random(&mut rng);

        // No explicit relation between b1 and p1, in order to make it fail.
        let x = SecretScalar::<Curve>::new(&mut rng);
        let p1a = Curve::point_random(&mut rng);
        let p1b = Curve::point_random(&mut rng);

        let public = DvPublicBorrowed::<Curve>::new(&dv, &b1a, &b1b, &p1a, &p1b);
        let wit = DvWitness::new(x);

        let proof = DvProof::prove(public, &wit, &mut rng);
        let res = proof.verify(public);

        assert!(res.is_err(), "wrong relation should fail")
    }

    #[test]
    fn serde_roundtrip() {
        let mut rng = test_rng();
        let b0 = Curve::point_random(&mut rng);
        let (dv, _ds) = DesignatedPair::new(b0, &mut rng).into_tuple();

        // The other group generators.
        let b1a = Curve::point_random(&mut rng);
        let b1b = Curve::point_random(&mut rng);

        // Since we are in the second branch here we need to make the relation real.
        let x = SecretScalar::<Curve>::new(&mut rng);
        let p1a = b1a * x.expose();
        let p1b = b1b * x.expose();

        let public = DvPublicBorrowed::<Curve>::new(&dv, &b1a, &b1b, &p1a, &p1b);
        let wit = DvWitness::new(x);

        let proof = DvProof::prove(public, &wit, &mut rng);

        let json = serde_json::to_value(proof).unwrap();
        let de: DvProof<Curve> = serde_json::from_value(json).unwrap();

        de.verify(public)
            .expect("serde round-trip must preserve the proof");
    }
}

// endregion
