//! Sigma-protocol core traits and concrete implementations.
//!
//! This module defines a minimal, auditable interface for Sigma-style proofs
//! over discrete-logarithm groups. It standardizes transcript handling so that
//! challenge derivation is stable across prover and verifier.
//!
//! ---------------------------------------------------------------------------
//! Design principles
//! ---------------------------------------------------------------------------
//! 1. Canonical transcript semantics. All public inputs are absorbed exactly
//!    once, immediately after domain separation, in a fixed order defined by
//!    each protocol.
//! 2. Minimal mutable state. The prover state stores only ephemeral randomness
//!    and the commitment material required to serialize the proof. It is
//!    consumed by `complete` and must be zeroized on drop.
//! 3. Explicit steps. Prover side: init, commit, derive challenge, compute
//!    responses. Verifier side: absorb(public, proof), derive challenge, check
//!    relations.
//
//! ---------------------------------------------------------------------------
//! Transcript contract
//! ---------------------------------------------------------------------------
//! - Each protocol declares a unique, immutable byte string `DOMAIN`.
//! - Both prover and verifier must call `start_proof` before any other
//!   transcript operation for a given instance. `start_proof` appends domain
//!   separation and absorbs the public statement once in canonical order.
//! - The helper methods `prove` and `verify` implement the canonical flow.
//!   Custom flows must mirror them.
//
//! ---------------------------------------------------------------------------
//! Pitfalls avoided
//! ---------------------------------------------------------------------------
//! - Transcript divergence. Domain separation and one-shot public absorption
//!   make detached verification and proving traverse the same transcript trace.
//! - Sticky randomness. Ephemeral state implements Zeroize and is consumed by
//!   `complete`, so temporary scalars do not linger in memory.
//!
//! With these rules, heterogeneous Sigma-protocols share one algebraic
//! interface and a common audit trail, and compose cleanly via Fiat-Shamir.

use core::fmt::Debug;

use dlog_group::{group::Group, utils::RandomBytesProvider};
use merlin::Transcript;
use rand_chacha::ChaChaRng;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::elgamal::ciphertext::Ciphertext;
use crate::error::Error;

// -----------------------------------------------------------------------------
// Submodules with concrete proofs
// -----------------------------------------------------------------------------

// pub mod compound;
pub mod disjunctive;
pub mod dvzkp;
pub mod exp;
pub mod fingerprints;
pub mod log_equality;
pub mod not_identity;
pub mod plaintext;
pub mod shuffle;
pub mod ver_decr;
pub mod zero;

/// Core trait.
pub trait SigmaProtocol {
    /// Protocol-wide domain separator (unique per proof type).
    ///
    /// Once published, this constant must not change. If a breaking change is
    /// needed, define a new protocol type with a different `DOMAIN`.
    const DOMAIN: &'static [u8];

    /// Borrowed public input (to avoid cloning in implementations).
    ///
    /// Use a thin view struct or a tuple of references.
    type Public<'a>: Debug + Clone
    where
        Self: 'a;

    /// Witness owned by the prover.
    type Witness: Debug + Zeroize + ZeroizeOnDrop;

    /// Final proof object.
    type Proof: Debug + Clone + Serialize + for<'de> Deserialize<'de>;

    /// Ephemeral state across `init` and `commit`. It is consumed by
    /// `complete`.
    type State: Debug + Zeroize + ZeroizeOnDrop;

    // -------------------------------------------------------------------------
    // Public absorption
    // -------------------------------------------------------------------------
    /// Absorb the public statement into the transcript.
    fn absorb_public(public: Self::Public<'_>, transcript: &mut Transcript);

    // -------------------------------------------------------------------------
    // Prover
    // -------------------------------------------------------------------------
    /// Initialize ephemeral randomness and state.
    ///
    /// Draw all randomness required by the commitment step and store only what
    /// is needed by `commit` and `complete`.
    fn init<R: RngCore + CryptoRng>(public: Self::Public<'_>, rng: &mut R) -> Self::State;

    /// Produce and absorb commitments.
    ///
    /// Requirements:
    /// - compute commitments from `state` and `witness`;
    /// - append the commitment bytes to `transcript`;
    /// - retain in `state` anything needed later to complete a `Proof`.
    fn commit(
        public: Self::Public<'_>,
        state: &mut Self::State,
        witness: &Self::Witness,
        transcript: &mut Transcript,
    );

    /// Derive the challenge and compute responses to produce a final `Proof`
    /// object. Consume `state`.
    fn complete(
        state: Self::State,
        witness: &Self::Witness,
        transcript: &mut Transcript,
    ) -> Self::Proof;

    // -------------------------------------------------------------------------
    // Verifier
    // -------------------------------------------------------------------------
    /// Replay transcript absorption using only `proof`.
    ///
    /// This must mirror the prover's commitment absorption exactly. Do not
    /// derive the challenge here.
    fn update_transcript(proof: &Self::Proof, transcript: &mut Transcript) -> Result<(), Error>;

    /// Re-derive the challenge and check the algebraic relations.
    fn verify_relation(
        public: Self::Public<'_>,
        proof: &Self::Proof,
        transcript: &mut Transcript,
    ) -> Result<(), Error>;

    // -------------------------------------------------------------------------
    // Convenience helpers
    // -------------------------------------------------------------------------
    /// One-shot proving: start_proof, init, commit, complete.
    fn prove<R: RngCore + CryptoRng>(
        public: Self::Public<'_>,
        witness: &Self::Witness,
        transcript: &mut Transcript,
        rng: &mut R,
    ) -> Self::Proof {
        transcript.start_proof(Self::DOMAIN, public.clone(), |tr, p| Self::absorb_public(p, tr));
        let mut state = Self::init(public.clone(), rng);
        Self::commit(public, &mut state, witness, transcript);
        Self::complete(state, witness, transcript)
    }

    /// Verification with a fresh transcript.
    fn verify(
        public: Self::Public<'_>,
        proof: &Self::Proof,
        transcript: &mut Transcript,
    ) -> Result<(), Error> {
        transcript.start_proof(Self::DOMAIN, public.clone(), |tr, p| Self::absorb_public(p, tr));
        Self::update_transcript(proof, transcript)?;
        Self::verify_relation(public, proof, transcript)
    }
}

// -----------------------------------------------------------------------------
// Helper trait that hangs off the proof type
// -----------------------------------------------------------------------------
/// Convenience one-shoot proof.
///
/// Implement this trait by setting `type Protocol = YourProtocol<...>;`.
/// The default methods enforce the canonical flow.
pub trait Proof: Sized {
    type Protocol: SigmaProtocol<Proof = Self>;

    /// One-shot proving that hides the Transcript object.
    fn prove<'a, R>(
        public: <Self::Protocol as SigmaProtocol>::Public<'a>,
        witness: &<Self::Protocol as SigmaProtocol>::Witness,
        rng: &mut R,
    ) -> Self
    where
        R: RngCore + CryptoRng,
    {
        let mut tr = Transcript::new(b"");
        <Self::Protocol as SigmaProtocol>::prove(public, witness, &mut tr, rng)
    }

    /// One-shot verification that hides the Transcript object.
    fn verify<'a>(
        &self,
        public: <Self::Protocol as SigmaProtocol>::Public<'a>,
    ) -> Result<(), Error> {
        let mut tr = Transcript::new(b"");
        <Self::Protocol as SigmaProtocol>::verify(public, self, &mut tr)
    }
}

// -----------------------------------------------------------------------------
// Transcript helpers
// -----------------------------------------------------------------------------

/// Extension trait for Merlin transcripts with group-specific helpers.
///
/// Methods standardize the absorption of points, scalars, and ciphertexts,
/// and the derivation of challenges and replayable RNGs.
pub trait TranscriptForGroup {
    /// Begin a proof with `proof_label` and absorb the public statement once.
    ///
    /// The closure `absorb_public` implements the canonical public absorption
    /// for the protocol. It is executed immediately after domain separation.
    fn start_proof<P, F>(&mut self, proof_label: &'static [u8], public: P, absorb_public: F)
    where
        P: Clone,
        F: FnOnce(&mut Transcript, P);

    /// Append raw bytes into the transcript under a stable label.
    fn append_bytes(&mut self, label: &'static [u8], bytes: &[u8]);

    /// Append a group point under `label`.
    fn append_point<G: Group>(&mut self, label: &'static [u8], point: &G::Point);

    /// Append a scalar under `label`.
    fn append_scalar<G: Group>(&mut self, label: &'static [u8], scalar: &G::Scalar);

    /// Append an ElGamal ciphertext under `label`.
    fn append_ciphertext<G: Group>(&mut self, label: &'static [u8], ciphertext: &Ciphertext<G>);

    /// Derive a challenge scalar. All public input and commitments must have
    /// been absorbed before calling this.
    fn challenge_scalar<G: Group>(&mut self, label: &'static [u8]) -> G::Scalar;

    /// Derive a deterministic ChaCha RNG from the transcript.
    /// Suitable for shuffles or sampling that must be replayable.
    fn challenge_shuffle<G: Group>(&mut self, label: &'static [u8]) -> ChaChaRng;
}

impl TranscriptForGroup for Transcript {
    fn start_proof<P, F>(&mut self, proof_label: &'static [u8], public: P, absorb_public: F)
    where
        P: Clone,
        F: FnOnce(&mut Transcript, P),
    {
        self.append_message(b"dom-sep", proof_label);
        absorb_public(self, public);
    }

    fn append_bytes(&mut self, label: &'static [u8], bytes: &[u8]) {
        self.append_message(label, bytes);
    }

    fn append_point<G: Group>(&mut self, label: &'static [u8], point: &G::Point) {
        let mut output = vec![0_u8; G::POINT_SIZE];
        G::point_to_bytes(&mut output, point);
        self.append_bytes(label, &output);
    }

    fn append_scalar<G: Group>(&mut self, label: &'static [u8], scalar: &G::Scalar) {
        let mut output = vec![0_u8; G::SCALAR_SIZE];
        G::scalar_to_bytes(&mut output, scalar);
        self.append_bytes(label, &output);
    }

    fn append_ciphertext<G: Group>(&mut self, label: &'static [u8], ciphertext: &Ciphertext<G>) {
        let output = ciphertext.to_bytes();
        self.append_bytes(label, &output);
    }

    fn challenge_scalar<G: Group>(&mut self, label: &'static [u8]) -> G::Scalar {
        G::scalar_from_random_bytes(RandomBytesProvider::new(self, label))
    }

    fn challenge_shuffle<G: Group>(&mut self, label: &'static [u8]) -> ChaChaRng {
        G::rng_from_random_bytes(RandomBytesProvider::new(self, label))
    }
}

#[cfg(test)]
pub mod prelude {
    pub use dlog_group::group::Group;
    pub use merlin::Transcript;
    pub use rand::rngs::StdRng;
    pub use rand::{CryptoRng, RngCore, SeedableRng};

    use crate::elgamal::keys::{ElGamalParams, PublicKey};
    pub use crate::proofs::{Proof, SigmaProtocol, TranscriptForGroup};

    pub use crate::elgamal::keys::KeyPair;
    pub use crate::Curve;

    pub use dlog_group::group::{GroupPoint, GroupScalar};

    pub use rand::thread_rng;

    pub type Scalar = <Curve as GroupScalar>::Scalar;

    pub fn test_rng() -> StdRng {
        StdRng::seed_from_u64(7)
    }

    pub fn setup() -> (StdRng, ElGamalParams<Curve>, PublicKey<Curve>) {
        let mut rng = StdRng::seed_from_u64(7);
        let params = ElGamalParams::<Curve>::new(&mut rng);
        let (_sk, pk) = KeyPair::<Curve>::new_from_params(&params, &mut rng).into_tuple();
        (rng, params, pk)
    }
}
