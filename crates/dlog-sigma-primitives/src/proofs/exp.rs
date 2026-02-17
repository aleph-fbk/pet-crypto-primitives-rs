use crate::{elgamal::keys::SecretScalar, serde::CiphertextHelper};
use dlog_group::serde::ScalarHelper;
use serde::{Deserialize, Serialize};

use dlog_group::group::Group;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    elgamal::{
        ciphertext::Ciphertext,
        keys::{ElGamalParams, PublicKey},
    },
    error::Error,
    proofs::{Proof as ProofTrait, SigmaProtocol, TranscriptForGroup},
};

#[derive(Clone, Debug)]
pub struct ExpPublicBorrowed<'a, G: Group> {
    pub public_key: &'a PublicKey<G>,
    pub params: &'a ElGamalParams<G>,
    pub ciphertext: &'a Ciphertext<G>,
    pub base: &'a G::Point,
}

impl<'a, G: Group> ExpPublicBorrowed<'a, G> {
    pub fn new(
        public_key: &'a PublicKey<G>,
        params: &'a ElGamalParams<G>,
        ciphertext: &'a Ciphertext<G>,
        base: &'a G::Point,
    ) -> Self {
        Self {
            public_key,
            params,
            ciphertext,
            base,
        }
    }
}

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct ExpWitness<G: Group> {
    pub random_scalar: SecretScalar<G>,
    pub pt: SecretScalar<G>,
}

impl<G: Group> ExpWitness<G> {
    pub fn new(random_scalar: SecretScalar<G>, pt: SecretScalar<G>) -> Self {
        Self { random_scalar, pt }
    }
}

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct ExpState<G: Group> {
    randomness1: SecretScalar<G>,
    randomness2: SecretScalar<G>,
    commitment: Ciphertext<G>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct ExpProof<G: Group> {
    #[serde(with = "CiphertextHelper::<G>")]
    pub commitment: Ciphertext<G>,
    #[serde(with = "ScalarHelper::<G>")]
    pub response1: G::Scalar,
    #[serde(with = "ScalarHelper::<G>")]
    pub response2: G::Scalar,
}

pub struct ExpProtocol<G: Group>(core::marker::PhantomData<G>);

impl<G: Group> SigmaProtocol for ExpProtocol<G> {
    const DOMAIN: &'static [u8] = b"exp";

    type Public<'a>
        = ExpPublicBorrowed<'a, G>
    where
        Self: 'a;
    type Witness = ExpWitness<G>;
    type Proof = ExpProof<G>;
    type State = ExpState<G>;

    fn absorb_public(public: Self::Public<'_>, transcript: &mut Transcript) {
        transcript.append_point::<G>(b"base", public.base);
        transcript.append_bytes(b"pk", &public.public_key.to_bytes());
        transcript.append_ciphertext(b"ciphertext", public.ciphertext);
    }

    fn init<R: RngCore + CryptoRng>(public: Self::Public<'_>, rng: &mut R) -> Self::State {
        let randomness1 = SecretScalar::new(rng);
        let randomness2 = SecretScalar::new(rng);

        let mut commitment = public.public_key.to_ciphertext(public.params) * randomness1.expose();
        commitment.blinded_point += *public.base * randomness2.expose();

        ExpState {
            randomness1,
            randomness2,
            commitment,
        }
    }

    fn commit(
        _public: Self::Public<'_>,
        state: &mut Self::State,
        _witness: &Self::Witness,
        transcript: &mut Transcript,
    ) {
        transcript.append_ciphertext(b"commitment", &state.commitment);
    }

    fn complete(
        state: Self::State,
        witness: &Self::Witness,
        transcript: &mut Transcript,
    ) -> Self::Proof {
        let c = transcript.challenge_scalar::<G>(b"c");
        let response1 = c * witness.random_scalar.expose() + state.randomness1.expose();
        let response2 = c * witness.pt.expose() + state.randomness2.expose();

        ExpProof {
            commitment: state.commitment,
            response1,
            response2,
        }
    }

    fn update_transcript(proof: &Self::Proof, transcript: &mut Transcript) -> Result<(), Error> {
        transcript.append_ciphertext(b"commitment", &proof.commitment);
        Ok(())
    }

    fn verify_relation(
        public: Self::Public<'_>,
        proof: &Self::Proof,
        transcript: &mut Transcript,
    ) -> Result<(), Error> {
        let c = transcript.challenge_scalar::<G>(b"c");

        let mut lhs = public.public_key.to_ciphertext(public.params) * &proof.response1;
        lhs.blinded_point += *public.base * &proof.response2;

        let rhs = proof.commitment + (*public.ciphertext * &c);

        if lhs == rhs {
            Ok(())
        } else {
            Err(Error::CommitmentMismatch)
        }
    }
}

impl<G: Group> ProofTrait for ExpProof<G> {
    type Protocol = ExpProtocol<G>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elgamal::{ciphertext::ExtendedCiphertext, keys::KeyPair};
    use dlog_group::group::{GroupPoint, GroupScalar};
    use rand::thread_rng;

    #[test]
    fn verify_exp_proof() {
        let mut rng = thread_rng();
        let params: ElGamalParams<crate::Curve> = ElGamalParams::new(&mut rng);
        let (_, pk) = KeyPair::new_from_params(&params, &mut rng).into_tuple();
        let message = <crate::Curve as GroupScalar>::Scalar::random(&mut rng);
        let ct = ExtendedCiphertext::exp_new(&message, &pk, &params, &mut rng);

        let base = <crate::Curve as GroupPoint>::generator();
        let public = ExpPublicBorrowed {
            public_key: &pk,
            params: &params,
            ciphertext: &ct.inner,
            base: &base,
        };

        let witness = ExpWitness::new(ct.random_scalar, SecretScalar(message));
        let proof = ExpProof::prove(public.clone(), &witness, &mut rng);

        proof.verify(public).unwrap();
    }
}
