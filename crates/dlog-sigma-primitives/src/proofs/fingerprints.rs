//! Decryption and prove of correctness
use dlog_group::serde::ScalarHelper;
use serde::{Deserialize, Serialize};

use dlog_group::group::Group;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};

use crate::{elgamal::ciphertext::Ciphertext, error::Error};

use super::TranscriptForGroup;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct VerifiableFingerprints<G: Group> {
    pub fp_lists: Vec<Vec<Ciphertext<G>>>,
    pub comm_lists: Vec<Vec<Ciphertext<G>>>,
    #[serde(with = "ScalarHelper::<G>")]
    pub response: G::Scalar,
}

impl<G: Group> VerifiableFingerprints<G> {
    /// Compute verifiable fingerprints of a list of lists of ciphertexts
    pub fn new<R: RngCore + CryptoRng>(
        ct_lists: Vec<Vec<Ciphertext<G>>>,
        rng: &mut R,
        transcript: &mut Transcript,
    ) -> Self {
        let z = G::scalar_random(rng);
        let t = G::scalar_random(rng);

        let mut fp_lists = vec![];
        let mut comm_lists = vec![];
        for ct_list in ct_lists {
            let mut fp_list = vec![];
            let mut comm_list = vec![];
            for ct in ct_list {
                let fp = ct * &z;
                let comm = ct * &t;
                transcript.append_ciphertext(b"fp", &fp);
                transcript.append_ciphertext(b"comm", &comm);
                fp_list.push(fp);
                comm_list.push(comm);
            }
            fp_lists.push(fp_list);
            comm_lists.push(comm_list);
        }

        // Challenge
        let challenge = transcript.challenge_scalar::<G>(b"c");

        // Response
        let response = t + &(challenge * &z);

        Self {
            fp_lists,
            comm_lists,
            response,
        }
    }

    /// Verify the proof that the fingerprints are correct, given the list of lists of original
    /// ciphertexts
    pub fn verify(
        &self,
        originals: &[Vec<Ciphertext<G>>],
        transcript: &mut Transcript,
    ) -> Result<(), Error> {
        // maybe add proper error here
        if originals.len() != self.fp_lists.len() {
            panic!("incoherent lengths of inputs");
        };
        for (original, fp) in originals.iter().zip(self.fp_lists.iter()) {
            if original.len() != fp.len() {
                panic!("incoherent lengths of inputs");
            };
        }
        for (fps, comms) in self.fp_lists.iter().zip(&self.comm_lists) {
            for (fp, comm) in fps.iter().zip(comms) {
                transcript.append_ciphertext(b"fp", fp);
                transcript.append_ciphertext(b"comm", comm);
            }
        }
        let challenge = transcript.challenge_scalar::<G>(b"c");

        for ((orig_row, fps_row), comm_row) in
            originals.iter().zip(&self.fp_lists).zip(&self.comm_lists)
        {
            for ((orig, fp), comm) in orig_row.iter().zip(fps_row).zip(comm_row) {
                let lhs = *orig * &self.response;
                let rhs = (*fp * &challenge) + comm;
                if lhs != rhs {
                    return Err(Error::CommitmentMismatch);
                }
            }
        }

        Ok(())
    }
}

// region: ---Tests

#[cfg(test)]
mod test {
    use crate::prelude::{Curve, *};
    use rand::thread_rng;

    use crate::elgamal::keys::{ElGamalParams, KeyPair};

    use super::*;

    #[test]
    fn verify_proof() {
        let mut rng = thread_rng();
        let params: ElGamalParams<Curve> = ElGamalParams::new(&mut rng);
        let (_, pk) = KeyPair::new_from_params(&params, &mut rng).into_tuple();

        let mut originals_list = vec![];
        for _ in 0..3 {
            let mut originals = vec![];
            // Make a list of random ciphertexts
            for _ in 0..2 {
                let value = Curve::point_random(&mut rng);
                originals.push(pk.encrypt(value, &params, &mut rng).inner);
            }
            originals_list.push(originals);
        }

        // Finally start the proof
        let mut transcript = Transcript::new(b"test");

        let proof = VerifiableFingerprints::new(originals_list.clone(), &mut rng, &mut transcript);

        let mut transcript1 = Transcript::new(b"test");

        proof.verify(&originals_list, &mut transcript1).unwrap();
    }
}
