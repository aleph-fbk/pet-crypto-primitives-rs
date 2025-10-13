//! Shuffle of Known Content (JG05, Sec. 3).
//!
//! Scope.
//! - This module proves that a Pedersen commitment C' opens to a permutation of
//!   a *public* list of scalars. It does not perform re-encryption; callers
//!   compose this proof with ElGamal operations externally.
//!
//! Construction outline.
//! - Outer layer reduces shuffle to a known-content instance by defining m`'_i =
//!   i * lambda + t_i` where `t_i` are derived from the transcript and lambda is a
//!   scalar challenge. The prover publishes a commitment `C' = (c * lambda +
//!   c_d) + com(f; 0)`, where `c = com(perm indices; r_c)`, `c_d =
//!   com(messages_d;  r_cd)`, `f_i = t_{perm(i)} - messages_d[i]`.
//! - Inner layer (KnownContentShuffle) proves that C' opens to a permutation of
//!   the known list `[m'_i]`. This follows JG05, Sec. 3, with a simple
//!   product-check using a random x.
//!
//! Transcript schedule (both sides must mirror exactly):
//!   1) append (commit, commit_d)
//!   2) derive RNG from label "c" and sample t_i
//!   3) append f list with label "f"
//!   4) derive lambda
//!   5) compute C' and append with label "c_prime"
//!   6) KnownContentShuffle:
//!      - derive x
//!      - append (c_d, c_delta, c_a)
//!      - derive e
//!      - check two Pedersen equalities and the folding relation

use dlog_group::group::Group;
use dlog_group::serde::{ScalarHelper, VecHelper};
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::{
    elgamal::{
        ciphertext::{Ciphertext, ExtendedCiphertext},
        keys::{ElGamalParams, PublicKey},
    },
    error::Error,
    pedersen::commitment::{ExtendedPedersen, Parameters, Pedersen},
    proofs::TranscriptForGroup,
};

// # Known-content shuffle (inner proof)

/// Proof that a Pedersen commitment opens to a permutation of a known list of
/// scalars.
///
/// Public inputs:
/// - params: Pedersen parameters `(H, G_i, list_len)`.
/// - commitment: `C' = com(m_{pi(i)}; r_c)`.
/// - messages: `[m_i] (known, in natural order)`.
///
/// Witness:
/// - perm: permutation pi on `{0..n-1}`.
/// - r_c: opening randomness of commitment.
///
/// Construction (JG05, Sec. 3):
/// - Draw x uniformly at random via transcript.
/// - Use product argument over `(m_{pi(i)} - x)` with auxiliary commitments c_d,
///   c_delta, c_a.
/// - Draw e as second challenge; respond with (f, z) and (f_delta, z_delta).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct KnownContentShuffle<G: Group> {
    /// C' used in this inner argument (carried for coherence checks).
    commitment: Pedersen<G>,
    // Commitments of the inner NIZK
    c_d: Pedersen<G>,
    c_delta: Pedersen<G>,
    c_a: Pedersen<G>,
    // Responses
    #[serde(with = "VecHelper::<ScalarHelper<G>, 2>")]
    f: Vec<G::Scalar>,
    #[serde(with = "ScalarHelper::<G>")]
    z: G::Scalar,
    #[serde(with = "VecHelper::<ScalarHelper<G>, 2>")]
    f_delta: Vec<G::Scalar>,
    #[serde(with = "ScalarHelper::<G>")]
    z_delta: G::Scalar,
}

impl<G: Group> KnownContentShuffle<G> {
    /// Prover: construct a KnownContentShuffle proof.
    ///
    /// Preconditions:
    /// - perm.len() == messages.len() == params.list_len >= 2.
    ///
    /// Transcript:
    /// - Appends: "commitment", "c_d", "c_delta", "c_a".
    /// - Challenges: x (before inner commits) and e (after).
    pub fn new<R>(
        params: &Parameters<G>,
        commitment: &ExtendedPedersen<G>,
        perm: &[usize],
        messages: &[G::Scalar],
        transcript: &mut Transcript,
        rng: &mut R,
    ) -> Self
    where
        R: CryptoRng + RngCore,
    {
        debug_assert_eq!(perm.len(), params.list_len);
        debug_assert!(perm.len() > 1);

        transcript.append_bytes(b"commitment", &commitment.to_pedersen().to_bytes());

        // First challenge x.
        // JG05 suggests a small integer range; here we sample mod p which is safe.
        let x = transcript.challenge_scalar::<G>(b"x");

        // Draw d[i], delta[i]; delta[n-1] = 0. Compute running products a[i].
        let n = params.list_len;
        let d0 = G::scalar_random(rng);
        let delta0 = d0;
        let mut d = Vec::with_capacity(n);
        let mut delta = Vec::with_capacity(n);
        let mut a = Vec::with_capacity(n);
        d.push(d0);
        delta.push(delta0);
        a.push(messages[perm[0]] - &x);
        for i in 1..n - 1 {
            d.push(G::scalar_random(rng));
            delta.push(G::scalar_random(rng));
            a.push(a[i - 1] * &(messages[perm[i]] - &x));
        }
        d.push(G::scalar_random(rng));
        delta.push(G::Scalar::from(0u64));
        a.push(a[n - 2] * &(messages[perm[n - 1]] - &x));

        // Inner commitments.
        let c_d_ex = ExtendedPedersen::var_commit(params, &d, rng).unwrap();
        let c_d = c_d_ex.to_pedersen();
        transcript.append_bytes(b"c_d", &c_d.to_bytes());

        let mut v_delta = Vec::with_capacity(n - 1);
        for i in 0..n - 1 {
            v_delta.push(G::Scalar::from(0u64) - &(delta[i] * &d[i + 1]));
        }
        let c_delta_ex = ExtendedPedersen::var_commit(params, &v_delta, rng).unwrap();
        let c_delta = c_delta_ex.to_pedersen();
        transcript.append_bytes(b"c_delta", &c_delta.to_bytes());

        let mut v_a = Vec::with_capacity(n - 1);
        for i in 0..n - 1 {
            v_a.push(
                delta[i + 1] - &((messages[perm[i + 1]] - &x) * &delta[i]) - &(a[i] * &d[i + 1]),
            );
        }
        let c_a_ex = ExtendedPedersen::var_commit(params, &v_a, rng).unwrap();
        let c_a = c_a_ex.to_pedersen();
        transcript.append_bytes(b"c_a", &c_a.to_bytes());

        // Second challenge e.
        let e = transcript.challenge_scalar::<G>(b"e");

        // Responses.
        let mut f = Vec::with_capacity(n);
        for i in 0..n - 1 {
            f.push(e * &messages[perm[i]] + &d[i]);
        }
        f.push(e * &messages[perm[n - 1]] + &d[n - 1]);

        let mut f_delta = Vec::with_capacity(n - 1);
        for i in 0..n - 1 {
            f_delta.push(
                e * &(delta[i + 1]
                    - &((messages[perm[i + 1]] - &x) * &delta[i])
                    - &(a[i] * &d[i + 1]))
                    - &(delta[i] * &d[i + 1]),
            );
        }

        // z values accumulate the commitment randomness.
        let z = e * commitment.randomness.expose() + c_d_ex.randomness.expose();
        let z_delta = e * c_a_ex.randomness.expose() + c_delta_ex.randomness.expose();

        Self {
            commitment: commitment.to_pedersen(),
            c_d,
            c_delta,
            c_a,
            f,
            z,
            f_delta,
            z_delta,
        }
    }

    /// Verifier: check the KnownContentShuffle proof.
    ///
    /// Returns Ok(()) iff both Pedersen equalities hold and the folding
    /// relation matches.
    pub fn verify(
        &self,
        params: &Parameters<G>,
        messages: &[G::Scalar],
        transcript: &mut Transcript,
    ) -> Result<(), Error> {
        if messages.len() != params.list_len {
            return Err(Error::LengthMismatch);
        }

        transcript.append_bytes(b"commitment", &self.commitment.to_bytes());
        let x = transcript.challenge_scalar::<G>(b"x");

        transcript.append_bytes(b"c_d", &self.c_d.to_bytes());
        transcript.append_bytes(b"c_delta", &self.c_delta.to_bytes());
        transcript.append_bytes(b"c_a", &self.c_a.to_bytes());

        let e = transcript.challenge_scalar::<G>(b"e");

        // Two Pedersen equalities bind (f, z) and (f_delta, z_delta).
        let lhs = (self.commitment * &e) + self.c_d;
        let rhs = Pedersen::var_commit_with_randomness(params, &self.f, &self.z);
        if lhs != rhs {
            return Err(Error::CommitmentMismatch);
        }
        let lhs = (self.c_a * &e) + self.c_delta;
        let rhs = Pedersen::var_commit_with_randomness(params, &self.f_delta, &self.z_delta);
        if lhs != rhs {
            return Err(Error::CommitmentMismatch);
        }

        // Folding check over messages.
        let n = params.list_len;
        if self.f.len() != n || self.f_delta.len() != n - 1 {
            return Err(Error::LengthMismatch);
        }
        let (first_f, rest_f) = self.f.split_first().ok_or(Error::LengthMismatch)?;
        let (first_msg, rest_msgs) = messages.split_first().ok_or(Error::LengthMismatch)?;

        let mut ff = *first_f - &(e * &x);
        let mut check = *first_msg - &x;
        let inv_e = G::scalar_inv(e);
        for ((f_i, msg_i), d_i) in rest_f.iter().zip(rest_msgs).zip(self.f_delta.iter()) {
            ff = (ff * &(*f_i - &(e * &x)) + d_i) * &inv_e;
            check *= *msg_i - &x;
        }
        if ff != check * &e {
            return Err(Error::CommitmentMismatch);
        }
        Ok(())
    }
}

// # Outer shuffle: builder + proof

/// Prover-side builder for the outer shuffle proof.
///
/// It commits to:
/// ```text
/// - c     = com(perm indices; r_c)
/// - c_d   = com(messages_d;  r_d)
/// ```
///
/// Then it derives transcript RNG to obtain t_i and publishes
/// - `f_i = t_{perm(i)} - messages_d[i]`
///
/// Finally, it reduces to a known-content instance by defining
/// ```text
/// - m'_i = i * lambda + t_i
/// - C' = (c * lambda + c_d) + com(f; 0)
/// ```
#[derive(Debug)]
pub struct ShuffleBuilder<G: Group> {
    commit: ExtendedPedersen<G>,
    commit_d: ExtendedPedersen<G>,
    messages_d: Vec<G::Scalar>,
}

impl<G: Group> ShuffleBuilder<G> {
    /// Initialize the builder; commits to the permutation indices and to fresh
    /// masks.
    ///
    /// Arguments:
    /// - params: Pedersen parameters.
    /// - perm: permutation over {0..n-1}. Only the scalars form is used to
    ///   commit.
    /// - rng: source of randomness.
    pub fn new<R: RngCore + CryptoRng>(
        params: &Parameters<G>,
        perm: &[usize],
        rng: &mut R,
    ) -> Self {
        let perm_scalars = perm
            .iter()
            .map(|&x| G::Scalar::from(x as u64))
            .collect::<Vec<_>>();
        let commit = ExtendedPedersen::var_commit(params, &perm_scalars, rng).unwrap();

        let mut messages_d = Vec::with_capacity(params.list_len);
        for _ in 0..params.list_len {
            messages_d.push(G::scalar_random(rng));
        }
        let commit_d = ExtendedPedersen::var_commit(params, &messages_d, rng).unwrap();

        Self {
            commit,
            commit_d,
            messages_d,
        }
    }

    /// Accumulator for the ElGamal linkage: `E_d = sum(messages_d[i] *
    /// Shuffled[i]) + Enc_id`.
    pub fn get_e_d<R: RngCore + CryptoRng>(
        &self,
        pk: &PublicKey<G>,
        el_params: &ElGamalParams<G>,
        shuffled: &[Ciphertext<G>],
        rng: &mut R,
    ) -> ExtendedCiphertext<G> {
        let identity_encryption = ExtendedCiphertext::id_new(pk, el_params, rng);
        let msm = Ciphertext::var_msm(shuffled, &self.messages_d);
        msm + &identity_encryption
    }

    /// Append c and c_d to the transcript.
    pub fn update_transcript1(&self, transcript: &mut Transcript) {
        transcript.append_bytes(b"commit", &self.commit.inner.to_bytes());
        transcript.append_bytes(b"commit_d", &self.commit_d.inner.to_bytes());
    }

    /// Append the f list with label "f", using canonical scalar encoding.
    pub fn update_transcript2(&self, transcript: &mut Transcript, f_list: &[G::Scalar]) {
        let mut buffer = vec![0u8; G::SCALAR_SIZE];
        for f in f_list {
            G::scalar_to_bytes(&mut buffer, f);
            transcript.append_message(b"f", &buffer);
        }
    }

    /// Derive transcript RNG and compute:
    /// - `t_i` from the "c" challenge RNG;
    /// - `f_i = t_{perm(i)} - messages_d[i]`.
    pub fn compute_t(
        &self,
        perm: &[usize],
        transcript: &mut Transcript,
    ) -> (Vec<G::Scalar>, Vec<G::Scalar>) {
        let mut challenge_rng = transcript.challenge_shuffle::<G>(b"c");
        let t_list = (0..perm.len())
            .map(|_| G::scalar_random(&mut challenge_rng))
            .collect::<Vec<_>>();

        let mut f_list = Vec::with_capacity(perm.len());
        for i in 0..perm.len() {
            f_list.push(t_list[perm[i]] - &self.messages_d[i]);
        }
        (f_list, t_list)
    }

    /// Complete the outer proof by reducing to a KnownContentShuffle instance
    /// and proving it.
    ///
    /// Transcript:
    /// - After update_transcript2, this takes the "lambda" challenge, appends
    ///   "c_prime", then invokes KnownContentShuffle::new which appends its own
    ///   inner commitments.
    pub fn complete<R: RngCore + CryptoRng>(
        self,
        params: &Parameters<G>,
        f_list: &[G::Scalar],
        t_list: &[G::Scalar],
        perm: &[usize],
        transcript: &mut Transcript,
        rng: &mut R,
    ) -> Shuffle<G> {
        let lambda = transcript.challenge_scalar::<G>(b"lambda");

        // Cloning pedersen commitments for return value
        let c = self.commit.to_pedersen();
        let c_d = self.commit_d.to_pedersen();

        // C' reduction: (c * lambda + c_d) + com(f; 0).
        let pre = (self.commit * &lambda) + self.commit_d;
        let commit_f =
            ExtendedPedersen::var_commit_with_randomness(params, f_list, &G::Scalar::from(0u64));
        let c_prime = (pre.to_pedersen())
            + Pedersen::var_commit_with_randomness(params, f_list, &G::Scalar::from(0u64));
        transcript.append_bytes(b"c_prime", &c_prime.to_bytes());

        // Known-content messages m'_i = i * lambda + t_i.
        let mut messages = Vec::with_capacity(t_list.len());
        for (i, t) in t_list.iter().enumerate() {
            messages.push(G::Scalar::from(i as u64) * &lambda + t);
        }

        // Inner proof on C' w.r.t. messages m'.
        let kcs =
            KnownContentShuffle::new(params, &(pre + commit_f), perm, &messages, transcript, rng);

        Shuffle {
            c,
            c_d,
            f: f_list.to_owned(),
            kcs,
        }
    }
}

/// Outer shuffle proof object.
///
/// Public components:
/// - c, c_d, f, and the inner KnownContentShuffle proof over C'.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Shuffle<G: Group> {
    // outer commitments
    c: Pedersen<G>,
    c_d: Pedersen<G>,
    // outer responses
    #[serde(with = "VecHelper::<ScalarHelper<G>, 2>")]
    f: Vec<G::Scalar>,
    // inner argument over C' and m'
    kcs: KnownContentShuffle<G>,
}

impl<G: Group> Shuffle<G> {
    /// Build the ElGamal accumulator E_d for linkage checks.
    ///
    /// `E_d = sum_i (-f_i) * Shuffled[i] + Enc_id(randomness_d)`.
    pub fn get_e_d(
        &self,
        pk: &PublicKey<G>,
        el_params: &ElGamalParams<G>,
        shuffled: &[Ciphertext<G>],
        randomness_d: &G::Scalar,
    ) -> Ciphertext<G> {
        let identity_encryption =
            Ciphertext::from_randomness(pk, el_params, &G::identity(), randomness_d);
        let neg_f = self
            .f
            .iter()
            .map(|c| G::Scalar::from(0u64) - c)
            .collect::<Vec<_>>();
        let msm = Ciphertext::var_msm(shuffled, &neg_f);
        msm + identity_encryption
    }

    /// Check coherence of shuffled re-encryption with the NIZKP.
    ///
    /// Verifies that:
    ///   `e_d - sum_i Originals[i]*t_i + sum_i Shuffled[i]*f_i = Enc_id(z)`
    #[allow(clippy::too_many_arguments)]
    pub fn check_re_encryption(
        &self,
        pk: &PublicKey<G>,
        params: &ElGamalParams<G>,
        e_d: &Ciphertext<G>,
        z: &G::Scalar,
        t: &[G::Scalar],
        originals: &[Ciphertext<G>],
        shuffled: &[Ciphertext<G>],
    ) -> Result<(), Error> {
        let mut lhs = *e_d;
        for i in 0..originals.len() {
            lhs -= originals[i] * &t[i];
            lhs += shuffled[i] * &self.f[i];
        }
        let rhs = pk.encrypt_id(params, z).inner;
        if lhs != rhs {
            return Err(Error::CommitmentMismatch);
        }
        Ok(())
    }

    /// Verify the outer proof and return the derived t_i to be used for linkage
    /// checks.
    ///
    /// Transcript:
    /// - Replays "commit", "commit_d", samples t from "c", appends f with label
    ///   "f", derives lambda, checks C' equality, then calls the inner verifier
    ///   which derives x and e and checks the KCS relations.
    pub fn verify(
        &self,
        params: &Parameters<G>,
        transcript: &mut Transcript,
    ) -> Result<Vec<G::Scalar>, Error> {
        transcript.append_bytes(b"commit", &self.c.to_bytes());
        transcript.append_bytes(b"commit_d", &self.c_d.to_bytes());

        // RNG for t_i.
        let mut challenge_rng = transcript.challenge_shuffle::<G>(b"c");
        let t_list = (0..params.list_len)
            .map(|_| G::scalar_random(&mut challenge_rng))
            .collect::<Vec<_>>();

        // Append f list, exactly as the prover did.
        let mut buffer = vec![0u8; G::SCALAR_SIZE];
        for f_i in &self.f {
            G::scalar_to_bytes(&mut buffer, f_i);
            transcript.append_message(b"f", &buffer);
        }

        // Reduction scalar and C' check.
        let lambda = transcript.challenge_scalar::<G>(b"lambda");
        let kcs_c = ((self.c * &lambda) + self.c_d)
            + Pedersen::var_commit_with_randomness(params, &self.f, &G::Scalar::from(0u64));
        if self.kcs.commitment != kcs_c {
            return Err(Error::CommitmentMismatch);
        }
        transcript.append_bytes(b"c_prime", &kcs_c.to_bytes());

        // Messages for the inner proof.
        let mut messages = Vec::with_capacity(t_list.len());
        for (i, t) in t_list.iter().enumerate() {
            messages.push(G::Scalar::from(i as u64) * &lambda + t);
        }

        // Inner verification on C' and m'.
        self.kcs.verify(params, &messages, transcript)?;
        Ok(t_list)
    }
}

// region:    --- Tests

#[cfg(test)]
mod tests {
    use crate::Curve;
    use rand::{seq::SliceRandom, thread_rng};

    use dlog_group::group::{GroupPoint, GroupScalar};

    use super::*;
    use crate::elgamal::keys::KeyPair;

    #[test]
    fn verify_shuffle_proof() {
        let mut rng = thread_rng();
        let params = Parameters::new(10, &mut rng);
        let mut perm: Vec<usize> = (0..10).collect();
        perm.shuffle(&mut rng);
        let originals = perm
            .clone()
            .into_iter()
            .map(|_x| Curve::scalar_random(&mut rng))
            .collect::<Vec<_>>();
        let mut shuffled = vec![];
        for i in perm.clone() {
            shuffled.push(originals[i])
        }
        let commitment =
            ExtendedPedersen::<Curve>::var_commit(&params, &shuffled, &mut rng).unwrap();
        let mut transcript = Transcript::new(b"test");

        let proof = KnownContentShuffle::new(
            &params,
            &commitment,
            &perm,
            &originals,
            &mut transcript,
            &mut rng,
        );

        let mut transcript1 = Transcript::new(b"test");
        proof.verify(&params, &shuffled, &mut transcript1).unwrap()
    }

    #[test]
    fn verify_shuffle_builder_proof() {
        let mut rng = thread_rng();
        let params: Parameters<Curve> = Parameters::new(10, &mut rng);
        let mut perm: Vec<usize> = (0..10).collect();
        perm.shuffle(&mut rng);
        let messages = perm
            .clone()
            .into_iter()
            .map(|x| <Curve as GroupScalar>::Scalar::from(x as u64))
            .collect::<Vec<_>>();
        // Generate ElGamal Public Key
        let el_params = ElGamalParams::new(&mut rng);
        let (_sk, pk) = KeyPair::<Curve>::new_from_params(&el_params, &mut rng).into_tuple();
        // Generate the ciphertexts and shuffle them
        let originals = messages
            .into_iter()
            .map(|_m| pk.encrypt(Curve::point_random(&mut rng), &el_params, &mut rng))
            .collect::<Vec<_>>();
        let mut shuffled = vec![];
        for i in perm.clone() {
            shuffled.push(originals[i].inner)
        }
        // Prover
        let builder: ShuffleBuilder<_> = ShuffleBuilder::new(&params, &perm, &mut rng);
        let mut transcript = Transcript::new(b"test");
        builder.update_transcript1(&mut transcript);
        let (f_list, t_list) = builder.compute_t(&perm, &mut transcript);
        builder.update_transcript2(&mut transcript, &f_list);
        let proof: Shuffle<_> =
            builder.complete(&params, &f_list, &t_list, &perm, &mut transcript, &mut rng);

        // Verifier
        let mut transcript1 = Transcript::new(b"test");
        proof.verify(&params, &mut transcript1).unwrap();
    }

    #[test]
    fn verify_shuffle_builder_re_encryption() {
        let mut rng = thread_rng();
        let params: Parameters<Curve> = Parameters::new(10, &mut rng);
        let mut perm: Vec<usize> = (0..10).collect();
        perm.shuffle(&mut rng);
        let messages = perm
            .clone()
            .into_iter()
            .map(|x| <Curve as GroupScalar>::Scalar::from(x as u64))
            .collect::<Vec<_>>();
        // Generate ElGamal Public Key
        let el_params = ElGamalParams::new(&mut rng);
        let (_sk, pk) = KeyPair::<Curve>::new_from_params(&el_params, &mut rng).into_tuple();
        // Generate the ciphertexts and shuffle them
        let originals = messages
            .into_iter()
            .map(|_m| {
                pk.encrypt(Curve::point_random(&mut rng), &el_params, &mut rng)
                    .inner
            })
            .collect::<Vec<_>>();
        let mut shuffled = vec![];
        for i in perm.clone() {
            shuffled.push(originals[i])
        }
        // Prover
        let builder: ShuffleBuilder<_> = ShuffleBuilder::new(&params, &perm, &mut rng);
        let mut transcript = Transcript::new(b"test");
        builder.update_transcript1(&mut transcript);
        let (f_list, t_list) = builder.compute_t(&perm, &mut transcript);
        builder.update_transcript2(&mut transcript, &f_list);
        let e_d = builder.get_e_d(&pk, &el_params, &shuffled, &mut rng);
        let proof: Shuffle<_> =
            builder.complete(&params, &f_list, &t_list, &perm, &mut transcript, &mut rng);

        // Verifier
        let mut transcript1 = Transcript::new(b"test");
        let t_list = proof.verify(&params, &mut transcript1).unwrap();
        proof
            .check_re_encryption(
                &pk,
                &el_params,
                &e_d.inner,
                e_d.random_scalar.expose(),
                &t_list,
                &originals,
                &shuffled,
            )
            .unwrap();
    }
}
// endregion
