use dlog_sigma_primitives::prelude::*;
use merlin::Transcript;
use rand_core::OsRng;

#[test]
fn elgamal_basic_round_trip() {
    let mut rng = OsRng;

    // (sk, pk) sampled in the selected Curve
    let params = ElGamalParams::<Curve>::new(&mut rng);
    let (sk, pk) = KeyPair::<Curve>::new_from_params(&params, &mut rng).into_tuple();

    // Sample a random message
    let m = Curve::generator() * Curve::scalar_random(&mut rng);

    // Encrypt and decrypt
    let (ct, _r) = pk.encrypt(m, &params, &mut rng).into_tuple();

    let m_dec = sk.decrypt(&ct);

    assert_eq!(m, m_dec);
}

#[test]
fn pedersen_basic_round_trip() {
    use dlog_sigma_primitives::pedersen::commitment::{ExtendedPedersen, Parameters};

    let mut rng = OsRng;

    // Choose a maximum supported message vector length and derive generators.
    let list_len = 50;
    let params = Parameters::<Curve>::new(list_len, &mut rng);

    // Sample 40 messages (scalars) to commit.
    let messages: Vec<<Curve as GroupScalar>::Scalar> =
        (0..40u64).map(|_| Curve::scalar_random(&mut rng)).collect();

    // Variable-time, parallelized commitment (use const_commit for constant-time
    // needs).
    let (com, r) = ExtendedPedersen::var_commit(&params, &messages, &mut rng)
        .unwrap()
        .open();

    // Verify with the provided opening (messages and randomness).
    assert!(com.verify(&params, &messages, &r).is_ok());
}

#[test]
fn zero_basic_round_trip() {
    use dlog_sigma_primitives::proofs::zero::{ZeroProtocol, ZeroPublicBorrowed};
    let mut rng = OsRng;

    let params: ElGamalParams<Curve> = ElGamalParams::new(&mut rng);
    let (_sk, pk) = KeyPair::new_from_params(&params, &mut rng).into_tuple();

    // Zero plaintext (group identity)
    let ct = pk
        .encrypt(Curve::identity(), &params, &mut rng)
        .into_tuple();

    let public = ZeroPublicBorrowed::new(&pk, &params, ct.0);

    // Prover
    let mut tr_p = Transcript::new(b"example");
    let proof = ZeroProtocol::prove(public, &ct.1, &mut tr_p, &mut rng);

    // Verifier
    let mut tr_v = Transcript::new(b"example");
    ZeroProtocol::verify(public, &proof, &mut tr_v).expect("verification");
}
