//! M-ElGamal keys and parameters.
//!
//! Points of interest:
//! 1. SecretScalar is non-cloneable and zeroizes on drop.
//! 2. SecretKey zeroizes on drop; PublicKey and ElGamalParams are Copy-safe.

use core::ops;
use dlog_group::group::Group;
use dlog_group::serde::PointHelper;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::proofs::ver_decr::{DecOk, DecOkProtocol};
use crate::proofs::SigmaProtocol;
use crate::{error::Error, proofs::ver_decr::DecOkPublicBorrowed};

use super::ciphertext::{Ciphertext, DiscreteLogTable, ExtendedCiphertext};

/// Secret wrapper around a group scalar that zeroizes on drop.
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct SecretScalar<G: Group>(pub(crate) G::Scalar);

impl<G: Group> SecretScalar<G> {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        SecretScalar(G::scalar_random(rng))
    }
    pub fn expose(&self) -> &G::Scalar {
        &self.0
    }
}

impl<G: Group> From<u64> for SecretScalar<G> {
    fn from(value: u64) -> Self {
        SecretScalar(G::Scalar::from(value))
    }
}

// Operator impls consuming secrets, no extra copies.
impl<G: Group> ops::Add for SecretScalar<G> {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        SecretScalar(self.0 + &rhs.0)
    }
}

impl<G: Group> ops::AddAssign for SecretScalar<G> {
    fn add_assign(&mut self, rhs: Self) {
        self.0 = self.0 + &rhs.0;
    }
}

impl<G: Group> ops::Sub for SecretScalar<G> {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        SecretScalar(self.0 - &rhs.0)
    }
}

impl<G: Group> ops::SubAssign for SecretScalar<G> {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 = self.0 - &rhs.0;
    }
}

impl<G: Group> ops::Mul<&G::Scalar> for SecretScalar<G> {
    type Output = Self;
    fn mul(self, k: &G::Scalar) -> Self::Output {
        SecretScalar(self.0 * k)
    }
}

// &Secret * &Scalar -> Secret (borrowed self, borrowed rhs)
impl<G: Group> ops::Mul<&SecretScalar<G>> for &SecretScalar<G> {
    type Output = SecretScalar<G>;
    fn mul(self, rhs: &SecretScalar<G>) -> Self::Output {
        let mut out = SecretScalar(G::Scalar::from(0u64));
        out += self.expose();
        out = out * rhs.expose();
        out
    }
}

impl<G: Group> ops::Add<&G::Scalar> for SecretScalar<G> {
    type Output = Self;
    fn add(self, rhs: &G::Scalar) -> Self::Output {
        SecretScalar(self.0 + rhs)
    }
}

impl<G: Group> ops::AddAssign<&G::Scalar> for SecretScalar<G> {
    fn add_assign(&mut self, rhs: &G::Scalar) {
        self.0 = self.0 + rhs;
    }
}

impl<G: Group> ops::Sub<&G::Scalar> for SecretScalar<G> {
    type Output = Self;
    fn sub(self, rhs: &G::Scalar) -> Self::Output {
        SecretScalar(self.0 - rhs)
    }
}

impl<G: Group> ops::SubAssign<&G::Scalar> for SecretScalar<G> {
    fn sub_assign(&mut self, rhs: &G::Scalar) {
        self.0 = self.0 - rhs;
    }
}

/// M-ElGamal Secret Keys (sk1, sk2).
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey<G: Group>(SecretScalar<G>, SecretScalar<G>);

impl<G: Group> SecretKey<G> {
    /// Create a fresh secret key.
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self(SecretScalar::new(rng), SecretScalar::new(rng))
    }

    /// Expose the underlying scalars (read-only).
    pub fn expose_scalars(&self) -> (&G::Scalar, &G::Scalar) {
        (self.0.expose(), self.1.expose())
    }

    /// Deserialize from bytes; expects two concatenated scalars.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 2 * G::SCALAR_SIZE {
            return None;
        }
        Some(Self(
            SecretScalar(G::scalar_from_bytes(&bytes[..G::SCALAR_SIZE])?),
            SecretScalar(G::scalar_from_bytes(&bytes[G::SCALAR_SIZE..])?),
        ))
    }

    /// Decrypt a [`Ciphertext`] to a group point.
    ///
    /// Computes `M = C - [sk1 * r]G1 - [sk2 * r]G2`.
    pub fn decrypt(&self, ciphertext: &Ciphertext<G>) -> G::Point {
        ciphertext.blinded_point
            - &((ciphertext.random_point * self.0.expose())
                + &(ciphertext.random_point2 * self.1.expose()))
    }

    /// Decrypt with a correctness proof (non-interactive).
    pub fn ver_decrypt<R: RngCore + CryptoRng>(
        &self,
        params: &ElGamalParams<G>,
        ciphertext: &Ciphertext<G>,
        transcript: &mut Transcript,
        rng: &mut R,
    ) -> DecOk<G> {
        let plaintext = self.decrypt(ciphertext);
        let binding = self.to_public(params);
        let public = DecOkPublicBorrowed::new(params, &binding, ciphertext, &plaintext);
        DecOkProtocol::prove(public, self, transcript, rng)
    }

    pub fn to_public(&self, params: &ElGamalParams<G>) -> PublicKey<G> {
        PublicKey::new_from_params(self, params)
    }
}

/// M-ElGamal parameters: two independent base points `g1` and `g2`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ElGamalParams<G: Group> {
    #[serde(with = "PointHelper::<G>")]
    pub g1: G::Point,
    #[serde(with = "PointHelper::<G>")]
    pub g2: G::Point,
}

impl<G: Group> ElGamalParams<G> {
    /// Sample two random (independent) points.
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        // On prime-order groups, random points are generators with overwhelming
        // probability.
        let g1 = G::point_random(rng);
        let g2 = G::point_random(rng);
        Self { g1, g2 }
    }

    /// Serialize `(G1, G2)` as `G1 || G2`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = vec![0u8; 2 * G::POINT_SIZE];
        G::point_to_bytes(&mut buffer[..G::POINT_SIZE], &self.g1);
        G::point_to_bytes(&mut buffer[G::POINT_SIZE..], &self.g2);
        buffer
    }

    /// Deserialize `(G1, G2)` from `G1 || G2`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 2 * G::POINT_SIZE {
            return Err(Error::InvalidByteSize);
        }
        let g1 = G::point_from_bytes(&bytes[..G::POINT_SIZE]).ok_or(Error::InvalidPoint)?;
        let g2 = G::point_from_bytes(&bytes[G::POINT_SIZE..]).ok_or(Error::InvalidPoint)?;
        // Use logical OR, not bitwise OR.
        if G::is_id(&g1) || G::is_id(&g2) {
            Err(Error::IdentityKey)
        } else {
            Ok(Self { g1, g2 })
        }
    }
}

/// M-ElGamal public key `H = [sk1]G1 + [sk2]G2`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PublicKey<G: Group> {
    #[serde(with = "PointHelper::<G>")]
    pub h: G::Point,
}

impl<G: Group> PublicKey<G> {
    /// Generate parameters and public key from a secret key.
    pub fn new<R: RngCore + CryptoRng>(sk: &SecretKey<G>, rng: &mut R) -> (ElGamalParams<G>, Self) {
        let params = ElGamalParams::new(rng);
        let h = params.g1 * sk.0.expose() + &(params.g2 * sk.1.expose());
        (params, Self { h })
    }

    /// Compute public key from an existing parameter set.
    pub fn new_from_params(sk: &SecretKey<G>, params: &ElGamalParams<G>) -> Self {
        let h = params.g1 * sk.0.expose() + &(params.g2 * sk.1.expose());
        Self { h }
    }

    /// Encrypt a point.
    pub fn encrypt<R: RngCore + CryptoRng>(
        &self,
        value: G::Point,
        params: &ElGamalParams<G>,
        rng: &mut R,
    ) -> ExtendedCiphertext<G> {
        ExtendedCiphertext::new(self, params, value, rng)
    }

    /// Encrypt the group identity with supplied randomness (utility).
    pub fn encrypt_id(
        &self,
        params: &ElGamalParams<G>,
        randomness: &G::Scalar,
    ) -> ExtendedCiphertext<G> {
        ExtendedCiphertext::id_new_from_randomness(self, params, randomness)
    }

    /// Decrypt given the encryption randomness (returns the plaintext point).
    pub fn dec_with_rnd(
        &self,
        params: &ElGamalParams<G>,
        ct: Ciphertext<G>,
        random_scalar: &G::Scalar,
    ) -> Result<G::Point, Error> {
        ct.decrypt(self, params, random_scalar)
    }

    /// Exponential decryption (recover scalar exponent) given randomness.
    pub fn exp_dec_with_rnd(
        &self,
        params: &ElGamalParams<G>,
        table: &DiscreteLogTable<G>,
        ct: &Ciphertext<G>,
        random_scalar: &G::Scalar,
    ) -> Result<G::Scalar, Error> {
        ct.exp_decrypt(self, params, table, random_scalar)
    }

    /// Serialize the public key point.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = vec![0u8; G::POINT_SIZE];
        G::point_to_bytes(&mut buffer[..], &self.h);
        buffer
    }

    /// Deserialize a public key from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != G::POINT_SIZE {
            return Err(Error::InvalidByteSize);
        }
        let h = G::point_from_bytes(bytes).ok_or(Error::InvalidPoint)?;
        if G::is_id(&h) {
            Err(Error::IdentityKey)
        } else {
            Ok(Self { h })
        }
    }

    /// View the public key as a `Ciphertext` shaped tuple `(G1, G2, H)`.
    pub fn to_ciphertext(&self, params: &ElGamalParams<G>) -> Ciphertext<G> {
        Ciphertext::<G> {
            random_point: params.g1,
            random_point2: params.g2,
            blinded_point: self.h,
        }
    }
}

impl<G: Group> ops::Mul<&G::Scalar> for &PublicKey<G> {
    type Output = PublicKey<G>;
    fn mul(self, k: &G::Scalar) -> Self::Output {
        PublicKey { h: self.h * k }
    }
}

impl<G: Group> ops::Mul<u64> for &PublicKey<G> {
    type Output = PublicKey<G>;
    fn mul(self, k: u64) -> Self::Output {
        self * &G::Scalar::from(k)
    }
}

/// Convenience wrapper holding a secret/public keypair.
pub struct KeyPair<G: Group> {
    sk: SecretKey<G>,
    pk: PublicKey<G>,
}

impl<G: Group> KeyPair<G> {
    /// Generate a new keypair for given parameters.
    pub fn new_from_params<R: CryptoRng + RngCore>(params: &ElGamalParams<G>, rng: &mut R) -> Self {
        let sk = SecretKey::<G>::new(rng);
        Self {
            pk: PublicKey::<G>::new_from_params(&sk, params),
            sk,
        }
    }
    pub fn public(&self) -> &PublicKey<G> {
        &self.pk
    }
    pub fn secret(&self) -> &SecretKey<G> {
        &self.sk
    }
    pub fn into_tuple(self) -> (SecretKey<G>, PublicKey<G>) {
        (self.sk, self.pk)
    }
}

// region:    --- Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Curve;
    use dlog_group::group::GroupPoint;
    use rand::thread_rng;

    #[test]
    fn pk_serialization_roundtrip() {
        let mut rng = thread_rng();
        let sk = SecretKey::<Curve>::new(&mut rng);
        let (_, pk) = PublicKey::<Curve>::new(&sk, &mut rng);

        let bytes = pk.to_bytes();
        let pk_de = PublicKey::<Curve>::from_bytes(&bytes).unwrap();

        assert_eq!(pk, pk_de);
    }

    #[test]
    fn decrypt_ok() {
        let mut rng = thread_rng();
        let sk = SecretKey::<Curve>::new(&mut rng);
        let (params, pk) = PublicKey::<Curve>::new(&sk, &mut rng);

        let value = Curve::point_random(&mut rng);
        let enc = pk.encrypt(value, &params, &mut rng);
        let decrypt = sk.decrypt(&enc.inner);

        assert_eq!(value, decrypt);
    }

    #[test]
    fn params_bytes_roundtrip() {
        let mut rng = thread_rng();
        let params = ElGamalParams::<Curve>::new(&mut rng);
        let bytes = params.to_bytes();
        let de = ElGamalParams::<Curve>::from_bytes(&bytes).unwrap();
        assert_eq!(params, de);
    }
}

// endregion:    --- Tests
