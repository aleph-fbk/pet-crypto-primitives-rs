//! M-ElGamal encryption over prime-order groups.

use dlog_group::serde::PointHelper;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use core::{marker::PhantomData, ops};
use rand_core::{CryptoRng, RngCore};
use std::collections::HashMap;

use crate::{elgamal::keys::PublicKey, error::Error};
use dlog_group::group::Group;

use super::keys::{ElGamalParams, SecretScalar};

/// Ciphertext for M-ElGamal encryption: `([r]G1, [r]G2, [r]H + M)`.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize, Zeroize)]
pub struct Ciphertext<G: Group> {
    #[serde(with = "PointHelper::<G>")]
    pub random_point: G::Point, // [r]G1
    #[serde(with = "PointHelper::<G>")]
    pub random_point2: G::Point, // [r]G2
    #[serde(with = "PointHelper::<G>")]
    pub blinded_point: G::Point, // [r]H + M
}

impl<G: Group> Ciphertext<G> {
    /// Encrypt a group point `value`.
    pub fn new<R: RngCore + CryptoRng>(
        public_key: &PublicKey<G>,
        params: &ElGamalParams<G>,
        value: G::Point,
        rng: &mut R,
    ) -> Self {
        let r = SecretScalar::<G>::new(rng);
        let random_point = params.g1 * r.expose();
        let random_point2 = params.g2 * r.expose();
        let blinded_point = public_key.h * r.expose() + &value;

        Self {
            random_point,
            random_point2,
            blinded_point,
        }
    }

    /// Encrypt a scalar `value` as `m = [value] generator`.
    pub fn exp_new<R: RngCore + CryptoRng>(
        public_key: &PublicKey<G>,
        params: &ElGamalParams<G>,
        value: G::Scalar,
        rng: &mut R,
    ) -> Self {
        let r = SecretScalar::<G>::new(rng);
        let random_point = params.g1 * r.expose();
        let random_point2 = params.g2 * r.expose();
        let blinded_point = public_key.h * r.expose() + &(G::generator() * &value);

        Self {
            random_point,
            random_point2,
            blinded_point,
        }
    }

    /// Homomorphic subtraction of a plaintext point.
    #[inline]
    pub fn hom_sub(&self, rhs: &G::Point) -> Ciphertext<G> {
        Ciphertext {
            random_point: self.random_point,
            random_point2: self.random_point2,
            blinded_point: self.blinded_point - rhs,
        }
    }

    /// Additive identity ciphertext (all components = identity).
    #[inline]
    pub fn zero() -> Self {
        Self {
            random_point: G::identity(),
            random_point2: G::identity(),
            blinded_point: G::identity(),
        }
    }

    #[inline]
    pub fn random_point(&self) -> &G::Point {
        &self.random_point
    }
    #[inline]
    pub fn random_point2(&self) -> &G::Point {
        &self.random_point2
    }
    #[inline]
    pub fn blinded_point(&self) -> &G::Point {
        &self.blinded_point
    }

    /// Serialize as `[r]G1 || [r]G2 || [r]H + M`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0_u8; 3 * G::POINT_SIZE];
        G::point_to_bytes(&mut bytes[..G::POINT_SIZE], &self.random_point);
        G::point_to_bytes(
            &mut bytes[G::POINT_SIZE..2 * G::POINT_SIZE],
            &self.random_point2,
        );
        G::point_to_bytes(&mut bytes[2 * G::POINT_SIZE..], &self.blinded_point);
        bytes
    }

    /// Deserialize from `[r]G1 || [r]G2 || [r]H + M`.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 3 * G::POINT_SIZE {
            return None;
        }
        Some(Ciphertext {
            random_point: G::point_from_bytes(&bytes[..G::POINT_SIZE])?,
            random_point2: G::point_from_bytes(&bytes[G::POINT_SIZE..2 * G::POINT_SIZE])?,
            blinded_point: G::point_from_bytes(&bytes[2 * G::POINT_SIZE..])?,
        })
    }

    /// Weighted sum `Σ [i+1]ct[i]`.
    pub fn ranked_sum(ciphertexts: &[Self]) -> Self {
        let mut out = Ciphertext::zero();
        for (index, ct) in ciphertexts.iter().enumerate() {
            out += *ct * &G::Scalar::from((index + 1) as u64);
        }
        out
    }

    /// Decrypt given the randomness `r` used in encryption.
    pub fn decrypt(
        self,
        public_key: &PublicKey<G>,
        params: &ElGamalParams<G>,
        random_scalar: &G::Scalar,
    ) -> Result<G::Point, Error> {
        if params.g1 * random_scalar != self.random_point {
            return Err(Error::RandomPointMismatch);
        }
        if params.g2 * random_scalar != self.random_point2 {
            return Err(Error::RandomPointMismatch);
        }
        Ok(self.blinded_point - &(public_key.h * random_scalar))
    }

    /// Exponential decryption: recover `value` s.t. `m = [value] generator`
    /// using a discrete log lookup `table`.
    pub fn exp_decrypt(
        self,
        public_key: &PublicKey<G>,
        params: &ElGamalParams<G>,
        table: &DiscreteLogTable<G>,
        random_scalar: &G::Scalar,
    ) -> Result<G::Scalar, Error> {
        if params.g1 * random_scalar != self.random_point {
            return Err(Error::RandomPointMismatch);
        }
        if params.g2 * random_scalar != self.random_point2 {
            return Err(Error::RandomPointMismatch);
        }
        let diff = self.blinded_point - &(public_key.h * random_scalar);
        match table.get(&diff) {
            Some(value) => Ok(G::Scalar::from(value)),
            None => Err(Error::ElementNotFound),
        }
    }

    /// Re-encrypt (add fresh randomness) homomorphically.
    pub fn re_encrypt<R: CryptoRng + RngCore>(
        self,
        public_key: &PublicKey<G>,
        params: &ElGamalParams<G>,
        rng: &mut R,
    ) -> ExtendedCiphertext<G> {
        ExtendedCiphertext::id_new(public_key, params, rng) + self
    }

    pub(crate) fn from_randomness(
        public_key: &PublicKey<G>,
        params: &ElGamalParams<G>,
        value: &G::Point,
        randomness: &G::Scalar,
    ) -> Self {
        let random_point = params.g1 * randomness;
        let random_point2 = params.g2 * randomness;
        let blinded_point = public_key.h * randomness + value;
        Self {
            random_point,
            random_point2,
            blinded_point,
        }
    }

    /// Variable-time multi-scalar-mul over ciphertext components.
    pub(crate) fn var_msm(cts: &[Ciphertext<G>], scalars: &[G::Scalar]) -> Self {
        debug_assert_eq!(cts.len(), scalars.len());
        let mut r1 = Vec::with_capacity(cts.len());
        let mut r2 = Vec::with_capacity(cts.len());
        let mut bp = Vec::with_capacity(cts.len());
        for ct in cts {
            r1.push(ct.random_point);
            r2.push(ct.random_point2);
            bp.push(ct.blinded_point);
        }
        Self {
            random_point: G::vartime_multi_mul(scalars, r1),
            random_point2: G::vartime_multi_mul(scalars, r2),
            blinded_point: G::vartime_multi_mul(scalars, bp),
        }
    }

    /// Wrap into an `ExtendedCiphertext`, taking ownership and recording `t` as
    /// randomness.
    pub fn to_extended(self, t: G::Scalar) -> ExtendedCiphertext<G> {
        ExtendedCiphertext {
            inner: self,
            random_scalar: SecretScalar::<G>(t),
        }
    }
}

// Add / Sub / Mul implemented for value + ref combos to avoid copies.
impl<G: Group> ops::Add for Ciphertext<G> {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self {
            random_point: self.random_point + &rhs.random_point,
            random_point2: self.random_point2 + &rhs.random_point2,
            blinded_point: self.blinded_point + &rhs.blinded_point,
        }
    }
}
impl<'a, G: Group> ops::Add<&'a Ciphertext<G>> for &'a Ciphertext<G> {
    type Output = Ciphertext<G>;
    fn add(self, rhs: &'a Ciphertext<G>) -> Self::Output {
        Ciphertext {
            random_point: self.random_point + &rhs.random_point,
            random_point2: self.random_point2 + &rhs.random_point2,
            blinded_point: self.blinded_point + &rhs.blinded_point,
        }
    }
}
impl<'a, G: Group> ops::Add<&'a Ciphertext<G>> for Ciphertext<G> {
    type Output = Ciphertext<G>;
    fn add(self, rhs: &'a Ciphertext<G>) -> Self::Output {
        Ciphertext {
            random_point: self.random_point + &rhs.random_point,
            random_point2: self.random_point2 + &rhs.random_point2,
            blinded_point: self.blinded_point + &rhs.blinded_point,
        }
    }
}
impl<'a, G: Group> ops::Add<&'a ExtendedCiphertext<G>> for Ciphertext<G> {
    type Output = ExtendedCiphertext<G>;
    fn add(self, rhs: &'a ExtendedCiphertext<G>) -> Self::Output {
        ExtendedCiphertext {
            inner: Ciphertext {
                random_point: self.random_point + &rhs.inner.random_point,
                random_point2: self.random_point2 + &rhs.inner.random_point2,
                blinded_point: self.blinded_point + &rhs.inner.blinded_point,
            },
            random_scalar: SecretScalar(*rhs.random_scalar.expose()),
        }
    }
}
impl<G: Group> ops::AddAssign for Ciphertext<G> {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}
impl<G: Group> ops::Sub for Ciphertext<G> {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self {
            random_point: self.random_point - &rhs.random_point,
            random_point2: self.random_point2 - &rhs.random_point2,
            blinded_point: self.blinded_point - &rhs.blinded_point,
        }
    }
}
impl<G: Group> ops::SubAssign for Ciphertext<G> {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}
impl<G: Group> ops::Mul<&G::Scalar> for Ciphertext<G> {
    type Output = Self;
    fn mul(self, rhs: &G::Scalar) -> Self {
        Self {
            random_point: self.random_point * rhs,
            random_point2: self.random_point2 * rhs,
            blinded_point: self.blinded_point * rhs,
        }
    }
}
impl<G: Group> ops::Mul<u64> for Ciphertext<G> {
    type Output = Self;
    fn mul(self, rhs: u64) -> Self {
        let s = G::Scalar::from(rhs);
        self * &s
    }
}
impl<G: Group> ops::Neg for Ciphertext<G> {
    type Output = Self;
    fn neg(self) -> Self::Output {
        Self {
            random_point: G::point_inv(self.random_point),
            random_point2: G::point_inv(self.random_point2),
            blinded_point: G::point_inv(self.blinded_point),
        }
    }
}

/// Discrete-log lookup table for `[x] generator`.
#[derive(Debug, Clone, PartialEq)]
pub struct DiscreteLogTable<G: Group> {
    inner: HashMap<Vec<u8>, u64>,
    _marker: PhantomData<G>,
}

impl<G: Group> DiscreteLogTable<G> {
    /// Build a lookup table over the curve generator for the provided `values`.
    pub fn new(values: impl IntoIterator<Item = u64>) -> Self {
        let inner = values
            .into_iter()
            .filter(|&v| v != 0)
            .map(|i| {
                let point = G::generator() * &G::Scalar::from(i);
                let mut bytes = vec![0_u8; G::POINT_SIZE];
                G::point_to_bytes(&mut bytes, &point);
                (bytes, i)
            })
            .collect();

        Self {
            inner,
            _marker: PhantomData,
        }
    }

    /// Get `x` such that `decrypted_element = [x] generator`, or `None`.
    pub fn get(&self, decrypted_element: &G::Point) -> Option<u64> {
        if G::is_id(decrypted_element) {
            Some(0)
        } else {
            let mut bytes = vec![0_u8; G::POINT_SIZE];
            G::point_to_bytes(&mut bytes, decrypted_element);
            self.inner.get(&bytes).copied()
        }
    }
}

/// Convenience extension: ciphertext + stored randomness.
#[derive(Debug)]
pub struct ExtendedCiphertext<G: Group> {
    pub inner: Ciphertext<G>,
    pub(crate) random_scalar: SecretScalar<G>,
}

impl<G: Group> ExtendedCiphertext<G> {
    /// Encrypt a point and store the randomness.
    pub fn new<R: CryptoRng + RngCore>(
        public_key: &PublicKey<G>,
        params: &ElGamalParams<G>,
        value: G::Point,
        rng: &mut R,
    ) -> Self {
        let r = SecretScalar::<G>::new(rng);
        let random_point = params.g1 * r.expose();
        let random_point2 = params.g2 * r.expose();
        let blinded_point = public_key.h * r.expose() + &value;

        Self {
            inner: Ciphertext {
                random_point,
                random_point2,
                blinded_point,
            },
            random_scalar: r,
        }
    }

    /// Encrypt the additive identity and store the randomness.
    pub fn id_new<R: CryptoRng + RngCore>(
        public_key: &PublicKey<G>,
        params: &ElGamalParams<G>,
        rng: &mut R,
    ) -> Self {
        let r = SecretScalar::<G>::new(rng);
        let random_point = params.g1 * r.expose();
        let random_point2 = params.g2 * r.expose();
        let blinded_point = public_key.h * r.expose() + &G::identity();

        Self {
            inner: Ciphertext {
                random_point,
                random_point2,
                blinded_point,
            },
            random_scalar: r,
        }
    }

    /// Same as `id_new`, but use caller-provided `randomness`.
    pub fn id_new_from_randomness(
        public_key: &PublicKey<G>,
        params: &ElGamalParams<G>,
        randomness: &G::Scalar,
    ) -> Self {
        let random_point = params.g1 * randomness;
        let random_point2 = params.g2 * randomness;
        let blinded_point = public_key.h * randomness + &G::identity();

        Self {
            inner: Ciphertext {
                random_point,
                random_point2,
                blinded_point,
            },
            random_scalar: SecretScalar::<G>(*randomness),
        }
    }

    /// Encrypt a scalar `value` as `value·generator` and store the randomness.
    pub fn exp_new<R: RngCore + CryptoRng>(
        value: &G::Scalar,
        public_key: &PublicKey<G>,
        params: &ElGamalParams<G>,
        rng: &mut R,
    ) -> Self {
        let r = SecretScalar::<G>::new(rng);
        let random_point = params.g1 * r.expose();
        let random_point2 = params.g2 * r.expose();
        let blinded_point = public_key.h * r.expose() + &(G::generator() * value);

        Self {
            inner: Ciphertext {
                random_point,
                random_point2,
                blinded_point,
            },
            random_scalar: r,
        }
    }

    /// Additive identity (keeps `random_scalar = 0`).
    pub fn zero() -> Self {
        Self {
            inner: Ciphertext::zero(),
            random_scalar: SecretScalar::<G>::from(0_u64),
        }
    }

    /// Check if this is an encryption of the identity under `public_key`.
    pub fn is_zero(&self, public_key: &PublicKey<G>) -> bool {
        self.inner.blinded_point - &(public_key.h * self.random_scalar.expose()) == G::identity()
    }

    #[inline]
    pub fn expose(&self) -> &G::Scalar {
        self.random_scalar.expose()
    }
    #[inline]
    pub fn to_inner(&self) -> Ciphertext<G> {
        self.inner
    }
    #[inline]
    pub fn into_tuple(self) -> (Ciphertext<G>, SecretScalar<G>) {
        (self.inner, self.random_scalar)
    }

    /// Weighted sum `Σ (i+1) · ct[i]`, tracking randomness.
    pub fn ranked_sum(ciphertexts: &[Self]) -> Self {
        let mut inner = Ciphertext::zero();
        let mut random_scalar = G::Scalar::from(0u64);
        for (index, ct) in ciphertexts.iter().enumerate() {
            let w = G::Scalar::from((index + 1) as u64);
            inner += ct.inner * &w;
            random_scalar = random_scalar + &(w * ct.random_scalar.expose());
        }
        Self {
            inner,
            random_scalar: SecretScalar::<G>(random_scalar),
        }
    }
}

impl<G: Group> ops::Add for ExtendedCiphertext<G> {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        Self {
            inner: self.inner + rhs.inner,
            random_scalar: self.random_scalar + rhs.random_scalar.expose(),
        }
    }
}
impl<G: Group> ops::Add<Ciphertext<G>> for ExtendedCiphertext<G> {
    type Output = Self;
    fn add(self, rhs: Ciphertext<G>) -> Self::Output {
        Self {
            inner: self.inner + rhs,
            random_scalar: self.random_scalar,
        }
    }
}
impl<G: Group> ops::AddAssign for ExtendedCiphertext<G> {
    fn add_assign(&mut self, rhs: Self) {
        self.inner += rhs.inner;
        self.random_scalar += rhs.random_scalar.expose();
    }
}
impl<G: Group> ops::Sub for ExtendedCiphertext<G> {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        Self {
            inner: self.inner - rhs.inner,
            random_scalar: self.random_scalar - rhs.random_scalar.expose(),
        }
    }
}

// region:    --- Tests

#[cfg(test)]
mod tests {
    use crate::{
        elgamal::{
            ciphertext::{DiscreteLogTable, ExtendedCiphertext},
            keys::{ElGamalParams, KeyPair},
        },
        error::Error,
        Curve,
    };
    use dlog_group::group::{GroupPoint, GroupScalar};
    use rand::thread_rng;

    type Scalar = <Curve as GroupScalar>::Scalar;

    #[test]
    fn dlog_table() {
        let table = DiscreteLogTable::<Curve>::new(1..100);
        let decrypted_element = Curve::generator() * Scalar::from(50u64);
        assert_eq!(table.get(&decrypted_element), Some(50u64));
    }

    #[test]
    fn decrypt() {
        let mut rng = thread_rng();
        let params = ElGamalParams::new(&mut rng);
        let (_, pk) = KeyPair::new_from_params(&params, &mut rng).into_tuple();
        let s = Scalar::from(30u64);

        let ct1 = ExtendedCiphertext::exp_new(&s, &pk, &params, &mut rng);

        let table = DiscreteLogTable::<Curve>::new(1..100);
        let dec = ct1
            .inner
            .exp_decrypt(&pk, &params, &table, ct1.expose())
            .unwrap();

        assert_eq!(dec, s);
    }

    #[test]
    fn error_check() {
        let mut rng = thread_rng();
        let params = ElGamalParams::new(&mut rng);
        let (_, pk) = KeyPair::new_from_params(&params, &mut rng).into_tuple();
        let wrong_params = ElGamalParams::new(&mut rng);
        let s = Scalar::from(200u64);
        let ct = ExtendedCiphertext::exp_new(&s, &pk, &params, &mut rng);
        let table = DiscreteLogTable::<Curve>::new(1..100);

        let dec = ct.inner.exp_decrypt(&pk, &params, &table, ct.expose());
        assert_eq!(dec, Err(Error::ElementNotFound));
        let dec = ct
            .inner
            .exp_decrypt(&pk, &wrong_params, &table, ct.expose());
        assert_eq!(dec, Err(Error::RandomPointMismatch));
    }

    #[test]
    fn serialization() {
        let mut rng = thread_rng();
        let params = ElGamalParams::new(&mut rng);
        let (_, pk) = KeyPair::new_from_params(&params, &mut rng).into_tuple();
        let ct = super::Ciphertext::new(&pk, &params, Curve::identity(), &mut rng);

        let json = serde_json::to_value(ct).unwrap();
        let de: super::Ciphertext<Curve> = serde_json::from_value(json).unwrap();
        assert_eq!(ct, de);
    }

    #[test]
    fn api() {
        let mut rng = thread_rng();
        let params = ElGamalParams::<Curve>::new(&mut rng);
        let (sk, pk) = KeyPair::new_from_params(&params, &mut rng).into_tuple();
        let message = Curve::point_random(&mut rng);
        let ext_ct = pk.encrypt(message, &params, &mut rng);
        let ct = ext_ct.to_inner();
        let dec = sk.decrypt(&ct);
        assert_eq!(message, dec);
    }
}

// endregion: --- Tests
