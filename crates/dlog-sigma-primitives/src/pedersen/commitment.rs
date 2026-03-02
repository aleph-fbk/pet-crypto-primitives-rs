use std::ops;

use dlog_group::serde::{PointHelper, VecHelper};
use serde::{Deserialize, Serialize};

use dlog_group::group::Group;
use rand_core::{CryptoRng, RngCore};

use crate::{elgamal::keys::SecretScalar, error::Error};

/// Public parameters for Pedersen commitments.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Parameters<G: Group> {
    #[serde(with = "PointHelper::<G>")]
    pub point: G::Point, // blinding base H
    #[serde(with = "VecHelper::<PointHelper<G>, 2>")]
    pub generators: Vec<G::Point>,
    pub list_len: usize,
}

impl<G: Group> Parameters<G> {
    /// Sample fresh parameters with `list_len` generators and one blinding base
    /// point.
    pub fn new<R: RngCore + CryptoRng>(list_len: usize, rng: &mut R) -> Self {
        let generators = (0..list_len)
            .map(|_| G::point_random(rng))
            .collect::<Vec<_>>();
        let point = G::point_random(rng);
        Self {
            point,
            generators,
            list_len,
        }
    }
}

/// A Pedersen commitment: `C = [r]H + Σ [mᵢ]Gᵢ`.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct Pedersen<G: Group> {
    #[serde(with = "PointHelper::<G>")]
    pub commitment: G::Point,
}

impl<G: Group> Pedersen<G> {
    pub fn var_commit<R: RngCore + CryptoRng>(
        params: &Parameters<G>,
        messages: &[G::Scalar],
        rng: &mut R,
    ) -> Result<Self, Error> {
        if messages.len() > params.list_len {
            return Err(Error::LengthMismatch);
        }
        let r = SecretScalar::<G>::new(rng);
        Ok(Self::var_commit_with_randomness(
            params,
            messages,
            r.expose(),
        ))
    }

    pub fn const_commit<R: RngCore + CryptoRng>(
        params: &Parameters<G>,
        messages: &[G::Scalar],
        rng: &mut R,
    ) -> Result<Self, Error> {
        if messages.len() > params.list_len {
            return Err(Error::LengthMismatch);
        }
        let r = SecretScalar::<G>::new(rng);
        Ok(Self::const_commit_with_randomness(
            params,
            messages,
            r.expose(),
        ))
    }

    pub fn var_commit_with_randomness(
        params: &Parameters<G>,
        messages: &[G::Scalar],
        randomness: &G::Scalar,
    ) -> Self {
        debug_assert!(messages.len() <= params.list_len);

        let mut scalars = Vec::with_capacity(1 + messages.len());
        let mut points = Vec::with_capacity(1 + messages.len());

        scalars.push(randomness);
        points.push(params.point);
        scalars.extend(messages);
        points.extend_from_slice(&params.generators[..messages.len()]);

        let commitment = G::vartime_multi_mul(scalars, points);
        Self { commitment }
    }

    pub fn const_commit_with_randomness(
        params: &Parameters<G>,
        messages: &[G::Scalar],
        randomness: &G::Scalar,
    ) -> Self {
        debug_assert!(messages.len() <= params.list_len);

        let mut scalars = Vec::with_capacity(1 + messages.len());
        let mut points = Vec::with_capacity(1 + messages.len());

        scalars.push(randomness);
        points.push(params.point);
        scalars.extend(messages);
        points.extend_from_slice(&params.generators[..messages.len()]);

        let commitment = G::constime_multi_mul(scalars, points);
        Self { commitment }
    }

    /// Verify that `(messages, randomness)` open this commitment under
    /// `params`.
    pub fn verify(
        &self,
        params: &Parameters<G>,
        messages: &[G::Scalar],
        randomness: &G::Scalar,
    ) -> Result<(), Error> {
        if messages.len() > params.list_len {
            return Err(Error::LengthMismatch);
        }
        let recomputed =
            Pedersen::const_commit_with_randomness(params, messages, randomness).commitment;
        if self.commitment == recomputed {
            Ok(())
        } else {
            Err(Error::PedersenCommitmentMismatch)
        }
    }

    pub fn to_extended(self, randomness: G::Scalar) -> ExtendedPedersen<G> {
        ExtendedPedersen {
            inner: self,
            randomness: SecretScalar(randomness),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0u8; G::POINT_SIZE];
        G::point_to_bytes(&mut bytes, &self.commitment);
        bytes
    }

    pub fn from_bytes<A: AsRef<[u8]>>(bytes: A) -> Option<Self> {
        let p = G::point_from_bytes(&bytes.as_ref()[..G::POINT_SIZE])?;
        if G::is_id(&p) {
            None
        } else {
            Some(Pedersen { commitment: p })
        }
    }
}

impl<G: Group> ops::Add for Pedersen<G> {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self {
            commitment: self.commitment + &rhs.commitment,
        }
    }
}
impl<G: Group> ops::AddAssign for Pedersen<G> {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}
impl<G: Group> ops::Sub for Pedersen<G> {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self {
            commitment: self.commitment - &rhs.commitment,
        }
    }
}
impl<G: Group> ops::SubAssign for Pedersen<G> {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}
impl<G: Group> ops::Mul<&G::Scalar> for Pedersen<G> {
    type Output = Self;
    fn mul(self, rhs: &G::Scalar) -> Self {
        Self {
            commitment: self.commitment * rhs,
        }
    }
}

/// Pedersen commitment plus the blinding scalar.
#[derive(Debug)]
pub struct ExtendedPedersen<G: Group> {
    pub inner: Pedersen<G>,
    pub randomness: SecretScalar<G>,
}

impl<G: Group> ExtendedPedersen<G> {
    pub fn open(self) -> (Pedersen<G>, G::Scalar) {
        (self.inner, *self.randomness.expose())
    }
    pub fn var_commit<R: RngCore + CryptoRng>(
        params: &Parameters<G>,
        messages: &[G::Scalar],
        rng: &mut R,
    ) -> Result<Self, Error> {
        if messages.len() > params.list_len {
            return Err(Error::LengthMismatch);
        }
        let randomness = SecretScalar::new(rng);
        let inner = Pedersen::var_commit_with_randomness(params, messages, randomness.expose());
        Ok(Self { inner, randomness })
    }

    pub fn var_commit_with_randomness(
        params: &Parameters<G>,
        messages: &[G::Scalar],
        randomness: &G::Scalar,
    ) -> Self {
        let inner = Pedersen::var_commit_with_randomness(params, messages, randomness);
        Self {
            inner,
            randomness: SecretScalar(*randomness),
        }
    }

    pub fn const_commit<R: RngCore + CryptoRng>(
        params: &Parameters<G>,
        messages: &[G::Scalar],
        rng: &mut R,
    ) -> Result<Self, Error> {
        if messages.len() > params.list_len {
            return Err(Error::LengthMismatch);
        }
        let randomness = SecretScalar::new(rng);
        let inner = Pedersen::const_commit_with_randomness(params, messages, randomness.expose());
        Ok(Self { inner, randomness })
    }

    pub fn to_pedersen(&self) -> Pedersen<G> {
        self.inner
    }
}

impl<G: Group> ops::Add for ExtendedPedersen<G> {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self {
            inner: self.inner + rhs.inner,
            randomness: self.randomness + rhs.randomness,
        }
    }
}
impl<G: Group> ops::AddAssign for ExtendedPedersen<G> {
    fn add_assign(&mut self, rhs: Self) {
        self.inner += rhs.inner;
        self.randomness += rhs.randomness.expose();
    }
}
impl<G: Group> ops::Sub for ExtendedPedersen<G> {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self {
            inner: self.inner - rhs.inner,
            randomness: self.randomness - rhs.randomness.expose(),
        }
    }
}
impl<G: Group> ops::Mul<&G::Scalar> for ExtendedPedersen<G> {
    type Output = Self;
    fn mul(self, rhs: &G::Scalar) -> Self {
        Self {
            inner: self.inner * rhs,
            randomness: self.randomness * rhs,
        }
    }
}

// region: --- Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Curve;
    use dlog_group::group::GroupScalar;
    use rand::thread_rng;

    type Scalar = <Curve as GroupScalar>::Scalar;

    #[test]
    fn commit_and_open() {
        let mut rng = thread_rng();
        let params = Parameters::<Curve>::new(5, &mut rng);
        let messages: Vec<Scalar> = (0..5).map(|_| Curve::scalar_random(&mut rng)).collect();

        let commitment = ExtendedPedersen::var_commit(&params, &messages, &mut rng).unwrap();
        let res = commitment
            .inner
            .verify(&params, &messages, commitment.randomness.expose());
        assert!(res.is_ok());
    }

    #[test]
    fn serialize_commitment() {
        {
            use serde_json;

            let mut rng = thread_rng();
            let params = Parameters::<Curve>::new(3, &mut rng);
            let messages: Vec<Scalar> = (0..3).map(|_| Curve::scalar_random(&mut rng)).collect();
            let commitment = ExtendedPedersen::const_commit(&params, &messages, &mut rng).unwrap();

            let json = serde_json::to_string(&params).unwrap();
            let de_params: Parameters<Curve> = serde_json::from_str(&json).unwrap();

            let json = serde_json::to_string(&commitment.inner).unwrap();
            let de_commitment: Pedersen<Curve> = serde_json::from_str(&json).unwrap();

            let res = de_commitment.verify(&de_params, &messages, commitment.randomness.expose());
            assert!(res.is_ok());
        }
    }

    #[test]
    fn homomorphic_properties() {
        let mut rng = thread_rng();
        let params = Parameters::<Curve>::new(3, &mut rng);
        let msgs1: Vec<Scalar> = (0..3).map(|_| Curve::scalar_random(&mut rng)).collect();
        let msgs2: Vec<Scalar> = (0..3).map(|_| Curve::scalar_random(&mut rng)).collect();

        let c1 = ExtendedPedersen::var_commit(&params, &msgs1, &mut rng).unwrap();
        let c2 = ExtendedPedersen::var_commit(&params, &msgs2, &mut rng).unwrap();

        let expected_r = c1.randomness.expose() + c2.randomness.expose();
        let c_sum = c1 + c2;

        let expected_msgs: Vec<Scalar> = msgs1.iter().zip(&msgs2).map(|(a, b)| *a + b).collect();

        assert!(c_sum
            .inner
            .verify(&params, &expected_msgs, &expected_r)
            .is_ok());
    }

    #[test]
    fn const_vs_var_commitment_equivalence() {
        let mut rng = thread_rng();
        let params = Parameters::<Curve>::new(4, &mut rng);
        let messages: Vec<Scalar> = (0..4).map(|_| Curve::scalar_random(&mut rng)).collect();
        let r = Curve::scalar_random(&mut rng);

        let c_var = Pedersen::var_commit_with_randomness(&params, &messages, &r);
        let c_const = Pedersen::const_commit_with_randomness(&params, &messages, &r);

        assert_eq!(c_var, c_const, "var_commit and const_commit mismatch");
    }
}

// endregion: --- Tests
