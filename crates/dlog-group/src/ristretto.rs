//! Wrapper around [`ristretto`]
//!
//! [`ristretto`]: https://docs.rs/curve25519-dalek/latest/curve25519_dalek/ristretto/index.html

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::{Identity, IsIdentity, VartimeMultiscalarMul},
};
use rand_core::{CryptoRng, RngCore};

use crate::{
    group::{Group, GroupPoint, GroupScalar},
    utils::RandomBytesProvider,
};

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub struct RistrettoGroup(());

impl Group for RistrettoGroup {
    fn vartime_multi_mul<'a, I, J>(scalars: I, points: J) -> Self::Point
    where
        I: IntoIterator<Item = &'a Self::Scalar>,
        J: IntoIterator<Item = Self::Point>,
    {
        RistrettoPoint::vartime_multiscalar_mul(scalars, points)
    }
}

impl GroupPoint for RistrettoGroup {
    type Point = RistrettoPoint;

    const POINT_SIZE: usize = 32;

    fn identity() -> Self::Point {
        Self::Point::identity()
    }

    fn generator() -> Self::Point {
        RISTRETTO_BASEPOINT_POINT
    }

    fn is_id(point: &Self::Point) -> bool {
        point.is_identity()
    }

    fn point_inv(point: Self::Point) -> Self::Point {
        -point
    }

    fn point_random<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Point {
        RistrettoPoint::random(rng)
    }

    fn point_to_bytes(buffer: &mut [u8], point: &Self::Point) {
        buffer.copy_from_slice(&point.compress().to_bytes());
    }

    fn point_from_bytes(buffer: &[u8]) -> Option<Self::Point> {
        CompressedRistretto::from_slice(buffer).ok()?.decompress()
    }
}

impl GroupScalar for RistrettoGroup {
    type Scalar = Scalar;

    const SCALAR_SIZE: usize = 32;

    fn scalar_random<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar {
        let mut uniform_bytes = [0u8; 64];
        rng.try_fill_bytes(&mut uniform_bytes).unwrap();
        Scalar::from_bytes_mod_order_wide(&uniform_bytes)
    }

    fn scalar_inv(scalar: Self::Scalar) -> Self::Scalar {
        scalar.invert()
    }

    fn scalar_from_random_bytes(source: RandomBytesProvider<'_>) -> Self::Scalar {
        let mut scalar_bytes = [0_u8; 64];
        source.fill_bytes(&mut scalar_bytes);
        Scalar::from_bytes_mod_order_wide(&scalar_bytes)
    }

    fn scalar_from_bytes(buffer: &[u8]) -> Option<Self::Scalar> {
        let bytes: &[u8; 32] = buffer.try_into().expect("Incorrect byte size");
        Scalar::from_canonical_bytes(*bytes).into()
    }

    fn scalar_to_bytes(buffer: &mut [u8], scalar: &Self::Scalar) {
        buffer.copy_from_slice(&scalar.to_bytes());
    }
}

// region:    --- Tests

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::scalar::Scalar;
    use rand::{thread_rng, Rng};

    macro_rules! scalar_operation {
        ($rng: ident, $opr:tt) => {
            let r1: u64 = $rng.gen();
            let r2: u64 = $rng.gen();

            let group_scalar_opr = Scalar::from(r1) $opr Scalar::from(r2);
            let ristretto_scalar_opr = Scalar::from(r1) $opr Scalar::from(r2);
            assert_eq!(group_scalar_opr, ristretto_scalar_opr);
        };
    }

    #[test]
    fn scalar_operations() {
        // check that the Scalar and the Scalar operations lead to the same result
        let mut rng = rand::thread_rng();
        scalar_operation!(rng, +);
        scalar_operation!(rng, -);
        scalar_operation!(rng, *);
    }

    #[test]
    fn point_isid() {
        let mut rng = rand::thread_rng();
        let scalar = RistrettoGroup::scalar_random(&mut rng);
        let zero = RistrettoGroup::generator() * scalar - RistrettoGroup::generator() * scalar;
        assert_eq!(zero, RistrettoGroup::identity());
    }

    #[test]
    fn point_from_bytes() {
        let g = RistrettoGroup::generator();
        let mut bytes = [0u8; 32];
        RistrettoGroup::point_to_bytes(&mut bytes, &g);
        let g_from_bytes = RistrettoGroup::point_from_bytes(&bytes).unwrap();

        assert_eq!(g, g_from_bytes)
    }

    #[test]
    fn scalar_from_bytes() {
        let mut rng = thread_rng();
        let e = RistrettoGroup::scalar_random(&mut rng);
        let mut bytes = [0u8; 32];
        RistrettoGroup::scalar_to_bytes(&mut bytes, &e);
        let e_from_bytes = RistrettoGroup::scalar_from_bytes(&bytes).unwrap();

        assert_eq!(e, e_from_bytes)
    }
}

// endregion: --- Tests
