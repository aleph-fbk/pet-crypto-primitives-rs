//! Wrapper around [`p256`]
//!
//! [`p256`]: https://docs.rs/p256/latest/p256/

use p256::elliptic_curve::sec1::FromEncodedPoint;
use p256::{
    elliptic_curve::{group::GroupEncoding, Field, Group as OriginalGroup, PrimeField},
    AffinePoint, EncodedPoint, FieldBytes, ProjectivePoint, Scalar,
};
use rand_core::{CryptoRng, RngCore};

use crate::group::{Group, GroupPoint, GroupScalar};

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub struct P256Group(());

impl Group for P256Group {}

impl GroupPoint for P256Group {
    type Point = ProjectivePoint;

    const POINT_SIZE: usize = 33;

    fn identity() -> Self::Point {
        Self::Point::identity()
    }

    fn generator() -> Self::Point {
        ProjectivePoint::GENERATOR
    }

    fn is_id(point: &Self::Point) -> bool {
        point.is_identity().into()
    }

    fn point_inv(point: Self::Point) -> Self::Point {
        -point
    }

    fn point_random<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Point {
        ProjectivePoint::random(rng)
    }

    fn point_to_bytes(buffer: &mut [u8], point: &Self::Point) {
        buffer.copy_from_slice(&point.to_bytes());
    }

    fn point_from_bytes(buffer: &[u8]) -> Option<Self::Point> {
        let encoded = EncodedPoint::from_bytes(buffer).ok()?;
        let affine = AffinePoint::from_encoded_point(&encoded);
        affine.map(ProjectivePoint::from).into()
    }
}

impl GroupScalar for P256Group {
    type Scalar = Scalar;

    const SCALAR_SIZE: usize = 32;

    fn scalar_random<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar {
        Scalar::random(rng)
    }

    fn scalar_inv(scalar: Self::Scalar) -> Self::Scalar {
        scalar.invert().unwrap()
    }

    fn scalar_from_bytes(buffer: &[u8]) -> Option<Self::Scalar> {
        if buffer.len() != Self::SCALAR_SIZE {
            return None;
        }
        let mut fb = FieldBytes::default();
        fb.copy_from_slice(buffer);
        Scalar::from_repr(fb).into()
    }

    fn scalar_to_bytes(buffer: &mut [u8], scalar: &Self::Scalar) {
        buffer.copy_from_slice(scalar.to_repr().as_ref());
    }
}

// region:    --- Tests

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

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
    fn point_from_bytes() {
        let g = P256Group::generator();
        let mut bytes = [0u8; P256Group::POINT_SIZE];
        P256Group::point_to_bytes(&mut bytes, &g);
        let g_from_bytes = P256Group::point_from_bytes(&bytes).unwrap();

        assert_eq!(g, g_from_bytes)
    }

    #[test]
    fn scalar_from_bytes() {
        let mut rng = rand::thread_rng();
        let e = P256Group::scalar_random(&mut rng);
        let mut bytes = [0u8; P256Group::SCALAR_SIZE];
        P256Group::scalar_to_bytes(&mut bytes, &e);
        let e_from_bytes = P256Group::scalar_from_bytes(&bytes).unwrap();

        assert_eq!(e, e_from_bytes)
    }
}

// endregion: --- Tests
