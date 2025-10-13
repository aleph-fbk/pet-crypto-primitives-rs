//! Wrapper around [`k256`]
//!
//! [`k256`]: https://docs.rs/k256/latest/k256/

use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::{
    elliptic_curve::{sec1::ToEncodedPoint, Field, Group as OriginalGroup, PrimeField},
    AffinePoint, EncodedPoint, FieldBytes, ProjectivePoint, Scalar,
};
use rand_core::{CryptoRng, RngCore};

use crate::group::{Group, GroupPoint, GroupScalar};

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub struct K256Group(());

impl Group for K256Group {}

impl GroupPoint for K256Group {
    type Point = ProjectivePoint;

    const POINT_SIZE: usize = 33;

    fn identity() -> Self::Point {
        ProjectivePoint::IDENTITY
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

    fn point_random<R: CryptoRng + RngCore>(rng: &mut R) -> Self::Point {
        ProjectivePoint::random(rng)
    }

    fn point_to_bytes(buffer: &mut [u8], point: &Self::Point) {
        let encoded_point = point.to_encoded_point(true);
        buffer.copy_from_slice(encoded_point.as_bytes());
    }

    fn point_from_bytes(buffer: &[u8]) -> Option<Self::Point> {
        let encoded = EncodedPoint::from_bytes(buffer).ok()?;
        let affine = AffinePoint::from_encoded_point(&encoded);
        affine.map(ProjectivePoint::from).into()
    }
}

impl GroupScalar for K256Group {
    type Scalar = Scalar;

    const SCALAR_SIZE: usize = 32;

    fn scalar_random<R: CryptoRng + RngCore>(rng: &mut R) -> Self::Scalar {
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
        let scalar = K256Group::scalar_random(&mut rng);
        let zero = K256Group::generator() * scalar - K256Group::generator() * scalar;
        assert_eq!(zero, K256Group::identity());
    }

    #[test]
    fn point_from_bytes() {
        let g = K256Group::generator();
        let mut bytes = [0u8; K256Group::POINT_SIZE];
        K256Group::point_to_bytes(&mut bytes, &g);
        let g_from_bytes = K256Group::point_from_bytes(&bytes).unwrap();

        assert_eq!(g, g_from_bytes)
    }

    #[test]
    fn scalar_from_bytes() {
        let mut rng = thread_rng();
        let e = K256Group::scalar_random(&mut rng);
        let mut bytes = [0u8; K256Group::SCALAR_SIZE];
        K256Group::scalar_to_bytes(&mut bytes, &e);
        let e_from_bytes = K256Group::scalar_from_bytes(&bytes).unwrap();

        assert_eq!(e, e_from_bytes)
    }
}

// endregion: --- Tests
