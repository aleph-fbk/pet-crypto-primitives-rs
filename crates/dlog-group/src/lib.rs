//! Wrapper around different rust implementations of prime-order groups in which
//! the [decisional Diffie–Hellman][DDH] (DDH), [computational
//! Diffie–Hellman][CDH] (CDH) and [discrete log][DLP] (DL) problems are
//! believed to be hard.
//!
//! Currently supports the following Elliptic-Curve Groups:
//! [`ristretto`] used by default, [`p256`], [`k256`] and [`p384`] enabled by
//! features.
//!
//! [DDH]: https://en.wikipedia.org/wiki/Decisional_Diffie%E2%80%93Hellman_assumption
//! [CDH]: https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_problem
//! [DLP]: https://en.wikipedia.org/wiki/Discrete_logarithm
//!
//! [`ristretto`]: https://docs.rs/curve25519-dalek/latest/curve25519_dalek/ristretto/index.html
//! [`p256`]: https://docs.rs/p256/latest/p256/
//! [`k256`]: https://docs.rs/k256/latest/k256/
//! [`p384`]: https://docs.rs/p384/latest/p384/
//!
//! # Example
//! ```ignore
//! // Import the ristretto backend and the Trait specifications
//! use dlog_group::prelude::*;
//! use rand::thread_rng;
//!
//! // Generete an `rng` for a random scalar `r`
//! let mut rng = rand::thread_rng();
//!
//! // Do the following simple check `g = g^{1 + r}/g^r`
//! let group_generator = G::generator();
//! let r = G::scalar_random(&mut rng);
//!
//! let group_pow = group_generator * &r;
//! let group_mul = group_generator + &group_pow;
//! let group_div = group_mul - &group_pow;
//!
//! assert_eq!(group_div, group_generator);
//! ```

#![cfg_attr(docsrs, feature(doc_auto_cfg))]

#[cfg(feature = "k256")]
pub mod k256;
#[cfg(feature = "p256")]
pub mod p256;
#[cfg(feature = "p384")]
pub mod p384;
#[cfg(feature = "ristretto")]
pub mod ristretto;
pub mod serde;

pub mod utils {
    use core::{fmt, str};

    use merlin::Transcript;

    /// Provides an arbitrary number of random bytes.
    pub struct RandomBytesProvider<'a> {
        transcript: &'a mut Transcript,
        label: &'static [u8],
    }

    impl fmt::Debug for RandomBytesProvider<'_> {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            let label = str::from_utf8(self.label).unwrap_or("(non-utf8 label)");
            formatter
                .debug_struct("RandomBytesProvider")
                .field("label", &label)
                .finish()
        }
    }

    impl<'a> RandomBytesProvider<'a> {
        pub fn new(transcript: &'a mut Transcript, label: &'static [u8]) -> Self {
            Self { transcript, label }
        }

        /// Writes random bytes into the specified buffer. As follows from the
        /// signature, this method can only be called once for a
        /// provider instance.
        pub fn fill_bytes(self, dest: &mut [u8]) {
            self.transcript.challenge_bytes(self.label, dest);
        }
    }
}

/// Define a Trait for a generic Elliptic Curve Group
pub mod group {
    use core::{fmt, ops};
    use rand_chacha::ChaChaRng;
    use rand_core::{CryptoRng, RngCore, SeedableRng};
    use zeroize::Zeroize;

    use crate::utils::RandomBytesProvider;

    pub trait Group:
        GroupPoint + GroupScalar + fmt::Debug + Copy + Clone + PartialEq + 'static
    {
        // Not CT
        fn vartime_multi_mul<'a, I, J>(scalars: I, points: J) -> Self::Point
        where
            I: IntoIterator<Item = &'a Self::Scalar>,
            J: IntoIterator<Item = Self::Point>,
        {
            // TODO: Should at least add parallelization, for example with rayon
            Self::constime_multi_mul(scalars, points)
        }
        // CT
        fn constime_multi_mul<'a, I, J>(scalars: I, points: J) -> Self::Point
        where
            I: IntoIterator<Item = &'a Self::Scalar>,
            J: IntoIterator<Item = Self::Point>,
        {
            scalars
                .into_iter()
                .zip(points)
                .fold(Self::identity(), |acc, (m, g)| acc + &(g * m))
        }
    }
    /// Abstraction for Points of the group.
    pub trait GroupPoint: GroupScalar {
        type Point: Clone
            + Copy
            + Eq
            + PartialEq
            + for<'a> ops::Add<&'a Self::Point, Output = Self::Point>
            + ops::AddAssign
            + for<'a> ops::Sub<&'a Self::Point, Output = Self::Point>
            + ops::SubAssign
            + for<'a> ops::Mul<&'a Self::Scalar, Output = Self::Point>
            + Zeroize
            + fmt::Debug;

        /// Byte size of a serialized [`Self::Point`].
        const POINT_SIZE: usize;
        /// Initialize Point as a generator of the group
        fn generator() -> Self::Point;
        /// Generate a random Point.
        fn point_random<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Point;
        /// Return the identity Point of the group.
        fn identity() -> Self::Point;
        /// Check if the Point is the identity of the group.
        fn is_id(point: &Self::Point) -> bool;
        /// Group inverse.
        fn point_inv(point: Self::Point) -> Self::Point;

        /// Serializes `Point` into the provided `buffer`, which is guaranteed
        /// to have length [`Self::POINT_SIZE`].
        fn point_to_bytes(buffer: &mut [u8], point: &Self::Point);
        /// Deserializes a Point from `buffer`, which is guaranteed to have
        /// length [`Self::POINT_SIZE`]. This method returns `None` if
        /// the buffer does not correspond to a representation of a
        /// valid scalar.
        fn point_from_bytes(buffer: &[u8]) -> Option<Self::Point>;
    }

    /// Abstraction for Scalars involved in the group operations.
    pub trait GroupScalar {
        type Scalar: Clone
            + Default
            + Copy
            + Eq
            + PartialEq
            + fmt::Debug
            + From<u64>
            + for<'a> ops::Add<&'a Self::Scalar, Output = Self::Scalar>
            + ops::AddAssign
            + for<'a> ops::Sub<&'a Self::Scalar, Output = Self::Scalar>
            + ops::SubAssign
            + for<'a> ops::Mul<&'a Self::Scalar, Output = Self::Scalar>
            + ops::MulAssign
            + Zeroize;

        /// Byte size of a serialized [`Self::Scalar`].
        const SCALAR_SIZE: usize;
        /// Generate a random scalar.
        fn scalar_random<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar;
        /// Modular inverse.
        fn scalar_inv(scalar: Self::Scalar) -> Self::Scalar;
        /// Generate a scalar from an unknown sized vector of bytes, used for
        /// challenges in zero-knowledge proofs.
        fn scalar_from_random_bytes(source: RandomBytesProvider<'_>) -> Self::Scalar {
            let mut rng_seed = <ChaChaRng as SeedableRng>::Seed::default();
            source.fill_bytes(&mut rng_seed);
            let mut rng = ChaChaRng::from_seed(rng_seed);
            Self::scalar_random(&mut rng)
        }
        /// Generate an rng from an unknown sized vector of bytes, used for
        /// challenges in zero-knowledge proofs.
        fn rng_from_random_bytes(source: RandomBytesProvider<'_>) -> ChaChaRng {
            let mut rng_seed = <ChaChaRng as SeedableRng>::Seed::default();
            source.fill_bytes(&mut rng_seed);
            ChaChaRng::from_seed(rng_seed)
        }
        // Serializes the scalar into the provided `buffer`, which is guaranteed to have
        // length
        /// [`Self::SCALAR_SIZE`].
        fn scalar_to_bytes(buffer: &mut [u8], scalar: &Self::Scalar);
        /// Deserializes the scalar from `buffer`, which is guaranteed to have
        /// length [`Self::SCALAR_SIZE`]. This method returns `None` if
        /// the buffer does not correspond to a representation of a
        /// valid scalar.
        fn scalar_from_bytes(buffer: &[u8]) -> Option<Self::Scalar>;
    }
}
