//! Pedersen commitment over a prime-order group.
//!
//! Let m = (m_1,...,m_n) in F^n and r in F. Public parameters are:
//! - H in G: blinding base
//! - G_1,...,G_n in G: independent generators
//!
//! The commitment is:
//!   C(m; r) = r*H + sum_i m_i*G_i
//!
//! Security (informal):
//! - Perfectly hiding if r is uniform and independent.
//! - Computationally binding under discrete log.
//! - Homomorphic: C(m;r) + C(m';r') = C(m+m'; r+r') and k*C(m;r) = C(k*m; k*r).
//!
//! Example:
//! ```rust
//! # use rand::thread_rng;
//! # use dlog_sigma_primitives::pedersen::commitment::{Parameters, Pedersen, ExtendedPedersen};
//! # use dlog_sigma_primitives::Curve;
//! # use dlog_group::group::GroupScalar;
//! # pub type Scalar = <Curve as GroupScalar>::Scalar;
//!
//! # fn main() {
//! let mut rng = thread_rng();
//! let params = Parameters::<Curve>::new(3, &mut rng);
//! let m = [Scalar::from(3u64), Scalar::from(4u64), Scalar::from(5u64)];
//!
//! // Extended commitment with randomness carried
//! let com = ExtendedPedersen::var_commit(&params, &m, &mut rng).unwrap();
//! let (com_open, r_open) = com.open();
//! let res = com_open.verify(&params, &m, &r_open);
//! assert!(res.is_ok());
//! # }
//! ```
pub mod commitment;
