//! Errors related to this crate.

use core::fmt;

/// Unified error type for this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    // --- Public key conversion ---
    /// Invalid size of the byte buffer.
    InvalidByteSize,
    /// Byte buffer has correct size, but does not represent a valid point.
    InvalidPoint,
    /// Underlying point is the group identity (disallowed for public keys).
    IdentityKey,

    // --- Verification ---
    /// Restored commitment does not match the one provided in the proof.
    CommitmentMismatch,
    /// Transcript-derived challenge does not match expectations.
    ChallengeMismatch,
    /// Pedersen commitment check failed.
    PedersenCommitmentMismatch,
    /// Re-encryption / ciphertext relation failed to verify.
    CiphertextMismatch,
    /// Length/shape of provided inputs does not match.
    LengthMismatch,
    /// Input vectors/matrices do not have the required shape/order.
    InvalidInputShape,

    // --- Decryption ---
    /// Random point reconstructed from randomness does not match.
    RandomPointMismatch,
    /// Required element not found (e.g., lookup table too small).
    ElementNotFound,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            // Public key conversion
            Error::InvalidByteSize => "invalid byte buffer size",
            Error::InvalidPoint => {
                "byte buffer has correct size but does not represent a valid point"
            }
            Error::IdentityKey => "underlying point is the group identity",

            // Verification
            Error::CommitmentMismatch => "commitment does not match the one provided in the proof",
            Error::ChallengeMismatch => {
                "challenge does not match the one derived from the transcript"
            }
            Error::PedersenCommitmentMismatch => "Pedersen commitment check failed",
            Error::CiphertextMismatch => "ciphertext relation failed to verify",
            Error::LengthMismatch => "length does not match",
            Error::InvalidInputShape => "invalid input shape/order for verification",

            // Decryption
            Error::RandomPointMismatch => {
                "random point reconstructed from randomness does not match"
            }
            Error::ElementNotFound => "element not found (e.g., lookup table may be too small)",
        })
    }
}

impl std::error::Error for Error {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecryptionError {
    RandomPointMismatch,
    ElementNotFound,
}
impl From<DecryptionError> for Error {
    fn from(e: DecryptionError) -> Self {
        match e {
            DecryptionError::RandomPointMismatch => Error::RandomPointMismatch,
            DecryptionError::ElementNotFound => Error::ElementNotFound,
        }
    }
}
