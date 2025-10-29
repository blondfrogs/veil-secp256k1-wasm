//! Veil Crypto Library
//!
//! Pure Rust implementation of Veil's cryptographic primitives for RingCT transactions.
//! This library reimplements the Veil-specific functions from the C secp256k1 fork.

#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(missing_docs)]

pub mod ecdh;
pub mod keyimage;
pub mod pedersen;
pub mod borromean;
pub mod rangeproof;
pub mod mlsag;  // Pure Rust implementation!
pub mod utils;  // Pure Rust utilities
// TODO: Reimplement these in pure Rust (currently use C FFI)
// pub mod stealth;

// Re-export main functions for easy access
pub use ecdh::ecdh_veil;
pub use keyimage::get_keyimage;
pub use pedersen::{pedersen_blind_sum, pedersen_commit};
pub use borromean::{borromean_hash, borromean_sign, borromean_verify};
pub use rangeproof::{rangeproof_sign, rangeproof_verify, rangeproof_rewind, RangeProofSignResult, RangeProofVerifyResult, RangeProofRewindResult};
pub use mlsag::{prepare_mlsag, generate_mlsag, verify_mlsag, PrepareMlsagResult, GenerateMlsagResult};
pub use utils::{derive_pubkey, point_add_scalar, point_multiply, private_add};

// Re-export k256 types for users who need them
pub use k256::{PublicKey, SecretKey};

/// Error types for Veil crypto operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VeilCryptoError {
    /// Invalid public key
    InvalidPublicKey,
    /// Invalid secret key
    InvalidSecretKey,
    /// Invalid signature
    InvalidSignature,
    /// Invalid commitment
    InvalidCommitment,
    /// Invalid range proof
    InvalidRangeProof,
    /// MLSAG generation failed
    MlsagGenerationFailed,
    /// MLSAG verification failed
    MlsagVerificationFailed,
    /// Generic error with message
    Other(String),
}

impl std::fmt::Display for VeilCryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPublicKey => write!(f, "Invalid public key"),
            Self::InvalidSecretKey => write!(f, "Invalid secret key"),
            Self::InvalidSignature => write!(f, "Invalid signature"),
            Self::InvalidCommitment => write!(f, "Invalid commitment"),
            Self::InvalidRangeProof => write!(f, "Invalid range proof"),
            Self::MlsagGenerationFailed => write!(f, "MLSAG generation failed"),
            Self::MlsagVerificationFailed => write!(f, "MLSAG verification failed"),
            Self::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for VeilCryptoError {}

/// Result type for Veil crypto operations
pub type Result<T> = std::result::Result<T, VeilCryptoError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = VeilCryptoError::InvalidPublicKey;
        assert_eq!(format!("{}", err), "Invalid public key");
    }
}
