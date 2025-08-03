// EF-Compliant FRI Commitment for accumulation/warp
// This replaces KZG to meet "NO trusted setups" requirement

pub use crate::accumulation::warp::fri_commitment::*;

// Re-export optimized FRI from main implementation
pub type FRICommitmentScheme<F> = OptimizedFRICommitmentScheme<F>;
pub type FRICommitment = OptimizedFRICommitment;
pub type FRIOpeningProof<F> = OptimizedFRIOpeningProof<F>;
