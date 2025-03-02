pub mod circuit_impl;
pub mod prover;
pub mod accumulation;
pub mod evm_accumulation;

// Export the main circuit types
#[cfg(feature = "accumulation")]
pub use circuit_impl::PCDCircuit;
#[cfg(not(feature = "accumulation"))]
pub use circuit_impl::DataPredicateCircuit;

// Export the prover functions
pub use prover::{generate_proving_key, generate_proof, verify_proof};

// Feature flag for accumulation-based PCD
#[cfg(feature = "accumulation")]
pub use accumulation as pcd_impl;
#[cfg(feature = "accumulation")]
pub use evm_accumulation as evm_pcd;

// Default to traditional PCD implementation
#[cfg(not(feature = "accumulation"))]
pub use accumulation::dummy as pcd_impl;
