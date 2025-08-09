pub mod circuit_impl;
pub mod prover;
pub mod accumulation;
pub mod evm_accumulation;
pub mod bytecode_analyzer;
pub mod tensor_zoda;
pub mod zoda_accumulation;
pub mod reed_solomon;
pub mod benchmarks;
pub mod gateway;
pub mod api;
pub mod complete_evm_matrix;
pub mod complete_evm_matrix_tests;
pub mod performance_test;

#[cfg(test)]
mod zk_tests;

// Export the main circuit types
#[cfg(feature = "accumulation")]
pub use circuit_impl::PCDCircuit;
#[cfg(not(feature = "accumulation"))]
pub use circuit_impl::DataPredicateCircuit;

// Export the prover functions
pub use prover::{generate_proving_key, generate_proof, verify_proof};

// Feature flags for different PCD implementations
// Feature flag for traditional PCD using Groth16
#[cfg(all(feature = "accumulation", not(feature = "zoda")))]
pub use accumulation as pcd_impl;
#[cfg(all(feature = "accumulation", not(feature = "zoda")))]
pub use evm_accumulation as evm_pcd;
#[cfg(all(feature = "accumulation", not(feature = "zoda")))]
pub use evm_accumulation::EVMAccumulator;

// Feature flag for ZODA-based PCD (The Accidental Computer)
#[cfg(feature = "zoda")]
pub use zoda_accumulation as pcd_impl;
#[cfg(feature = "zoda")]
pub use zoda_accumulation as evm_pcd;
#[cfg(feature = "zoda")]
pub use zoda_accumulation::ZODAAccumulationAdapter as EVMAccumulator;

// Default to traditional PCD implementation
#[cfg(not(any(feature = "accumulation", feature = "zoda")))]
pub use accumulation::dummy as pcd_impl;

// Export the AI Agent Security Gateway components
pub use gateway::{DeploymentGateway, GatewaySettings, VerificationResult, SecurityReport, SecurityWarning, Severity, create_default_gateway};

// Export the CLI runner for the gateway
pub use gateway::run_cli;
