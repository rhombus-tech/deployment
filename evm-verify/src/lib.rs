use ark_bn254::Bn254;
use ark_groth16::Groth16;
use ark_snark::SNARK;
use ark_ec::PairingEngine;

use tracing_subscriber;
use rand::rngs::OsRng;

// Conditional imports to avoid compilation errors
#[cfg(any(feature = "circuits", test))]
use crate::circuits::access::AccessControlCircuit;
#[cfg(any(feature = "common", test))]
use crate::common::DeploymentData;
#[cfg(any(feature = "bytecode", test))]
use crate::bytecode::types::RuntimeAnalysis;
#[cfg(any(feature = "utils", test))]
use crate::utils::address_to_field;

type Fr = <Bn254 as PairingEngine>::Fr;

// Core modules
pub mod analysis;
pub mod api;
pub mod block_execution;
pub mod bytecode;
pub mod circuits;
pub mod crypto;
pub mod common;
pub mod ethereum;
pub mod state_trie;
pub mod vm;
pub mod proving;
pub mod execution;

// Accumulation module for WARP integration
#[cfg(feature = "accumulation")]
pub mod accumulation;

// Our new EF compliance proof module
// pub mod ef_compliance_prover; // Removed due to compilation errors

// Production-grade infrastructure modules
pub mod error;
pub mod logging;
pub mod metrics;
pub mod config;
pub mod monitoring;
pub mod middleware;
pub mod profiling;
pub mod utils;
pub mod fractal_network;

// Production infrastructure re-exports
pub use error::{ZkEvmError as ZodaError, ErrorSeverity, ErrorCategory, ZkEvmError};
pub use logging::{ZkEvmLogger as ZodaLogger, LogConfig, ZkEvmLogger};
pub use metrics::{ZkEvmMetrics as ZodaMetrics, PerformanceSummary};
pub use config::{ZkEvmConfig as ZodaConfig, NetworkConfig, ProvingConfig, ZkEvmConfig};
pub use monitoring::production::{ZodaMonitoring, HealthStatus, SystemHealth};
pub use profiling::{ZodaPerformanceProfiler, PerformanceReport, BottleneckReport};

// VM re-exports 
pub use circuits::{ExecutionContext, BlockContext};

// Production logging initialization
pub fn init_production_logging() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    Ok(())
}

// Type aliases for compatibility
pub type ZodaResult<T> = Result<T, ZodaError>;
pub type RecoveryStrategy = ErrorCategory;

// Integration tests for ZODA proof verification
#[cfg(feature = "integration-tests")]
pub mod integration_test;

// Simple contract integration tests
#[cfg(feature = "integration-tests")]
pub mod simple_contract_test;
pub mod prover;
pub mod pcc;
pub mod pcd;

// Re-export the UnifiedVerifier for easier access
pub use api::UnifiedVerifier;

/// Generate proving key
pub fn generate_proving_key<C>(circuit: C) -> <Groth16<Bn254> as SNARK<Fr>>::ProvingKey
where
    C: ark_relations::r1cs::ConstraintSynthesizer<Fr> + Clone,
{
    // Generate proving key
    let (pk, _) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut OsRng).unwrap();

    pk
}

/// Generate proof
pub fn generate_proof<C>(
    circuit: C,
    pk: &<Groth16<Bn254> as SNARK<Fr>>::ProvingKey,
) -> Result<ark_groth16::Proof<Bn254>, ark_relations::r1cs::SynthesisError>
where
    C: ark_relations::r1cs::ConstraintSynthesizer<Fr>,
{
    // Generate proof
    let proof = Groth16::<Bn254>::prove(pk, circuit, &mut OsRng)?;

    Ok(proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::Zero;

    #[test]
    fn test_generate_keys() {
        // Create deployment data with valid owner
        let mut deployment = DeploymentData::default();
        deployment.owner = ethers::types::H160::from_low_u64_be(0x1234);

        // Create runtime analysis with matching caller
        let mut runtime = RuntimeAnalysis::default();
        runtime.caller = deployment.owner;

        // Create access control circuit
        let circuit = AccessControlCircuit::<Fr>::new(
            deployment.clone(),
            runtime.clone(),
        );

        // Generate proving key
        let pk = generate_proving_key(circuit);

        // Ensure proving key is valid
        assert!(!pk.vk.alpha_g1.is_zero());
    }

    #[test]
    fn test_generate_proof() {
        // Create deployment data with valid owner
        let mut deployment = DeploymentData::default();
        deployment.owner = ethers::types::H160::from_low_u64_be(0x1234);

        // Create runtime analysis with matching caller
        let mut runtime = RuntimeAnalysis::default();
        runtime.caller = deployment.owner;

        // Create access control circuit
        let circuit = AccessControlCircuit::<Fr>::new(
            deployment.clone(),
            runtime.clone(),
        );

        // Generate proving key
        let pk = generate_proving_key(circuit.clone());

        // Generate proof
        let proof = generate_proof(circuit, &pk).unwrap();

        // Ensure proof is valid
        assert!(!proof.a.is_zero());
    }

    #[test]
    fn test_generate_keys_circuit_specific() {
        // Create deployment data with valid owner
        let mut deployment = DeploymentData::default();
        deployment.owner = ethers::types::H160::from_low_u64_be(0x1234);

        // Create runtime analysis with matching caller
        let mut runtime = RuntimeAnalysis::default();
        runtime.caller = deployment.owner;

        // Create access control circuit
        let circuit = AccessControlCircuit::<Fr>::new(
            deployment.clone(),
            runtime.clone(),
        );

        // Generate proving and verifying keys
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut OsRng).unwrap();

        // Generate proof
        let proof = Groth16::<Bn254>::prove(&pk, circuit.clone(), &mut OsRng).unwrap();

        // Get public inputs
        let owner_val = address_to_field::<Fr>(deployment.owner);
        let caller_val = address_to_field::<Fr>(runtime.caller);
        let public_inputs = vec![owner_val, caller_val];

        // Verify proof
        assert!(Groth16::<Bn254>::verify(&vk, &public_inputs, &proof).unwrap());
    }
}
