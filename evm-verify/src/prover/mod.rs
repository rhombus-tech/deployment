use ark_bn254::{Bn254, Fr};
use ark_groth16::{
    Groth16,
    ProvingKey,
    VerifyingKey,
    prepare_verifying_key,
};
use ark_snark::SNARK;
use ark_std::rand::thread_rng;
use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};

use crate::bytecode::types::RuntimeAnalysis;
use crate::circuits::access::AccessControlCircuit;
use crate::common::DeploymentData;
use crate::utils::address_to_field;

/// Deployment prover
pub struct DeploymentProver {
    /// Deployment data
    pub deployment: DeploymentData,
    /// Runtime analysis
    pub runtime: RuntimeAnalysis,
    /// Access control proving key
    pub access_pk: ProvingKey<Bn254>,
    /// Access control verifying key
    pub access_vk: VerifyingKey<Bn254>,
}

impl DeploymentProver {
    /// Create new deployment prover
    pub fn new(deployment: DeploymentData, runtime: RuntimeAnalysis) -> Self {
        // Create circuit
        let circuit = AccessControlCircuit::<Fr>::new(
            deployment.clone(),
            runtime.clone(),
        );

        // Generate random parameters
        let mut rng = thread_rng();
        let params = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng).unwrap();

        // Get proving and verifying keys
        let access_pk = params.0;
        let access_vk = params.1;

        Self {
            deployment,
            runtime,
            access_pk,
            access_vk,
        }
    }

    /// Get public inputs for the circuit
    fn get_public_inputs(&self) -> Vec<Fr> {
        vec![
            address_to_field(self.deployment.owner),
            address_to_field(self.runtime.caller),
        ]
    }

    /// Prove deployment
    pub fn prove(&self) -> bool {
        // Create circuit
        let circuit = AccessControlCircuit::<Fr>::new(
            self.deployment.clone(),
            self.runtime.clone(),
        );

        // Check if circuit is satisfiable
        let cs = ConstraintSystem::<Fr>::new_ref();
        if circuit.clone().generate_constraints(cs.clone()).is_err() || !cs.is_satisfied().unwrap() {
            return false;
        }

        // Get public inputs
        let public_inputs = self.get_public_inputs();

        // Create proof
        let mut rng = thread_rng();
        let proof = match Groth16::<Bn254>::prove(&self.access_pk, circuit, &mut rng) {
            Ok(p) => p,
            Err(_) => return false,
        };

        // Verify proof
        let pvk = prepare_verifying_key(&self.access_vk);
        Groth16::<Bn254>::verify_with_processed_vk(&pvk, &public_inputs, &proof).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::types::H160;
    
    #[test]
    fn test_deployment_prover() {
        // Create deployment data with valid owner
        let mut deployment = DeploymentData::default();
        deployment.owner = H160::from_low_u64_be(0x1234);

        // Create runtime analysis with matching caller
        let mut runtime = RuntimeAnalysis::default();
        runtime.caller = deployment.owner;

        // Create prover
        let prover = DeploymentProver::new(deployment, runtime);

        // Prove deployment
        let valid = prover.prove();
        assert!(valid);
    }

    #[test]
    fn test_deployment_prover_invalid() {
        // Create deployment data with valid owner
        let mut deployment = DeploymentData::default();
        deployment.owner = H160::from_low_u64_be(0x1234);

        // Create runtime analysis with non-matching caller
        let mut runtime = RuntimeAnalysis::default();
        runtime.caller = H160::from_low_u64_be(0x5678); // Different from owner

        // Create prover
        let prover = DeploymentProver::new(deployment, runtime);

        // Prove deployment - should fail since caller != owner
        let valid = prover.prove();
        assert!(!valid);
    }
}
