use ark_bn254::{Bn254, Fr};
use ark_groth16::{
    Groth16,
    ProvingKey,
    VerifyingKey,
    prepare_verifying_key,
};
use ark_snark::{SNARK, CircuitSpecificSetupSNARK};
use ark_std::rand::thread_rng;

use crate::bytecode::types::RuntimeAnalysis;
use crate::circuits::access::AccessControlCircuit;
use crate::common::DeploymentData;

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

    /// Prove deployment
    pub fn prove(&self) -> bool {
        // Create circuit
        let circuit = AccessControlCircuit::<Fr>::new(
            self.deployment.clone(),
            self.runtime.clone(),
        );

        // Create proof
        let mut rng = thread_rng();
        let proof = Groth16::<Bn254>::prove(&self.access_pk, circuit, &mut rng).unwrap();

        // Verify proof
        let pvk = prepare_verifying_key(&self.access_vk);
        Groth16::<Bn254>::verify_with_processed_vk(&pvk, &[], &proof).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deployment_prover() {
        // Create deployment data
        let deployment = DeploymentData::default();

        // Create runtime analysis
        let runtime = RuntimeAnalysis::default();

        // Create prover
        let prover = DeploymentProver::new(deployment, runtime);

        // Prove deployment
        let valid = prover.prove();
        assert!(valid);
    }

    #[test]
    fn test_deployment_prover_invalid() {
        // Create deployment data
        let deployment = DeploymentData::default();

        // Create runtime analysis
        let runtime = RuntimeAnalysis::default();

        // Create prover
        let prover = DeploymentProver::new(deployment, runtime);

        // Create invalid deployment data
        let invalid_deployment = DeploymentData {
            owner: ethers::types::H160::zero(),
            ..Default::default()
        };

        // Prove deployment
        let valid = prover.prove();
        assert!(!valid);
    }
}
