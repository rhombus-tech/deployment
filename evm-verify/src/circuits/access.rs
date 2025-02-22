use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_r1cs_std::{prelude::*, fields::fp::FpVar};
use ethers::types::H160;

use crate::common::DeploymentData;
use crate::bytecode::types::RuntimeAnalysis;
use crate::utils::address_to_field;

/// Circuit for verifying access control
#[derive(Clone)]
pub struct AccessControlCircuit<F: PrimeField> {
    /// Deployment data
    deployment: DeploymentData,

    /// Runtime analysis
    runtime: RuntimeAnalysis,

    /// Phantom data
    _phantom: std::marker::PhantomData<F>,
}

impl<F: PrimeField> AccessControlCircuit<F> {
    /// Create new access control circuit
    pub fn new(deployment: DeploymentData, runtime: RuntimeAnalysis) -> Self {
        Self {
            deployment,
            runtime,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for AccessControlCircuit<F> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<F>,
    ) -> Result<(), SynthesisError> {
        // Convert owner address to field
        let owner_val = address_to_field::<F>(self.deployment.owner);
        let owner_var = FpVar::new_input(cs.clone(), || Ok(owner_val))?;

        // Convert caller address to field
        let caller_val = address_to_field::<F>(self.runtime.caller);
        let caller_var = FpVar::new_input(cs.clone(), || Ok(caller_val))?;

        // Ensure caller is owner by enforcing equality
        owner_var.enforce_equal(&caller_var)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_access_control_valid() {
        // Create deployment data with valid owner
        let mut deployment = DeploymentData::default();
        deployment.owner = H160::from_low_u64_be(0x1234);

        // Create runtime analysis with matching caller
        let mut runtime = RuntimeAnalysis::default();
        runtime.caller = deployment.owner;

        // Create circuit
        let circuit = AccessControlCircuit::<Fr>::new(
            deployment,
            runtime,
        );

        // Create constraint system
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Generate constraints
        circuit.generate_constraints(cs.clone()).unwrap();

        // Check constraints are satisfied
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_access_control_invalid() {
        // Create deployment data with zero owner
        let mut deployment = DeploymentData::default();
        deployment.owner = H160::zero();

        // Create runtime analysis with non-matching caller
        let mut runtime = RuntimeAnalysis::default();
        runtime.caller = H160::from_low_u64_be(0x1234);

        // Create circuit
        let circuit = AccessControlCircuit::<Fr>::new(
            deployment,
            runtime,
        );

        // Create constraint system
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Generate constraints
        let result = circuit.generate_constraints(cs.clone());

        // Check constraints are not satisfied
        assert!(result.is_err() || !cs.is_satisfied().unwrap());
    }
}
