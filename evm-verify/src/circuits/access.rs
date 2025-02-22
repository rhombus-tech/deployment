use ark_ff::PrimeField;
use ark_relations::r1cs::{
    ConstraintSynthesizer,
    ConstraintSystemRef,
    SynthesisError,
};
use ark_r1cs_std::{
    prelude::*,
    fields::fp::FpVar,
};
use std::marker::PhantomData;

use ethers::types::H160;

use crate::common::DeploymentData;
use crate::bytecode::types::RuntimeAnalysis;
use crate::utils::address_to_field;

/// Access control circuit
#[derive(Clone)]
pub struct AccessControlCircuit<F: PrimeField> {
    /// Deployment data
    pub deployment: DeploymentData,
    /// Runtime analysis
    pub runtime: RuntimeAnalysis,
    /// Phantom data
    _phantom: PhantomData<F>,
}

impl<F: PrimeField> AccessControlCircuit<F> {
    /// Create new access control circuit
    pub fn new(
        deployment: DeploymentData,
        runtime: RuntimeAnalysis,
    ) -> Self {
        Self {
            deployment,
            runtime,
            _phantom: PhantomData,
        }
    }

    /// Get owner variable
    fn owner_var(&self, cs: ConstraintSystemRef<F>) -> Result<FpVar<F>, SynthesisError> {
        let owner_field = address_to_field::<F>(self.deployment.owner);
        FpVar::new_witness(cs, || Ok(owner_field))
    }

    /// Get caller variable
    fn caller_var(&self, cs: ConstraintSystemRef<F>) -> Result<FpVar<F>, SynthesisError> {
        let caller_field = address_to_field::<F>(self.runtime.caller);
        FpVar::new_witness(cs, || Ok(caller_field))
    }

    /// Check owner is not zero
    fn check_owner_not_zero(
        &self,
        cs: ConstraintSystemRef<F>,
        owner_var: &FpVar<F>,
    ) -> Result<(), SynthesisError> {
        // Create variable for zero
        let zero_var = FpVar::new_constant(cs.clone(), F::zero())?;

        // Ensure owner is not zero
        owner_var.enforce_not_equal(&zero_var)?;

        Ok(())
    }

    /// Check caller matches owner
    fn check_caller_matches_owner(
        &self,
        cs: ConstraintSystemRef<F>,
        caller_var: &FpVar<F>,
        owner_var: &FpVar<F>,
    ) -> Result<(), SynthesisError> {
        // Ensure caller matches owner
        caller_var.enforce_equal(owner_var)?;

        Ok(())
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for AccessControlCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Get owner and caller variables
        let owner_var = self.owner_var(cs.clone())?;
        let caller_var = self.caller_var(cs.clone())?;

        // Check owner is not zero
        self.check_owner_not_zero(cs.clone(), &owner_var)?;

        // Check caller matches owner
        self.check_caller_matches_owner(cs.clone(), &caller_var, &owner_var)?;

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
