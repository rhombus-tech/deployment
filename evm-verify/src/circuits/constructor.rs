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

use ethers::types::{H160, U256};

use crate::common::DeploymentData;
use crate::bytecode::types::RuntimeAnalysis;
use crate::utils::address_to_field;

/// Constructor circuit
#[derive(Clone)]
pub struct ConstructorCircuit<F: PrimeField> {
    /// Deployment data
    pub deployment: DeploymentData,
    /// Runtime analysis
    pub runtime: RuntimeAnalysis,
    /// Phantom data
    _phantom: PhantomData<F>,
}

impl<F: PrimeField> ConstructorCircuit<F> {
    /// Create new constructor circuit
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

    /// Get caller variable
    fn caller_var(&self, cs: ConstraintSystemRef<F>) -> Result<FpVar<F>, SynthesisError> {
        let caller_field = address_to_field::<F>(self.runtime.caller);
        FpVar::new_witness(cs, || Ok(caller_field))
    }

    /// Check caller is not zero
    fn check_caller_not_zero(
        &self,
        cs: ConstraintSystemRef<F>,
        caller_var: &FpVar<F>,
    ) -> Result<(), SynthesisError> {
        // Create variable for zero
        let zero_var = FpVar::new_constant(cs.clone(), F::zero())?;

        // Ensure caller is not zero
        caller_var.enforce_not_equal(&zero_var)?;

        Ok(())
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for ConstructorCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Get caller variable
        let caller_var = self.caller_var(cs.clone())?;

        // Check caller is not zero
        self.check_caller_not_zero(cs.clone(), &caller_var)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_constructor_valid() {
        // Create deployment data
        let deployment = DeploymentData::default();

        // Create runtime analysis with valid caller
        let mut runtime = RuntimeAnalysis::default();
        runtime.caller = H160::from_low_u64_be(0x1234);

        // Create circuit
        let circuit = ConstructorCircuit::<Fr>::new(
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
    fn test_constructor_invalid() {
        // Create deployment data
        let deployment = DeploymentData::default();

        // Create runtime analysis with zero caller
        let mut runtime = RuntimeAnalysis::default();
        runtime.caller = H160::zero();

        // Create circuit
        let circuit = ConstructorCircuit::<Fr>::new(
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
