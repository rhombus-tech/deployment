use ark_ff::PrimeField;
use ark_relations::r1cs::{
    ConstraintSynthesizer,
    ConstraintSystemRef,
    SynthesisError,
};
use ark_r1cs_std::{
    prelude::*,
    fields::fp::FpVar,
    boolean::Boolean,
};
use std::marker::PhantomData;

use ethers::types::{H256, U256};

use crate::common::DeploymentData;
use crate::bytecode::types::{RuntimeAnalysis, StateTransition};
use crate::utils::{slot_to_field, value_to_field};

/// State transition circuit
pub struct StateTransitionCircuit<F: PrimeField> {
    /// Deployment data
    pub deployment: DeploymentData,
    /// Runtime analysis
    pub runtime: RuntimeAnalysis,
    /// Phantom data
    _phantom: PhantomData<F>,
}

impl<F: PrimeField> StateTransitionCircuit<F> {
    /// Create new state transition circuit
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

    /// Get slot variable
    fn slot_var(&self, cs: ConstraintSystemRef<F>, slot: H256) -> Result<FpVar<F>, SynthesisError> {
        let slot_field = slot_to_field::<F>(slot);
        FpVar::new_witness(cs, || Ok(slot_field))
    }

    /// Get value variable
    fn value_var(&self, cs: ConstraintSystemRef<F>, value: U256) -> Result<FpVar<F>, SynthesisError> {
        let value_field = value_to_field::<F>(value);
        FpVar::new_witness(cs, || Ok(value_field))
    }

    /// Get write variable
    fn write_var(&self, cs: ConstraintSystemRef<F>, write: bool) -> Result<Boolean<F>, SynthesisError> {
        Boolean::new_witness(cs, || Ok(write))
    }

    /// Check slot is not zero
    fn check_slot_not_zero(
        &self,
        cs: ConstraintSystemRef<F>,
        slot_var: &FpVar<F>,
    ) -> Result<(), SynthesisError> {
        // Create variable for zero
        let zero_var = FpVar::new_constant(cs.clone(), F::zero())?;

        // Ensure slot is not zero
        slot_var.enforce_not_equal(&zero_var)?;

        Ok(())
    }

    /// Check value is not zero
    fn check_value_not_zero(
        &self,
        cs: ConstraintSystemRef<F>,
        value_var: &FpVar<F>,
    ) -> Result<(), SynthesisError> {
        // Create variable for zero
        let zero_var = FpVar::new_constant(cs.clone(), F::zero())?;

        // Ensure value is not zero
        value_var.enforce_not_equal(&zero_var)?;

        Ok(())
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for StateTransitionCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Get variables for each state transition
        for transition in &self.runtime.state_transitions {
            // Get slot variable
            let slot_var = self.slot_var(cs.clone(), transition.slot)?;

            // Get value variable
            let value_var = self.value_var(cs.clone(), transition.value)?;

            // Get write variable
            let _write_var = self.write_var(cs.clone(), transition.write)?;

            // Check slot is not zero
            self.check_slot_not_zero(cs.clone(), &slot_var)?;

            // Check value is not zero
            self.check_value_not_zero(cs.clone(), &value_var)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_state_transition_valid() {
        // Create deployment data
        let deployment = DeploymentData::default();

        // Create runtime analysis with valid state transition
        let mut runtime = RuntimeAnalysis::default();
        runtime.state_transitions.push(StateTransition {
            slot: H256::random(),
            value: U256::from(2),
            write: true,
            pc: 0,
        });

        // Create circuit
        let circuit = StateTransitionCircuit::<Fr>::new(
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
    fn test_state_transition_invalid() {
        // Create deployment data
        let deployment = DeploymentData::default();

        // Create runtime analysis with invalid state transition
        let mut runtime = RuntimeAnalysis::default();
        runtime.state_transitions.push(StateTransition {
            slot: H256::zero(),
            value: U256::zero(),
            write: true,
            pc: 0,
        });

        // Create circuit
        let circuit = StateTransitionCircuit::<Fr>::new(
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
