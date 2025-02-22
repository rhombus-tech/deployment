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

use ethers::types::{H256, U256};

use crate::common::DeploymentData;
use crate::bytecode::types::{RuntimeAnalysis, StorageAccess};
use crate::utils::{slot_to_field, value_to_field};

/// Storage circuit
pub struct StorageCircuit<F: PrimeField> {
    /// Deployment data
    pub deployment: DeploymentData,
    /// Runtime analysis
    pub runtime: RuntimeAnalysis,
    /// Phantom data
    _phantom: PhantomData<F>,
}

impl<F: PrimeField> StorageCircuit<F> {
    /// Create new storage circuit
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
    fn value_var(&self, cs: ConstraintSystemRef<F>, value: Option<H256>) -> Result<FpVar<F>, SynthesisError> {
        match value {
            Some(hash) => {
                let value_field = slot_to_field::<F>(hash);
                FpVar::new_witness(cs, || Ok(value_field))
            },
            None => FpVar::new_constant(cs, F::zero()),
        }
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

impl<F: PrimeField> ConstraintSynthesizer<F> for StorageCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Get variables for each storage access
        for access in &self.runtime.storage_accesses {
            // Get slot variable
            let slot_var = self.slot_var(cs.clone(), access.slot)?;

            // Get value variable
            let value_var = self.value_var(cs.clone(), access.value)?;

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
    fn test_storage_circuit() {
        // Create deployment data
        let deployment = DeploymentData::default();

        // Create runtime analysis with valid storage access
        let mut runtime = RuntimeAnalysis::default();
        runtime.storage_accesses.push(StorageAccess {
            slot: H256::random(),
            value: Some(H256::random()),
            is_init: false,
            pc: 0,
            write: true,
        });

        // Create circuit
        let circuit = StorageCircuit::<Fr>::new(
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
    fn test_storage_circuit_invalid() {
        // Create deployment data
        let deployment = DeploymentData::default();

        // Create runtime analysis with invalid storage access
        let mut runtime = RuntimeAnalysis::default();
        runtime.storage_accesses.push(StorageAccess {
            slot: H256::zero(),
            value: None,
            is_init: false,
            pc: 0,
            write: true,
        });

        // Create circuit
        let circuit = StorageCircuit::<Fr>::new(
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
