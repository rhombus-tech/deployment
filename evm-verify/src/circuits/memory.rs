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
use ethers::types::U256;

use crate::common::DeploymentData;
use crate::bytecode::types::RuntimeAnalysis;
use crate::utils::value_to_field;

/// Memory safety circuit
pub struct MemorySafetyCircuit<F: PrimeField> {
    /// Deployment data
    pub deployment: DeploymentData,
    /// Runtime analysis
    pub runtime: RuntimeAnalysis,
    /// Phantom data
    _phantom: PhantomData<F>,
}

impl<F: PrimeField> MemorySafetyCircuit<F> {
    /// Create new memory safety circuit
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

    /// Check memory access is valid
    fn check_memory_access(
        &self,
        cs: ConstraintSystemRef<F>,
        offset: U256,
        size: U256,
    ) -> Result<(), SynthesisError> {
        // Create variables for offset and size
        let offset_field = value_to_field::<F>(offset);
        let size_field = value_to_field::<F>(size);
        let offset_var = FpVar::new_witness(cs.clone(), || Ok(offset_field))?;
        let size_var = FpVar::new_witness(cs.clone(), || Ok(size_field))?;

        // Create variable for max memory size
        let max_size_var = FpVar::new_constant(cs.clone(), F::from(0x10000u64))?;

        // Check offset + size <= max_size
        let sum = offset + size;
        let sum_field = value_to_field::<F>(sum);
        let sum_var = FpVar::new_witness(cs.clone(), || Ok(sum_field))?;

        // Ensure sum_var = offset_var + size_var
        sum_var.enforce_equal(&(offset_var + size_var))?;

        // Ensure sum_var <= max_size_var
        let is_valid = sum_var.is_cmp(&max_size_var, core::cmp::Ordering::Less, false)?;
        is_valid.enforce_equal(&Boolean::constant(true))?;

        Ok(())
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for MemorySafetyCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Check each memory access
        for access in &self.runtime.memory_accesses {
            self.check_memory_access(cs.clone(), access.offset, access.size)?;
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
    fn test_memory_safety_valid() {
        // Create deployment data
        let deployment = DeploymentData::default();

        // Create runtime analysis
        let runtime = RuntimeAnalysis::default();

        // Create circuit
        let circuit = MemorySafetyCircuit::<Fr>::new(
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
    fn test_memory_safety_invalid() {
        // Create deployment data
        let deployment = DeploymentData::default();

        // Create runtime analysis with invalid memory access
        let mut runtime = RuntimeAnalysis::default();
        runtime.memory_accesses.push(crate::bytecode::types::MemoryAccess {
            offset: U256::from(0x10000),
            size: U256::from(32),
            pc: 0,
            write: true,
        });

        // Create circuit
        let circuit = MemorySafetyCircuit::<Fr>::new(
            deployment,
            runtime,
        );

        // Create constraint system
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Generate constraints
        circuit.generate_constraints(cs.clone()).unwrap();

        // Check constraints are not satisfied
        assert!(!cs.is_satisfied().unwrap());
    }
}
