use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ethers::types::{Address, H256, U256};
use std::marker::PhantomData;
use std::cmp::Ordering;

use crate::bytecode::types::{RuntimeAnalysis, StorageAccess, MemoryAccess};
use crate::common::DeploymentData;

/// EVM State for PCD verification
#[derive(Clone, Debug)]
pub struct EVMState {
    /// Storage state
    pub storage: Vec<(H256, U256)>,
    /// Memory state
    pub memory: Vec<MemoryAccess>,
    /// Storage access patterns
    pub storage_access: Vec<StorageAccess>,
    /// Delegate call targets
    pub delegate_targets: Vec<Address>,
}

impl EVMState {
    /// Create state from runtime analysis
    pub fn from_runtime(runtime: &RuntimeAnalysis) -> Self {
        Self {
            storage: runtime.final_state.clone(),
            memory: runtime.memory_accesses.clone(),
            storage_access: Vec::new(), // TODO: Add from runtime
            delegate_targets: Vec::new(), // TODO: Extract from runtime
        }
    }

    /// Verify state transition is valid
    pub fn verify_transition(&self, prev_state: &EVMState) -> bool {
        // Verify storage transitions follow access patterns
        for (slot, value) in &self.storage {
            if let Some(access) = self.storage_access.iter()
                .find(|a| &a.slot == slot) {
                
                // Check if write is allowed
                if !access.write {
                    // Value must match previous state
                    if let Some((_, prev_value)) = prev_state.storage
                        .iter()
                        .find(|(s, _)| s == slot) {
                        if value != prev_value {
                            return false;
                        }
                    }
                }
            }
        }
        true
    }
}

/// Circuit for verifying EVM state transitions
pub struct EVMStateCircuit<F: PrimeField> {
    /// Previous state (if any)
    pub prev_state: Option<EVMState>,
    /// Current state
    pub curr_state: EVMState,
    /// Deployment data
    pub deployment: DeploymentData,
    /// Phantom data for type parameter
    pub _phantom: PhantomData<F>,
}

impl<F: PrimeField> EVMStateCircuit<F> {
    /// Create new circuit from runtime analysis
    pub fn new(deployment: DeploymentData, runtime: RuntimeAnalysis) -> Self {
        let curr_state = EVMState::from_runtime(&runtime);
        
        Self {
            prev_state: None, // Will be set during upgrade verification
            curr_state,
            deployment,
            _phantom: PhantomData,
        }
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for EVMStateCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // 1. Convert storage state to field elements
        let curr_storage_vars: Vec<(FpVar<F>, FpVar<F>)> = self.curr_state.storage
            .iter()
            .map(|(slot, value)| {
                let slot_var = FpVar::new_witness(
                    cs.clone(), 
                    || Ok(F::from(slot.as_fixed_bytes()[0] as u64))
                )?;
                let value_var = FpVar::new_witness(
                    cs.clone(),
                    || Ok(F::from(value.as_u64()))
                )?;
                Ok((slot_var, value_var))
            })
            .collect::<Result<_, SynthesisError>>()?;

        // 2. If we have previous state, verify transitions
        if let Some(prev_state) = self.prev_state {
            let prev_storage_vars: Vec<(FpVar<F>, FpVar<F>)> = prev_state.storage
                .iter()
                .map(|(slot, value)| {
                    let slot_var = FpVar::new_witness(
                        cs.clone(),
                        || Ok(F::from(slot.as_fixed_bytes()[0] as u64))
                    )?;
                    let value_var = FpVar::new_witness(
                        cs.clone(),
                        || Ok(F::from(value.as_u64()))
                    )?;
                    Ok((slot_var, value_var))
                })
                .collect::<Result<_, SynthesisError>>()?;

            // Verify storage transitions
            for (slot, curr_value) in &curr_storage_vars {
                if let Some(access) = self.curr_state.storage_access.iter()
                    .find(|a| F::from(a.slot.as_fixed_bytes()[0] as u64) == slot.value().unwrap()) {
                    
                    if !access.write {
                        // Must match previous value
                        if let Some((_, prev_value)) = prev_storage_vars.iter()
                            .find(|(s, _)| s.value().unwrap() == slot.value().unwrap()) {
                            curr_value.enforce_equal(prev_value)?;
                        }
                    }
                }
            }
        }

        // 3. Verify memory safety
        for access in &self.curr_state.memory {
            // Add memory safety constraints
            let offset_var = FpVar::new_witness(
                cs.clone(),
                || Ok(F::from(access.offset.as_u64()))
            )?;
            let size_var = FpVar::new_witness(
                cs.clone(),
                || Ok(F::from(access.size.as_u64()))
            )?;
            
            // Ensure memory access is within bounds
            let max_size = FpVar::new_constant(cs.clone(), F::from(u32::MAX as u64))?;
            offset_var.enforce_cmp(&max_size, Ordering::Less, false)?;
            size_var.enforce_cmp(&max_size, Ordering::Less, false)?;
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
    fn test_basic_state_transition() -> Result<(), SynthesisError> {
        // Create test states
        let prev_state = EVMState {
            storage: vec![(H256::zero(), U256::from(1))],
            memory: vec![MemoryAccess {
                offset: U256::from(0),
                size: U256::from(32),
                pc: 0,
                write: true,
            }],
            storage_access: vec![],
            delegate_targets: vec![],
        };

        let curr_state = EVMState {
            storage: vec![(H256::zero(), U256::from(2))],
            memory: vec![MemoryAccess {
                offset: U256::from(0),
                size: U256::from(32),
                pc: 0,
                write: true,
            }],
            storage_access: vec![],
            delegate_targets: vec![],
        };

        // Create test deployment data
        let deployment = DeploymentData::default();

        // Create and test circuit
        let circuit = EVMStateCircuit::<Fr>::new(deployment, RuntimeAnalysis {
            code_offset: 0,
            code_length: 0,
            initial_state: prev_state.storage.clone(),
            final_state: curr_state.storage.clone(),
            memory_accesses: curr_state.memory.clone(),
            memory_allocations: vec![],
            max_memory: 32,
            caller: Address::zero(),
            memory_accesses_new: vec![],
            memory_allocations_new: vec![],
            state_transitions: vec![],
            storage_accesses: vec![],
            access_checks: vec![],
            constructor_calls: vec![],
            storage_accesses_new: vec![],
            warnings: vec![],
        });

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone())?;
        
        assert!(cs.is_satisfied()?);
        Ok(())
    }
}
