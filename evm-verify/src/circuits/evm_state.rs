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
            storage_access: runtime.storage_accesses.clone(),
            delegate_targets: Vec::new(), // TODO: Extract from runtime
        }
    }

    /// Convert state to field elements for PCD
    pub fn to_field_elements<F: PrimeField>(&self) -> Vec<F> {
        let mut elements = Vec::new();
        
        // Convert storage state
        for (slot, value) in &self.storage {
            elements.push(F::from(slot.to_low_u64_be()));
            elements.push(F::from(value.as_u64()));
        }
        
        // Convert memory accesses
        for access in &self.memory {
            elements.push(F::from(access.offset.as_u64()));
            elements.push(F::from(access.size.as_u64()));
            elements.push(F::from(access.pc as u64));
            elements.push(F::from(access.write as u64));
        }
        
        elements
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

/// Circuit for verifying EVM state transitions with PCD
pub struct EVMStateCircuit<F: PrimeField> {
    /// Previous state (if any)
    pub prev_state: Option<EVMState>,
    /// Current state
    pub curr_state: EVMState,
    /// Deployment data
    pub deployment: DeploymentData,
    /// Public inputs for PCD chain verification
    pub public_inputs: Vec<F>,
    /// Public outputs for next proof in chain
    pub public_outputs: Vec<F>,
    /// Phantom data for type parameter
    pub _phantom: PhantomData<F>,
}

impl<F: PrimeField> EVMStateCircuit<F> {
    /// Create new circuit from runtime analysis
    pub fn new(deployment: DeploymentData, runtime: RuntimeAnalysis) -> Self {
        let curr_state = EVMState::from_runtime(&runtime);
        let public_inputs = Vec::new(); // Will be populated during proof generation
        let public_outputs = curr_state.to_field_elements(); // Current state becomes output
        
        Self {
            prev_state: None, // Will be set during upgrade verification
            curr_state,
            deployment,
            public_inputs,
            public_outputs,
            _phantom: PhantomData,
        }
    }

    /// Set previous state and update public inputs
    pub fn with_previous_state(mut self, prev_state: EVMState) -> Self {
        self.public_inputs = prev_state.to_field_elements();
        self.prev_state = Some(prev_state);
        self
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
                    || Ok(F::from(slot.to_low_u64_be()))
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
                        || Ok(F::from(slot.to_low_u64_be()))
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
                // Find matching previous state slot
                if let Some((prev_slot, prev_value)) = prev_storage_vars
                    .iter()
                    .find(|(s, _)| s.value().unwrap() == slot.value().unwrap()) {
                    
                    // If write not allowed, enforce value stays same
                    if let Some(access) = self.curr_state.storage_access.iter()
                        .find(|a| F::from(a.slot.to_low_u64_be()) == slot.value().unwrap()) {
                        if !access.write {
                            curr_value.enforce_equal(prev_value)?;
                        }
                        // If write is allowed, no additional constraints needed
                    } else {
                        // If no access pattern found, value must stay same
                        curr_value.enforce_equal(prev_value)?;
                    }
                } else {
                    // If slot not in previous state, must have write access
                    let has_write_access = self.curr_state.storage_access.iter()
                        .any(|a| F::from(a.slot.to_low_u64_be()) == slot.value().unwrap() && a.write);
                    if !has_write_access {
                        // No write access, cannot create new slot
                        return Err(SynthesisError::Unsatisfiable);
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_relations::r1cs::ConstraintSystem;

    fn create_test_state(storage_value: u64, write_allowed: bool) -> EVMState {
        EVMState {
            storage: vec![(H256::zero(), U256::from(storage_value))],
            memory: vec![MemoryAccess {
                offset: U256::zero(),
                size: U256::from(32),
                pc: 0,
                write: write_allowed,
            }],
            storage_access: vec![StorageAccess {
                slot: H256::zero(),
                value: None,
                is_init: false,
                pc: 0,
                write: write_allowed,
            }],
            delegate_targets: vec![],
        }
    }

    #[test]
    fn test_basic_state_transition() -> Result<(), SynthesisError> {
        // Create test states
        let prev_state = create_test_state(1, true);
        let curr_state = create_test_state(2, true);

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
            storage_accesses: vec![StorageAccess {
                slot: H256::zero(),
                value: None,
                is_init: false,
                pc: 0,
                write: true,
            }],
            access_checks: vec![],
            constructor_calls: vec![],
            storage_accesses_new: vec![],
            warnings: vec![],
        }).with_previous_state(prev_state);

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone())?;
        
        assert!(cs.is_satisfied()?);
        Ok(())
    }

    #[test]
    fn test_state_to_field_elements() {
        let state = create_test_state(1, true);
        let elements = state.to_field_elements::<Fr>();
        
        assert!(!elements.is_empty());
        assert_eq!(elements[0], Fr::from(0u64)); // slot
        assert_eq!(elements[1], Fr::from(1u64)); // value
        assert_eq!(elements[2], Fr::from(0u64)); // offset
        assert_eq!(elements[3], Fr::from(32u64)); // size
        assert_eq!(elements[4], Fr::from(0u64)); // pc
        assert_eq!(elements[5], Fr::from(1u64)); // write flag
    }

    #[test]
    fn test_pcd_public_inputs() -> Result<(), SynthesisError> {
        let prev_state = create_test_state(1, true);
        let curr_state = create_test_state(2, true);
        let deployment = DeploymentData::default();

        // Create circuit with previous state
        let circuit = EVMStateCircuit::<Fr>::new(deployment.clone(), RuntimeAnalysis {
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
        }).with_previous_state(prev_state.clone());

        // Verify public inputs match previous state
        assert_eq!(circuit.public_inputs, prev_state.to_field_elements::<Fr>());
        
        // Verify public outputs match current state
        assert_eq!(circuit.public_outputs, curr_state.to_field_elements::<Fr>());

        Ok(())
    }

    #[test]
    fn test_invalid_state_transition() -> Result<(), SynthesisError> {
        // Create states where write is not allowed but value changes
        let prev_state = create_test_state(1, false); // write not allowed
        let curr_state = create_test_state(2, false); // different value

        let deployment = DeploymentData::default();
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
        }).with_previous_state(prev_state);

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone())?;
        
        // Should fail because write is not allowed but value changed
        assert!(!cs.is_satisfied()?);
        Ok(())
    }

    #[test]
    fn test_empty_state_conversion() {
        let empty_state = EVMState {
            storage: vec![],
            memory: vec![],
            storage_access: vec![],
            delegate_targets: vec![],
        };

        let elements = empty_state.to_field_elements::<Fr>();
        assert!(elements.is_empty(), "Empty state should convert to empty field elements");
    }

    #[test]
    fn test_multiple_storage_slots() {
        let state = EVMState {
            storage: vec![
                (H256::zero(), U256::from(1)),
                (H256::from_low_u64_be(1), U256::from(2)),
                (H256::from_low_u64_be(2), U256::from(3)),
            ],
            memory: vec![],
            storage_access: vec![],
            delegate_targets: vec![],
        };

        let elements = state.to_field_elements::<Fr>();
        
        // Should have 6 elements (3 slots * 2 fields each)
        assert_eq!(elements.len(), 6);
        
        // Verify each slot-value pair
        assert_eq!(elements[0], Fr::from(0u64)); // first slot
        assert_eq!(elements[1], Fr::from(1u64)); // first value
        assert_eq!(elements[2], Fr::from(1u64)); // second slot
        assert_eq!(elements[3], Fr::from(2u64)); // second value
        assert_eq!(elements[4], Fr::from(2u64)); // third slot
        assert_eq!(elements[5], Fr::from(3u64)); // third value
    }
}
