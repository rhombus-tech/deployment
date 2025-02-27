use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_r1cs_std::{
    fields::fp::FpVar,
    prelude::*,
    boolean::Boolean,
    ToBitsGadget,
};
use ethers::types::{Address, H256, U256};
use std::marker::PhantomData;

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

    /// Verify memory bounds and overlaps
    fn verify_memory_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        memory_vars: &[(FpVar<F>, FpVar<F>, FpVar<F>, Boolean<F>)]
    ) -> Result<(), SynthesisError> {
        // Verify memory access constraints
        for (i, (offset, size, pc, write)) in memory_vars.iter().enumerate() {
            // 1. Verify memory bounds
            self.verify_memory_bounds(cs.clone(), offset, size)?;
            
            // 2. Check for overlapping writes
            if write.value().unwrap_or(false) {
                for (j, (other_offset, other_size, other_pc, other_write)) in memory_vars.iter().enumerate() {
                    if i != j && other_write.value().unwrap_or(false) {
                        // Ensure no overlapping writes at different program counters
                        if pc.value().unwrap_or(F::zero()) != other_pc.value().unwrap_or(F::zero()) {
                            self.verify_no_overlap(cs.clone(), offset, size, other_offset, other_size)?;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Verify memory access bounds
    fn verify_memory_bounds(
        &self,
        cs: ConstraintSystemRef<F>,
        offset: &FpVar<F>,
        size: &FpVar<F>
    ) -> Result<(), SynthesisError> {
        // Maximum memory size (32-bit)
        let max_size = FpVar::new_constant(cs.clone(), F::from(u32::MAX as u64))?;
        
        // Convert to bits for comparison
        let offset_bits = offset.to_bits_le()?;
        let size_bits = size.to_bits_le()?;
        let max_bits = max_size.to_bits_le()?;
        
        // Compare bit by bit
        let mut offset_le_max = Boolean::new_constant(cs.clone(), true)?;
        let mut size_le_max = Boolean::new_constant(cs.clone(), true)?;
        
        for (o, m) in offset_bits.iter().zip(max_bits.iter()) {
            let o_not = o.not();
            let o_implies_m = o_not.or(m)?;
            offset_le_max = offset_le_max.and(&o_implies_m)?;
        }
        
        for (s, m) in size_bits.iter().zip(max_bits.iter()) {
            let s_not = s.not();
            let s_implies_m = s_not.or(m)?;
            size_le_max = size_le_max.and(&s_implies_m)?;
        }
        
        // Verify offset + size doesn't overflow
        let end_offset = offset + size;
        let end_bits = end_offset.to_bits_le()?;
        
        let mut end_le_max = Boolean::new_constant(cs.clone(), true)?;
        for (e, m) in end_bits.iter().zip(max_bits.iter()) {
            let e_not = e.not();
            let e_implies_m = e_not.or(m)?;
            end_le_max = end_le_max.and(&e_implies_m)?;
        }

        // All bounds must be satisfied
        offset_le_max.enforce_equal(&Boolean::new_constant(cs.clone(), true)?)?;
        size_le_max.enforce_equal(&Boolean::new_constant(cs.clone(), true)?)?;
        end_le_max.enforce_equal(&Boolean::new_constant(cs.clone(), true)?)?;

        Ok(())
    }

    /// Verify no overlap between memory regions
    fn verify_no_overlap(
        &self,
        cs: ConstraintSystemRef<F>,
        offset1: &FpVar<F>,
        size1: &FpVar<F>,
        offset2: &FpVar<F>,
        size2: &FpVar<F>
    ) -> Result<(), SynthesisError> {
        let end1 = offset1 + size1;
        let end2 = offset2 + size2;
        
        let offset1_bits = offset1.to_bits_le()?;
        let offset2_bits = offset2.to_bits_le()?;
        let end1_bits = end1.to_bits_le()?;
        let end2_bits = end2.to_bits_le()?;
        
        // Check if regions overlap:
        // Either offset1 >= end2 OR offset2 >= end1
        let mut offset1_ge_end2 = Boolean::new_constant(cs.clone(), true)?;
        let mut offset2_ge_end1 = Boolean::new_constant(cs.clone(), true)?;
        
        for (o1, e2) in offset1_bits.iter().zip(end2_bits.iter()) {
            let o1_not = o1.not();
            let o1_implies_e2 = e2.or(&o1_not)?;
            offset1_ge_end2 = offset1_ge_end2.and(&o1_implies_e2)?;
        }
        
        for (o2, e1) in offset2_bits.iter().zip(end1_bits.iter()) {
            let o2_not = o2.not();
            let o2_implies_e1 = e1.or(&o2_not)?;
            offset2_ge_end1 = offset2_ge_end1.and(&o2_implies_e1)?;
        }
        
        // At least one must be true
        let no_overlap = offset1_ge_end2.or(&offset2_ge_end1)?;
        no_overlap.enforce_equal(&Boolean::new_constant(cs.clone(), true)?)?;

        Ok(())
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for EVMStateCircuit<F> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<F>
    ) -> Result<(), SynthesisError> {
        // Convert memory accesses to circuit variables
        let mut memory_vars = Vec::new();
        for access in &self.curr_state.memory {
            let offset = FpVar::new_witness(cs.clone(), || Ok(F::from(access.offset.as_u64())))?;
            let size = FpVar::new_witness(cs.clone(), || Ok(F::from(access.size.as_u64())))?;
            let pc = FpVar::new_witness(cs.clone(), || Ok(F::from(access.pc as u64)))?;
            let write = Boolean::new_witness(cs.clone(), || Ok(access.write))?;
            memory_vars.push((offset, size, pc, write));
        }

        // Handle previous state
        if let Some(ref prev_state) = self.prev_state {
            // Convert storage states to field variables
            let prev_storage_vars: Vec<(FpVar<F>, FpVar<F>)> = prev_state.storage
                .iter()
                .map(|(slot, value)| {
                    let slot_var = FpVar::new_witness(cs.clone(), || Ok(F::from(slot.to_low_u64_be())))?;
                    let value_var = FpVar::new_witness(cs.clone(), || Ok(F::from(value.as_u64())))?;
                    Ok((slot_var, value_var))
                })
                .collect::<Result<Vec<_>, SynthesisError>>()?;

            let curr_storage_vars: Vec<(FpVar<F>, FpVar<F>)> = self.curr_state.storage
                .iter()
                .map(|(slot, value)| {
                    let slot_var = FpVar::new_witness(cs.clone(), || Ok(F::from(slot.to_low_u64_be())))?;
                    let value_var = FpVar::new_witness(cs.clone(), || Ok(F::from(value.as_u64())))?;
                    Ok((slot_var, value_var))
                })
                .collect::<Result<Vec<_>, SynthesisError>>()?;

            // Map slots to write permissions
            let mut slot_write_permissions = std::collections::HashMap::new();
            for access in &self.curr_state.storage_access {
                slot_write_permissions.insert(access.slot, access.write);
            }

            // Verify storage state transitions
            for (curr_slot, curr_value) in curr_storage_vars.iter() {
                if let Some((prev_slot, prev_value)) = prev_storage_vars
                    .iter()
                    .find(|(s, _)| s.value().unwrap_or(F::zero()) == curr_slot.value().unwrap_or(F::zero()))
                {
                    // If slot exists in previous state, verify write permissions
                    let slot_u64 = curr_slot.value().unwrap_or(F::zero());
                    let slot_bytes = slot_u64.to_string().as_bytes().to_vec();
                    let mut slot_h256 = H256::zero();
                    let len = std::cmp::min(slot_bytes.len(), 32);
                    slot_h256.0[..len].copy_from_slice(&slot_bytes[..len]);

                    if let Some(&write_allowed) = slot_write_permissions.get(&slot_h256) {
                        if !write_allowed {
                            // If write not allowed, value must stay the same
                            curr_value.enforce_equal(prev_value)?;
                        }
                    } else {
                        // If no explicit permission, value must stay the same
                        curr_value.enforce_equal(prev_value)?;
                    }
                } else {
                    // If slot doesn't exist in previous state, must have write permission
                    let slot_u64 = curr_slot.value().unwrap_or(F::zero());
                    let slot_bytes = slot_u64.to_string().as_bytes().to_vec();
                    let mut slot_h256 = H256::zero();
                    let len = std::cmp::min(slot_bytes.len(), 32);
                    slot_h256.0[..len].copy_from_slice(&slot_bytes[..len]);

                    if let Some(&write_allowed) = slot_write_permissions.get(&slot_h256) {
                        if !write_allowed {
                            return Err(SynthesisError::Unsatisfiable);
                        }
                    } else {
                        return Err(SynthesisError::Unsatisfiable);
                    }
                }
            }
        }

        // Verify memory constraints
        self.verify_memory_constraints(cs.clone(), &memory_vars)?;

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
