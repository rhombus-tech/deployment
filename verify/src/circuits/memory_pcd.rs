use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use pcc::circuits::memory::MemorySafetyCircuit;

/// A circuit that verifies a proof-carrying data chain
#[derive(Clone)]
pub struct LocalPCDCircuit<F: PrimeField> {
    /// Previous state
    pub prev_state: Option<Vec<F>>,
    /// Current state
    pub curr_state: Vec<F>,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for LocalPCDCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Create variables for current state as public inputs
        let curr_vars: Vec<FpVar<F>> = self.curr_state
            .iter()
            .map(|val| FpVar::new_input(cs.clone(), || Ok(*val)))
            .collect::<Result<_, _>>()?;

        // If we have a previous state, enforce PCD transition rules
        if let Some(prev_state) = self.prev_state {
            // Create variables for previous state as public inputs
            let prev_vars: Vec<FpVar<F>> = prev_state
                .iter()
                .map(|val| FpVar::new_input(cs.clone(), || Ok(*val)))
                .collect::<Result<_, _>>()?;

            // For each pair of previous and current state variables, enforce the transition rule
            for (prev, curr) in prev_vars.iter().zip(curr_vars.iter()) {
                // Example transition rule: current = previous + 1
                let one = FpVar::one();
                let expected = prev.clone() + one;
                curr.enforce_equal(&expected)?;
            }
        }

        Ok(())
    }
}

/// A circuit that combines memory safety verification with proof-carrying data
#[derive(Clone)]
pub struct MemorySafetyPCDCircuit<F: PrimeField> {
    /// Previous state and its memory safety proof
    pub prev_state: Option<(Vec<F>, Vec<(u64, u64)>, Vec<(u64, u64)>)>,
    
    /// Current state
    pub curr_state: Vec<F>,
    
    /// Current memory accesses (offset, size)
    pub memory_accesses: Vec<(u64, u64)>,
    
    /// Current memory allocations (address, size)
    pub allocations: Vec<(u64, u64)>,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for MemorySafetyPCDCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Create variables for current state as public inputs
        let curr_vars: Vec<FpVar<F>> = self.curr_state
            .iter()
            .map(|val| FpVar::new_input(cs.clone(), || Ok(*val)))
            .collect::<Result<_, _>>()?;

        // Create memory safety circuit for current state
        let memory_circuit = MemorySafetyCircuit::new(
            self.memory_accesses.clone(),
            self.allocations.clone(),
        );
        
        // Generate memory safety constraints
        memory_circuit.generate_constraints(cs.clone())?;

        // If we have a previous state, enforce PCD transition rules
        if let Some((prev_state, prev_accesses, prev_allocs)) = self.prev_state {
            // Create variables for previous state as public inputs
            let prev_vars: Vec<FpVar<F>> = prev_state
                .iter()
                .map(|val| FpVar::new_input(cs.clone(), || Ok(*val)))
                .collect::<Result<_, _>>()?;

            // Create memory safety circuit for previous state
            let prev_memory_circuit = MemorySafetyCircuit::new(
                prev_accesses,
                prev_allocs,
            );
            
            // Generate memory safety constraints for previous state
            prev_memory_circuit.generate_constraints(cs.clone())?;

            // Create PCD circuit for state transition
            let pcd_circuit = LocalPCDCircuit {
                prev_state: Some(prev_state),
                curr_state: self.curr_state.clone(),
            };
            
            // Generate PCD transition constraints
            pcd_circuit.generate_constraints(cs.clone())?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_memory_safety_pcd_circuit() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        
        // Test initial state (no previous state)
        let circuit = MemorySafetyPCDCircuit {
            prev_state: None,
            curr_state: vec![Fr::from(1u32)],
            memory_accesses: vec![(0, 4)], // Single 4-byte read at offset 0
            allocations: vec![(0, 65536)], // One page allocated at address 0
        };

        assert!(circuit.generate_constraints(cs.clone()).is_ok());
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_memory_safety_pcd_transition() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        
        // Test state transition
        let circuit = MemorySafetyPCDCircuit {
            prev_state: Some((
                vec![Fr::from(1u32)],
                vec![(0, 4)],     // Previous 4-byte read
                vec![(0, 65536)], // Previous page allocation
            )),
            curr_state: vec![Fr::from(2u32)], // Current state = previous + 1
            memory_accesses: vec![(4, 4)],    // New 4-byte read at offset 4
            allocations: vec![(0, 65536)],    // Same page allocation
        };

        assert!(circuit.generate_constraints(cs.clone()).is_ok());
        assert!(cs.is_satisfied().unwrap());
    }
}
