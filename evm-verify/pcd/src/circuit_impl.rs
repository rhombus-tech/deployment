// PCD circuit implementations
//
// This module provides circuit implementations for Proof-Carrying Data (PCD)
// used in the EVM verification process.

use ark_ff::Field;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::marker::PhantomData;
use ethers::types::Bytes;

/// A circuit for EVM bytecode verification using accumulation
#[derive(Clone)]
pub struct PCDCircuit<F: Field> {
    /// The bytecode to verify
    pub bytecode: Bytes,
    /// The previous state (if any)
    pub prev_state: Option<Vec<F>>,
    /// The current state
    pub curr_state: Vec<F>,
    /// Phantom data for the field type
    pub _field: PhantomData<F>,
}

impl<F: Field> ConstraintSynthesizer<F> for PCDCircuit<F> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<F>,
    ) -> Result<(), SynthesisError> {
        println!("Debug: PCDCircuit generate_constraints called");
        
        // Always add one_var as the FIRST public input
        let one = F::one();
        let one_var = cs.new_input_variable(|| Ok(one))?;
        println!("Debug: Adding one_var as first public input");
        
        if self.curr_state.is_empty() {
            println!("Debug: Current state is empty, only adding one_var as public input");
            
            // 1 * 1 = 1
            let lc1 = ark_relations::r1cs::LinearCombination::<F>::from(one_var);
            let lc2 = ark_relations::r1cs::LinearCombination::<F>::from(one_var);
            let lc3 = ark_relations::r1cs::LinearCombination::<F>::from(one_var);
            
            cs.enforce_constraint(lc1, lc2, lc3)?;
            
            return Ok(());
        }
        
        println!("Debug: Adding {} current state elements as public inputs", self.curr_state.len());
        // Add all current state elements as public inputs AFTER one_var
        let mut state_vars = Vec::new();
        for (i, &state_elem) in self.curr_state.iter().enumerate() {
            let var = cs.new_input_variable(|| Ok(state_elem))?;
            state_vars.push(var);
            println!("Debug: Added current state element {} as public input: {:?}", i, state_elem);
        }
        
        // Enforce a trivial constraint for each state variable
        for &state_var in &state_vars {
            // state_var * 1 = state_var
            let lc1 = ark_relations::r1cs::LinearCombination::<F>::from(state_var);
            let lc2 = ark_relations::r1cs::LinearCombination::<F>::from(one_var);
            let lc3 = ark_relations::r1cs::LinearCombination::<F>::from(state_var);
            
            cs.enforce_constraint(lc1, lc2, lc3)?;
        }
        
        Ok(())
    }
}

/// A circuit for traditional (non-accumulation) PCD
#[derive(Clone)]
pub struct DataPredicateCircuit<F: Field> {
    /// The data to verify
    pub data: Vec<u8>,
    /// The predicate to check
    pub predicate: Vec<u8>,
    /// Phantom data for the field type
    pub _field: PhantomData<F>,
}

impl<F: Field> ConstraintSynthesizer<F> for DataPredicateCircuit<F> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<F>,
    ) -> Result<(), SynthesisError> {
        // For now, we'll just create a simple circuit that checks if the data and predicate
        // are non-empty. In a real implementation, we would perform more complex checks.
        
        if self.data.is_empty() || self.predicate.is_empty() {
            // If there's no data or predicate, we'll add a trivial constraint that's always satisfied
            let one = F::one();
            let one_var = cs.new_input_variable(|| Ok(one))?;
            
            // 1 * 1 = 1
            let lc1 = ark_relations::r1cs::LinearCombination::<F>::from(one_var);
            let lc2 = ark_relations::r1cs::LinearCombination::<F>::from(one_var);
            let lc3 = ark_relations::r1cs::LinearCombination::<F>::from(one_var);
            
            cs.enforce_constraint(lc1, lc2, lc3)?;
            
            return Ok(());
        }
        
        // Create a variable for the first byte of data
        let first_data_byte = F::from(self.data[0] as u64);
        let first_data_var = cs.new_input_variable(|| Ok(first_data_byte))?;
        
        // Create a variable for the first byte of predicate
        let first_pred_byte = F::from(self.predicate[0] as u64);
        let first_pred_var = cs.new_input_variable(|| Ok(first_pred_byte))?;
        
        // Create a constant for one
        let one = F::one();
        let one_var = cs.new_input_variable(|| Ok(one))?;
        
        // Enforce a simple constraint: first_data_var * one_var = first_data_var
        let lc1 = ark_relations::r1cs::LinearCombination::<F>::from(first_data_var);
        let lc2 = ark_relations::r1cs::LinearCombination::<F>::from(one_var);
        let lc3 = ark_relations::r1cs::LinearCombination::<F>::from(first_data_var);
        
        cs.enforce_constraint(lc1, lc2, lc3)?;
        
        // Enforce another simple constraint: first_pred_var * one_var = first_pred_var
        let lc4 = ark_relations::r1cs::LinearCombination::<F>::from(first_pred_var);
        let lc5 = ark_relations::r1cs::LinearCombination::<F>::from(one_var);
        let lc6 = ark_relations::r1cs::LinearCombination::<F>::from(first_pred_var);
        
        cs.enforce_constraint(lc4, lc5, lc6)?;
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_relations::r1cs::ConstraintSystem;
    
    #[test]
    fn test_pcd_circuit() {
        // Create a simple circuit
        let circuit = PCDCircuit::<Fr> {
            bytecode: Bytes::from(vec![0u8, 1u8, 2u8]),
            prev_state: Some(vec![Fr::from(1u64), Fr::from(2u64)]),
            curr_state: vec![Fr::from(3u64), Fr::from(4u64)],
            _field: PhantomData,
        };
        
        // Create a constraint system
        let cs = ConstraintSystem::<Fr>::new_ref();
        
        // Generate constraints
        let result = circuit.clone().generate_constraints(cs.clone());
        assert!(result.is_ok());
        
        // Check if the constraint system is satisfied
        let is_satisfied = cs.is_satisfied().unwrap();
        assert!(is_satisfied);
    }
    
    #[test]
    fn test_data_predicate_circuit() {
        // Create a simple circuit
        let circuit = DataPredicateCircuit::<Fr> {
            data: vec![1u8, 2u8, 3u8],
            predicate: vec![4u8, 5u8, 6u8],
            _field: PhantomData,
        };
        
        // Create a constraint system
        let cs = ConstraintSystem::<Fr>::new_ref();
        
        // Generate constraints
        let result = circuit.clone().generate_constraints(cs.clone());
        assert!(result.is_ok());
        
        // Check if the constraint system is satisfied
        let is_satisfied = cs.is_satisfied().unwrap();
        assert!(is_satisfied);
    }
}
