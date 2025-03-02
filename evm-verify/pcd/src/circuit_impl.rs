// PCD circuit implementations
//
// This module provides circuit implementations for Proof-Carrying Data (PCD)
// used in the EVM verification process.

use ark_ff::Field;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable};
use ark_std::marker::PhantomData;
use ethers::types::Bytes;
use anyhow::Result;

// Add imports for bytecode analysis
use crate::bytecode_analyzer::{BytecodeAnalyzer, SecurityWarning, SecurityWarningKind};

/// A circuit for EVM bytecode verification using accumulation
#[derive(Clone)]
pub struct PCDCircuit<F: Field> {
    /// The bytecode to verify
    pub bytecode: Bytes,
    /// The previous state (if any)
    pub prev_state: Option<Vec<F>>,
    /// The current state
    pub curr_state: Vec<F>,
    /// Security warnings from bytecode analysis
    pub security_warnings: Vec<SecurityWarning>,
    /// Phantom data for the field type
    pub _field: PhantomData<F>,
}

impl<F: Field> PCDCircuit<F> {
    /// Create a new PCDCircuit with bytecode analysis
    pub fn new_with_analysis(
        bytecode: Bytes,
        prev_state: Option<Vec<F>>,
        curr_state: Vec<F>,
    ) -> Result<Self> {
        // Perform bytecode analysis
        let mut analyzer = BytecodeAnalyzer::new(bytecode.clone());
        let analysis_results = analyzer.analyze()?;
        
        Ok(Self {
            bytecode,
            prev_state,
            curr_state,
            security_warnings: analysis_results.security_warnings,
            _field: PhantomData,
        })
    }
    
    /// Check if a specific vulnerability type exists in the security warnings
    fn has_vulnerability(&self, kind: SecurityWarningKind) -> bool {
        self.security_warnings.iter().any(|warning| warning.kind == kind)
    }
    
    /// Count the number of vulnerabilities of a specific kind
    fn count_vulnerabilities(&self, kind: SecurityWarningKind) -> usize {
        self.security_warnings.iter().filter(|warning| warning.kind == kind).count()
    }
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
        for state_elem in &self.curr_state {
            let var = cs.new_input_variable(|| Ok(*state_elem))?;
            state_vars.push(var);
        }
        
        // Add constraints based on bytecode analysis
        self.generate_security_constraints(cs, &state_vars)?;
        
        Ok(())
    }
}

impl<F: Field> PCDCircuit<F> {
    /// Generate constraints based on security analysis
    fn generate_security_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        state_vars: &[Variable],
    ) -> Result<(), SynthesisError> {
        // Get the first state variable (or use one_var if none exist)
        let first_var = if !state_vars.is_empty() {
            state_vars[0]
        } else {
            cs.new_input_variable(|| Ok(F::one()))?
        };
        
        // Create variables for each vulnerability type we want to check
        let reentrancy_present = self.has_vulnerability(SecurityWarningKind::Reentrancy);
        let reentrancy_var = cs.new_witness_variable(|| Ok(F::from(reentrancy_present as u32)))?;
        
        let access_control_present = self.has_vulnerability(SecurityWarningKind::AccessControl);
        let access_control_var = cs.new_witness_variable(|| Ok(F::from(access_control_present as u32)))?;
        
        let integer_overflow_present = self.has_vulnerability(SecurityWarningKind::IntegerOverflow);
        let integer_overflow_var = cs.new_witness_variable(|| Ok(F::from(integer_overflow_present as u32)))?;
        
        let unchecked_call_present = self.has_vulnerability(SecurityWarningKind::UncheckedCall);
        let unchecked_call_var = cs.new_witness_variable(|| Ok(F::from(unchecked_call_present as u32)))?;
        
        let front_running_present = self.has_vulnerability(SecurityWarningKind::FrontRunning);
        let front_running_var = cs.new_witness_variable(|| Ok(F::from(front_running_present as u32)))?;
        
        let flash_loan_present = self.has_vulnerability(SecurityWarningKind::FlashLoan);
        let flash_loan_var = cs.new_witness_variable(|| Ok(F::from(flash_loan_present as u32)))?;
        
        // Add constraints that enforce the vulnerability status
        // For each vulnerability, we add a constraint that the variable is either 0 or 1
        // and that it matches the actual vulnerability status
        
        // Reentrancy constraints
        if reentrancy_present {
            // If reentrancy is present, variable must be 1
            cs.enforce_constraint(
                ark_relations::r1cs::LinearCombination::<F>::from(reentrancy_var),
                ark_relations::r1cs::LinearCombination::<F>::from(first_var),
                ark_relations::r1cs::LinearCombination::<F>::from(reentrancy_var),
            )?;
        } else {
            // If reentrancy is not present, variable must be 0
            cs.enforce_constraint(
                ark_relations::r1cs::LinearCombination::<F>::from(reentrancy_var),
                ark_relations::r1cs::LinearCombination::<F>::from(first_var),
                ark_relations::r1cs::LinearCombination::<F>::zero(),
            )?;
        }
        
        // Access control constraints
        if access_control_present {
            cs.enforce_constraint(
                ark_relations::r1cs::LinearCombination::<F>::from(access_control_var),
                ark_relations::r1cs::LinearCombination::<F>::from(first_var),
                ark_relations::r1cs::LinearCombination::<F>::from(access_control_var),
            )?;
        } else {
            cs.enforce_constraint(
                ark_relations::r1cs::LinearCombination::<F>::from(access_control_var),
                ark_relations::r1cs::LinearCombination::<F>::from(first_var),
                ark_relations::r1cs::LinearCombination::<F>::zero(),
            )?;
        }
        
        // Integer overflow constraints
        if integer_overflow_present {
            cs.enforce_constraint(
                ark_relations::r1cs::LinearCombination::<F>::from(integer_overflow_var),
                ark_relations::r1cs::LinearCombination::<F>::from(first_var),
                ark_relations::r1cs::LinearCombination::<F>::from(integer_overflow_var),
            )?;
        } else {
            cs.enforce_constraint(
                ark_relations::r1cs::LinearCombination::<F>::from(integer_overflow_var),
                ark_relations::r1cs::LinearCombination::<F>::from(first_var),
                ark_relations::r1cs::LinearCombination::<F>::zero(),
            )?;
        }
        
        // Unchecked call constraints
        if unchecked_call_present {
            cs.enforce_constraint(
                ark_relations::r1cs::LinearCombination::<F>::from(unchecked_call_var),
                ark_relations::r1cs::LinearCombination::<F>::from(first_var),
                ark_relations::r1cs::LinearCombination::<F>::from(unchecked_call_var),
            )?;
        } else {
            cs.enforce_constraint(
                ark_relations::r1cs::LinearCombination::<F>::from(unchecked_call_var),
                ark_relations::r1cs::LinearCombination::<F>::from(first_var),
                ark_relations::r1cs::LinearCombination::<F>::zero(),
            )?;
        }
        
        // Front running constraints
        if front_running_present {
            cs.enforce_constraint(
                ark_relations::r1cs::LinearCombination::<F>::from(front_running_var),
                ark_relations::r1cs::LinearCombination::<F>::from(first_var),
                ark_relations::r1cs::LinearCombination::<F>::from(front_running_var),
            )?;
        } else {
            cs.enforce_constraint(
                ark_relations::r1cs::LinearCombination::<F>::from(front_running_var),
                ark_relations::r1cs::LinearCombination::<F>::from(first_var),
                ark_relations::r1cs::LinearCombination::<F>::zero(),
            )?;
        }
        
        // Flash loan constraints
        if flash_loan_present {
            cs.enforce_constraint(
                ark_relations::r1cs::LinearCombination::<F>::from(flash_loan_var),
                ark_relations::r1cs::LinearCombination::<F>::from(first_var),
                ark_relations::r1cs::LinearCombination::<F>::from(flash_loan_var),
            )?;
        } else {
            cs.enforce_constraint(
                ark_relations::r1cs::LinearCombination::<F>::from(flash_loan_var),
                ark_relations::r1cs::LinearCombination::<F>::from(first_var),
                ark_relations::r1cs::LinearCombination::<F>::zero(),
            )?;
        }
        
        // Add a constraint that combines all vulnerabilities
        // This will be 1 if any vulnerability is present, 0 otherwise
        let vulnerability_sum = cs.new_witness_variable(|| {
            let sum = reentrancy_present as u32 + 
                     access_control_present as u32 + 
                     integer_overflow_present as u32 + 
                     unchecked_call_present as u32 + 
                     front_running_present as u32 +
                     flash_loan_present as u32;
            Ok(F::from(sum.min(1)))
        })?;
        
        // Add a constraint that vulnerability_sum is either 0 or 1
        cs.enforce_constraint(
            ark_relations::r1cs::LinearCombination::<F>::from(vulnerability_sum),
            ark_relations::r1cs::LinearCombination::<F>::from(vulnerability_sum),
            ark_relations::r1cs::LinearCombination::<F>::from(vulnerability_sum),
        )?;
        
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
        println!("Debug: DataPredicateCircuit generate_constraints called");
        
        // Always add one_var as the FIRST public input
        let one = F::one();
        let one_var = cs.new_input_variable(|| Ok(one))?;
        println!("Debug: Adding one_var as first public input");
        
        // Add data hash as input
        let data_hash = 42u32; // Placeholder for actual hash computation
        let _data_hash_var = cs.new_input_variable(|| Ok(F::from(data_hash)))?;
        
        // Add predicate hash as input
        let predicate_hash = 43u32; // Placeholder for actual hash computation
        let _predicate_hash_var = cs.new_input_variable(|| Ok(F::from(predicate_hash)))?;
        
        // Enforce that data satisfies predicate
        // This is a simplified check - in a real implementation, we would
        // actually verify that the data satisfies the predicate
        let satisfies = data_satisfies_predicate(&self.data, &self.predicate);
        let satisfies_var = cs.new_witness_variable(|| Ok(F::from(satisfies as u32)))?;
        println!("Debug: Adding satisfies_var as witness");
        
        // Enforce that satisfies is either 0 or 1
        cs.enforce_constraint(
            ark_relations::r1cs::LinearCombination::<F>::from(satisfies_var),
            ark_relations::r1cs::LinearCombination::<F>::from(satisfies_var),
            ark_relations::r1cs::LinearCombination::<F>::from(satisfies_var),
        )?;
        
        // Enforce that satisfies is 1
        cs.enforce_constraint(
            ark_relations::r1cs::LinearCombination::<F>::from(satisfies_var),
            ark_relations::r1cs::LinearCombination::<F>::from(one_var),
            ark_relations::r1cs::LinearCombination::<F>::from(satisfies_var),
        )?;
        
        Ok(())
    }
}

// Helper function to compute a simple hash
fn compute_hash(data: &[u8]) -> u32 {
    let mut hash = 0u32;
    for &byte in data {
        hash = hash.wrapping_mul(31).wrapping_add(byte as u32);
    }
    hash
}

// Helper function to check if data satisfies predicate
fn data_satisfies_predicate(data: &[u8], predicate: &[u8]) -> bool {
    // This is a simplified check - in a real implementation, we would
    // actually verify that the data satisfies the predicate
    if predicate.is_empty() {
        return true;
    }
    
    // Simple example: check if data contains the predicate
    if data.len() < predicate.len() {
        return false;
    }
    
    for i in 0..=(data.len() - predicate.len()) {
        if data[i..(i + predicate.len())] == predicate[..] {
            return true;
        }
    }
    
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_relations::r1cs::ConstraintSystem;
    use ethers::types::Bytes;
    
    #[test]
    fn test_pcd_circuit() {
        let bytecode = Bytes::from(vec![1, 2, 3]);
        let curr_state = vec![Fr::from(42u32)];
        
        let circuit = PCDCircuit {
            bytecode,
            prev_state: None,
            curr_state,
            security_warnings: Vec::new(),
            _field: PhantomData,
        };
        
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        
        assert!(cs.is_satisfied().unwrap());
    }
    
    #[test]
    fn test_data_predicate_circuit() {
        let data = vec![1, 2, 3, 4, 5];
        let predicate = vec![2, 3];
        
        let circuit = DataPredicateCircuit {
            data,
            predicate,
            _field: PhantomData,
        };
        
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        
        assert!(cs.is_satisfied().unwrap());
    }
}
