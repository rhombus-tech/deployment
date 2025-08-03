use ark_ff::Field;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_r1cs_std::{prelude::*, boolean::Boolean, fields::fp::FpVar};

use crate::circuits::DataPredicateCircuit;

/// EVM opcodes relevant for reentrancy detection
const SLOAD: u8 = 0x54;
const SSTORE: u8 = 0x55;
const CALL: u8 = 0xF1;
const STATICCALL: u8 = 0xFA;
const DELEGATECALL: u8 = 0xF4;

/// Circuit for detecting reentrancy vulnerabilities using PCD
#[derive(Clone)]
pub struct ReentrancyPCDCircuit<F: Field> {
    /// Previous state transitions
    pub prev_state: Option<Vec<F>>,
    
    /// Current state transitions
    pub curr_state: Vec<F>,
    
    /// Sequence of operations (SLOAD, CALL, SSTORE)
    pub operations: Vec<u8>,
    
    /// Original bytecode
    pub bytecode: Vec<u8>,
    
    /// Flag indicating if reentrancy was detected
    pub reentrancy_detected: bool,
}

impl<F: Field> ReentrancyPCDCircuit<F> {
    /// Create a new reentrancy PCD circuit
    pub fn new(prev_state: Option<Vec<F>>, curr_state: Vec<F>, operations: Vec<u8>, bytecode: Vec<u8>) -> Self {
        // Detect reentrancy by checking for SLOAD -> CALL -> SSTORE pattern
        let reentrancy_detected = Self::detect_reentrancy_pattern(&operations);
        
        Self {
            prev_state,
            curr_state,
            operations,
            bytecode,
            reentrancy_detected,
        }
    }
    
    /// Detect reentrancy pattern in operations
    fn detect_reentrancy_pattern(operations: &[u8]) -> bool {
        if operations.len() < 3 {
            return false;
        }
        
        let mut has_sload = false;
        let mut has_call_after_sload = false;
        
        for op in operations {
            match *op {
                SLOAD => {
                    has_sload = true;
                }
                CALL | STATICCALL | DELEGATECALL if has_sload => {
                    has_call_after_sload = true;
                }
                SSTORE if has_sload && has_call_after_sload => {
                    return true;
                }
                _ => {}
            }
        }
        
        false
    }
}

impl<F: Field + ark_ff::PrimeField> ConstraintSynthesizer<F> for ReentrancyPCDCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Create a variable for reentrancy detection result
        let reentrancy_var = Boolean::new_witness(cs.clone(), || Ok(self.reentrancy_detected))?;
        reentrancy_var.enforce_equal(&Boolean::constant(self.reentrancy_detected))?;
        
        // If we have previous state, enforce transition rules
        if let Some(prev_state) = self.prev_state {
            // Create variables for previous state
            let prev_vars: Vec<FpVar<F>> = prev_state
                .iter()
                .map(|val| FpVar::new_input(cs.clone(), || Ok(*val)))
                .collect::<Result<_, _>>()?;
            
            // Create variables for current state
            let curr_vars: Vec<FpVar<F>> = self.curr_state
                .iter()
                .map(|val| FpVar::new_input(cs.clone(), || Ok(*val)))
                .collect::<Result<_, _>>()?;
            
            // Enforce state transition rules
            // For reentrancy, we need to check if the state changes after a call
            
            // This is a simplified implementation
            // In a real implementation, we would check if the state changes after a call
            // by comparing specific storage slots before and after the call
        }
        
        Ok(())
    }
}

impl<F: Field + ark_ff::PrimeField> DataPredicateCircuit<F> for ReentrancyPCDCircuit<F> {
    fn get_predicate_inputs(&self) -> Vec<F> {
        let mut inputs = Vec::new();
        
        // Add reentrancy detection result as a predicate input
        inputs.push(if self.reentrancy_detected {
            F::one()
        } else {
            F::zero()
        });
        
        inputs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    
    #[test]
    fn test_reentrancy_detection() {
        // Sample bytecode
        let bytecode = vec![0x60, 0x80, 0x60, 0x40, 0x52];
        
        // Test case 1: No reentrancy (SLOAD -> SSTORE)
        let operations1 = vec![SLOAD, SSTORE];
        assert!(!ReentrancyPCDCircuit::<Fr>::detect_reentrancy_pattern(&operations1));
        
        // Create circuit to test constructor
        let circuit1 = ReentrancyPCDCircuit::<Fr>::new(
            None,
            vec![Fr::from(1u64), Fr::from(2u64)],
            operations1.clone(),
            bytecode.clone(),
        );
        assert!(!circuit1.reentrancy_detected);
        
        // Test case 2: No reentrancy (CALL -> SSTORE)
        let operations2 = vec![CALL, SSTORE];
        assert!(!ReentrancyPCDCircuit::<Fr>::detect_reentrancy_pattern(&operations2));
        
        // Test case 3: Reentrancy (SLOAD -> CALL -> SSTORE)
        let operations3 = vec![SLOAD, CALL, SSTORE];
        assert!(ReentrancyPCDCircuit::<Fr>::detect_reentrancy_pattern(&operations3));
        
        // Create circuit to test constructor
        let circuit3 = ReentrancyPCDCircuit::<Fr>::new(
            None,
            vec![Fr::from(1u64), Fr::from(2u64)],
            operations3.clone(),
            bytecode.clone(),
        );
        assert!(circuit3.reentrancy_detected);
        
        // Test case 4: Reentrancy with other operations in between
        let operations4 = vec![SLOAD, 0x01, 0x02, CALL, 0x03, SSTORE];
        assert!(ReentrancyPCDCircuit::<Fr>::detect_reentrancy_pattern(&operations4));
        
        // Test case 5: Reentrancy with DELEGATECALL
        let operations5 = vec![SLOAD, DELEGATECALL, SSTORE];
        assert!(ReentrancyPCDCircuit::<Fr>::detect_reentrancy_pattern(&operations5));
    }
}
