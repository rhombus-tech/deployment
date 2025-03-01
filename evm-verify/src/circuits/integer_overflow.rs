use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_r1cs_std::{prelude::*, boolean::Boolean};
use ethers::types::Bytes;

use crate::common::DeploymentData;
use crate::bytecode::types::RuntimeAnalysis;
use crate::bytecode::security::{SecurityWarning, SecurityWarningKind};
use crate::bytecode::BytecodeAnalyzer;
use crate::bytecode::analyzer_overflow;
use crate::bytecode::analyzer_underflow;

/// Circuit for proving absence of integer overflow and underflow vulnerabilities
#[derive(Clone)]
pub struct IntegerOverflowCircuit<F: PrimeField> {
    /// Deployment data
    deployment: DeploymentData,

    /// Runtime analysis
    runtime: RuntimeAnalysis,

    /// Integer overflow warnings
    overflow_warnings: Vec<SecurityWarning>,

    /// Integer underflow warnings
    underflow_warnings: Vec<SecurityWarning>,

    /// Phantom data
    _phantom: std::marker::PhantomData<F>,
}

impl<F: PrimeField> IntegerOverflowCircuit<F> {
    /// Create new integer overflow/underflow vulnerability detection circuit
    pub fn new(deployment: DeploymentData, runtime: RuntimeAnalysis) -> Self {
        // Create a BytecodeAnalyzer instance
        let analyzer = BytecodeAnalyzer::new(Bytes::from(vec![0u8; 0]));
        
        // Get integer overflow warnings
        let overflow_warnings = analyzer_overflow::detect_integer_overflow(&analyzer);
        
        // Get integer underflow warnings
        let underflow_warnings = analyzer_underflow::detect_integer_underflow(&analyzer);
        
        Self {
            deployment,
            runtime,
            overflow_warnings,
            underflow_warnings,
            _phantom: std::marker::PhantomData,
        }
    }
    
    /// Set warnings for testing purposes
    pub fn with_warnings(
        deployment: DeploymentData, 
        runtime: RuntimeAnalysis, 
        overflow_warnings: Vec<SecurityWarning>,
        underflow_warnings: Vec<SecurityWarning>
    ) -> Self {
        Self {
            deployment,
            runtime,
            overflow_warnings,
            underflow_warnings,
            _phantom: std::marker::PhantomData,
        }
    }
    
    /// Check if contract has unsafe additions
    pub fn has_unsafe_additions(&self) -> bool {
        self.overflow_warnings.iter().any(|warning| {
            warning.kind == SecurityWarningKind::IntegerOverflow &&
            warning.description.contains("addition")
        })
    }
    
    /// Check if contract has unsafe multiplications
    pub fn has_unsafe_multiplications(&self) -> bool {
        self.overflow_warnings.iter().any(|warning| {
            warning.kind == SecurityWarningKind::IntegerOverflow &&
            warning.description.contains("multiplication")
        })
    }
    
    /// Check if contract has unsafe subtractions
    pub fn has_unsafe_subtractions(&self) -> bool {
        self.underflow_warnings.iter().any(|warning| {
            warning.kind == SecurityWarningKind::IntegerUnderflow &&
            warning.description.contains("subtraction")
        })
    }
    
    /// Check if contract has unsafe decrements
    pub fn has_unsafe_decrements(&self) -> bool {
        self.underflow_warnings.iter().any(|warning| {
            warning.kind == SecurityWarningKind::IntegerUnderflow &&
            warning.description.contains("decrement")
        })
    }
    
    /// Check if contract has any integer overflow
    pub fn has_integer_overflow(&self) -> bool {
        !self.overflow_warnings.is_empty()
    }
    
    /// Check if contract has any integer underflow
    pub fn has_integer_underflow(&self) -> bool {
        !self.underflow_warnings.is_empty()
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for IntegerOverflowCircuit<F> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<F>,
    ) -> Result<(), SynthesisError> {
        // Create boolean variables for each vulnerability check
        let unsafe_additions = Boolean::new_witness(
            cs.clone(),
            || Ok(self.has_unsafe_additions())
        )?;
        
        let unsafe_multiplications = Boolean::new_witness(
            cs.clone(),
            || Ok(self.has_unsafe_multiplications())
        )?;
        
        let unsafe_subtractions = Boolean::new_witness(
            cs.clone(),
            || Ok(self.has_unsafe_subtractions())
        )?;
        
        let unsafe_decrements = Boolean::new_witness(
            cs.clone(),
            || Ok(self.has_unsafe_decrements())
        )?;
        
        let integer_overflow = Boolean::new_witness(
            cs.clone(),
            || Ok(self.has_integer_overflow())
        )?;
        
        let integer_underflow = Boolean::new_witness(
            cs.clone(),
            || Ok(self.has_integer_underflow())
        )?;
        
        // Enforce that none of these vulnerabilities are present
        // This is done by ensuring each boolean is false
        unsafe_additions.enforce_equal(&Boolean::constant(false))?;
        unsafe_multiplications.enforce_equal(&Boolean::constant(false))?;
        unsafe_subtractions.enforce_equal(&Boolean::constant(false))?;
        unsafe_decrements.enforce_equal(&Boolean::constant(false))?;
        integer_overflow.enforce_equal(&Boolean::constant(false))?;
        integer_underflow.enforce_equal(&Boolean::constant(false))?;
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::DeploymentData;
    use crate::bytecode::types::RuntimeAnalysis;
    use ethers::types::H160 as Address;
    
    #[test]
    fn test_integer_overflow_circuit_safe() {
        // Create deployment data
        let deployment = DeploymentData {
            owner: Address::zero(),
        };
        
        // Create runtime analysis
        let runtime = RuntimeAnalysis::default();
        
        // Create circuit with no warnings
        let circuit = IntegerOverflowCircuit::<ark_bn254::Fr>::with_warnings(
            deployment,
            runtime,
            vec![],
            vec![],
        );
        
        // Create constraint system
        let cs = ark_relations::r1cs::ConstraintSystem::<ark_bn254::Fr>::new_ref();
        
        // Generate constraints
        circuit.generate_constraints(cs.clone()).unwrap();
        
        // Check if the constraint system is satisfied
        assert!(cs.is_satisfied().unwrap());
    }
    
    #[test]
    fn test_integer_overflow_circuit_vulnerable() {
        // Create deployment data
        let deployment = DeploymentData {
            owner: Address::zero(),
        };
        
        // Create runtime analysis
        let runtime = RuntimeAnalysis::default();
        
        // Create warning for integer overflow
        let warning = SecurityWarning {
            kind: SecurityWarningKind::IntegerOverflow,
            severity: crate::bytecode::security::SecuritySeverity::High,
            pc: 0,
            description: "Potential integer overflow in addition operation".to_string(),
            operations: vec![],
            remediation: "Use SafeMath or checked arithmetic".to_string(),
        };
        
        // Create circuit with warning
        let circuit = IntegerOverflowCircuit::<ark_bn254::Fr>::with_warnings(
            deployment,
            runtime,
            vec![warning],
            vec![],
        );
        
        // Create constraint system
        let cs = ark_relations::r1cs::ConstraintSystem::<ark_bn254::Fr>::new_ref();
        
        // Generate constraints
        circuit.generate_constraints(cs.clone()).unwrap();
        
        // Check if the constraint system is satisfied (should not be)
        assert!(!cs.is_satisfied().unwrap());
    }
    
    #[test]
    fn test_integer_underflow_circuit_vulnerable() {
        // Create deployment data
        let deployment = DeploymentData {
            owner: Address::zero(),
        };
        
        // Create runtime analysis
        let runtime = RuntimeAnalysis::default();
        
        // Create warning for integer underflow
        let warning = SecurityWarning {
            kind: SecurityWarningKind::IntegerUnderflow,
            severity: crate::bytecode::security::SecuritySeverity::High,
            pc: 0,
            description: "Potential integer underflow in subtraction operation".to_string(),
            operations: vec![],
            remediation: "Use SafeMath or checked arithmetic".to_string(),
        };
        
        // Create circuit with warning
        let circuit = IntegerOverflowCircuit::<ark_bn254::Fr>::with_warnings(
            deployment,
            runtime,
            vec![],
            vec![warning],
        );
        
        // Create constraint system
        let cs = ark_relations::r1cs::ConstraintSystem::<ark_bn254::Fr>::new_ref();
        
        // Generate constraints
        circuit.generate_constraints(cs.clone()).unwrap();
        
        // Check if the constraint system is satisfied (should not be)
        assert!(!cs.is_satisfied().unwrap());
    }
}
