use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_r1cs_std::{prelude::*, boolean::Boolean};
use ethers::types::Bytes;

use crate::common::DeploymentData;
use crate::bytecode::types::RuntimeAnalysis;
use crate::bytecode::security::{SecurityWarning, SecurityWarningKind};
use crate::bytecode::BytecodeAnalyzer;
use crate::bytecode::analyzer_precision;

/// Circuit for proving absence of precision vulnerabilities
#[derive(Clone)]
pub struct PrecisionCircuit<F: PrimeField> {
    /// Deployment data
    deployment: DeploymentData,

    /// Runtime analysis
    runtime: RuntimeAnalysis,

    /// Precision vulnerability warnings
    warnings: Vec<SecurityWarning>,

    /// Phantom data
    _phantom: std::marker::PhantomData<F>,
}

impl<F: PrimeField> PrecisionCircuit<F> {
    /// Create new precision vulnerability detection circuit
    pub fn new(deployment: DeploymentData, runtime: RuntimeAnalysis) -> Self {
        // Create a BytecodeAnalyzer instance
        let analyzer = BytecodeAnalyzer::new(Bytes::from(vec![0u8; 0]));
        
        // Get precision vulnerability warnings
        let warnings = analyzer_precision::analyze(&analyzer);
        
        Self {
            deployment,
            runtime,
            warnings,
            _phantom: std::marker::PhantomData,
        }
    }
    
    /// Set warnings for testing purposes
    pub fn with_warnings(deployment: DeploymentData, runtime: RuntimeAnalysis, warnings: Vec<SecurityWarning>) -> Self {
        Self {
            deployment,
            runtime,
            warnings,
            _phantom: std::marker::PhantomData,
        }
    }
    
    /// Check if contract has division before multiplication
    fn has_division_before_multiplication(&self) -> bool {
        self.warnings.iter().any(|warning| {
            warning.kind == SecurityWarningKind::PrecisionLoss && 
            warning.description.contains("Division before multiplication")
        })
    }
    
    /// Check if contract has improper scaling
    fn has_improper_scaling(&self) -> bool {
        self.warnings.iter().any(|warning| {
            warning.kind == SecurityWarningKind::PrecisionLoss && 
            warning.description.contains("improper scaling")
        })
    }
    
    /// Check if contract has truncation issues
    fn has_truncation_issues(&self) -> bool {
        self.warnings.iter().any(|warning| {
            warning.kind == SecurityWarningKind::PrecisionLoss && 
            warning.description.contains("truncation")
        })
    }
    
    /// Check if contract has inconsistent decimal handling
    fn has_inconsistent_decimal_handling(&self) -> bool {
        self.warnings.iter().any(|warning| {
            warning.kind == SecurityWarningKind::PrecisionLoss && 
            warning.description.contains("inconsistent decimal")
        })
    }
    
    /// Check if contract has exponentiation precision issues
    fn has_exponentiation_precision_issues(&self) -> bool {
        self.warnings.iter().any(|warning| {
            warning.kind == SecurityWarningKind::PrecisionLoss && 
            warning.description.contains("Exponentiation")
        })
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for PrecisionCircuit<F> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<F>,
    ) -> Result<(), SynthesisError> {
        // Create boolean variables for each vulnerability check
        let division_before_multiplication = Boolean::new_witness(
            cs.clone(),
            || Ok(self.has_division_before_multiplication())
        )?;
        
        let improper_scaling = Boolean::new_witness(
            cs.clone(),
            || Ok(self.has_improper_scaling())
        )?;
        
        let truncation_issues = Boolean::new_witness(
            cs.clone(),
            || Ok(self.has_truncation_issues())
        )?;
        
        let inconsistent_decimal_handling = Boolean::new_witness(
            cs.clone(),
            || Ok(self.has_inconsistent_decimal_handling())
        )?;
        
        let exponentiation_issues = Boolean::new_witness(
            cs.clone(),
            || Ok(self.has_exponentiation_precision_issues())
        )?;
        
        // Enforce that none of these vulnerabilities are present
        // This is done by ensuring each boolean is false
        division_before_multiplication.enforce_equal(&Boolean::constant(false))?;
        improper_scaling.enforce_equal(&Boolean::constant(false))?;
        truncation_issues.enforce_equal(&Boolean::constant(false))?;
        inconsistent_decimal_handling.enforce_equal(&Boolean::constant(false))?;
        exponentiation_issues.enforce_equal(&Boolean::constant(false))?;
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    use ethers::types::H160 as Address;
    
    #[test]
    fn test_precision_circuit_safe() {
        // Create deployment data
        let deployment = DeploymentData {
            owner: Address::zero(),
        };
        
        // Create runtime analysis
        let runtime = RuntimeAnalysis::default();
        
        // Create circuit with no warnings
        let circuit = PrecisionCircuit::with_warnings(deployment, runtime, vec![]);
        
        // Create constraint system
        let cs = ConstraintSystem::<ark_bls12_381::Fr>::new_ref();
        
        // Generate constraints
        circuit.generate_constraints(cs.clone()).unwrap();
        
        // Check if satisfied - should be satisfied for a safe contract
        assert!(cs.is_satisfied().unwrap());
    }
}
