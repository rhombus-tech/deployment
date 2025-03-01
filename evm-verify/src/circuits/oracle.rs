use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_r1cs_std::{prelude::*, boolean::Boolean};
use ethers::types::Bytes;

use crate::common::DeploymentData;
use crate::bytecode::types::RuntimeAnalysis;
use crate::bytecode::security::{SecurityWarning, SecurityWarningKind};
use crate::bytecode::BytecodeAnalyzer;
use crate::bytecode::analyzer_oracle;

/// Circuit for proving absence of oracle manipulation vulnerabilities
#[derive(Clone)]
pub struct OracleCircuit<F: PrimeField> {
    /// Deployment data
    deployment: DeploymentData,

    /// Runtime analysis
    runtime: RuntimeAnalysis,

    /// Oracle manipulation warnings
    warnings: Vec<SecurityWarning>,

    /// Phantom data
    _phantom: std::marker::PhantomData<F>,
}

impl<F: PrimeField> OracleCircuit<F> {
    /// Create new oracle manipulation circuit
    pub fn new(deployment: DeploymentData, runtime: RuntimeAnalysis) -> Self {
        // Create a BytecodeAnalyzer instance with empty bytecode
        // In a real implementation, we would extract bytecode from runtime
        let analyzer = BytecodeAnalyzer::new(Bytes::from(vec![0u8; 0]));
        
        // Get oracle manipulation warnings
        let warnings = analyzer_oracle::detect_oracle_vulnerabilities(&analyzer);
        
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
    
    /// Check if contract has single-source oracle dependency
    fn has_single_source_oracle_dependency(&self) -> bool {
        self.warnings.iter().any(|warning| {
            warning.kind == SecurityWarningKind::OracleManipulation && 
            warning.description.contains("single oracle source")
        })
    }
    
    /// Check if contract has unverified oracle data
    fn has_unverified_oracle_data(&self) -> bool {
        self.warnings.iter().any(|warning| {
            warning.kind == SecurityWarningKind::OracleManipulation && 
            warning.description.contains("without validation")
        })
    }
    
    /// Check if contract has stale oracle data
    fn has_stale_oracle_data(&self) -> bool {
        self.warnings.iter().any(|warning| {
            warning.kind == SecurityWarningKind::OracleManipulation && 
            warning.description.contains("stale data")
        })
    }
    
    /// Check if contract has manipulable price feed
    fn has_manipulable_price_feed(&self) -> bool {
        self.warnings.iter().any(|warning| {
            warning.kind == SecurityWarningKind::OracleManipulation && 
            warning.description.contains("price manipulation")
        })
    }
    
    /// Check if contract has flash loan attack vector
    fn has_flash_loan_attack_vector(&self) -> bool {
        self.warnings.iter().any(|warning| {
            warning.kind == SecurityWarningKind::OracleManipulation && 
            warning.description.contains("flash loan")
        })
    }
    
    /// Check if contract lacks TWAP mechanisms
    fn lacks_twap_mechanisms(&self) -> bool {
        self.warnings.iter().any(|warning| {
            warning.kind == SecurityWarningKind::OracleManipulation && 
            warning.description.contains("TWAP")
        })
    }
    
    /// Check if contract lacks circuit breakers
    fn lacks_circuit_breakers(&self) -> bool {
        self.warnings.iter().any(|warning| {
            warning.kind == SecurityWarningKind::OracleManipulation && 
            warning.description.contains("circuit breakers")
        })
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for OracleCircuit<F> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<F>,
    ) -> Result<(), SynthesisError> {
        // Create boolean variables for each vulnerability type
        let single_source_dependency = Boolean::new_witness(
            cs.clone(),
            || Ok(self.has_single_source_oracle_dependency())
        )?;
        
        let unverified_data = Boolean::new_witness(
            cs.clone(),
            || Ok(self.has_unverified_oracle_data())
        )?;
        
        let stale_data = Boolean::new_witness(
            cs.clone(),
            || Ok(self.has_stale_oracle_data())
        )?;
        
        let manipulable_price_feed = Boolean::new_witness(
            cs.clone(),
            || Ok(self.has_manipulable_price_feed())
        )?;
        
        let flash_loan_attack_vector = Boolean::new_witness(
            cs.clone(),
            || Ok(self.has_flash_loan_attack_vector())
        )?;
        
        let lacks_twap = Boolean::new_witness(
            cs.clone(),
            || Ok(self.lacks_twap_mechanisms())
        )?;
        
        let lacks_circuit_breakers = Boolean::new_witness(
            cs.clone(),
            || Ok(self.lacks_circuit_breakers())
        )?;
        
        // Enforce that none of these vulnerabilities are present
        // This is done by ensuring each boolean is false
        single_source_dependency.enforce_equal(&Boolean::constant(false))?;
        unverified_data.enforce_equal(&Boolean::constant(false))?;
        stale_data.enforce_equal(&Boolean::constant(false))?;
        manipulable_price_feed.enforce_equal(&Boolean::constant(false))?;
        flash_loan_attack_vector.enforce_equal(&Boolean::constant(false))?;
        lacks_twap.enforce_equal(&Boolean::constant(false))?;
        lacks_circuit_breakers.enforce_equal(&Boolean::constant(false))?;
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    use ethers::types::H160 as Address;
    
    #[test]
    fn test_oracle_circuit_safe() {
        // Create a constraint system
        let cs = ConstraintSystem::<ark_bn254::Fr>::new_ref();
        
        // Create deployment data and runtime analysis
        let deployment = DeploymentData {
            owner: Address::zero(),
        };
        
        let runtime = RuntimeAnalysis::default();
        
        // Create circuit with no warnings
        let circuit = OracleCircuit::with_warnings(
            deployment,
            runtime,
            vec![]
        );
        
        // Generate constraints
        assert!(circuit.generate_constraints(cs.clone()).is_ok());
        
        // Check that constraints are satisfied
        assert!(cs.is_satisfied().unwrap());
    }
    
    #[test]
    fn test_oracle_circuit_vulnerable() {
        // Create a constraint system
        let cs = ConstraintSystem::<ark_bn254::Fr>::new_ref();
        
        // Create deployment data and runtime analysis
        let deployment = DeploymentData {
            owner: Address::zero(),
        };
        
        let runtime = RuntimeAnalysis::default();
        
        // Create a warning
        let warning = SecurityWarning {
            kind: SecurityWarningKind::OracleManipulation,
            severity: crate::bytecode::security::SecuritySeverity::High,
            pc: 0,
            description: "Contract relies on a single oracle source that can be manipulated".to_string(),
            operations: vec![],
            remediation: "Use multiple oracle sources and implement a median or weighted average".to_string(),
        };
        
        // Create circuit with a warning
        let circuit = OracleCircuit::with_warnings(
            deployment,
            runtime,
            vec![warning]
        );
        
        // Generate constraints
        assert!(circuit.generate_constraints(cs.clone()).is_ok());
        
        // Check that constraints are not satisfied
        assert!(!cs.is_satisfied().unwrap());
    }
}
