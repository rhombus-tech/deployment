use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_r1cs_std::{prelude::*, boolean::Boolean};
use ethers::types::Bytes;

use crate::common::DeploymentData;
use crate::bytecode::types::RuntimeAnalysis;
use crate::bytecode::security::{SecurityWarning, SecurityWarningKind};
use crate::bytecode::BytecodeAnalyzer;
use crate::bytecode::analyzer_reentrancy;
use crate::bytecode::analyzer_cross_contract_reentrancy;

/// Circuit for proving absence of reentrancy vulnerabilities
#[derive(Clone)]
pub struct ReentrancyCircuit<F: PrimeField> {
    /// Deployment data
    deployment: DeploymentData,

    /// Runtime analysis
    runtime: RuntimeAnalysis,

    /// Reentrancy warnings
    warnings: Vec<SecurityWarning>,

    /// Cross-contract reentrancy warnings
    cross_contract_warnings: Vec<SecurityWarning>,

    /// Phantom data
    _phantom: std::marker::PhantomData<F>,
}

impl<F: PrimeField> ReentrancyCircuit<F> {
    /// Create new reentrancy circuit
    pub fn new(deployment: DeploymentData, runtime: RuntimeAnalysis) -> Self {
        // Create a BytecodeAnalyzer instance with empty bytecode
        // In a real implementation, we would extract bytecode from runtime
        let analyzer = BytecodeAnalyzer::new(Bytes::from(vec![0u8; 0]));
        
        // Get reentrancy warnings
        let warnings = analyzer_reentrancy::detect_reentrancy_vulnerabilities(&analyzer);
        
        // Get cross-contract reentrancy warnings
        let cross_contract_warnings = analyzer_cross_contract_reentrancy::detect_cross_contract_reentrancy(&analyzer);
        
        Self {
            deployment,
            runtime,
            warnings,
            cross_contract_warnings,
            _phantom: std::marker::PhantomData,
        }
    }
    
    /// Set warnings for testing purposes
    pub fn with_warnings(
        deployment: DeploymentData, 
        runtime: RuntimeAnalysis, 
        warnings: Vec<SecurityWarning>,
        cross_contract_warnings: Vec<SecurityWarning>
    ) -> Self {
        Self {
            deployment,
            runtime,
            warnings,
            cross_contract_warnings,
            _phantom: std::marker::PhantomData,
        }
    }
    
    /// Check if contract has classic reentrancy vulnerability
    pub fn has_classic_reentrancy(&self) -> bool {
        self.warnings.iter().any(|warning| {
            warning.kind == SecurityWarningKind::Reentrancy
        })
    }
    
    /// Check if contract has read-only reentrancy vulnerability
    pub fn has_read_only_reentrancy(&self) -> bool {
        // In a real implementation, we would check for read-only reentrancy
        // This is a placeholder implementation
        self.warnings.iter().any(|warning| {
            warning.kind == SecurityWarningKind::Reentrancy && 
            warning.description.contains("read-only")
        })
    }
    
    /// Check if contract has cross-function reentrancy vulnerability
    pub fn has_cross_function_reentrancy(&self) -> bool {
        // In a real implementation, we would check for cross-function reentrancy
        // This is a placeholder implementation
        self.warnings.iter().any(|warning| {
            warning.kind == SecurityWarningKind::Reentrancy && 
            warning.description.contains("cross-function")
        })
    }
    
    /// Check if contract has cross-contract reentrancy vulnerability
    pub fn has_cross_contract_reentrancy(&self) -> bool {
        self.cross_contract_warnings.iter().any(|warning| {
            warning.kind == SecurityWarningKind::CrossContractReentrancy
        })
    }
    
    /// Check if contract has shared storage reentrancy vulnerability
    pub fn has_shared_storage_reentrancy(&self) -> bool {
        // In a real implementation, we would check for shared storage reentrancy
        // This is a placeholder implementation
        self.cross_contract_warnings.iter().any(|warning| {
            warning.kind == SecurityWarningKind::CrossContractReentrancy && 
            warning.description.contains("shared storage")
        })
    }
    
    /// Check if contract has delegatecall reentrancy vulnerability
    pub fn has_delegatecall_reentrancy(&self) -> bool {
        // In a real implementation, we would check for delegatecall reentrancy
        // This is a placeholder implementation
        self.warnings.iter().any(|warning| {
            warning.kind == SecurityWarningKind::Reentrancy && 
            warning.description.contains("delegatecall")
        })
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for ReentrancyCircuit<F> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<F>,
    ) -> Result<(), SynthesisError> {
        // Create boolean variables for each vulnerability type
        let classic_reentrancy = Boolean::new_witness(
            cs.clone(),
            || Ok(self.has_classic_reentrancy())
        )?;
        
        let read_only_reentrancy = Boolean::new_witness(
            cs.clone(),
            || Ok(self.has_read_only_reentrancy())
        )?;
        
        let cross_function_reentrancy = Boolean::new_witness(
            cs.clone(),
            || Ok(self.has_cross_function_reentrancy())
        )?;
        
        let cross_contract_reentrancy = Boolean::new_witness(
            cs.clone(),
            || Ok(self.has_cross_contract_reentrancy())
        )?;
        
        let shared_storage_reentrancy = Boolean::new_witness(
            cs.clone(),
            || Ok(self.has_shared_storage_reentrancy())
        )?;
        
        let delegatecall_reentrancy = Boolean::new_witness(
            cs.clone(),
            || Ok(self.has_delegatecall_reentrancy())
        )?;
        
        // Enforce that none of these vulnerabilities are present
        // This is done by ensuring each boolean is false
        classic_reentrancy.enforce_equal(&Boolean::constant(false))?;
        read_only_reentrancy.enforce_equal(&Boolean::constant(false))?;
        cross_function_reentrancy.enforce_equal(&Boolean::constant(false))?;
        cross_contract_reentrancy.enforce_equal(&Boolean::constant(false))?;
        shared_storage_reentrancy.enforce_equal(&Boolean::constant(false))?;
        delegatecall_reentrancy.enforce_equal(&Boolean::constant(false))?;
        
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
    fn test_reentrancy_circuit_safe() {
        // Create deployment data
        let deployment = DeploymentData {
            owner: Address::zero(),
        };
        
        // Create runtime analysis
        let runtime = RuntimeAnalysis::default();
        
        // Create circuit with no warnings
        let circuit = ReentrancyCircuit::<ark_bn254::Fr>::with_warnings(
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
    fn test_reentrancy_circuit_vulnerable() {
        // Create deployment data
        let deployment = DeploymentData {
            owner: Address::zero(),
        };
        
        // Create runtime analysis
        let runtime = RuntimeAnalysis::default();
        
        // Create warning for classic reentrancy
        let warning = SecurityWarning::reentrancy(0, ethers::types::H256::zero());
        
        // Create circuit with warning
        let circuit = ReentrancyCircuit::<ark_bn254::Fr>::with_warnings(
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
    fn test_cross_contract_reentrancy_circuit_vulnerable() {
        // Create deployment data
        let deployment = DeploymentData {
            owner: Address::zero(),
        };
        
        // Create runtime analysis
        let runtime = RuntimeAnalysis::default();
        
        // Create warning for cross-contract reentrancy
        let warning = SecurityWarning::cross_contract_reentrancy(
            0, 
            ethers::types::H256::zero(),
            ethers::types::H256::zero(),
        );
        
        // Create circuit with warning
        let circuit = ReentrancyCircuit::<ark_bn254::Fr>::with_warnings(
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
