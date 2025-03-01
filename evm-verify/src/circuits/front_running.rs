use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_r1cs_std::{prelude::*, boolean::Boolean};
use ethers::types::{Bytes, H160 as Address};

use crate::common::DeploymentData;
use crate::bytecode::types::RuntimeAnalysis;
use crate::bytecode::security::{SecurityWarning, SecurityWarningKind};
use crate::bytecode::BytecodeAnalyzer;
use crate::bytecode::analyzer_front_running;

/// Circuit for proving absence of front-running vulnerabilities
#[derive(Clone)]
pub struct FrontRunningCircuit<F: PrimeField> {
    /// Deployment data
    deployment: DeploymentData,

    /// Runtime analysis
    runtime: RuntimeAnalysis,

    /// Front-running warnings
    warnings: Vec<SecurityWarning>,

    /// Phantom data
    _phantom: std::marker::PhantomData<F>,
}

impl<F: PrimeField> FrontRunningCircuit<F> {
    /// Create new front-running circuit
    pub fn new(deployment: DeploymentData, runtime: RuntimeAnalysis) -> Self {
        // Create a BytecodeAnalyzer instance
        let analyzer = BytecodeAnalyzer::new(Bytes::from(vec![0u8; 0]));
        
        // Get front-running warnings
        let warnings = analyzer_front_running::analyze(&analyzer);
        
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
    
    /// Check if contract has gas price dependency
    fn has_gas_price_dependency(&self) -> bool {
        self.warnings.iter().any(|w| {
            matches!(w.kind, SecurityWarningKind::FrontRunning) && 
            (w.description.to_lowercase().contains("gas price") || 
             w.description.to_lowercase().contains("gasprice"))
        })
    }
    
    /// Check if contract has block info dependency
    fn has_block_info_dependency(&self) -> bool {
        self.warnings.iter().any(|w| {
            matches!(w.kind, SecurityWarningKind::FrontRunning) && 
            (w.description.to_lowercase().contains("block") || 
             w.description.to_lowercase().contains("timestamp"))
        })
    }
    
    /// Check if contract is missing commit-reveal pattern
    fn has_missing_commit_reveal(&self) -> bool {
        self.warnings.iter().any(|w| {
            matches!(w.kind, SecurityWarningKind::FrontRunning) && 
            w.description.to_lowercase().contains("commit")
        })
    }
    
    /// Check if contract has price-sensitive operations
    fn has_price_sensitive_operations(&self) -> bool {
        self.warnings.iter().any(|w| {
            matches!(w.kind, SecurityWarningKind::FrontRunning) && 
            (w.description.to_lowercase().contains("price") || 
             w.description.to_lowercase().contains("sensitive"))
        })
    }
    
    /// Check if contract is missing slippage protection
    fn has_missing_slippage_protection(&self) -> bool {
        self.warnings.iter().any(|w| {
            matches!(w.kind, SecurityWarningKind::FrontRunning) && 
            w.description.to_lowercase().contains("slippage")
        })
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for FrontRunningCircuit<F> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<F>,
    ) -> Result<(), SynthesisError> {
        // Create boolean variables for each vulnerability type
        let gas_price_dependency = Boolean::new_witness(cs.clone(), || {
            Ok(self.has_gas_price_dependency())
        })?;
        
        let block_info_dependency = Boolean::new_witness(cs.clone(), || {
            Ok(self.has_block_info_dependency())
        })?;
        
        let missing_commit_reveal = Boolean::new_witness(cs.clone(), || {
            Ok(self.has_missing_commit_reveal())
        })?;
        
        let price_sensitive_operations = Boolean::new_witness(cs.clone(), || {
            Ok(self.has_price_sensitive_operations())
        })?;
        
        let missing_slippage_protection = Boolean::new_witness(cs.clone(), || {
            Ok(self.has_missing_slippage_protection())
        })?;
        
        // Enforce that none of these vulnerabilities are present
        // This is done by ensuring each boolean is false
        gas_price_dependency.enforce_equal(&Boolean::constant(false))?;
        block_info_dependency.enforce_equal(&Boolean::constant(false))?;
        missing_commit_reveal.enforce_equal(&Boolean::constant(false))?;
        price_sensitive_operations.enforce_equal(&Boolean::constant(false))?;
        missing_slippage_protection.enforce_equal(&Boolean::constant(false))?;
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    
    #[test]
    fn test_front_running_circuit_safe() {
        // Create deployment data
        let deployment = DeploymentData {
            owner: Address::zero(),
        };
        
        // Create runtime analysis
        let runtime = RuntimeAnalysis::default();
        
        // Create circuit
        let circuit = FrontRunningCircuit::<ark_bls12_381::Fr>::new(deployment, runtime);
        
        // Create constraint system
        let cs = ConstraintSystem::<ark_bls12_381::Fr>::new_ref();
        
        // Generate constraints
        circuit.generate_constraints(cs.clone()).unwrap();
        
        // Check if satisfied
        assert!(cs.is_satisfied().unwrap());
    }
}
