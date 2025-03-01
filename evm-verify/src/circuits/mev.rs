use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_r1cs_std::{prelude::*, boolean::Boolean};
use ethers::types::Bytes;

use crate::common::DeploymentData;
use crate::bytecode::types::RuntimeAnalysis;
use crate::bytecode::security::{SecurityWarning, SecurityWarningKind};
use crate::bytecode::BytecodeAnalyzer;
use crate::bytecode::analyzer_mev;

/// Circuit for proving absence of MEV (Maximal Extractable Value) vulnerabilities
#[derive(Clone)]
pub struct MEVCircuit<F: PrimeField> {
    /// Deployment data
    deployment: DeploymentData,

    /// Runtime analysis
    runtime: RuntimeAnalysis,

    /// MEV vulnerability warnings
    warnings: Vec<SecurityWarning>,

    /// Phantom data
    _phantom: std::marker::PhantomData<F>,
}

impl<F: PrimeField> MEVCircuit<F> {
    /// Create new MEV vulnerability detection circuit
    pub fn new(deployment: DeploymentData, runtime: RuntimeAnalysis) -> Self {
        // Create a BytecodeAnalyzer instance
        let analyzer = BytecodeAnalyzer::new(Bytes::from(vec![0u8; 0]));
        
        // Get MEV vulnerability warnings
        let warnings = analyzer_mev::detect_mev_vulnerabilities(&analyzer);
        
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
    
    /// Check if contract has unprotected price operations
    fn has_unprotected_price_operations(&self) -> bool {
        self.warnings.iter().any(|warning| {
            warning.kind == SecurityWarningKind::MEVVulnerability && 
            warning.description.contains("unprotected price")
        })
    }
    
    /// Check if contract has DEX interactions without proper protection
    fn has_unprotected_dex_interactions(&self) -> bool {
        self.warnings.iter().any(|warning| {
            warning.kind == SecurityWarningKind::MEVVulnerability && 
            warning.description.contains("DEX interaction")
        })
    }
    
    /// Check if contract is missing slippage protection
    fn has_missing_slippage_protection(&self) -> bool {
        self.warnings.iter().any(|warning| {
            warning.kind == SecurityWarningKind::MEVVulnerability && 
            warning.description.contains("slippage protection")
        })
    }
    
    /// Check if contract lacks commit-reveal pattern
    fn lacks_commit_reveal_pattern(&self) -> bool {
        self.warnings.iter().any(|warning| {
            warning.kind == SecurityWarningKind::MEVVulnerability && 
            warning.description.contains("commit-reveal pattern")
        })
    }
    
    /// Check if contract lacks private mempool usage
    fn lacks_private_mempool_usage(&self) -> bool {
        self.warnings.iter().any(|warning| {
            warning.kind == SecurityWarningKind::MEVVulnerability && 
            warning.description.contains("private mempool")
        })
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for MEVCircuit<F> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<F>,
    ) -> Result<(), SynthesisError> {
        // Create boolean variables for each vulnerability check
        let unprotected_price_ops = Boolean::new_witness(
            cs.clone(),
            || Ok(self.has_unprotected_price_operations())
        )?;
        
        let unprotected_dex = Boolean::new_witness(
            cs.clone(),
            || Ok(self.has_unprotected_dex_interactions())
        )?;
        
        let missing_slippage = Boolean::new_witness(
            cs.clone(),
            || Ok(self.has_missing_slippage_protection())
        )?;
        
        let lacks_commit_reveal = Boolean::new_witness(
            cs.clone(),
            || Ok(self.lacks_commit_reveal_pattern())
        )?;
        
        let lacks_private_mempool = Boolean::new_witness(
            cs.clone(),
            || Ok(self.lacks_private_mempool_usage())
        )?;
        
        // Enforce that none of these vulnerabilities are present
        // This is done by ensuring each boolean is false
        unprotected_price_ops.enforce_equal(&Boolean::constant(false))?;
        unprotected_dex.enforce_equal(&Boolean::constant(false))?;
        missing_slippage.enforce_equal(&Boolean::constant(false))?;
        lacks_commit_reveal.enforce_equal(&Boolean::constant(false))?;
        lacks_private_mempool.enforce_equal(&Boolean::constant(false))?;
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    use ethers::types::H160 as Address;
    
    #[test]
    fn test_mev_circuit_safe() {
        // Create deployment data
        let deployment = DeploymentData {
            owner: Address::zero(),
        };
        
        // Create runtime analysis
        let runtime = RuntimeAnalysis::default();
        
        // Create circuit with no warnings
        let circuit = MEVCircuit::with_warnings(deployment, runtime, vec![]);
        
        // Create constraint system
        let cs = ConstraintSystem::<ark_bls12_381::Fr>::new_ref();
        
        // Generate constraints
        circuit.generate_constraints(cs.clone()).unwrap();
        
        // Check if satisfied - should be satisfied for a safe contract
        assert!(cs.is_satisfied().unwrap());
    }
}
