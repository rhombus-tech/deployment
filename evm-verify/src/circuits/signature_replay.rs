use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_r1cs_std::{prelude::*, boolean::Boolean};

use crate::common::DeploymentData;
use crate::bytecode::types::RuntimeAnalysis;
use crate::bytecode::security::{SecurityWarning, SecurityWarningKind};

/// Circuit for proving absence of signature replay vulnerabilities
#[derive(Clone)]
pub struct SignatureReplayCircuit<F: PrimeField> {
    /// Deployment data
    deployment: DeploymentData,

    /// Runtime analysis
    runtime: RuntimeAnalysis,

    /// Missing nonce protection warnings
    missing_nonce_warnings: Vec<SecurityWarning>,

    /// Missing expiration timestamp warnings
    missing_expiration_warnings: Vec<SecurityWarning>,

    /// ECRECOVER misuse warnings
    ecrecover_misuse_warnings: Vec<SecurityWarning>,

    /// Phantom data
    _phantom: std::marker::PhantomData<F>,
}

impl<F: PrimeField> SignatureReplayCircuit<F> {
    /// Create new signature replay vulnerability detection circuit
    pub fn new(deployment: DeploymentData, runtime: RuntimeAnalysis) -> Self {
        // In a real implementation, we would analyze the bytecode here
        // For now, we'll just create empty sets of warnings
        let missing_nonce_warnings = Vec::new();
        let missing_expiration_warnings = Vec::new();
        let ecrecover_misuse_warnings = Vec::new();
        
        Self {
            deployment,
            runtime,
            missing_nonce_warnings,
            missing_expiration_warnings,
            ecrecover_misuse_warnings,
            _phantom: std::marker::PhantomData,
        }
    }
    
    /// Set warnings for testing purposes
    pub fn with_warnings(
        deployment: DeploymentData, 
        runtime: RuntimeAnalysis, 
        missing_nonce_warnings: Vec<SecurityWarning>,
        missing_expiration_warnings: Vec<SecurityWarning>,
        ecrecover_misuse_warnings: Vec<SecurityWarning>
    ) -> Self {
        Self {
            deployment,
            runtime,
            missing_nonce_warnings,
            missing_expiration_warnings,
            ecrecover_misuse_warnings,
            _phantom: std::marker::PhantomData,
        }
    }
    
    /// Check if contract has missing nonce protection
    pub fn has_missing_nonce_protection(&self) -> bool {
        self.missing_nonce_warnings.iter().any(|w| w.kind == SecurityWarningKind::SignatureReplay)
    }
    
    /// Check if contract has missing expiration timestamp
    pub fn has_missing_expiration_timestamp(&self) -> bool {
        self.missing_expiration_warnings.iter().any(|w| w.kind == SecurityWarningKind::SignatureReplay)
    }
    
    /// Check if contract has ECRECOVER misuse
    pub fn has_ecrecover_misuse(&self) -> bool {
        self.ecrecover_misuse_warnings.iter().any(|w| w.kind == SecurityWarningKind::SignatureReplay)
    }
    
    /// Check if contract has any signature replay vulnerability
    pub fn has_any_signature_replay_vulnerability(&self) -> bool {
        self.has_missing_nonce_protection() || 
        self.has_missing_expiration_timestamp() || 
        self.has_ecrecover_misuse()
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for SignatureReplayCircuit<F> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<F>,
    ) -> Result<(), SynthesisError> {
        // Create boolean variables for each vulnerability check
        let missing_nonce_protection = Boolean::new_witness(
            cs.clone(),
            || Ok(self.has_missing_nonce_protection())
        )?;
        
        let missing_expiration_timestamp = Boolean::new_witness(
            cs.clone(),
            || Ok(self.has_missing_expiration_timestamp())
        )?;
        
        let ecrecover_misuse = Boolean::new_witness(
            cs.clone(),
            || Ok(self.has_ecrecover_misuse())
        )?;
        
        let any_signature_replay_vulnerability = Boolean::new_witness(
            cs.clone(),
            || Ok(self.has_any_signature_replay_vulnerability())
        )?;
        
        // Enforce that none of these vulnerabilities are present
        // This is done by ensuring each boolean is false
        missing_nonce_protection.enforce_equal(&Boolean::constant(false))?;
        missing_expiration_timestamp.enforce_equal(&Boolean::constant(false))?;
        ecrecover_misuse.enforce_equal(&Boolean::constant(false))?;
        any_signature_replay_vulnerability.enforce_equal(&Boolean::constant(false))?;
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::DeploymentData;
    use crate::bytecode::types::RuntimeAnalysis;
    use crate::bytecode::security::{SecuritySeverity, SecurityWarningKind, Operation};
    use ethers::types::H160 as Address;
    
    // Helper function to create a missing nonce warning
    fn create_missing_nonce_warning() -> SecurityWarning {
        SecurityWarning::new(
            SecurityWarningKind::SignatureReplay,
            SecuritySeverity::High,
            0,
            "Potential signature replay vulnerability: missing nonce protection".to_string(),
            vec![Operation::Cryptography {
                op_type: "signature_verification".to_string(),
                input: None,
            }],
            "Implement nonce-based protection to prevent signature replay attacks".to_string(),
        )
    }
    
    // Helper function to create a missing expiration warning
    fn create_missing_expiration_warning() -> SecurityWarning {
        SecurityWarning::new(
            SecurityWarningKind::SignatureReplay,
            SecuritySeverity::Medium,
            0,
            "Potential signature replay vulnerability: missing expiration timestamp".to_string(),
            vec![Operation::Cryptography {
                op_type: "signature_verification".to_string(),
                input: None,
            }],
            "Implement timestamp-based expiration to prevent signature replay attacks".to_string(),
        )
    }
    
    // Helper function to create an ECRECOVER misuse warning
    fn create_ecrecover_misuse_warning() -> SecurityWarning {
        SecurityWarning::new(
            SecurityWarningKind::SignatureReplay,
            SecuritySeverity::High,
            0,
            "Potential ECRECOVER misuse that may lead to signature replay".to_string(),
            vec![Operation::Cryptography {
                op_type: "ecrecover".to_string(),
                input: None,
            }],
            "Ensure proper validation of signatures to prevent replay attacks".to_string(),
        )
    }
    
    #[test]
    fn test_signature_replay_circuit_safe() {
        // Create deployment data
        let deployment = DeploymentData {
            owner: Address::zero(),
        };
        
        // Create runtime analysis
        let runtime = RuntimeAnalysis::default();
        
        // Create circuit with no warnings
        let circuit = SignatureReplayCircuit::<ark_bn254::Fr>::with_warnings(
            deployment,
            runtime,
            vec![],
            vec![],
            vec![],
        );
        
        // Create constraint system
        let cs = ark_relations::r1cs::ConstraintSystem::<ark_bn254::Fr>::new_ref();
        
        // Generate constraints
        circuit.generate_constraints(cs.clone()).unwrap();
        
        // Check if the constraint system is satisfied
        assert!(cs.is_satisfied().unwrap());
        assert_eq!(cs.num_constraints(), 8);
    }
    
    #[test]
    fn test_missing_nonce_protection() {
        // Create deployment data
        let deployment = DeploymentData {
            owner: Address::zero(),
        };
        
        // Create runtime analysis
        let runtime = RuntimeAnalysis::default();
        
        // Create warning for missing nonce protection
        let warning = create_missing_nonce_warning();
        
        // Create circuit with warning
        let circuit = SignatureReplayCircuit::<ark_bn254::Fr>::with_warnings(
            deployment,
            runtime,
            vec![warning],
            vec![],
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
    fn test_missing_expiration_timestamp() {
        // Create deployment data
        let deployment = DeploymentData {
            owner: Address::zero(),
        };
        
        // Create runtime analysis
        let runtime = RuntimeAnalysis::default();
        
        // Create warning for missing expiration timestamp
        let warning = create_missing_expiration_warning();
        
        // Create circuit with warning
        let circuit = SignatureReplayCircuit::<ark_bn254::Fr>::with_warnings(
            deployment,
            runtime,
            vec![],
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
    fn test_ecrecover_misuse() {
        // Create deployment data
        let deployment = DeploymentData {
            owner: Address::zero(),
        };
        
        // Create runtime analysis
        let runtime = RuntimeAnalysis::default();
        
        // Create warning for ECRECOVER misuse
        let warning = create_ecrecover_misuse_warning();
        
        // Create circuit with warning
        let circuit = SignatureReplayCircuit::<ark_bn254::Fr>::with_warnings(
            deployment,
            runtime,
            vec![],
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
    
    #[test]
    fn test_multiple_signature_replay_vulnerabilities() {
        // Create deployment data
        let deployment = DeploymentData {
            owner: Address::zero(),
        };
        
        // Create runtime analysis
        let runtime = RuntimeAnalysis::default();
        
        // Create warnings for multiple vulnerabilities
        let nonce_warning = create_missing_nonce_warning();
        let expiration_warning = create_missing_expiration_warning();
        let ecrecover_warning = create_ecrecover_misuse_warning();
        
        // Create circuit with multiple warnings
        let circuit = SignatureReplayCircuit::<ark_bn254::Fr>::with_warnings(
            deployment,
            runtime,
            vec![nonce_warning],
            vec![expiration_warning],
            vec![ecrecover_warning],
        );
        
        // Create constraint system
        let cs = ark_relations::r1cs::ConstraintSystem::<ark_bn254::Fr>::new_ref();
        
        // Generate constraints
        circuit.generate_constraints(cs.clone()).unwrap();
        
        // Check if the constraint system is satisfied (should not be)
        assert!(!cs.is_satisfied().unwrap());
    }
}
