use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_r1cs_std::{prelude::*, boolean::Boolean};
use ethers::types::{H256, U256};

use crate::common::DeploymentData;
use crate::bytecode::types::RuntimeAnalysis;
use crate::bytecode::security::{SecurityWarning, SecuritySeverity, SecurityWarningKind, Operation};

/// Circuit for proving absence of flash loan vulnerabilities
#[derive(Clone)]
pub struct FlashLoanCircuit<F: PrimeField> {
    /// Deployment data
    deployment: DeploymentData,

    /// Runtime analysis
    runtime: RuntimeAnalysis,

    /// Flash loan vulnerability warnings
    flash_loan_warnings: Vec<SecurityWarning>,

    /// Flash loan state manipulation warnings
    state_manipulation_warnings: Vec<SecurityWarning>,

    /// Missing slippage protection warnings
    slippage_protection_warnings: Vec<SecurityWarning>,

    /// Phantom data
    _phantom: std::marker::PhantomData<F>,
}

impl<F: PrimeField> FlashLoanCircuit<F> {
    /// Create new flash loan vulnerability detection circuit
    pub fn new(deployment: DeploymentData, runtime: RuntimeAnalysis) -> Self {
        // Analyze bytecode for flash loan vulnerabilities
        let flash_loan_warnings = Self::detect_flash_loan_vulnerabilities(&runtime);
        let state_manipulation_warnings = Self::detect_state_manipulation(&runtime);
        let slippage_protection_warnings = Self::detect_missing_slippage_protection(&runtime);
        
        Self {
            deployment,
            runtime,
            flash_loan_warnings,
            state_manipulation_warnings,
            slippage_protection_warnings,
            _phantom: std::marker::PhantomData,
        }
    }
    
    /// Set warnings for testing purposes
    pub fn with_warnings(
        deployment: DeploymentData, 
        runtime: RuntimeAnalysis, 
        flash_loan_warnings: Vec<SecurityWarning>,
        state_manipulation_warnings: Vec<SecurityWarning>,
        slippage_protection_warnings: Vec<SecurityWarning>
    ) -> Self {
        Self {
            deployment,
            runtime,
            flash_loan_warnings,
            state_manipulation_warnings,
            slippage_protection_warnings,
            _phantom: std::marker::PhantomData,
        }
    }
    
    /// Check if contract has price oracle dependencies
    pub fn has_price_oracle_dependencies(&self) -> bool {
        !self.flash_loan_warnings.is_empty()
    }
    
    /// Check if contract has state manipulation vulnerabilities
    pub fn has_state_manipulation_vulnerabilities(&self) -> bool {
        !self.state_manipulation_warnings.is_empty()
    }
    
    /// Check if contract has missing slippage protection
    pub fn has_missing_slippage_protection(&self) -> bool {
        !self.slippage_protection_warnings.is_empty()
    }
    
    /// Check if contract has any flash loan vulnerability
    pub fn has_any_flash_loan_vulnerability(&self) -> bool {
        self.has_price_oracle_dependencies() || 
        self.has_state_manipulation_vulnerabilities() || 
        self.has_missing_slippage_protection()
    }
    
    /// Detect flash loan vulnerabilities by analyzing runtime patterns
    fn detect_flash_loan_vulnerabilities(runtime: &RuntimeAnalysis) -> Vec<SecurityWarning> {
        let mut warnings = Vec::new();
        
        // Look for flash loan patterns based on available runtime data:
        // 1. Multiple external calls suggesting arbitrage
        // 2. Storage state changes indicating price manipulation
        // 3. Memory access patterns suggesting flash loan usage
        
        // Check for suspicious delegate call patterns
        for delegate_call in &runtime.delegate_calls {
            if runtime.storage_accesses.len() > 3 {
                warnings.push(SecurityWarning::new(
                    SecurityWarningKind::FlashLoanVulnerability,
                    SecuritySeverity::High,
                    delegate_call.pc,
                    "Flash loan attack pattern detected: Multiple delegate calls with storage changes".to_string(),
                    vec![Operation::ExternalCall {
                        target: H256::from(delegate_call.target),
                        value: U256::zero(),
                        data: vec![], // DelegateCall doesn't store actual data, just offset/size
                    }],
                    "Implement proper slippage protection and access controls".to_string(),
                ));
            }
        }
        
        // Check for rapid state transitions indicating price manipulation
        if runtime.state_transitions.len() > 5 {
            warnings.push(SecurityWarning::new(
                SecurityWarningKind::FlashLoanVulnerability,
                SecuritySeverity::Medium,
                0,
                "Multiple rapid state transitions detected - potential flash loan price manipulation".to_string(),
                vec![Operation::StorageWrite {
                    slot: H256::zero(),
                    value: U256::zero(),
                }],
                "Use time-weighted average prices (TWAP) or multiple oracle sources".to_string(),
            ));
        }
        
        // Check for large memory operations that might indicate arbitrage patterns
        let large_memory_ops = runtime.memory_accesses.iter()
            .filter(|access| access.size > U256::from(1000))
            .count();
        
        if large_memory_ops > 2 {
            warnings.push(SecurityWarning::new(
                SecurityWarningKind::FlashLoanVulnerability,
                SecuritySeverity::Medium,
                0,
                "Large memory operations detected - potential flash loan arbitrage pattern".to_string(),
                vec![Operation::MemoryWrite {
                    offset: U256::zero(),
                    size: U256::zero(),
                }],
                "Implement slippage protection and minimum return validation".to_string(),
            ));
        }
        
        warnings
    }
    
    /// Detect state manipulation vulnerabilities
    fn detect_state_manipulation(runtime: &RuntimeAnalysis) -> Vec<SecurityWarning> {
        let mut warnings = Vec::new();
        
        // Look for patterns indicating state manipulation based on available runtime data:
        // 1. Multiple sequential storage writes
        // 2. State changes followed by external calls (reentrancy risk)
        // 3. Reentrancy-prone patterns
        
        // Check for multiple storage writes (potential state manipulation)
        if runtime.storage_accesses.len() > 5 {
            let write_count = runtime.storage_accesses.iter()
                .filter(|access| access.write)
                .count();
            
            if write_count > 3 {
                warnings.push(SecurityWarning::new(
                    SecurityWarningKind::FlashLoanStateManipulation,
                    SecuritySeverity::High,
                    0,
                    "Multiple sequential storage writes detected - potential state manipulation".to_string(),
                    vec![Operation::StorageWrite {
                        slot: H256::zero(),
                        value: U256::zero(),
                    }],
                    "Use reentrancy guards and validate state changes".to_string(),
                ));
            }
        }
        
        // Check for reentrancy patterns (delegate calls with storage changes)
        if !runtime.delegate_calls.is_empty() && !runtime.storage_accesses.is_empty() {
            for delegate_call in &runtime.delegate_calls {
                warnings.push(SecurityWarning::new(
                    SecurityWarningKind::FlashLoanStateManipulation,
                    SecuritySeverity::Medium,
                    delegate_call.pc,
                    "State manipulation detected: Delegate call with storage changes".to_string(),
                    vec![Operation::ExternalCall {
                        target: H256::from(delegate_call.target),
                        value: U256::zero(),
                        data: vec![], // DelegateCall doesn't store actual data, just offset/size
                    }],
                    "Add access controls and state validation checks".to_string(),
                ));
            }
        }
        
        // Check for rapid state transitions indicating manipulation
        if runtime.state_transitions.len() > 10 {
            warnings.push(SecurityWarning::new(
                SecurityWarningKind::FlashLoanStateManipulation,
                SecuritySeverity::Medium,
                0,
                "Excessive state transitions detected - potential state manipulation attack".to_string(),
                vec![Operation::StorageWrite {
                    slot: H256::zero(),
                    value: U256::zero(),
                }],
                "Implement state change validation and rate limiting".to_string(),
            ));
        }
        
        warnings
    }
    
    /// Detect missing slippage protection
    fn detect_missing_slippage_protection(runtime: &RuntimeAnalysis) -> Vec<SecurityWarning> {
        let mut warnings = Vec::new();
        
        // Look for patterns indicating missing slippage protection based on available runtime data:
        // 1. Multiple external calls without validation (potential DEX interactions)
        // 2. Memory operations indicating token transfers without bounds checking
        // 3. Storage operations without proper validation
        
        // Check for external calls without proper validation (potential DEX swaps)
        let external_call_count = runtime.delegate_calls.len();
        
        if external_call_count > 1 {
            // Multiple external calls could indicate DEX arbitrage without slippage protection
            warnings.push(SecurityWarning::new(
                SecurityWarningKind::MissingSlippageProtection,
                SecuritySeverity::Medium,
                0,
                "Multiple external calls detected - potential DEX operations without slippage protection".to_string(),
                vec![Operation::ExternalCall {
                    target: H256::zero(),
                    value: U256::zero(),
                    data: vec![],
                }],
                "Implement minimum return amount checks and slippage tolerance".to_string(),
            ));
        }
        
        // Check for large memory operations without validation (potential token transfers)
        let large_memory_writes = runtime.memory_accesses.iter()
            .filter(|access| access.size > U256::from(32) && access.write) // Larger than a single word
            .count();
        
        if large_memory_writes > 2 {
            warnings.push(SecurityWarning::new(
                SecurityWarningKind::MissingSlippageProtection,
                SecuritySeverity::Low,
                0,
                "Large memory operations without validation - potential token transfers without slippage protection".to_string(),
                vec![Operation::MemoryWrite {
                    offset: U256::zero(),
                    size: U256::zero(),
                }],
                "Add proper amount validation and bounds checking".to_string(),
            ));
        }
        
        // Check for storage writes without associated access control
        let unprotected_writes = runtime.storage_accesses.iter()
            .filter(|access| access.write)
            .count();
        
        if unprotected_writes > 2 && runtime.access_checks.is_empty() {
            warnings.push(SecurityWarning::new(
                SecurityWarningKind::MissingSlippageProtection,
                SecuritySeverity::Medium,
                0,
                "Storage writes without access control - potential price manipulation without slippage protection".to_string(),
                vec![Operation::StorageWrite {
                    slot: H256::zero(),
                    value: U256::zero(),
                }],
                "Implement access control and slippage validation for price-sensitive operations".to_string(),
            ));
        }
        
        warnings
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for FlashLoanCircuit<F> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<F>,
    ) -> Result<(), SynthesisError> {
        // Create boolean variables for each vulnerability check
        let price_oracle_dependencies = Boolean::new_witness(
            cs.clone(),
            || Ok(self.has_price_oracle_dependencies())
        )?;
        
        let state_manipulation_vulnerabilities = Boolean::new_witness(
            cs.clone(),
            || Ok(self.has_state_manipulation_vulnerabilities())
        )?;
        
        let missing_slippage_protection = Boolean::new_witness(
            cs.clone(),
            || Ok(self.has_missing_slippage_protection())
        )?;
        
        let any_flash_loan_vulnerability = Boolean::new_witness(
            cs.clone(),
            || Ok(self.has_any_flash_loan_vulnerability())
        )?;
        
        // Enforce that none of these vulnerabilities are present
        // This is done by ensuring each boolean is false
        price_oracle_dependencies.enforce_equal(&Boolean::constant(false))?;
        state_manipulation_vulnerabilities.enforce_equal(&Boolean::constant(false))?;
        missing_slippage_protection.enforce_equal(&Boolean::constant(false))?;
        any_flash_loan_vulnerability.enforce_equal(&Boolean::constant(false))?;
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::DeploymentData;
    use crate::bytecode::types::RuntimeAnalysis;
    use crate::bytecode::security::{SecuritySeverity, SecurityWarningKind};
    use ethers::types::H160 as Address;
    
    #[test]
    fn test_flash_loan_circuit_safe() {
        // Create deployment data
        let deployment = DeploymentData {
            owner: Address::zero(),
        };
        
        // Create runtime analysis
        let runtime = RuntimeAnalysis::default();
        
        // Create circuit with no warnings
        let circuit = FlashLoanCircuit::<ark_bn254::Fr>::with_warnings(
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
    fn test_price_oracle_dependency_vulnerable() {
        // Create deployment data
        let deployment = DeploymentData {
            owner: Address::zero(),
        };
        
        // Create runtime analysis
        let runtime = RuntimeAnalysis::default();
        
        // Create warning for price oracle dependency
        let warning = SecurityWarning::flash_loan_vulnerability(0);
        
        // Create circuit with warning
        let circuit = FlashLoanCircuit::<ark_bn254::Fr>::with_warnings(
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
    fn test_state_manipulation_vulnerable() {
        // Create deployment data
        let deployment = DeploymentData {
            owner: Address::zero(),
        };
        
        // Create runtime analysis
        let runtime = RuntimeAnalysis::default();
        
        // Create warning for state manipulation
        let warning = SecurityWarning::flash_loan_state_manipulation(0);
        
        // Create circuit with warning
        let circuit = FlashLoanCircuit::<ark_bn254::Fr>::with_warnings(
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
    fn test_missing_slippage_protection_vulnerable() {
        // Create deployment data
        let deployment = DeploymentData {
            owner: Address::zero(),
        };
        
        // Create runtime analysis
        let runtime = RuntimeAnalysis::default();
        
        // Create warning for missing slippage protection
        let warning = SecurityWarning {
            kind: SecurityWarningKind::MissingSlippageProtection,
            severity: SecuritySeverity::High,
            pc: 0,
            description: "Missing slippage protection in swap operation".to_string(),
            operations: Vec::new(),
            remediation: "Implement slippage protection with minimum output amount checks".to_string(),
        };
        
        // Create circuit with warning
        let circuit = FlashLoanCircuit::<ark_bn254::Fr>::with_warnings(
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
    fn test_multiple_flash_loan_vulnerabilities() {
        // Create deployment data
        let deployment = DeploymentData {
            owner: Address::zero(),
        };
        
        // Create runtime analysis
        let runtime = RuntimeAnalysis::default();
        
        // Create warnings for multiple vulnerabilities
        let oracle_warning = SecurityWarning::flash_loan_vulnerability(0);
        let state_warning = SecurityWarning::flash_loan_state_manipulation(0);
        
        // Create circuit with multiple warnings
        let circuit = FlashLoanCircuit::<ark_bn254::Fr>::with_warnings(
            deployment,
            runtime,
            vec![oracle_warning],
            vec![state_warning],
            vec![],
        );
        
        // Create constraint system
        let cs = ark_relations::r1cs::ConstraintSystem::<ark_bn254::Fr>::new_ref();
        
        // Generate constraints
        circuit.generate_constraints(cs.clone()).unwrap();
        
        // Check if the constraint system is satisfied (should not be)
        assert!(!cs.is_satisfied().unwrap());
    }
}
