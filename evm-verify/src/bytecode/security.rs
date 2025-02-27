use ethers::types::{H256, U256};
use serde::{Serialize, Deserialize};

/// Operation type for security analysis
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Operation {
    /// Storage write operation
    StorageWrite {
        /// Storage slot
        slot: H256,
        /// Value written
        value: U256,
    },
    /// Delegate call operation
    DelegateCall {
        /// Target address
        target: H256,
        /// Call data
        data: Vec<u8>,
    },
    /// External call operation
    ExternalCall {
        /// Target address
        target: H256,
        /// Value sent
        value: U256,
        /// Call data
        data: Vec<u8>,
    },
    /// Self destruct operation
    SelfDestruct {
        /// Beneficiary address
        beneficiary: H256,
    },
    /// Memory write operation
    MemoryWrite {
        /// Memory offset
        offset: U256,
        /// Size of write
        size: U256,
    },
    /// Memory read operation
    MemoryRead {
        /// Memory offset
        offset: U256,
        /// Size of read
        size: U256,
    },
    /// External call with value
    ValueCall {
        /// Target address
        target: H256,
        /// Value sent
        value: U256,
    },
}

/// Security severity level
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecuritySeverity {
    /// Informational issue
    Info,
    /// Low severity issue
    Low,
    /// Medium severity issue
    Medium,
    /// High severity issue
    High,
    /// Critical severity issue
    Critical,
}

/// Security warning kind
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SecurityWarningKind {
    /// Reentrancy vulnerability
    Reentrancy,
    /// Read-only reentrancy vulnerability
    ReadOnlyReentrancy,
    /// Cross-function reentrancy vulnerability
    CrossFunctionReentrancy,
    /// Unprotected self destruct
    UnprotectedSelfDestruct,
    /// Unprotected delegate call
    UnprotectedDelegateCall,
    /// Unprotected external call
    UnprotectedExternalCall,
    /// Unchecked return value
    UncheckedReturnValue,
    /// Integer overflow/underflow
    IntegerOverflow,
    /// Use of tx.origin for authorization
    TxOriginAuth,
    /// Uninitialized storage
    UninitializedStorage,
    /// Unprotected state variable
    UnprotectedStateVariable,
    /// Arbitrary jump
    ArbitraryJump,
    /// Timestamp dependence
    TimestampDependence,
    /// Block number dependence
    BlockNumberDependence,
    /// Unchecked math
    UncheckedMath,
    /// Unused return value
    UnusedReturnValue,
    /// Other security issue
    Other(String),
}

/// Security warning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityWarning {
    /// Type of warning
    pub kind: SecurityWarningKind,
    /// Severity level
    pub severity: SecuritySeverity,
    /// Program counter where issue was detected
    pub pc: u64,
    /// Description of the issue
    pub description: String,
    /// Operations involved in the issue
    pub operations: Vec<Operation>,
    /// Suggested remediation
    pub remediation: String,
}

impl SecurityWarning {
    /// Create a new security warning
    pub fn new(
        kind: SecurityWarningKind,
        severity: SecuritySeverity,
        pc: u64,
        description: String,
        operations: Vec<Operation>,
        remediation: String,
    ) -> Self {
        Self {
            kind,
            severity,
            pc,
            description,
            operations,
            remediation,
        }
    }

    /// Create a reentrancy warning
    pub fn reentrancy(pc: u64, slot: H256) -> Self {
        Self::new(
            SecurityWarningKind::Reentrancy,
            SecuritySeverity::High,
            pc,
            format!("Potential reentrancy vulnerability detected at storage slot {:?}", slot),
            vec![Operation::StorageWrite { slot, value: U256::zero() }],
            "Implement checks-effects-interactions pattern or use a reentrancy guard".to_string(),
        )
    }

    /// Create a reentrancy warning with external call details
    pub fn reentrancy_with_call(pc: u64, slot: H256, target: H256, value: U256) -> Self {
        Self::new(
            SecurityWarningKind::Reentrancy,
            SecuritySeverity::High,
            pc,
            format!("Potential reentrancy vulnerability detected: state changes after external call to {:?}", target),
            vec![
                Operation::ExternalCall { 
                    target, 
                    value, 
                    data: vec![] 
                },
                Operation::StorageWrite { 
                    slot, 
                    value: U256::zero() 
                }
            ],
            "Implement checks-effects-interactions pattern: move all state changes before external calls, or use a reentrancy guard like OpenZeppelin's ReentrancyGuard".to_string(),
        )
    }

    /// Create a read-only reentrancy warning
    pub fn read_only_reentrancy(pc: u64, slot: H256, target: H256) -> Self {
        Self::new(
            SecurityWarningKind::ReadOnlyReentrancy,
            SecuritySeverity::Medium,
            pc,
            format!("Potential read-only reentrancy vulnerability detected: view function relies on storage that could be manipulated during reentrancy"),
            vec![
                Operation::ExternalCall { 
                    target, 
                    value: U256::zero(), 
                    data: vec![] 
                }
            ],
            "Ensure view functions don't rely on storage values that could be manipulated during reentrancy. Consider using reentrancy guards even for view functions if they're critical for business logic.".to_string(),
        )
    }

    /// Create a cross-function reentrancy warning
    pub fn cross_function_reentrancy(pc: u64, slot: H256, target: H256) -> Self {
        Self::new(
            SecurityWarningKind::CrossFunctionReentrancy,
            SecuritySeverity::High,
            pc,
            format!("Potential cross-function reentrancy vulnerability detected: external call could reenter through a different function that modifies the same state"),
            vec![
                Operation::ExternalCall { 
                    target, 
                    value: U256::zero(), 
                    data: vec![] 
                },
                Operation::StorageWrite { 
                    slot, 
                    value: U256::zero() 
                }
            ],
            "Implement a contract-wide reentrancy guard that protects all state-modifying functions, or ensure all functions follow the checks-effects-interactions pattern consistently.".to_string(),
        )
    }

    /// Create an unprotected self destruct warning
    pub fn unprotected_self_destruct(pc: u64, beneficiary: H256) -> Self {
        Self::new(
            SecurityWarningKind::UnprotectedSelfDestruct,
            SecuritySeverity::Critical,
            pc,
            format!("Unprotected self destruct operation detected"),
            vec![Operation::SelfDestruct { beneficiary }],
            "Add access control to self destruct operations".to_string(),
        )
    }

    /// Create an unprotected delegate call warning
    pub fn unprotected_delegate_call(pc: u64, target: H256, data: Vec<u8>) -> Self {
        Self::new(
            SecurityWarningKind::UnprotectedDelegateCall,
            SecuritySeverity::Critical,
            pc,
            format!("Unprotected delegate call operation detected"),
            vec![Operation::DelegateCall { target, data }],
            "Add access control to delegate call operations".to_string(),
        )
    }

    /// Create an integer overflow warning
    pub fn integer_overflow(pc: u64) -> Self {
        Self::new(
            SecurityWarningKind::IntegerOverflow,
            SecuritySeverity::High,
            pc,
            format!("Potential integer overflow/underflow detected"),
            vec![],
            "Use SafeMath or Solidity 0.8.0+ for automatic overflow checking".to_string(),
        )
    }

    /// Create an unprotected state variable warning
    pub fn unprotected_state_variable(pc: u64, slot: H256) -> Self {
        Self::new(
            SecurityWarningKind::UnprotectedStateVariable,
            SecuritySeverity::Medium,
            pc,
            format!("Unprotected state variable write detected at slot {:?}", slot),
            vec![Operation::StorageWrite { slot, value: U256::zero() }],
            "Add access control to state-changing operations".to_string(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_warning_creation() {
        let warning = SecurityWarning::reentrancy(123, H256::zero());
        assert_eq!(warning.kind, SecurityWarningKind::Reentrancy);
        assert_eq!(warning.severity, SecuritySeverity::High);
        assert_eq!(warning.pc, 123);
    }
    
    #[test]
    fn test_enhanced_reentrancy_detection() {
        let target = H256::random();
        let slot = H256::random();
        
        // Test standard reentrancy warning
        let warning = SecurityWarning::reentrancy_with_call(123, slot, target, U256::from(1000000));
        assert_eq!(warning.kind, SecurityWarningKind::Reentrancy);
        assert_eq!(warning.severity, SecuritySeverity::High);
        assert_eq!(warning.operations.len(), 2);
        
        // Test read-only reentrancy warning
        let ro_warning = SecurityWarning::read_only_reentrancy(456, slot, target);
        assert_eq!(ro_warning.kind, SecurityWarningKind::ReadOnlyReentrancy);
        assert_eq!(ro_warning.severity, SecuritySeverity::Medium);
        
        // Test cross-function reentrancy warning
        let cf_warning = SecurityWarning::cross_function_reentrancy(789, slot, target);
        assert_eq!(cf_warning.kind, SecurityWarningKind::CrossFunctionReentrancy);
        assert_eq!(cf_warning.severity, SecuritySeverity::High);
    }
}
