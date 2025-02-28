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
    /// Storage read operation
    StorageRead {
        /// Storage slot
        slot: H256,
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
    /// Block information operation
    BlockInformation {
        /// Type of block information
        info_type: String,
    },
    /// Transaction information operation
    TransactionInformation {
        /// Type of transaction information
        info_type: String,
    },
    /// Arithmetic operation
    Arithmetic {
        /// Type of arithmetic operation
        operation: String,
    },
}

/// Security warning type
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
    /// Unchecked call return value
    UncheckedCallReturn,
    /// Multiple external calls
    MultipleExternalCalls,
    /// Integer overflow/underflow
    IntegerOverflow,
    /// Use of tx.origin for authorization
    TxOriginAuth,
    /// Use of tx.origin
    TxOriginUsage,
    /// Uninitialized storage
    UninitializedStorage,
    /// Unprotected state variable
    UnprotectedStateVariable,
    /// Arbitrary jump
    ArbitraryJump,
    /// Timestamp dependence
    TimestampDependence,
    /// Timestamp manipulation
    TimestampManipulation,
    /// Block number dependence
    BlockNumberDependence,
    /// Front-running vulnerability
    FrontRunning,
    /// Price manipulation vulnerability
    PriceManipulation,
    /// Unchecked math
    UncheckedMath,
    /// Unused return value
    UnusedReturnValue,
    /// Delegate call misuse
    DelegateCallMisuse,
    /// Delegate call in constructor
    DelegateCallInConstructor,
    /// Other security issue
    Other(String),
    /// Unchecked external call
    UncheckedExternalCall,
    /// Gas limit issue
    GasLimitIssue,
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
            format!("Unprotected self destruct operation detected at position {}. This can be called by anyone to destroy the contract.", pc),
            vec![Operation::SelfDestruct { beneficiary }],
            "Add access control checks (e.g., onlyOwner modifier) before self-destruct operations.".to_string(),
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

    /// Create a delegate call misuse warning
    pub fn delegate_call_misuse(pc: u64, target: H256, data: Vec<u8>) -> Self {
        Self::new(
            SecurityWarningKind::DelegateCallMisuse,
            SecuritySeverity::Medium,
            pc,
            format!("Delegate call misuse detected"),
            vec![Operation::DelegateCall { target, data }],
            "Review delegate call usage and ensure it's not being misused".to_string(),
        )
    }

    /// Create a delegate call in constructor warning
    pub fn delegate_call_in_constructor(pc: u64, target: H256, data: Vec<u8>) -> Self {
        Self::new(
            SecurityWarningKind::DelegateCallInConstructor,
            SecuritySeverity::High,
            pc,
            format!("Delegate call in constructor detected at position {}. This can lead to unexpected behavior.", pc),
            vec![Operation::DelegateCall { target, data }],
            "Avoid using delegate calls in constructors as they can lead to unexpected behavior".to_string(),
        )
    }

    /// Create an unchecked external call warning
    pub fn unchecked_external_call(pc: u64, target: H256, value: U256) -> Self {
        Self {
            kind: SecurityWarningKind::UncheckedExternalCall,
            severity: SecuritySeverity::Medium,
            pc,
            description: format!("Unchecked external call at position {}. The return value of the call is not checked.", pc),
            operations: vec![Operation::ExternalCall {
                target,
                value,
                data: vec![],
            }],
            remediation: "Always check the return value of external calls to handle potential failures.".to_string(),
        }
    }
    
    /// Create a simplified unchecked call warning
    pub fn unchecked_call(pc: u64) -> Self {
        Self {
            kind: SecurityWarningKind::UncheckedCallReturn,
            severity: SecuritySeverity::Medium,
            pc,
            description: format!("Unchecked external call at position {}. The return value of the call is not checked.", pc),
            operations: vec![],
            remediation: "Always check the return value of external calls to handle potential failures.".to_string(),
        }
    }
    
    /// Create a tx.origin usage warning
    pub fn txorigin_usage(pc: u64) -> Self {
        Self {
            kind: SecurityWarningKind::TxOriginUsage,
            severity: SecuritySeverity::Medium,
            pc,
            description: format!("tx.origin usage detected at position {}. This can be vulnerable to phishing attacks.", pc),
            operations: vec![],
            remediation: "Use msg.sender instead of tx.origin for authorization checks.".to_string(),
        }
    }
    
    /// Create a gas limit issue warning
    pub fn gas_limit_issue(pc: u64) -> Self {
        Self {
            kind: SecurityWarningKind::GasLimitIssue,
            severity: SecuritySeverity::Medium,
            pc,
            description: format!("Gas limit dependency detected at position {}. This may lead to unpredictable behavior as gas limits can change.", pc),
            operations: vec![],
            remediation: "Avoid relying on block gas limit for critical contract logic as it can change over time.".to_string(),
        }
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
