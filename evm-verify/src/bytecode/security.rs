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
    /// Computation operation
    Computation {
        /// Operation type
        op_type: String,
        /// Gas cost
        gas_cost: u64,
    },
    /// Gas usage operation
    GasUsage {
        /// Gas amount
        amount: u64,
        /// Operation description
        description: String,
    },
    /// Storage operation
    Storage {
        /// Operation type
        op_type: String,
        /// Storage key (optional)
        key: Option<H256>,
    },
    /// Timestamp operation
    Timestamp,
    /// Comparison operation
    Comparison {
        /// Comparison type
        op_type: String,
    },
    /// Random operation
    Random {
        /// Random source
        source: String,
    },
    /// Cryptography operation
    Cryptography {
        /// Operation type
        op_type: String,
        /// Input data
        input: Option<Vec<u8>>,
    },
    /// Randomness operation
    Randomness {
        /// Source of randomness
        source: String,
        /// Predictability level (0-100)
        predictability: u8,
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
    /// Unprotected self destruct vulnerability
    UnprotectedSelfDestruct,
    /// Unprotected delegate call vulnerability
    UnprotectedDelegateCall,
    /// Integer overflow vulnerability
    IntegerOverflow,
    /// Integer underflow vulnerability
    IntegerUnderflow,
    /// Unprotected state variable vulnerability
    UnprotectedStateVariable,
    /// Delegate call misuse vulnerability
    DelegateCallMisuse,
    /// Delegate call in constructor vulnerability
    DelegateCallInConstructor,
    /// Unchecked external call vulnerability
    UncheckedExternalCall,
    /// Timestamp dependence vulnerability
    TimestampDependence,
    /// Flash loan vulnerability
    FlashLoanVulnerability,
    /// Flash loan state manipulation vulnerability
    FlashLoanStateManipulation,
    /// Missing slippage protection vulnerability
    MissingSlippageProtection,
    /// Insufficient timelock vulnerability
    InsufficientTimelock,
    /// Weak quorum requirement vulnerability
    WeakQuorumRequirement,
    /// Flash loan voting vulnerability
    FlashLoanVotingVulnerability,
    /// Centralized admin control vulnerability
    CentralizedAdminControl,
    /// Cross-contract reentrancy vulnerability
    CrossContractReentrancy,
    /// Access control vulnerability
    AccessControlVulnerability,
    /// Weak access control vulnerability
    WeakAccessControl,
    /// Inconsistent access control vulnerability
    InconsistentAccessControl,
    /// Hardcoded access control vulnerability
    HardcodedAccessControl,
    /// tx.origin usage vulnerability
    TxOriginUsage,
    /// Gas limit issue vulnerability
    GasLimitIssue,
    /// Unprotected upgrade function vulnerability
    UnprotectedUpgradeFunction,
    /// Storage layout incompatibility vulnerability
    StorageLayoutIncompatibility,
    /// Missing initializer vulnerability
    MissingInitializer,
    /// Untrusted implementation vulnerability
    UntrustedImplementation,
    /// Denial of Service vulnerability
    DenialOfService,
    /// Signature replay vulnerability
    SignatureReplay,
    /// Uninitialized proxy vulnerability
    UninitializedProxy,
    /// Storage collision vulnerability
    StorageCollision,
    /// Implementation shadowing vulnerability
    ImplementationShadowing,
    /// Weak randomness vulnerability
    WeakRandomness,
    /// Unchecked call return vulnerability
    UncheckedCallReturn,
    /// tx.origin for authorization vulnerability
    TxOriginAuth,
    /// Front-running vulnerability
    FrontRunning,
    /// Price manipulation vulnerability
    PriceManipulation,
    /// Block number dependence vulnerability
    BlockNumberDependence,
    /// Uninitialized storage vulnerability
    UninitializedStorage,
    /// MEV vulnerability
    MEVVulnerability,
    /// Oracle manipulation vulnerability
    OracleManipulation,
    /// Bitmask vulnerability
    BitMaskVulnerability,
    /// Governance vulnerability
    GovernanceVulnerability,
    /// Access control vulnerability (alias)
    AccessControl,
    /// Gas griefing vulnerability
    GasGriefing,
    /// Precision loss vulnerability
    PrecisionLoss,
    /// Event emission vulnerability
    EventEmissionVulnerability,
    /// Gas price dependency vulnerability (front-running related)
    GasPriceDependency,
    /// Block timestamp dependency vulnerability
    BlockTimestampDependency,
    /// Unsafe timestamp comparison vulnerability
    UnsafeTimestampComparison,
    /// Time-based randomness vulnerability
    TimeBasedRandomness,
    /// Other security issue
    Other(String),
}

impl Default for SecurityWarningKind {
    fn default() -> Self {
        SecurityWarningKind::Other("Unknown".to_string())
    }
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

impl Default for SecurityWarning {
    fn default() -> Self {
        Self {
            kind: SecurityWarningKind::default(),
            severity: SecuritySeverity::Info,
            pc: 0,
            description: String::new(),
            operations: Vec::new(),
            remediation: String::new(),
        }
    }
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
            "Potential integer overflow detected".to_string(),
            vec![],
            "Implement checks before addition or multiplication operations to prevent overflow, or use SafeMath".to_string(),
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
        Self::new(
            SecurityWarningKind::GasLimitIssue,
            SecuritySeverity::Medium,
            pc,
            "Gas limit issue detected".to_string(),
            vec![],
            "Consider optimizing gas usage or using smaller batches".to_string(),
        )
    }

    /// Create an access control vulnerability warning
    pub fn access_control_vulnerability(pc: u64) -> Self {
        Self::new(
            SecurityWarningKind::AccessControlVulnerability,
            SecuritySeverity::High,
            pc,
            "Missing access control for sensitive operation".to_string(),
            vec![],
            "Implement proper access control checks before sensitive operations".to_string(),
        )
    }

    /// Create a weak access control warning
    pub fn weak_access_control(pc: u64) -> Self {
        Self::new(
            SecurityWarningKind::WeakAccessControl,
            SecuritySeverity::High,
            pc,
            format!("Weak access control pattern detected at position {}. Using tx.origin for authentication is unsafe.", pc),
            vec![],
            "Replace tx.origin with msg.sender for authentication checks.".to_string(),
        )
    }

    /// Create an inconsistent access control warning
    pub fn inconsistent_access_control(pc: u64, protected_ops: usize, unprotected_ops: usize) -> Self {
        Self::new(
            SecurityWarningKind::InconsistentAccessControl,
            SecuritySeverity::Medium,
            pc,
            format!("Inconsistent access control detected: {} operations are protected while {} similar operations are unprotected", protected_ops, unprotected_ops),
            vec![],
            "Apply consistent access control patterns across similar operations.".to_string(),
        )
    }

    /// Create a hardcoded access control warning
    pub fn hardcoded_access_control(pc: u64) -> Self {
        Self::new(
            SecurityWarningKind::HardcodedAccessControl,
            SecuritySeverity::Medium,
            pc,
            format!("Hardcoded address used in access control at position {}. This may cause issues if the contract needs to be upgraded.", pc),
            vec![],
            "Use a modifiable access control scheme such as role-based access control.".to_string(),
        )
    }

    /// Create an integer underflow vulnerability warning
    pub fn integer_underflow(pc: u64) -> Self {
        Self::new(
            SecurityWarningKind::IntegerUnderflow,
            SecuritySeverity::High,
            pc,
            "Potential integer underflow detected".to_string(),
            vec![],
            "Implement checks before subtraction operations or use SafeMath".to_string(),
        )
    }

    /// Create a timestamp dependence warning
    pub fn timestamp_dependence(pc: u64) -> Self {
        Self::new(
            SecurityWarningKind::TimestampDependence,
            SecuritySeverity::Medium,
            pc,
            "Timestamp dependency detected".to_string(),
            vec![Operation::BlockInformation { info_type: "TIMESTAMP".to_string() }],
            "Avoid using block.timestamp for critical operations as it can be manipulated by miners".to_string(),
        )
    }

    /// Create a flash loan vulnerability warning
    pub fn flash_loan_vulnerability(pc: u64) -> Self {
        Self::new(
            SecurityWarningKind::FlashLoanVulnerability,
            SecuritySeverity::High,
            pc,
            "Flash loan vulnerability detected. Price oracle dependency without manipulation protection.".to_string(),
            vec![],
            "Use time-weighted average prices (TWAP), multiple price sources, or price feeds with manipulation resistance.".to_string(),
        )
    }

    /// Create a flash loan state manipulation warning
    pub fn flash_loan_state_manipulation(pc: u64) -> Self {
        Self::new(
            SecurityWarningKind::FlashLoanStateManipulation,
            SecuritySeverity::High,
            pc,
            "Flash loan state manipulation vulnerability detected. State changes after external calls without validation.".to_string(),
            vec![],
            "Implement checks-effects-interactions pattern and validate all external input before making state changes.".to_string(),
        )
    }

    /// Create a missing slippage protection warning
    pub fn missing_slippage_protection(pc: u64) -> Self {
        Self {
            kind: SecurityWarningKind::MissingSlippageProtection,
            severity: SecuritySeverity::High,
            pc,
            description: "Missing slippage protection in swap operation".to_string(),
            operations: Vec::new(),
            remediation: "Implement slippage protection with minimum output amount checks".to_string(),
        }
    }
    
    /// Create an insufficient timelock warning
    pub fn insufficient_timelock(pc: u64) -> Self {
        Self {
            kind: SecurityWarningKind::InsufficientTimelock,
            severity: SecuritySeverity::High,
            pc,
            description: "Insufficient timelock mechanism detected in governance function".to_string(),
            operations: Vec::new(),
            remediation: "Implement a longer timelock period (at least 24 hours recommended) for critical governance actions".to_string(),
        }
    }
    
    /// Create a weak quorum requirement warning
    pub fn weak_quorum_requirement(pc: u64) -> Self {
        Self {
            kind: SecurityWarningKind::WeakQuorumRequirement,
            severity: SecuritySeverity::High,
            pc,
            description: "Weak quorum requirement detected in governance voting mechanism".to_string(),
            operations: Vec::new(),
            remediation: "Increase quorum requirements to ensure sufficient participation in governance decisions".to_string(),
        }
    }
    
    /// Create a flash loan voting vulnerability warning
    pub fn flash_loan_voting_vulnerability(pc: u64) -> Self {
        Self {
            kind: SecurityWarningKind::FlashLoanVotingVulnerability,
            severity: SecuritySeverity::Critical,
            pc,
            description: "Potential flash loan vulnerability in governance voting mechanism".to_string(),
            operations: Vec::new(),
            remediation: "Implement voting weight snapshots or timelock mechanisms to prevent flash loan attacks on governance".to_string(),
        }
    }
    
    /// Create a centralized admin control warning
    pub fn centralized_admin_control(pc: u64) -> Self {
        Self {
            kind: SecurityWarningKind::CentralizedAdminControl,
            severity: SecuritySeverity::Medium,
            pc,
            description: "Centralized admin control detected in governance mechanism".to_string(),
            operations: Vec::new(),
            remediation: "Implement multi-signature requirements or decentralized governance mechanisms".to_string(),
        }
    }

    /// Create a gas price dependency warning (front-running vulnerability)
    pub fn gas_price_dependency(pc: u64) -> Self {
        Self {
            kind: SecurityWarningKind::GasPriceDependency,
            severity: SecuritySeverity::Medium,
            pc,
            description: "Gas price dependency detected. This code may be vulnerable to front-running attacks.".to_string(),
            operations: vec![],
            remediation: "Consider implementing a commit-reveal pattern or using a transaction ordering protection mechanism.".to_string(),
        }
    }

    /// Create a front-running vulnerability warning
    pub fn front_running(pc: u64) -> Self {
        Self {
            kind: SecurityWarningKind::FrontRunning,
            severity: SecuritySeverity::Medium,
            pc,
            description: "Front-running vulnerability detected. This code may be manipulated by miners or other users to gain an advantage.".to_string(),
            operations: vec![],
            remediation: "Implement transaction ordering protection, commit-reveal patterns, or batch processing to mitigate front-running.".to_string(),
        }
    }

    /// Create a block info dependency warning
    pub fn block_info_dependency(pc: u64) -> Self {
        Self {
            kind: SecurityWarningKind::BlockNumberDependence,
            severity: SecuritySeverity::Medium,
            pc,
            description: "Block information dependency detected. This code may be vulnerable to manipulation by miners.".to_string(),
            operations: vec![],
            remediation: "Avoid using block information for critical operations or implement additional safeguards.".to_string(),
        }
    }

    /// Create a missing commit-reveal pattern warning
    pub fn missing_commit_reveal(pc: u64) -> Self {
        Self {
            kind: SecurityWarningKind::FrontRunning,
            severity: SecuritySeverity::Medium,
            pc,
            description: "Missing commit-reveal pattern in a context where it's needed. This may lead to front-running vulnerabilities.".to_string(),
            operations: vec![],
            remediation: "Implement a commit-reveal pattern where users first submit a hash of their action and later reveal the actual action.".to_string(),
        }
    }

    /// Create a price-sensitive operation warning
    pub fn price_sensitive_operation(pc: u64) -> Self {
        Self {
            kind: SecurityWarningKind::PriceManipulation,
            severity: SecuritySeverity::Medium,
            pc,
            description: "Price-sensitive operation detected. This code may be vulnerable to price manipulation or front-running.".to_string(),
            operations: vec![],
            remediation: "Implement price feeds with time-weighted average prices or use decentralized oracles with manipulation resistance.".to_string(),
        }
    }

    /// Create a cross-contract reentrancy warning
    pub fn cross_contract_reentrancy(pc: u64, target: H256, contract_address: H256) -> Self {
        Self::new(
            SecurityWarningKind::CrossContractReentrancy,
            SecuritySeverity::Critical,
            pc,
            "Cross-contract reentrancy vulnerability detected".to_string(),
            vec![
                Operation::ExternalCall {
                    target,
                    value: U256::zero(),
                    data: vec![],
                },
                Operation::StorageWrite {
                    slot: H256::zero(),
                    value: U256::zero(),
                },
            ],
            "Implement checks-effects-interactions pattern across all contracts. Consider using ReentrancyGuard or similar mechanisms in all contracts that interact with each other.".to_string(),
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
