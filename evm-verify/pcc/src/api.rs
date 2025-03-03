// PCC API Types
//
// This module defines the data structures used by the PCC API.

use serde::{Serialize, Deserialize};

/// Type of vulnerability
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum VulnerabilityType {
    /// Reentrancy vulnerability
    Reentrancy,
    
    /// Integer overflow vulnerability
    IntegerOverflow,
    
    /// Integer underflow vulnerability
    IntegerUnderflow,
    
    /// Access control vulnerability
    AccessControl,
    
    /// Unchecked external call vulnerability
    UncheckedCall,
    
    /// Gas limit vulnerability
    GasLimit,
    
    /// TX.Origin usage vulnerability
    TxOrigin,
    
    /// Self-destruct vulnerability
    SelfDestruct,
    
    /// Delegate call vulnerability
    DelegateCall,
    
    /// User-controlled delegate call target vulnerability
    UserControlledDelegateCall,
    
    /// Delegate call context confusion vulnerability
    DelegateCallContextConfusion,
    
    /// Timestamp dependency vulnerability
    TimestampDependency,
    
    /// Front-running vulnerability
    FrontRunning,
    
    /// Transaction ordering dependency vulnerability
    TransactionOrderingDependency,
    
    /// Missing transaction ordering protection vulnerability
    MissingTransactionOrderingProtection,
    
    /// Sandwich attack vulnerability
    SandwichAttackVulnerability,
    
    /// Block number dependency vulnerability
    BlockNumberDependency,
    
    /// Uninitialized storage vulnerability
    UninitializedStorage,
    
    /// Flash loan vulnerability
    FlashLoan,
    
    /// Signature replay vulnerability
    SignatureReplay,
    
    /// Proxy contract vulnerability
    ProxyVulnerability,
    
    /// Oracle manipulation vulnerability
    OracleManipulation,
    
    /// Governance vulnerability
    GovernanceVulnerability,
    
    /// MEV vulnerability
    MEVVulnerability,
    
    /// Unbounded loop vulnerability
    UnboundedLoop,
    
    /// Bit mask vulnerability
    BitMaskVulnerability,
    
    /// Price manipulation vulnerability
    PriceManipulation,
    
    /// Block number dependence vulnerability
    BlockNumberDependence,
    
    /// Gas griefing vulnerability
    GasGriefing,
    
    /// Unknown vulnerability type
    Unknown,
    
    /// Other vulnerability type
    Other(String),
}
