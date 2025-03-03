// API module for the PCC library.
//
// This module defines the data structures used by the PCC API.

/// Type of vulnerability
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VulnerabilityType {
    /// Reentrancy vulnerability
    Reentrancy,
    
    /// Integer overflow vulnerability
    IntegerOverflow,
    
    /// Unbounded loop vulnerability
    UnboundedLoop,
    
    /// Unchecked call vulnerability
    UncheckedCall,
    
    /// Access control vulnerability
    AccessControl,
    
    /// Self-destruct vulnerability
    SelfDestruct,
    
    /// Oracle manipulation vulnerability
    OracleManipulation,
    
    /// MEV vulnerability
    MevVulnerability,
    
    /// Front-running vulnerability
    FrontRunning,
    
    /// Price manipulation vulnerability
    PriceManipulation,
    
    /// Block number dependence vulnerability
    BlockNumberDependence,
    
    /// Uninitialized storage vulnerability
    UninitializedStorage,
    
    /// Proxy vulnerability
    ProxyVulnerability,
    
    /// Gas griefing vulnerability
    GasGriefing,
    
    /// Weak randomness vulnerability
    WeakRandomness,
    
    /// Governance vulnerability
    GovernanceVulnerability,
    
    /// Bitmask vulnerability
    BitmaskVulnerability,
    
    /// Precision loss vulnerability in fixed-point arithmetic
    PrecisionLoss,
    
    /// Centralized control vulnerability
    CentralizedControl,
    
    /// Insufficient slippage protection in DeFi contracts
    InsufficientSlippageProtection,
    
    /// Timelock issue in governance contracts
    TimelockIssue,
    
    /// Unchecked return values from external calls
    UncheckedReturnValue,
    
    /// Other vulnerability type
    Other(u8),
    
    /// Unknown vulnerability type
    Unknown,
}
