// API Types for EVM Verify
//
// This module defines the data structures used by the EVM Verify API.

use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

/// Analysis report for a smart contract
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisReport {
    /// Timestamp when the analysis was performed
    pub timestamp: DateTime<Utc>,
    
    /// Size of the contract bytecode
    pub contract_size: usize,
    
    /// Detected vulnerabilities
    pub vulnerabilities: Vec<Vulnerability>,
    
    /// Number of delegate calls detected
    pub delegate_calls: usize,
    
    /// Number of memory accesses
    pub memory_accesses: usize,
    
    /// Number of storage accesses
    pub storage_accesses: usize,
    
    /// Configuration used for the analysis
    pub analysis_config: AnalysisConfig,
}

/// Vulnerability information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    /// Title of the vulnerability
    pub title: String,
    
    /// Detailed description
    pub description: String,
    
    /// Severity level
    pub severity: VulnerabilitySeverity,
    
    /// Location in the bytecode
    pub location: VulnerabilityLocation,
    
    /// Recommendation for fixing
    pub recommendation: String,
}

/// Severity levels for vulnerabilities
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum VulnerabilitySeverity {
    /// Informational issue, not a security concern
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

impl VulnerabilitySeverity {
    /// Determine severity from a warning message
    pub fn from_warning(warning: &str) -> Self {
        let warning_lower = warning.to_lowercase();
        
        if warning_lower.contains("reentrancy") {
            Self::High
        } else if warning_lower.contains("overflow") || warning_lower.contains("underflow") {
            Self::Medium
        } else if warning_lower.contains("access control") {
            Self::High
        } else if warning_lower.contains("delegate") {
            Self::Medium
        } else {
            Self::Low
        }
    }
}

/// Location of a vulnerability in the bytecode
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VulnerabilityLocation {
    /// Specific program counter
    ProgramCounter(usize),
    
    /// Storage slot
    StorageSlot(String),
    
    /// Unknown location
    Unknown,
}

/// Configuration for the analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisConfig {
    /// Whether to analyze constructor code
    pub analyze_constructor: bool,
    
    /// Whether to analyze runtime code
    pub analyze_runtime: bool,
    
    /// Maximum depth for analysis
    pub max_depth: usize,
    
    /// Whether to detect reentrancy vulnerabilities
    pub detect_reentrancy: bool,
    
    /// Whether to detect arithmetic vulnerabilities
    pub detect_arithmetic: bool,
    
    /// Whether to detect access control vulnerabilities
    pub detect_access_control: bool,
    
    /// Whether to detect delegate call vulnerabilities
    pub detect_delegate_call: bool,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            analyze_constructor: true,
            analyze_runtime: true,
            max_depth: 100,
            detect_reentrancy: true,
            detect_arithmetic: true,
            detect_access_control: true,
            detect_delegate_call: true,
        }
    }
}
