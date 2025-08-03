use crate::errors::Result;
use crate::transaction::{Transaction, TransactionSequence};
use crate::types::VerificationLevel;
use async_trait::async_trait;
use serde::{Serialize, Deserialize};
use std::fmt;

/// Result of a security verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Whether the verification passed
    valid: bool,
    /// Reason for failure, if any
    failure_reason: Option<String>,
    /// Warnings that don't prevent execution
    warnings: Vec<SecurityWarning>,
    /// Detailed report for the user
    detailed_report: Option<String>,
}

impl VerificationResult {
    /// Create a new successful verification result
    pub fn success() -> Self {
        Self {
            valid: true,
            failure_reason: None,
            warnings: Vec::new(),
            detailed_report: None,
        }
    }
    
    /// Create a new successful verification result with warnings
    pub fn success_with_warnings(warnings: Vec<SecurityWarning>) -> Self {
        Self {
            valid: true,
            failure_reason: None,
            warnings,
            detailed_report: None,
        }
    }
    
    /// Create a new failed verification result
    pub fn failure(reason: impl Into<String>) -> Self {
        Self {
            valid: false,
            failure_reason: Some(reason.into()),
            warnings: Vec::new(),
            detailed_report: None,
        }
    }
    
    /// Create a new failed verification result with detailed report
    pub fn failure_with_report(reason: impl Into<String>, report: impl Into<String>) -> Self {
        Self {
            valid: false,
            failure_reason: Some(reason.into()),
            warnings: Vec::new(),
            detailed_report: Some(report.into()),
        }
    }
    
    /// Add a detailed report to the result
    pub fn with_report(mut self, report: impl Into<String>) -> Self {
        self.detailed_report = Some(report.into());
        self
    }
    
    /// Add warnings to the result
    pub fn with_warnings(mut self, warnings: Vec<SecurityWarning>) -> Self {
        self.warnings.extend(warnings);
        self
    }
    
    /// Check if the verification passed
    pub fn is_valid(&self) -> bool {
        self.valid
    }
    
    /// Get the failure reason, if any
    pub fn failure_reason(&self) -> Option<&str> {
        self.failure_reason.as_deref()
    }
    
    /// Get the warnings
    pub fn warnings(&self) -> &[SecurityWarning] {
        &self.warnings
    }
    
    /// Get the detailed report, if any
    pub fn detailed_report(&self) -> Option<&str> {
        self.detailed_report.as_deref()
    }
}

/// Security warning types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityWarningKind {
    /// Reentrancy vulnerability
    Reentrancy,
    /// Access control vulnerability
    AccessControl,
    /// Integer overflow vulnerability
    IntegerOverflow,
    /// Integer underflow vulnerability
    IntegerUnderflow,
    /// Unchecked external call
    UncheckedCall,
    /// Front-running vulnerability
    FrontRunning,
    /// Price manipulation vulnerability
    PriceManipulation,
    /// MEV vulnerability
    MEVVulnerability,
    /// Oracle manipulation vulnerability
    OracleManipulation,
    /// Block number dependence vulnerability
    BlockNumberDependence,
    /// Uninitialized storage vulnerability
    UninitializedStorage,
    /// BitMask vulnerability
    BitMaskVulnerability,
    /// Governance vulnerability
    GovernanceVulnerability,
    /// Cross-contract reentrancy vulnerability
    CrossContractReentrancy,
    /// Precision loss vulnerability
    PrecisionLoss,
    /// Gas griefing vulnerability
    GasGriefing,
    /// Flash loan vulnerability
    FlashLoan,
    /// Upgradability vulnerability
    Upgradability,
    /// Other vulnerability type
    Other(String),
}

impl fmt::Display for SecurityWarningKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityWarningKind::Reentrancy => write!(f, "Reentrancy"),
            SecurityWarningKind::AccessControl => write!(f, "Access Control"),
            SecurityWarningKind::IntegerOverflow => write!(f, "Integer Overflow"),
            SecurityWarningKind::IntegerUnderflow => write!(f, "Integer Underflow"),
            SecurityWarningKind::UncheckedCall => write!(f, "Unchecked Call"),
            SecurityWarningKind::FrontRunning => write!(f, "Front Running"),
            SecurityWarningKind::PriceManipulation => write!(f, "Price Manipulation"),
            SecurityWarningKind::MEVVulnerability => write!(f, "MEV Vulnerability"),
            SecurityWarningKind::OracleManipulation => write!(f, "Oracle Manipulation"),
            SecurityWarningKind::BlockNumberDependence => write!(f, "Block Number Dependence"),
            SecurityWarningKind::UninitializedStorage => write!(f, "Uninitialized Storage"),
            SecurityWarningKind::BitMaskVulnerability => write!(f, "BitMask Vulnerability"),
            SecurityWarningKind::GovernanceVulnerability => write!(f, "Governance Vulnerability"),
            SecurityWarningKind::CrossContractReentrancy => write!(f, "Cross-Contract Reentrancy"),
            SecurityWarningKind::PrecisionLoss => write!(f, "Precision Loss"),
            SecurityWarningKind::GasGriefing => write!(f, "Gas Griefing"),
            SecurityWarningKind::FlashLoan => write!(f, "Flash Loan"),
            SecurityWarningKind::Upgradability => write!(f, "Upgradability"),
            SecurityWarningKind::Other(s) => write!(f, "Other: {}", s),
        }
    }
}

/// Severity level for security warnings
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    /// Informational issue, not a vulnerability
    Info,
    /// Low severity vulnerability
    Low,
    /// Medium severity vulnerability
    Medium,
    /// High severity vulnerability
    High,
    /// Critical severity vulnerability
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Info => write!(f, "Info"),
            Severity::Low => write!(f, "Low"),
            Severity::Medium => write!(f, "Medium"),
            Severity::High => write!(f, "High"),
            Severity::Critical => write!(f, "Critical"),
        }
    }
}

/// Location in bytecode where a vulnerability was detected
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BytecodeLocation {
    /// Offset in bytecode (in bytes)
    pub offset: usize,
    /// Length of the vulnerable section (in bytes)
    pub length: usize,
    /// Context description (e.g., function name if known)
    pub context: Option<String>,
}

/// Detailed security warning with context and remediation hints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityWarning {
    /// Type of vulnerability detected
    pub kind: SecurityWarningKind,
    /// Severity level
    pub severity: Severity,
    /// Human-readable description of the issue
    pub description: String,
    /// Location in bytecode where the vulnerability was found
    pub location: Option<BytecodeLocation>,
    /// Suggestion for how to fix the issue
    pub remediation_hint: String,
}

/// Trait for security verifiers
#[async_trait]
pub trait SecurityVerifier: Send + Sync {
    /// Verify a single transaction
    async fn verify_transaction(
        &self, 
        transaction: &Transaction,
        level: VerificationLevel,
    ) -> Result<VerificationResult>;
    
    /// Verify a transaction sequence
    async fn verify_sequence(
        &self,
        sequence: &TransactionSequence,
        level: VerificationLevel,
    ) -> Result<VerificationResult>;
}

/// Implementation of security verifier that uses our deployment gateway
pub struct DeploymentGatewayVerifier {
    /// Path to the gateway executable
    gateway_path: String,
}

impl DeploymentGatewayVerifier {
    /// Create a new deployment gateway verifier
    pub fn new(gateway_path: impl Into<String>) -> Self {
        Self {
            gateway_path: gateway_path.into(),
        }
    }
    
    /// Invoke the deployment gateway for verification
    async fn invoke_gateway(&self, bytecode: &[u8]) -> Result<Vec<SecurityWarning>> {
        // In a real implementation, this would invoke the EVM Verify deployment gateway
        // For now, we'll simulate its behavior
        
        // Look for common vulnerability patterns
        let mut warnings = Vec::new();
        
        // Check for reentrancy (CALL followed by SSTORE without checks)
        if self.contains_pattern(bytecode, &[0xF1, 0x55]) {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::Reentrancy,
                severity: Severity::Critical,
                description: "Potential reentrancy vulnerability detected".into(),
                location: Some(BytecodeLocation {
                    offset: 0,
                    length: 2,
                    context: None,
                }),
                remediation_hint: "Implement checks-effects-interactions pattern".into(),
            });
        }
        
        // Check for unchecked calls (CALL without ISZERO check)
        if bytecode.contains(&0xF1) && !self.contains_pattern(bytecode, &[0xF1, 0x15]) {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::UncheckedCall,
                severity: Severity::High,
                description: "Unchecked external call detected".into(),
                location: None,
                remediation_hint: "Check return value of external calls".into(),
            });
        }
        
        Ok(warnings)
    }
    
    /// Check if bytecode contains a specific pattern
    fn contains_pattern(&self, bytecode: &[u8], pattern: &[u8]) -> bool {
        bytecode.windows(pattern.len()).any(|window| window == pattern)
    }
}

#[async_trait]
impl SecurityVerifier for DeploymentGatewayVerifier {
    async fn verify_transaction(
        &self,
        transaction: &Transaction,
        level: VerificationLevel,
    ) -> Result<VerificationResult> {
        // For contract creation, verify the contract bytecode
        if let Some(code) = &transaction.code {
            let warnings = self.invoke_gateway(code).await?;
            
            // Check if there are any critical vulnerabilities
            let has_critical = warnings.iter()
                .any(|w| w.severity == Severity::Critical);
            
            if has_critical && level != VerificationLevel::None {
                return Ok(VerificationResult::failure_with_report(
                    "Critical security vulnerabilities detected",
                    format!("{} critical vulnerabilities found", 
                            warnings.iter().filter(|w| w.severity == Severity::Critical).count()),
                ).with_warnings(warnings));
            }
            
            // For less severe issues, just add warnings
            return Ok(VerificationResult::success_with_warnings(warnings));
        }
        
        // For normal transactions, verify the data
        if !transaction.data.is_empty() {
            let warnings = self.invoke_gateway(&transaction.data).await?;
            
            // Check if there are any critical vulnerabilities
            let has_critical = warnings.iter()
                .any(|w| w.severity == Severity::Critical);
            
            if has_critical && level != VerificationLevel::None {
                return Ok(VerificationResult::failure_with_report(
                    "Critical security vulnerabilities detected in transaction data",
                    format!("{} critical vulnerabilities found", 
                            warnings.iter().filter(|w| w.severity == Severity::Critical).count()),
                ).with_warnings(warnings));
            }
            
            // For less severe issues, just add warnings
            return Ok(VerificationResult::success_with_warnings(warnings));
        }
        
        // Simple value transfer, always safe
        Ok(VerificationResult::success())
    }
    
    async fn verify_sequence(
        &self,
        sequence: &TransactionSequence,
        level: VerificationLevel,
    ) -> Result<VerificationResult> {
        let mut all_warnings = Vec::new();
        
        // Verify each transaction
        for (i, tx) in sequence.transactions().iter().enumerate() {
            let result = self.verify_transaction(tx, level).await?;
            
            if !result.is_valid() {
                return Ok(VerificationResult::failure_with_report(
                    format!("Transaction {} failed verification: {}", i, 
                            result.failure_reason().unwrap_or("Unknown reason")),
                    result.detailed_report().unwrap_or("No detailed report available").to_string(),
                ));
            }
            
            all_warnings.extend(result.warnings().to_vec());
        }
        
        // Check for sequence-specific issues
        self.check_sequence_specific_issues(sequence, &mut all_warnings);
        
        // Check if there are any critical vulnerabilities
        let has_critical = all_warnings.iter()
            .any(|w| w.severity == Severity::Critical);
        
        if has_critical && level != VerificationLevel::None {
            return Ok(VerificationResult::failure_with_report(
                "Critical security vulnerabilities detected in transaction sequence",
                format!("{} critical vulnerabilities found", 
                        all_warnings.iter().filter(|w| w.severity == Severity::Critical).count()),
            ).with_warnings(all_warnings));
        }
        
        // For less severe issues, just add warnings
        Ok(VerificationResult::success_with_warnings(all_warnings))
    }
}

impl DeploymentGatewayVerifier {
    /// Check for issues specific to transaction sequences
    fn check_sequence_specific_issues(&self, sequence: &TransactionSequence, warnings: &mut Vec<SecurityWarning>) {
        // In a real implementation, this would look for patterns across multiple transactions
        // For now, we'll just add a placeholder check
        
        // Check for long sequences (potential DOS vector)
        if sequence.transactions().len() > 10 {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::Other("LongSequence".into()),
                severity: Severity::Medium,
                description: "Long transaction sequence may cause gas issues".into(),
                location: None,
                remediation_hint: "Consider breaking up into smaller sequences".into(),
            });
        }
    }
}
