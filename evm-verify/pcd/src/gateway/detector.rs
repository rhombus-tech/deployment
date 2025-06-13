use anyhow::Result;
use crate::circuit_impl::SecurityWarningKind;
use crate::api::VerificationStrategy;

/// Location in bytecode where a vulnerability was detected
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BytecodeLocation {
    /// Offset in bytecode (in bytes)
    pub offset: usize,
    /// Length of the vulnerable section (in bytes)
    pub length: usize,
    /// Context description (e.g., function name if known)
    pub context: Option<String>,
}

/// Severity level for security warnings
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub enum Severity {
    /// Informational issues that don't pose immediate risk
    Info,
    /// Issues that may pose risks in certain contexts
    Warning,
    /// Critical issues that should block deployment
    Critical,
}

/// Detailed security warning with context and remediation hints
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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

/// Core trait for all vulnerability detectors
pub trait VulnerabilityDetector {
    /// Analyze bytecode for vulnerabilities using the default Groth16 strategy
    fn detect(&self, bytecode: &[u8]) -> Result<Vec<SecurityWarning>> {
        self.detect_with_strategy(bytecode, VerificationStrategy::Groth16)
    }
    
    /// Analyze bytecode for vulnerabilities with a specific verification strategy
    fn detect_with_strategy(&self, bytecode: &[u8], strategy: VerificationStrategy) -> Result<Vec<SecurityWarning>>;
    
    /// Name of this detector
    fn name(&self) -> &'static str;
    
    /// Detailed description of what this detector checks
    fn description(&self) -> &'static str;
}

/// Creates severity level based on vulnerability type
#[allow(dead_code)]
pub fn severity_for_vulnerability(kind: &SecurityWarningKind) -> Severity {
    match kind {
        SecurityWarningKind::Reentrancy => Severity::Critical,
        SecurityWarningKind::AccessControl => Severity::Critical,
        SecurityWarningKind::IntegerOverflow => Severity::Critical,
        SecurityWarningKind::UncheckedCall => Severity::Warning,
        SecurityWarningKind::FrontRunning => Severity::Warning,
        SecurityWarningKind::FlashLoan => Severity::Warning,
        SecurityWarningKind::Other(name) => {
            if name == "CrossContractReentrancy" || 
               name == "UninitializedStorage" || 
               name == "GasGriefing" {
                Severity::Critical
            } else if name == "PrecisionLoss" || 
                    name == "MEVVulnerability" {
                Severity::Warning
            } else {
                Severity::Info
            }
        }
    }
}

/// Creates remediation hint based on vulnerability type
pub fn remediation_hint_for_vulnerability(kind: &SecurityWarningKind) -> String {
    match kind {
        SecurityWarningKind::Reentrancy => 
            "Use ReentrancyGuard pattern or implement checks-effects-interactions pattern".to_string(),
        
        SecurityWarningKind::AccessControl => 
            "Implement proper access control using modifiers or role-based permissions".to_string(),
        
        SecurityWarningKind::IntegerOverflow => 
            "Use SafeMath library or Solidity 0.8+ with built-in overflow checks".to_string(),
        
        SecurityWarningKind::UncheckedCall => 
            "Always check return values from external calls and handle errors".to_string(),
        
        SecurityWarningKind::FrontRunning => 
            "Use commit-reveal patterns or private transactions to prevent front-running".to_string(),
        
        SecurityWarningKind::FlashLoan => 
            "Implement reentrancy protection and avoid price oracle manipulation".to_string(),
        
        SecurityWarningKind::Other(name) => {
            match name.as_str() {
                "CrossContractReentrancy" => 
                    "Use ReentrancyGuard with global locks and avoid state changes after external calls to multiple contracts".to_string(),
                
                "UninitializedStorage" => 
                    "Initialize all storage variables either in constructor or before first read".to_string(),
                
                "GasGriefing" => 
                    "Set explicit gas limits for external calls and avoid unbounded loops".to_string(),
                
                "PrecisionLoss" => 
                    "Use fixed-point arithmetic libraries and avoid division before multiplication".to_string(),
                
                "MEVVulnerability" => 
                    "Use commit-reveal patterns, private transactions, or specify slippage limits".to_string(),
                
                _ => "Review this section of code for potential security issues".to_string()
            }
        }
    }
}
