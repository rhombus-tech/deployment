use anyhow::Result;
use ethers::types::Bytes;
use std::fmt;

/// Severity level of a security warning
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecuritySeverity {
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

impl fmt::Display for SecuritySeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecuritySeverity::Info => write!(f, "Info"),
            SecuritySeverity::Low => write!(f, "Low"),
            SecuritySeverity::Medium => write!(f, "Medium"),
            SecuritySeverity::High => write!(f, "High"),
            SecuritySeverity::Critical => write!(f, "Critical"),
        }
    }
}

/// Type of security warning
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityWarningKind {
    /// Reentrancy vulnerability
    Reentrancy,
    /// Access control vulnerability
    AccessControl,
    /// Integer overflow/underflow
    IntegerOverflow,
    /// Unchecked external call
    UncheckedCall,
    /// Front-running vulnerability
    FrontRunning,
    /// Flash loan vulnerability
    FlashLoan,
    /// Other vulnerability type
    Other(String),
}

impl fmt::Display for SecurityWarningKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityWarningKind::Reentrancy => write!(f, "Reentrancy"),
            SecurityWarningKind::AccessControl => write!(f, "Access Control"),
            SecurityWarningKind::IntegerOverflow => write!(f, "Integer Overflow"),
            SecurityWarningKind::UncheckedCall => write!(f, "Unchecked Call"),
            SecurityWarningKind::FrontRunning => write!(f, "Front Running"),
            SecurityWarningKind::FlashLoan => write!(f, "Flash Loan"),
            SecurityWarningKind::Other(s) => write!(f, "Other: {}", s),
        }
    }
}

/// Operation related to a security warning
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityOperation {
    /// Offset in bytecode
    pub offset: usize,
    /// Operation description
    pub description: String,
}

/// Security warning from bytecode analysis
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityWarning {
    /// Type of security warning
    pub kind: SecurityWarningKind,
    /// Severity of the warning
    pub severity: SecuritySeverity,
    /// Description of the warning
    pub description: String,
    /// Operations related to the warning
    pub operations: Vec<SecurityOperation>,
    /// Remediation suggestion
    pub remediation: String,
}

/// Results of bytecode analysis
#[derive(Debug, Clone)]
pub struct BytecodeAnalysisResults {
    /// Security warnings found in bytecode
    pub security_warnings: Vec<SecurityWarning>,
}

/// Simple bytecode analyzer for use in PCD circuits
pub struct BytecodeAnalyzer {
    /// Bytecode to analyze
    bytecode: Bytes,
}

impl BytecodeAnalyzer {
    /// Create a new bytecode analyzer
    pub fn new(bytecode: Bytes) -> Self {
        Self { bytecode }
    }
    
    /// Analyze bytecode for security vulnerabilities
    pub fn analyze(&mut self) -> Result<BytecodeAnalysisResults> {
        // This is a simplified analyzer that just checks for patterns in bytecode
        // In a real implementation, this would perform more sophisticated analysis
        let mut security_warnings = Vec::new();
        
        // Check for reentrancy pattern (simplified)
        // Look for CALL (0xF1) followed by SSTORE (0x55) pattern
        self.check_for_reentrancy_pattern(&mut security_warnings);
        
        // Check for unchecked external call pattern (simplified)
        // Look for CALL (0xF1) without checking return value
        self.check_for_unchecked_call(&mut security_warnings);
        
        Ok(BytecodeAnalysisResults { security_warnings })
    }
    
    /// Check for reentrancy pattern in bytecode
    fn check_for_reentrancy_pattern(&self, security_warnings: &mut Vec<SecurityWarning>) {
        let bytecode = self.bytecode.as_ref();
        
        for i in 0..bytecode.len().saturating_sub(1) {
            if i + 1 < bytecode.len() && bytecode[i] == 0xF1 {
                // Look for SSTORE after CALL
                for j in i + 1..bytecode.len() {
                    if bytecode[j] == 0x55 {
                        security_warnings.push(SecurityWarning {
                            kind: SecurityWarningKind::Reentrancy,
                            severity: SecuritySeverity::High,
                            description: "Potential reentrancy vulnerability: state update after external call".to_string(),
                            operations: vec![
                                SecurityOperation {
                                    offset: i,
                                    description: "External call (CALL)".to_string(),
                                },
                                SecurityOperation {
                                    offset: j,
                                    description: "State update (SSTORE)".to_string(),
                                },
                            ],
                            remediation: "Update state before making external calls or use a reentrancy guard".to_string(),
                        });
                        break;
                    }
                }
            }
        }
    }
    
    /// Check for unchecked external call pattern in bytecode
    fn check_for_unchecked_call(&self, security_warnings: &mut Vec<SecurityWarning>) {
        let bytecode = self.bytecode.as_ref();
        
        for i in 0..bytecode.len() {
            if bytecode[i] == 0xF1 && i + 1 < bytecode.len() && bytecode[i + 1] == 0x50 {
                // CALL followed by POP indicates unchecked return value
                security_warnings.push(SecurityWarning {
                    kind: SecurityWarningKind::UncheckedCall,
                    severity: SecuritySeverity::Medium,
                    description: "Unchecked external call: return value of CALL is not checked".to_string(),
                    operations: vec![
                        SecurityOperation {
                            offset: i,
                            description: "External call (CALL)".to_string(),
                        },
                        SecurityOperation {
                            offset: i + 1,
                            description: "Pop return value without checking (POP)".to_string(),
                        },
                    ],
                    remediation: "Check the return value of external calls and handle failures".to_string(),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_reentrancy_detection() {
        // Create bytecode with reentrancy pattern
        // CALL (0xF1) followed by some operations and then SSTORE (0x55)
        let bytecode = Bytes::from(vec![
            0x60, 0x00, // PUSH1 0x00
            0xF1,       // CALL
            0x60, 0x01, // PUSH1 0x01
            0x60, 0x00, // PUSH1 0x00
            0x55,       // SSTORE
        ]);
        
        let mut analyzer = BytecodeAnalyzer::new(bytecode);
        let results = analyzer.analyze().unwrap();
        
        assert_eq!(results.security_warnings.len(), 1);
        assert_eq!(results.security_warnings[0].kind, SecurityWarningKind::Reentrancy);
    }
    
    #[test]
    fn test_unchecked_call_detection() {
        // Create bytecode with unchecked call pattern
        // CALL (0xF1) followed by POP (0x50)
        let bytecode = Bytes::from(vec![
            0x60, 0x00, // PUSH1 0x00
            0xF1,       // CALL
            0x50,       // POP
        ]);
        
        let mut analyzer = BytecodeAnalyzer::new(bytecode);
        let results = analyzer.analyze().unwrap();
        
        assert_eq!(results.security_warnings.len(), 1);
        assert_eq!(results.security_warnings[0].kind, SecurityWarningKind::UncheckedCall);
    }
}
