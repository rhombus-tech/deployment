// EVM Verify API Module
//
// This module provides a unified interface for interacting with the EVM Verify tool.
// It serves as the main entry point for users and integrates all the analysis components.

mod types;
mod config;
mod report;

pub use types::*;
pub use config::*;
pub use report::*;

use anyhow::Result;
use ethers::types::Bytes;
use crate::bytecode::{BytecodeAnalyzer, AnalysisResults};
use crate::bytecode::security::SecurityWarning;

/// Main API for EVM Verify
pub struct EVMVerify {
    /// Configuration for the analysis
    config: AnalysisConfig,
}

impl EVMVerify {
    /// Create a new instance with default configuration
    pub fn new() -> Self {
        Self {
            config: AnalysisConfig::default(),
        }
    }

    /// Create a new instance with custom configuration
    pub fn with_config(config: AnalysisConfig) -> Self {
        Self { config }
    }

    /// Analyze bytecode and return a comprehensive report
    pub fn analyze_bytecode(&self, bytecode: Bytes) -> Result<AnalysisReport> {
        // Create bytecode analyzer
        let mut analyzer = BytecodeAnalyzer::new(bytecode);
        
        // Run the analysis
        let results = match analyzer.analyze() {
            Ok(results) => results,
            Err(e) => {
                // Create a minimal report with the error
                return Ok(AnalysisReport {
                    timestamp: chrono::Utc::now(),
                    contract_size: analyzer.bytecode_length(),
                    vulnerabilities: vec![Vulnerability {
                        title: format!("Analysis Error: {}", e),
                        description: format!("Failed to analyze bytecode: {}", e),
                        severity: VulnerabilitySeverity::Info,
                        vulnerability_type: VulnerabilityType::Unknown,
                        location: VulnerabilityLocation::Unknown,
                        recommendation: "Check if the bytecode is valid".to_string(),
                    }],
                    delegate_calls: 0,
                    memory_accesses: 0,
                    storage_accesses: 0,
                    analysis_config: self.config.clone(),
                });
            }
        };
        
        // Generate report
        self.generate_report(results)
    }

    /// Analyze bytecode from a hex string
    pub fn analyze_from_hex(&self, hex_string: &str) -> Result<AnalysisReport> {
        // Remove 0x prefix if present
        let clean_hex = hex_string.trim_start_matches("0x");
        
        // Convert hex to bytes
        let bytes = hex::decode(clean_hex)?;
        let bytecode = Bytes::from(bytes);
        
        self.analyze_bytecode(bytecode)
    }

    /// Generate a comprehensive analysis report
    fn generate_report(&self, results: AnalysisResults) -> Result<AnalysisReport> {
        // Extract vulnerabilities
        let vulnerabilities = results.warnings.iter()
            .map(|warning| {
                // Determine vulnerability type based on warning content
                let vulnerability_type = if warning.contains("reentrancy") {
                    VulnerabilityType::Reentrancy
                } else if warning.contains("integer overflow") {
                    VulnerabilityType::IntegerOverflow
                } else if warning.contains("integer underflow") {
                    VulnerabilityType::IntegerUnderflow
                } else if warning.contains("access control") {
                    VulnerabilityType::AccessControl
                } else if warning.contains("unchecked call") {
                    VulnerabilityType::UncheckedCall
                } else if warning.contains("gas limit") {
                    VulnerabilityType::GasLimit
                } else if warning.contains("tx.origin") {
                    VulnerabilityType::TxOrigin
                } else if warning.contains("self-destruct") {
                    VulnerabilityType::SelfDestruct
                } else if warning.contains("delegate call") {
                    VulnerabilityType::DelegateCall
                } else if warning.contains("timestamp dependency") {
                    VulnerabilityType::TimestampDependency
                } else if warning.contains("front-running") {
                    VulnerabilityType::FrontRunning
                } else if warning.contains("block number dependency") {
                    VulnerabilityType::BlockNumberDependency
                } else if warning.contains("uninitialized storage") {
                    VulnerabilityType::UninitializedStorage
                } else {
                    VulnerabilityType::Unknown
                };
                
                // Generate appropriate recommendation based on vulnerability type
                let recommendation = match vulnerability_type {
                    VulnerabilityType::Reentrancy => 
                        "Use ReentrancyGuard or check-effects-interactions pattern".to_string(),
                    VulnerabilityType::IntegerOverflow => 
                        "Use SafeMath or Solidity 0.8+ for automatic overflow checks".to_string(),
                    VulnerabilityType::IntegerUnderflow => 
                        "Use SafeMath or Solidity 0.8+ for automatic underflow checks".to_string(),
                    VulnerabilityType::AccessControl => 
                        "Implement proper access control mechanisms".to_string(),
                    VulnerabilityType::UncheckedCall => 
                        "Always check return values of external calls".to_string(),
                    VulnerabilityType::GasLimit => 
                        "Avoid loops with unbounded iterations".to_string(),
                    VulnerabilityType::TxOrigin => 
                        "Use msg.sender instead of tx.origin for authentication".to_string(),
                    VulnerabilityType::SelfDestruct => 
                        "Implement proper access controls for self-destruct operations".to_string(),
                    VulnerabilityType::DelegateCall => 
                        "Use delegatecall with extreme caution and proper validation".to_string(),
                    VulnerabilityType::TimestampDependency => 
                        "Avoid using block.timestamp for critical decisions".to_string(),
                    VulnerabilityType::FrontRunning => 
                        "Implement commit-reveal schemes or use a private mempool".to_string(),
                    VulnerabilityType::BlockNumberDependency => 
                        "Avoid using block.number for critical decisions".to_string(),
                    VulnerabilityType::UninitializedStorage => 
                        "Initialize all storage variables before reading from them".to_string(),
                    VulnerabilityType::Unknown => 
                        "Review the affected code".to_string(),
                };
                
                Vulnerability {
                    title: warning.clone(),
                    description: warning.clone(),
                    severity: VulnerabilitySeverity::from_warning(&warning),
                    vulnerability_type,
                    location: VulnerabilityLocation::Unknown,
                    recommendation,
                }
            })
            .collect();
        
        // Create the report
        let report = AnalysisReport {
            timestamp: chrono::Utc::now(),
            contract_size: results.runtime.code_length,
            vulnerabilities,
            delegate_calls: results.delegate_calls.len(),
            memory_accesses: results.memory_accesses.len(),
            storage_accesses: results.storage.len(),
            analysis_config: self.config.clone(),
        };
        
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_basic_analysis() -> Result<()> {
        // Create a simple contract bytecode
        let bytecode = Bytes::from(hex!("6080604052348015600f57600080fd5b50603f80601d6000396000f3fe6080604052600080fd00"));
        
        // Create analyzer with default config
        let analyzer = EVMVerify::new();
        
        // Run analysis
        let report = analyzer.analyze_bytecode(bytecode)?;
        
        // Basic validation
        assert!(report.timestamp <= chrono::Utc::now());
        assert!(report.contract_size > 0);
        
        Ok(())
    }
}
