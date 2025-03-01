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

use anyhow::{Result, Context};
use ethers::types::Bytes;
use crate::bytecode::{BytecodeAnalyzer, AnalysisResults};
use crate::bytecode::security::SecurityWarning;
use crate::bytecode::analyzer_access_control;
use crate::bytecode::analyzer_reentrancy;
use crate::bytecode::analyzer_cross_contract_reentrancy;
use crate::bytecode::analyzer_self_destruct;
use crate::bytecode::analyzer_unchecked_calls;
use crate::bytecode::analyzer_gas_limit;
use crate::bytecode::analyzer_overflow;
use crate::bytecode::analyzer_underflow;
use crate::bytecode::analyzer_timestamp;
use crate::bytecode::analyzer_signature_replay;
use crate::bytecode::analyzer_proxy;
use crate::bytecode::analyzer_oracle;
use crate::bytecode::analyzer_mev;
use crate::bytecode::analyzer_governance;
use crate::bytecode::analyzer_gas_griefing;
use crate::bytecode::analyzer_precision;

/// Main API for EVM Verify
/// 
/// This struct provides the main interface for analyzing EVM bytecode for security vulnerabilities.
/// It supports both comprehensive analysis and targeted analysis for specific vulnerability types.
/// 
/// # Examples
/// 
/// ```
/// use evm_verify::api::EVMVerify;
/// use ethers::types::Bytes;
/// 
/// // Create a new instance with default configuration
/// let verifier = EVMVerify::new();
/// 
/// // Analyze bytecode
/// let bytecode = Bytes::from(vec![0x60, 0x01, 0x60, 0x00, 0x55]); // PUSH1 1 PUSH1 0 SSTORE
/// let report = verifier.analyze_bytecode(bytecode).unwrap();
/// 
/// // Check for vulnerabilities
/// if !report.vulnerabilities.is_empty() {
///     println!("Found {} vulnerabilities!", report.vulnerabilities.len());
/// }
/// ```
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
    /// 
    /// # Arguments
    /// 
    /// * `config` - The configuration to use for analysis
    /// 
    /// # Examples
    /// 
    /// ```
    /// use evm_verify::api::{EVMVerify, ConfigManager};
    /// 
    /// // Create a custom configuration
    /// let config = ConfigManager::builder()
    ///     .detect_reentrancy(true)
    ///     .detect_access_control(true)
    ///     .build();
    /// 
    /// // Create a verifier with the custom configuration
    /// let verifier = EVMVerify::with_config(config);
    /// ```
    pub fn with_config(config: AnalysisConfig) -> Self {
        Self { config }
    }

    /// Analyze bytecode and return a comprehensive report
    /// 
    /// This method performs a full security analysis on the provided bytecode
    /// and returns a detailed report of all detected vulnerabilities.
    /// 
    /// # Arguments
    /// 
    /// * `bytecode` - The EVM bytecode to analyze
    /// 
    /// # Returns
    /// 
    /// A Result containing the analysis report or an error
    /// 
    /// # Examples
    /// 
    /// ```
    /// use evm_verify::api::EVMVerify;
    /// use ethers::types::Bytes;
    /// 
    /// let verifier = EVMVerify::new();
    /// let bytecode = Bytes::from(vec![0x60, 0x01, 0x60, 0x00, 0x55]); // PUSH1 1 PUSH1 0 SSTORE
    /// let report = verifier.analyze_bytecode(bytecode).unwrap();
    /// 
    /// println!("Analysis completed at: {}", report.timestamp);
    /// println!("Found {} vulnerabilities", report.vulnerabilities.len());
    /// ```
    pub fn analyze_bytecode(&self, bytecode: Bytes) -> Result<AnalysisReport> {
        // Create bytecode analyzer
        let mut analyzer = BytecodeAnalyzer::new(bytecode);
        
        // Set test mode based on the configuration
        analyzer.set_test_mode(self.config.test_mode);
        
        // Run the analysis
        let mut results = match analyzer.analyze() {
            Ok(r) => r,
            Err(e) => {
                // Create a minimal report with the error
                return Ok(AnalysisReport {
                    timestamp: chrono::Utc::now(),
                    contract_size: analyzer.bytecode_length(),
                    vulnerabilities: vec![Vulnerability {
                        title: "Analysis Error".to_string(),
                        description: format!("Error during analysis: {}", e),
                        severity: VulnerabilitySeverity::Error,
                        vulnerability_type: VulnerabilityType::Other,
                        location: VulnerabilityLocation::Unknown,
                        recommendation: "Check the bytecode format and try again.".to_string(),
                    }],
                    delegate_calls: 0,
                    memory_accesses: 0,
                    storage_accesses: 0,
                    analysis_config: self.config.clone(),
                });
            }
        };
        
        // Detect additional vulnerabilities based on configuration
        
        // Detect reentrancy vulnerabilities if enabled
        if self.config.detect_reentrancy {
            let reentrancy_warnings = analyzer_reentrancy::detect_reentrancy(&analyzer);
            for warning in reentrancy_warnings {
                results.add_warning(warning.description.clone());
            }
        }
        
        // Detect cross-contract reentrancy vulnerabilities if enabled
        if self.config.detect_cross_contract_reentrancy {
            let cross_contract_reentrancy_warnings = analyzer_cross_contract_reentrancy::detect_cross_contract_reentrancy(&analyzer);
            for warning in cross_contract_reentrancy_warnings {
                results.add_warning(warning.description.clone());
            }
        }
        
        // Detect access control vulnerabilities if enabled
        if self.config.detect_access_control {
            let access_control_warnings = analyzer_access_control::detect_access_control_vulnerabilities(&analyzer);
            for warning in access_control_warnings {
                results.add_warning(warning.description.clone());
            }
        }
        
        // Detect governance vulnerabilities if enabled
        if self.config.detect_governance {
            let governance_warnings = analyzer_governance::detect_governance_vulnerabilities(&analyzer);
            for warning in governance_warnings {
                results.add_warning(warning.description.clone());
            }
        }
        
        // Detect gas griefing vulnerabilities if enabled
        if self.config.detect_gas_griefing {
            let gas_griefing_warnings = analyzer_gas_griefing::analyze(&analyzer);
            for warning in gas_griefing_warnings {
                results.add_warning(warning.description.clone());
            }
        }
        
        // Detect precision and rounding vulnerabilities if enabled
        if self.config.detect_precision_loss {
            let precision_warnings = analyzer_precision::analyze(&analyzer);
            for warning in precision_warnings {
                results.add_warning(warning.description.clone());
            }
        }
        
        // Detect event emission vulnerabilities if enabled
        if self.config.detect_event_emission {
            let event_emission_warnings = analyzer.analyze_event_emission_vulnerabilities();
            for warning in event_emission_warnings {
                results.add_warning(warning.description.clone());
            }
        }
        
        self.generate_report(results)
    }
    
    /// Analyze bytecode from a hex string
    /// 
    /// This method accepts a hexadecimal string representation of bytecode,
    /// converts it to bytes, and performs a full security analysis.
    /// 
    /// # Arguments
    /// 
    /// * `hex_string` - A hexadecimal string representing the bytecode (with or without '0x' prefix)
    /// 
    /// # Returns
    /// 
    /// A Result containing the analysis report or an error
    /// 
    /// # Examples
    /// 
    /// ```
    /// use evm_verify::api::EVMVerify;
    /// 
    /// let verifier = EVMVerify::new();
    /// let hex_bytecode = "0x6001600055"; // PUSH1 1 PUSH1 0 SSTORE
    /// let report = verifier.analyze_from_hex(hex_bytecode).unwrap();
    /// 
    /// for vuln in &report.vulnerabilities {
    ///     println!("{}: {}", vuln.title, vuln.description);
    /// }
    /// ```
    pub fn analyze_from_hex(&self, hex_string: &str) -> Result<AnalysisReport> {
        let hex_string = hex_string.trim_start_matches("0x");
        let bytes = hex::decode(hex_string)
            .context("Failed to decode hex string to bytes")?;
        self.analyze_bytecode(Bytes::from(bytes))
    }
    
    /// Analyze bytecode specifically for access control vulnerabilities
    /// 
    /// This method focuses only on detecting access control issues such as:
    /// - Missing access controls on sensitive operations
    /// - Inconsistent access controls across similar operations
    /// - Weak access control mechanisms (e.g., using tx.origin)
    /// - Hardcoded addresses in access control checks
    /// 
    /// # Arguments
    /// 
    /// * `bytecode` - The EVM bytecode to analyze
    /// 
    /// # Returns
    /// 
    /// A Result containing a vector of detected access control vulnerabilities
    /// 
    /// # Examples
    /// 
    /// ```
    /// use evm_verify::api::EVMVerify;
    /// use ethers::types::Bytes;
    /// 
    /// let verifier = EVMVerify::new();
    /// let bytecode = Bytes::from(vec![0x60, 0x01, 0x60, 0x00, 0x55]); // PUSH1 1 PUSH1 0 SSTORE
    /// let vulnerabilities = verifier.analyze_access_control(bytecode).unwrap();
    /// 
    /// for vuln in vulnerabilities {
    ///     println!("Access control issue at PC {}: {}", vuln.pc, vuln.description);
    /// }
    /// ```
    pub fn analyze_access_control(&self, bytecode: Bytes) -> Result<Vec<SecurityWarning>> {
        if !self.config.detect_access_control {
            return Ok(vec![]);
        }
        
        let analyzer = BytecodeAnalyzer::new(bytecode);
        let warnings = analyzer_access_control::detect_access_control_vulnerabilities(&analyzer);
        Ok(warnings)
    }
    
    /// Analyze bytecode specifically for reentrancy vulnerabilities
    /// 
    /// This method focuses only on detecting reentrancy issues such as:
    /// - Standard reentrancy (state changes after external calls)
    /// - Read-only reentrancy
    /// - Cross-function reentrancy
    /// 
    /// # Arguments
    /// 
    /// * `bytecode` - The EVM bytecode to analyze
    /// 
    /// # Returns
    /// 
    /// A Result containing a vector of detected reentrancy vulnerabilities
    /// 
    /// # Examples
    /// 
    /// ```
    /// use evm_verify::api::EVMVerify;
    /// use ethers::types::Bytes;
    /// 
    /// let verifier = EVMVerify::new();
    /// let bytecode = Bytes::from(vec![/* bytecode with potential reentrancy */]);
    /// let vulnerabilities = verifier.analyze_reentrancy(bytecode).unwrap();
    /// 
    /// for vuln in vulnerabilities {
    ///     println!("Reentrancy issue at PC {}: {}", vuln.pc, vuln.description);
    /// }
    /// ```
    pub fn analyze_reentrancy(&self, bytecode: Bytes) -> Result<Vec<SecurityWarning>> {
        if !self.config.detect_reentrancy {
            return Ok(vec![]);
        }
        
        let analyzer = BytecodeAnalyzer::new(bytecode);
        let warnings = analyzer_reentrancy::detect_reentrancy_vulnerabilities(&analyzer);
        Ok(warnings)
    }

    /// Analyze bytecode specifically for cross-contract reentrancy vulnerabilities
    /// 
    /// This method focuses only on detecting complex cross-contract reentrancy issues such as:
    /// - State changes after external calls across multiple contracts
    /// - Shared storage between contracts
    /// - Complex call patterns that may enable reentrancy
    /// 
    /// # Arguments
    /// 
    /// * `bytecode` - The EVM bytecode to analyze
    /// 
    /// # Returns
    /// 
    /// A Result containing a vector of detected cross-contract reentrancy vulnerabilities
    /// 
    /// # Examples
    /// 
    /// ```
    /// use evm_verify::api::EVMVerify;
    /// use ethers::types::Bytes;
    /// 
    /// let verifier = EVMVerify::new();
    /// let bytecode = Bytes::from(vec![/* bytecode with potential cross-contract reentrancy */]);
    /// let vulnerabilities = verifier.analyze_cross_contract_reentrancy(bytecode).unwrap();
    /// 
    /// for vuln in vulnerabilities {
    ///     println!("Cross-contract reentrancy issue at PC {}: {}", vuln.pc, vuln.description);
    /// }
    /// ```
    pub fn analyze_cross_contract_reentrancy(&self, bytecode: Bytes) -> Result<Vec<SecurityWarning>> {
        let analyzer = BytecodeAnalyzer::new(bytecode);
        let warnings = analyzer_cross_contract_reentrancy::detect_cross_contract_reentrancy(&analyzer);
        Ok(warnings)
    }
    
    /// Analyze bytecode specifically for unchecked external call vulnerabilities
    /// 
    /// This method focuses only on detecting issues with external calls such as:
    /// - Unchecked return values from low-level calls
    /// - Missing error handling for external interactions
    /// 
    /// # Arguments
    /// 
    /// * `bytecode` - The EVM bytecode to analyze
    /// 
    /// # Returns
    /// 
    /// A Result containing a vector of detected unchecked call vulnerabilities
    /// 
    /// # Examples
    /// 
    /// ```
    /// use evm_verify::api::EVMVerify;
    /// use ethers::types::Bytes;
    /// 
    /// let verifier = EVMVerify::new();
    /// let bytecode = Bytes::from(vec![/* bytecode with potential unchecked calls */]);
    /// let vulnerabilities = verifier.analyze_unchecked_calls(bytecode).unwrap();
    /// 
    /// for vuln in vulnerabilities {
    ///     println!("Unchecked call issue at PC {}: {}", vuln.pc, vuln.description);
    /// }
    /// ```
    pub fn analyze_unchecked_calls(&self, bytecode: Bytes) -> Result<Vec<SecurityWarning>> {
        let analyzer = BytecodeAnalyzer::new(bytecode);
        let warnings = analyzer_unchecked_calls::detect_unchecked_calls(&analyzer);
        Ok(warnings)
    }
    
    /// Analyze bytecode specifically for self-destruct vulnerabilities
    /// 
    /// This method focuses only on detecting issues with self-destruct operations such as:
    /// - Unprotected self-destruct operations
    /// - Delegated self-destruct operations
    /// 
    /// # Arguments
    /// 
    /// * `bytecode` - The EVM bytecode to analyze
    /// 
    /// # Returns
    /// 
    /// A Result containing a vector of detected self-destruct vulnerabilities
    /// 
    /// # Examples
    /// 
    /// ```
    /// use evm_verify::api::EVMVerify;
    /// use ethers::types::Bytes;
    /// 
    /// let verifier = EVMVerify::new();
    /// let bytecode = Bytes::from(vec![/* bytecode with potential self-destruct issues */]);
    /// let vulnerabilities = verifier.analyze_self_destruct(bytecode).unwrap();
    /// 
    /// for vuln in vulnerabilities {
    ///     println!("Self-destruct issue at PC {}: {}", vuln.pc, vuln.description);
    /// }
    /// ```
    pub fn analyze_self_destruct(&self, bytecode: Bytes) -> Result<Vec<SecurityWarning>> {
        let analyzer = BytecodeAnalyzer::new(bytecode);
        let warnings = analyzer_self_destruct::detect_self_destruct_vulnerabilities(&analyzer);
        Ok(warnings)
    }
    
    /// Analyze bytecode specifically for gas limit vulnerabilities
    /// 
    /// This method focuses only on detecting issues with gas usage such as:
    /// - Loops without gas limits
    /// - Operations that could exceed block gas limits
    /// 
    /// # Arguments
    /// 
    /// * `bytecode` - The EVM bytecode to analyze
    /// 
    /// # Returns
    /// 
    /// A Result containing a vector of detected gas limit vulnerabilities
    /// 
    /// # Examples
    /// 
    /// ```
    /// use evm_verify::api::EVMVerify;
    /// use ethers::types::Bytes;
    /// 
    /// let verifier = EVMVerify::new();
    /// let bytecode = Bytes::from(vec![/* bytecode with potential gas limit issues */]);
    /// let vulnerabilities = verifier.analyze_gas_limit(bytecode).unwrap();
    /// 
    /// for vuln in vulnerabilities {
    ///     println!("Gas limit issue at PC {}: {}", vuln.pc, vuln.description);
    /// }
    /// ```
    pub fn analyze_gas_limit(&self, bytecode: Bytes) -> Result<Vec<SecurityWarning>> {
        let analyzer = BytecodeAnalyzer::new(bytecode);
        let warnings = analyzer_gas_limit::detect_gas_limit_vulnerabilities(&analyzer);
        Ok(warnings)
    }
    
    /// Analyze bytecode specifically for integer overflow vulnerabilities
    /// 
    /// This method focuses only on detecting arithmetic issues such as:
    /// - Integer overflow in addition operations
    /// - Integer overflow in multiplication operations
    /// - Missing SafeMath patterns
    /// 
    /// # Arguments
    /// 
    /// * `bytecode` - The EVM bytecode to analyze
    /// 
    /// # Returns
    /// 
    /// A Result containing a vector of detected integer overflow vulnerabilities
    /// 
    /// # Examples
    /// 
    /// ```
    /// use evm_verify::api::EVMVerify;
    /// use ethers::types::Bytes;
    /// 
    /// let verifier = EVMVerify::new();
    /// let bytecode = Bytes::from(vec![/* bytecode with potential overflow issues */]);
    /// let vulnerabilities = verifier.analyze_integer_overflow(bytecode).unwrap();
    /// 
    /// for vuln in vulnerabilities {
    ///     println!("Integer overflow issue at PC {}: {}", vuln.pc, vuln.description);
    /// }
    /// ```
    pub fn analyze_integer_overflow(&self, bytecode: Bytes) -> Result<Vec<SecurityWarning>> {
        if !self.config.detect_arithmetic {
            return Ok(vec![]);
        }
        
        let analyzer = BytecodeAnalyzer::new(bytecode);
        let warnings = analyzer_overflow::detect_integer_overflow(&analyzer);
        Ok(warnings)
    }
    
    /// Analyze bytecode specifically for integer underflow vulnerabilities
    /// 
    /// This method focuses only on detecting arithmetic issues such as:
    /// - Integer underflow in subtraction operations
    /// - Integer underflow in division operations
    /// - Missing SafeMath patterns
    /// 
    /// # Arguments
    /// 
    /// * `bytecode` - The EVM bytecode to analyze
    /// 
    /// # Returns
    /// 
    /// A Result containing a vector of detected integer underflow vulnerabilities
    /// 
    /// # Examples
    /// 
    /// ```
    /// use evm_verify::api::EVMVerify;
    /// use ethers::types::Bytes;
    /// 
    /// let verifier = EVMVerify::new();
    /// let bytecode = Bytes::from(vec![/* bytecode with potential underflow issues */]);
    /// let vulnerabilities = verifier.analyze_integer_underflow(bytecode).unwrap();
    /// 
    /// for vuln in vulnerabilities {
    ///     println!("Integer underflow issue at PC {}: {}", vuln.pc, vuln.description);
    /// }
    /// ```
    pub fn analyze_integer_underflow(&self, bytecode: Bytes) -> Result<Vec<SecurityWarning>> {
        let analyzer = BytecodeAnalyzer::new(bytecode);
        
        if !self.config.detect_arithmetic {
            println!("Arithmetic vulnerability detection disabled in config");
            return Ok(vec![]);
        }
        
        analyzer.detect_integer_underflow()
    }

    /// Analyze bytecode specifically for flash loan vulnerabilities
    /// 
    /// This method focuses only on detecting flash loan-related issues such as:
    /// - Price oracle manipulation vulnerabilities
    /// - State changes after external calls without validation
    /// - Missing slippage protection in swap operations
    /// 
    /// # Arguments
    /// 
    /// * `bytecode` - The EVM bytecode to analyze
    /// 
    /// # Returns
    /// 
    /// A Result containing a vector of detected flash loan vulnerabilities
    /// 
    /// # Examples
    /// 
    /// ```
    /// use evm_verify::api::EVMVerify;
    /// use ethers::types::Bytes;
    /// 
    /// let verifier = EVMVerify::new();
    /// let bytecode = Bytes::from(vec![/* bytecode with potential flash loan issues */]);
    /// let vulnerabilities = verifier.analyze_flash_loan_vulnerabilities(bytecode).unwrap();
    /// 
    /// for vuln in vulnerabilities {
    ///     println!("Flash loan issue at PC {}: {}", vuln.pc, vuln.description);
    /// }
    /// ```
    pub fn analyze_flash_loan_vulnerabilities(&self, bytecode: Bytes) -> Result<Vec<SecurityWarning>> {
        let analyzer = BytecodeAnalyzer::new(bytecode);
        
        if !self.config.detect_flash_loan {
            println!("Flash loan vulnerability detection disabled in config");
            return Ok(vec![]);
        }
        
        analyzer.detect_flash_loan_vulnerabilities()
    }

    /// Analyze bytecode specifically for timestamp dependency vulnerabilities
    /// 
    /// This method focuses only on detecting timestamp-related issues such as:
    /// - Critical operations dependent on block.timestamp
    /// - Timestamp manipulation vulnerabilities
    /// - Time-based conditions that could be manipulated by miners
    /// 
    /// # Arguments
    /// 
    /// * `bytecode` - The EVM bytecode to analyze
    /// 
    /// # Returns
    /// 
    /// A Result containing a vector of detected timestamp dependency vulnerabilities
    /// 
    /// # Examples
    /// 
    /// ```
    /// use evm_verify::api::EVMVerify;
    /// use ethers::types::Bytes;
    /// 
    /// let verifier = EVMVerify::new();
    /// let bytecode = Bytes::from(vec![/* bytecode with potential timestamp issues */]);
    /// let vulnerabilities = verifier.analyze_timestamp_dependencies(bytecode).unwrap();
    /// 
    /// for vuln in vulnerabilities {
    ///     println!("Timestamp dependency issue at PC {}: {}", vuln.pc, vuln.description);
    /// }
    /// ```
    pub fn analyze_timestamp_dependencies(&self, bytecode: Bytes) -> Result<Vec<SecurityWarning>> {
        let analyzer = BytecodeAnalyzer::new(bytecode);
        let warnings = analyzer_timestamp::detect_timestamp_dependencies(&analyzer);
        Ok(warnings)
    }

    /// Analyze bytecode specifically for signature replay vulnerabilities
    /// 
    /// This method analyzes EVM bytecode to detect potential signature replay vulnerabilities,
    /// such as missing nonce or timestamp checks in signature verification.
    /// 
    /// # Arguments
    /// 
    /// * `bytecode` - The bytecode to analyze
    /// 
    /// # Returns
    /// 
    /// A Result containing a vector of security warnings or an error
    /// 
    /// # Examples
    /// 
    /// ```
    /// use evm_verify::api::EVMVerify;
    /// use ethers::types::Bytes;
    /// 
    /// let verifier = EVMVerify::new();
    /// let bytecode = Bytes::from(vec![0x1b, 0x60, 0x00, 0x52]); // ECRECOVER PUSH1 0 MSTORE
    /// let vulnerabilities = verifier.analyze_signature_replay(bytecode).unwrap();
    /// 
    /// for vuln in vulnerabilities {
    ///     println!("{:?}: {}", vuln.kind, vuln.description);
    /// }
    /// ```
    pub fn analyze_signature_replay(&self, bytecode: Bytes) -> Result<Vec<SecurityWarning>> {
        // Create bytecode analyzer
        let mut analyzer = BytecodeAnalyzer::new(bytecode);
        
        // Run the analysis
        analyzer.analyze()?;
        
        // Get signature replay vulnerabilities
        let warnings = analyzer_signature_replay::detect_signature_replay_vulnerabilities(&analyzer);
        
        Ok(warnings)
    }
    
    /// Analyze bytecode specifically for proxy contract vulnerabilities
    /// 
    /// This method analyzes EVM bytecode to detect potential vulnerabilities in proxy contracts,
    /// such as uninitialized proxies, storage collisions, and implementation shadowing.
    /// 
    /// # Arguments
    /// 
    /// * `bytecode` - The bytecode to analyze
    /// 
    /// # Returns
    /// 
    /// A Result containing a vector of security warnings or an error
    /// 
    /// # Examples
    /// 
    /// ```
    /// use evm_verify::api::EVMVerify;
    /// use ethers::types::Bytes;
    /// 
    /// let verifier = EVMVerify::new();
    /// let bytecode = Bytes::from(vec![0xf4, 0x60, 0x00, 0x54]); // DELEGATECALL PUSH1 0 SLOAD
    /// let vulnerabilities = verifier.analyze_proxy_vulnerabilities(bytecode).unwrap();
    /// 
    /// for vuln in vulnerabilities {
    ///     println!("{:?}: {}", vuln.kind, vuln.description);
    /// }
    /// ```
    pub fn analyze_proxy_vulnerabilities(&self, bytecode: Bytes) -> Result<Vec<SecurityWarning>> {
        // Create bytecode analyzer
        let mut analyzer = BytecodeAnalyzer::new(bytecode);
        
        // Run the analysis
        analyzer.analyze()?;
        
        // Get proxy vulnerabilities
        let warnings = analyzer_proxy::detect_proxy_vulnerabilities(&analyzer);
        
        Ok(warnings)
    }

    /// Analyze bytecode specifically for oracle manipulation vulnerabilities
    /// 
    /// This method analyzes EVM bytecode to detect potential oracle manipulation vulnerabilities,
    /// such as using untrusted oracles, or failing to validate oracle responses.
    /// 
    /// # Arguments
    /// 
    /// * `bytecode` - The bytecode to analyze
    /// 
    /// # Returns
    /// 
    /// A Result containing a vector of security warnings or an error
    /// 
    /// # Examples
    /// 
    /// ```
    /// use evm_verify::api::EVMVerify;
    /// use ethers::types::Bytes;
    /// 
    /// let verifier = EVMVerify::new();
    /// let bytecode = Bytes::from(vec![0x1b, 0x60, 0x00, 0x52]); // ECRECOVER PUSH1 0 MSTORE
    /// let vulnerabilities = verifier.analyze_oracle_manipulation(bytecode).unwrap();
    /// 
    /// for vuln in vulnerabilities {
    ///     println!("{:?}: {}", vuln.kind, vuln.description);
    /// }
    /// ```
    pub fn analyze_oracle_manipulation(&self, bytecode: Bytes) -> Result<Vec<SecurityWarning>> {
        // Create bytecode analyzer
        let mut analyzer = BytecodeAnalyzer::new(bytecode);
        
        // Run the analysis
        analyzer.analyze().context("Failed to analyze bytecode")?;
        
        // Get oracle manipulation vulnerabilities
        analyzer.detect_oracle_manipulation()
    }

    /// Analyze bytecode specifically for MEV (Maximal Extractable Value) vulnerabilities
    /// 
    /// This method analyzes EVM bytecode to detect potential MEV vulnerabilities,
    /// such as unprotected price-sensitive operations, missing slippage protection,
    /// and absence of commit-reveal patterns.
    /// 
    /// # Arguments
    /// 
    /// * `bytecode` - The EVM bytecode to analyze
    /// 
    /// # Returns
    /// 
    /// A Result containing a vector of security warnings or an error
    /// 
    /// # Examples
    /// 
    /// ```
    /// use evm_verify::api::EVMVerify;
    /// use ethers::types::Bytes;
    /// 
    /// let verifier = EVMVerify::new();
    /// let bytecode = Bytes::from(vec![0x60, 0x01, 0x60, 0x00, 0x55]); // PUSH1 1 PUSH1 0 SSTORE
    /// let vulnerabilities = verifier.analyze_mev_vulnerabilities(bytecode).unwrap();
    /// 
    /// for vuln in vulnerabilities {
    ///     println!("{:?}: {}", vuln.kind, vuln.description);
    /// }
    /// ```
    pub fn analyze_mev_vulnerabilities(&self, bytecode: Bytes) -> Result<Vec<SecurityWarning>> {
        // Create bytecode analyzer
        let mut analyzer = BytecodeAnalyzer::new(bytecode);
        
        // Run the analysis
        analyzer.analyze().context("Failed to analyze bytecode")?;
        
        // Get MEV vulnerabilities
        analyzer.detect_mev_vulnerabilities()
    }

    /// Analyze bytecode specifically for governance vulnerabilities
    /// 
    /// This method analyzes EVM bytecode to detect potential governance vulnerabilities,
    /// such as missing or weak access controls, or improper use of governance mechanisms.
    /// 
    /// # Arguments
    /// 
    /// * `bytecode` - The bytecode to analyze
    /// 
    /// # Returns
    /// 
    /// A Result containing a vector of security warnings or an error
    /// 
    /// # Examples
    /// 
    /// ```
    /// use evm_verify::api::EVMVerify;
    /// use ethers::types::Bytes;
    /// 
    /// let verifier = EVMVerify::new();
    /// let bytecode = Bytes::from(vec![0x60, 0x01, 0x60, 0x00, 0x55]); // PUSH1 1 PUSH1 0 SSTORE
    /// let vulnerabilities = verifier.analyze_governance_vulnerabilities(bytecode).unwrap();
    /// 
    /// for vuln in vulnerabilities {
    ///     println!("{:?}: {}", vuln.kind, vuln.description);
    /// }
    /// ```
    pub fn analyze_governance_vulnerabilities(&self, bytecode: Bytes) -> Result<Vec<SecurityWarning>> {
        let analyzer = BytecodeAnalyzer::new(bytecode);
        
        if !self.config.detect_governance {
            println!("Governance vulnerability detection disabled in config");
            return Ok(vec![]);
        }
        
        Ok(analyzer_governance::detect_governance_vulnerabilities(&analyzer))
    }

    /// Analyze bytecode specifically for gas griefing vulnerabilities
    /// 
    /// This method analyzes EVM bytecode to detect potential gas griefing vulnerabilities,
    /// such as unbounded loops, expensive operations in loops, missing gas limits in external calls,
    /// and insufficient gas stipends.
    /// 
    /// # Arguments
    /// 
    /// * `bytecode` - The EVM bytecode to analyze
    /// 
    /// # Returns
    /// 
    /// A Result containing a vector of security warnings or an error
    /// 
    /// # Examples
    /// 
    /// ```
    /// use evm_verify::api::EVMVerify;
    /// use ethers::types::Bytes;
    /// 
    /// let verifier = EVMVerify::new();
    /// let bytecode = Bytes::from(vec![
    ///     0x5b, // JUMPDEST (loop start)
    ///     0x60, 0x01, // PUSH1 1
    ///     0x54, // SLOAD (expensive operation)
    ///     0x60, 0x00, // PUSH1 0
    ///     0x57, // JUMPI (conditional jump)
    /// ]);
    /// let vulnerabilities = verifier.analyze_gas_griefing_vulnerabilities(bytecode).unwrap();
    /// 
    /// for vuln in vulnerabilities {
    ///     println!("{:?}: {}", vuln.kind, vuln.description);
    /// }
    /// ```
    pub fn analyze_gas_griefing_vulnerabilities(&self, bytecode: Bytes) -> Result<Vec<SecurityWarning>> {
        let mut analyzer = BytecodeAnalyzer::new(bytecode);
        
        // Set test mode based on the configuration
        analyzer.set_test_mode(self.config.test_mode);
        
        let warnings = analyzer_gas_griefing::analyze(&analyzer);
        
        Ok(warnings)
    }

    /// Analyze bytecode specifically for precision vulnerabilities
    /// 
    /// This method analyzes EVM bytecode to detect potential precision vulnerabilities,
    /// such as division by zero, or precision loss in arithmetic operations.
    /// 
    /// # Arguments
    /// 
    /// * `bytecode` - The EVM bytecode to analyze
    /// 
    /// # Returns
    /// 
    /// A Result containing a vector of security warnings or an error
    /// 
    /// # Examples
    /// 
    /// ```
    /// use evm_verify::api::EVMVerify;
    /// use ethers::types::Bytes;
    /// 
    /// let verifier = EVMVerify::new();
    /// let bytecode = Bytes::from(vec![0x60, 0x01, 0x60, 0x00, 0x55]); // PUSH1 1 PUSH1 0 SSTORE
    /// let vulnerabilities = verifier.analyze_precision_vulnerabilities(bytecode).unwrap();
    /// 
    /// for vuln in vulnerabilities {
    ///     println!("{:?}: {}", vuln.kind, vuln.description);
    /// }
    /// ```
    pub fn analyze_precision_vulnerabilities(&self, bytecode: Bytes) -> Result<Vec<SecurityWarning>> {
        let analyzer = BytecodeAnalyzer::new(bytecode);
        let warnings = analyzer_precision::analyze(&analyzer);
        Ok(warnings)
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
                } else if warning.contains("flash loan") {
                    VulnerabilityType::FlashLoan
                } else if warning.contains("signature replay") {
                    VulnerabilityType::SignatureReplay
                } else if warning.contains("uninitialized proxy") || warning.contains("proxy") {
                    VulnerabilityType::ProxyVulnerability
                } else if warning.contains("oracle manipulation") || warning.contains("oracle") {
                    VulnerabilityType::OracleManipulation
                } else if warning.contains("governance") || warning.contains("timelock") || warning.contains("quorum") {
                    VulnerabilityType::GovernanceVulnerability
                } else {
                    VulnerabilityType::Other
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
                    VulnerabilityType::Other => 
                        "Review and fix the identified issue".to_string(),
                    VulnerabilityType::FlashLoan => 
                        "Implement flash loan protection mechanisms".to_string(),
                    VulnerabilityType::SignatureReplay => 
                        "Implement signature replay protection mechanisms".to_string(),
                    VulnerabilityType::ProxyVulnerability => 
                        "Implement proxy vulnerability protection mechanisms".to_string(),
                    VulnerabilityType::OracleManipulation => 
                        "Implement oracle manipulation protection mechanisms".to_string(),
                    VulnerabilityType::GovernanceVulnerability => 
                        "Implement proper timelock mechanisms, secure quorum requirements, and flash loan protection in governance systems".to_string(),
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

    /// Set test mode for the analyzer
    /// 
    /// This method enables or disables test mode for the analyzer.
    /// When test mode is enabled, certain features like memory access tracking are disabled,
    /// which is useful for testing.
    /// 
    /// # Arguments
    /// 
    /// * `enabled` - Whether to enable test mode
    /// 
    /// # Examples
    /// 
    /// ```
    /// use evm_verify::api::EVMVerify;
    /// 
    /// let mut verifier = EVMVerify::new();
    /// verifier.set_test_mode(true);
    /// 
    /// // Now analyze bytecode with test mode enabled
    /// ```
    pub fn set_test_mode(&mut self, enabled: bool) {
        self.config.test_mode = enabled;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use crate::bytecode::SecurityWarningKind;

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

    #[test]
    fn test_integer_underflow_detection() -> Result<()> {
        // Create bytecode with a potential integer underflow vulnerability
        // This bytecode contains a SUB operation (0x03) without proper checks
        let bytecode = Bytes::from(vec![
            // PUSH1 0x05
            0x60, 0x05,
            // PUSH1 0x0A
            0x60, 0x0A,
            // SUB (subtract without checking if result will underflow)
            0x03,
            // PUSH1 0x00
            0x60, 0x00,
            // SSTORE (store result at storage slot 0)
            0x55
        ]);
        
        // Create analyzer with default config
        let analyzer = EVMVerify::new();
        
        // Run specific underflow analysis
        let warnings = analyzer.analyze_integer_underflow(bytecode)?;
        
        // Verify that we detected the vulnerability
        assert!(!warnings.is_empty(), "Should have detected integer underflow vulnerability");
        
        // Verify the warning type
        let warning = &warnings[0];
        assert_eq!(warning.kind, SecurityWarningKind::IntegerUnderflow);
        
        Ok(())
    }

    #[test]
    fn test_timestamp_dependency_detection() -> Result<()> {
        // Create test bytecode with timestamp dependency
        let bytecode = Bytes::from(vec![
            0x42, // TIMESTAMP
            0x60, 0x05, // PUSH1 5
            0x10, // LT
            0x60, 0x00, // PUSH1 0
            0x57, // JUMPI
        ]);
        
        // Create verifier
        let mut verifier = EVMVerify::new();
        verifier.set_test_mode(true);
        
        // Analyze for timestamp dependencies
        let vulnerabilities = verifier.analyze_timestamp_dependencies(bytecode)?;
        
        // Verify at least one vulnerability was found
        assert!(!vulnerabilities.is_empty());
        
        // Verify the vulnerability is correctly identified
        let vuln = &vulnerabilities[0];
        assert_eq!(vuln.kind, SecurityWarningKind::TimestampDependence);
        
        Ok(())
    }

    #[test]
    fn test_governance_vulnerability_detection() -> Result<()> {
        // Create test bytecode with governance vulnerability
        // This simulates a contract with insufficient timelock (small timestamp comparison)
        let bytecode = Bytes::from(vec![
            0x42, // TIMESTAMP
            0x60, 0x0A, // PUSH1 10 (very small timelock of 10 seconds)
            0x11, // GT
            0x60, 0x00, // PUSH1 0
            0x55, // SSTORE
        ]);
        
        // Create verifier
        let mut verifier = EVMVerify::new();
        verifier.set_test_mode(true);
        
        // Analyze for governance vulnerabilities
        let vulnerabilities = verifier.analyze_governance_vulnerabilities(bytecode)?;
        
        // Verify at least one vulnerability was found
        assert!(!vulnerabilities.is_empty());
        
        // Verify the vulnerability is correctly identified
        let vuln = &vulnerabilities[0];
        assert_eq!(vuln.kind, SecurityWarningKind::InsufficientTimelock);
        
        Ok(())
    }
}
