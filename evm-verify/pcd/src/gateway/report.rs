use chrono::{DateTime, Utc};
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use super::detector::SecurityWarning;

/// Detailed security report for a contract or action sequence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityReport {
    /// When the report was generated
    pub timestamp: DateTime<Utc>,
    /// Contract hash (if available)
    pub contract_hash: Option<String>,
    /// Size of analyzed bytecode in bytes
    pub bytecode_size: usize,
    /// Summary of findings by severity
    pub summary: SecuritySummary,
    /// Detailed security warnings
    pub warnings: Vec<SecurityWarning>,
    /// Executed detectors and their status
    pub detectors: Vec<DetectorResult>,
}

/// Summary of security findings by severity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySummary {
    /// Count of critical issues
    pub critical_count: usize,
    /// Count of warning-level issues
    pub warning_count: usize,
    /// Count of informational issues
    pub info_count: usize,
}

/// Result of running a security detector
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorResult {
    /// Detector name
    pub name: String,
    /// Detector description
    pub description: String,
    /// Whether the detector executed successfully
    pub execution_success: bool,
    /// Number of issues found by this detector
    pub issues_found: usize,
}

/// Security report generator
pub struct SecurityReportGenerator {
    // Future extension: Add custom formatting options, etc.
}

impl SecurityReportGenerator {
    /// Create a new security report generator
    pub fn new() -> Self {
        Self {}
    }
    
    /// Generate a security report for contract bytecode
    pub fn generate(&self, bytecode: &[u8], warnings: &[SecurityWarning]) -> SecurityReport {
        // Calculate summary by severity
        let mut critical_count = 0;
        let mut warning_count = 0;
        let mut info_count = 0;
        
        for warning in warnings {
            match warning.severity {
                super::detector::Severity::Critical => critical_count += 1,
                super::detector::Severity::Warning => warning_count += 1,
                super::detector::Severity::Info => info_count += 1,
            }
        }
        
        // Group warnings by detector
        let mut detector_map: HashMap<String, (String, usize)> = HashMap::new();
        
        for warning in warnings {
            let detector_name = match &warning.kind {
                crate::circuit_impl::SecurityWarningKind::Reentrancy => "Reentrancy Detector".to_string(),
                crate::circuit_impl::SecurityWarningKind::AccessControl => "Access Control Detector".to_string(),
                crate::circuit_impl::SecurityWarningKind::IntegerOverflow => "Integer Overflow Detector".to_string(),
                crate::circuit_impl::SecurityWarningKind::UncheckedCall => "Unchecked Call Detector".to_string(),
                crate::circuit_impl::SecurityWarningKind::FrontRunning => "Front Running Detector".to_string(),
                crate::circuit_impl::SecurityWarningKind::FlashLoan => "Flash Loan Detector".to_string(),
                crate::circuit_impl::SecurityWarningKind::Other(name) => {
                    match name.as_str() {
                        "CrossContractReentrancy" => "Cross-Contract Reentrancy Detector".to_string(),
                        "UninitializedStorage" => "Uninitialized Storage Detector".to_string(),
                        "GasGriefing" => "Gas Griefing Detector".to_string(),
                        "PrecisionLoss" => "Precision Loss Detector".to_string(),
                        "MEVVulnerability" => "MEV Vulnerability Detector".to_string(),
                        _ => format!("Other Detector: {}", name),
                    }
                }
            };
            
            let description = match &warning.kind {
                crate::circuit_impl::SecurityWarningKind::Reentrancy => 
                    "Detects reentrancy vulnerabilities".to_string(),
                crate::circuit_impl::SecurityWarningKind::AccessControl => 
                    "Detects access control issues".to_string(),
                crate::circuit_impl::SecurityWarningKind::IntegerOverflow => 
                    "Detects integer overflow vulnerabilities".to_string(),
                crate::circuit_impl::SecurityWarningKind::UncheckedCall => 
                    "Detects unchecked external calls".to_string(),
                crate::circuit_impl::SecurityWarningKind::FrontRunning => 
                    "Detects front-running vulnerabilities".to_string(),
                crate::circuit_impl::SecurityWarningKind::FlashLoan => 
                    "Detects flash loan vulnerabilities".to_string(),
                crate::circuit_impl::SecurityWarningKind::Other(name) => {
                    match name.as_str() {
                        "CrossContractReentrancy" => 
                            "Detects reentrancy across multiple contracts".to_string(),
                        "UninitializedStorage" => 
                            "Detects reading from uninitialized storage".to_string(),
                        "GasGriefing" => 
                            "Detects gas griefing vulnerabilities".to_string(),
                        "PrecisionLoss" => 
                            "Detects numerical precision loss".to_string(),
                        "MEVVulnerability" => 
                            "Detects MEV exploitation opportunities".to_string(),
                        _ => format!("Other vulnerability: {}", name),
                    }
                }
            };
            
            let entry = detector_map.entry(detector_name).or_insert((description, 0));
            entry.1 += 1;
        }
        
        // Generate detector results
        let mut detectors = Vec::new();
        for (name, (description, count)) in detector_map {
            detectors.push(DetectorResult {
                name,
                description,
                execution_success: true,
                issues_found: count,
            });
        }
        
        // Calculate simple contract hash (if needed, use a more robust method)
        let contract_hash = if !bytecode.is_empty() {
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(bytecode);
            let hash = hasher.finalize();
            Some(format!("{:x}", hash))
        } else {
            None
        };
        
        SecurityReport {
            timestamp: Utc::now(),
            contract_hash,
            bytecode_size: bytecode.len(),
            summary: SecuritySummary {
                critical_count,
                warning_count,
                info_count,
            },
            warnings: warnings.to_vec(),
            detectors,
        }
    }
    
    /// Generate a security report for an action sequence
    pub fn generate_sequence_report(&self, actions: &[Vec<u8>], warnings: &[SecurityWarning]) -> SecurityReport {
        // Simple concatenation of bytecode for hash generation
        // In a more sophisticated implementation, consider a more meaningful representation
        let concatenated: Vec<u8> = actions.iter().flat_map(|a| a.iter().copied()).collect();
        
        let mut report = self.generate(&concatenated, warnings);
        report.bytecode_size = actions.iter().map(|a| a.len()).sum();
        
        report
    }
    
    /// Format a security report as human-readable text
    pub fn format_report_text(&self, report: &SecurityReport) -> String {
        let mut output = String::new();
        
        // Report header
        output.push_str("===========================================\n");
        output.push_str("        SECURITY VERIFICATION REPORT       \n");
        output.push_str("===========================================\n\n");
        
        // Timestamp and hash
        output.push_str(&format!("Timestamp: {}\n", report.timestamp.format("%Y-%m-%d %H:%M:%S UTC")));
        if let Some(hash) = &report.contract_hash {
            output.push_str(&format!("Contract hash: {}\n", hash));
        }
        output.push_str(&format!("Bytecode size: {} bytes\n\n", report.bytecode_size));
        
        // Summary section
        output.push_str("SUMMARY\n-------\n");
        output.push_str(&format!("Critical issues: {}\n", report.summary.critical_count));
        output.push_str(&format!("Warnings: {}\n", report.summary.warning_count));
        output.push_str(&format!("Info: {}\n\n", report.summary.info_count));
        
        // Warnings section if there are any
        if !report.warnings.is_empty() {
            output.push_str("SECURITY ISSUES\n--------------\n");
            
            for (i, warning) in report.warnings.iter().enumerate() {
                let severity_str = match warning.severity {
                    super::detector::Severity::Critical => "[CRITICAL]",
                    super::detector::Severity::Warning => "[WARNING]",
                    super::detector::Severity::Info => "[INFO]",
                };
                
                output.push_str(&format!("{}. {} {}\n", i + 1, severity_str, warning.description));
                
                if let Some(loc) = &warning.location {
                    if let Some(ctx) = &loc.context {
                        output.push_str(&format!("   Location: {} (offset {})\n", ctx, loc.offset));
                    } else {
                        output.push_str(&format!("   Location: offset {}\n", loc.offset));
                    }
                }
                
                output.push_str(&format!("   Remediation: {}\n\n", warning.remediation_hint));
            }
        } else {
            output.push_str("No security issues detected.\n\n");
        }
        
        // Detectors section
        output.push_str("DETECTORS EXECUTED\n-----------------\n");
        for detector in &report.detectors {
            let status = if detector.execution_success { "SUCCESS" } else { "FAILED" };
            output.push_str(&format!("- {} ({}): {} issue(s) found\n", 
                detector.name, status, detector.issues_found));
        }
        
        output
    }
    
    /// Format a security report as JSON
    pub fn format_report_json(&self, report: &SecurityReport) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(report)
    }
}
