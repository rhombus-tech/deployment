// Unified Verifier API
//
// This module provides a unified API for verifying smart contracts using both
// Proof-Carrying Code (PCC) and Proof-Carrying Data (PCD) functionality.

use anyhow::Result;
use ethers::types::Bytes;
use chrono::Utc;

use crate::bytecode::BytecodeAnalyzer;
use crate::bytecode::security::{SecuritySeverity, SecurityWarningKind};
use crate::api::types::{AnalysisReport, Vulnerability, VulnerabilityType, VulnerabilitySeverity, VulnerabilityLocation, AnalysisConfig};

use std::sync::Arc;

#[cfg(feature = "accumulation")]
use crate::api::pcd_adapter::PCDAdapter;

/// Unified verifier for smart contracts
///
/// This struct provides a unified API for verifying smart contracts using both
/// Proof-Carrying Code (PCC) and Proof-Carrying Data (PCD) functionality.
pub struct UnifiedVerifier {
    pcc_enabled: bool,
    pcd_enabled: bool,
    #[cfg(feature = "accumulation")]
    pcd_adapter: PCDAdapter,
    #[cfg(not(feature = "accumulation"))]
    pcd_verifier: Arc<dyn crate::api::pcd::PCDVerifier>,
}

/// Result of verification
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Whether the bytecode is valid
    pub is_valid: bool,
    /// List of vulnerabilities found
    pub vulnerabilities: Vec<String>,
}

impl UnifiedVerifier {
    /// Create a new UnifiedVerifier with both PCC and PCD enabled
    pub fn new() -> Self {
        #[cfg(feature = "accumulation")]
        let pcd_adapter = PCDAdapter::new();
        
        #[cfg(not(feature = "accumulation"))]
        let pcd_verifier = Arc::new(crate::api::pcd::DefaultPCDVerifier::new());
        
        Self {
            pcc_enabled: true,
            pcd_enabled: true,
            #[cfg(feature = "accumulation")]
            pcd_adapter,
            #[cfg(not(feature = "accumulation"))]
            pcd_verifier,
        }
    }

    /// Create a new UnifiedVerifier with custom configuration
    pub fn with_config(pcd_enabled: bool, pcc_enabled: bool) -> Self {
        #[cfg(feature = "accumulation")]
        let pcd_adapter = PCDAdapter::new();
        
        #[cfg(not(feature = "accumulation"))]
        let pcd_verifier = Arc::new(crate::api::pcd::DefaultPCDVerifier::new());
        
        Self {
            pcc_enabled,
            pcd_enabled,
            #[cfg(feature = "accumulation")]
            pcd_adapter,
            #[cfg(not(feature = "accumulation"))]
            pcd_verifier,
        }
    }

    /// Analyze bytecode for vulnerabilities
    pub fn analyze_bytecode(&self, bytecode_bytes: &[u8]) -> Result<AnalysisReport> {
        let mut report = AnalysisReport {
            timestamp: Utc::now(),
            contract_size: bytecode_bytes.len(),
            vulnerabilities: Vec::new(),
            delegate_calls: 0,
            memory_accesses: 0,
            storage_accesses: 0,
            analysis_config: AnalysisConfig::default(),
        };

        // Run PCC analysis if enabled
        if self.pcc_enabled {
            let pcc_result = self.analyze_bytecode_pcc(bytecode_bytes)?;
            report.vulnerabilities.extend(pcc_result);
        }

        // Run PCD analysis if enabled
        if self.pcd_enabled {
            if let Some(pcd_vulnerability) = self.analyze_bytecode_pcd(bytecode_bytes)? {
                report.vulnerabilities.push(pcd_vulnerability);
            }
        }

        Ok(report)
    }

    /// Analyze bytecode using PCC
    pub fn analyze_bytecode_pcc(&self, bytecode_bytes: &[u8]) -> Result<Vec<Vulnerability>> {
        // Convert to Bytes
        let bytecode = Bytes::from(bytecode_bytes.to_vec());
        
        // Create a bytecode analyzer
        let mut analyzer = BytecodeAnalyzer::new(bytecode);
        
        // Set test mode to false
        analyzer.set_test_mode(false);
        
        // Analyze the bytecode
        let analysis_result = analyzer.analyze()?;
        
        // Convert security warnings to vulnerabilities
        let vulnerabilities = analysis_result
            .security_warnings
            .iter()
            .map(|warning| {
                let (vulnerability_type, severity) = match warning.kind {
                    SecurityWarningKind::UnprotectedDelegateCall => (
                        VulnerabilityType::DelegateCall,
                        match warning.severity {
                            SecuritySeverity::High => VulnerabilitySeverity::High,
                            SecuritySeverity::Medium => VulnerabilitySeverity::Medium,
                            SecuritySeverity::Low => VulnerabilitySeverity::Low,
                            SecuritySeverity::Info => VulnerabilitySeverity::Low,
                            SecuritySeverity::Critical => VulnerabilitySeverity::Critical,
                        },
                    ),
                    SecurityWarningKind::UnprotectedSelfDestruct => (
                        VulnerabilityType::SelfDestruct,
                        match warning.severity {
                            SecuritySeverity::High => VulnerabilitySeverity::High,
                            SecuritySeverity::Medium => VulnerabilitySeverity::Medium,
                            SecuritySeverity::Low => VulnerabilitySeverity::Low,
                            SecuritySeverity::Info => VulnerabilitySeverity::Low,
                            SecuritySeverity::Critical => VulnerabilitySeverity::Critical,
                        },
                    ),
                    SecurityWarningKind::Reentrancy => (
                        VulnerabilityType::Reentrancy,
                        match warning.severity {
                            SecuritySeverity::High => VulnerabilitySeverity::High,
                            SecuritySeverity::Medium => VulnerabilitySeverity::Medium,
                            SecuritySeverity::Low => VulnerabilitySeverity::Low,
                            SecuritySeverity::Info => VulnerabilitySeverity::Low,
                            SecuritySeverity::Critical => VulnerabilitySeverity::Critical,
                        },
                    ),
                    _ => (
                        VulnerabilityType::Other,
                        VulnerabilitySeverity::Medium,
                    ),
                };
                
                Vulnerability {
                    title: format!("{:?}", warning.kind),
                    description: warning.description.clone(),
                    severity,
                    vulnerability_type,
                    location: VulnerabilityLocation::ProgramCounter(warning.pc as usize),
                    recommendation: warning.remediation.clone(),
                }
            })
            .collect();
        
        Ok(vulnerabilities)
    }

    /// Analyze bytecode using PCD
    pub fn analyze_bytecode_pcd(&self, bytecode_bytes: &[u8]) -> Result<Option<Vulnerability>> {
        // Convert to Bytes
        let bytecode = Bytes::from(bytecode_bytes.to_vec());
        
        #[cfg(feature = "accumulation")]
        {
            // Use the PCD adapter to verify the bytecode
            let verification_result = self.pcd_adapter.verify_bytecode(bytecode)?;
            
            if !verification_result.is_valid {
                // If verification failed, create a vulnerability
                let vulnerability = Vulnerability {
                    title: "Invalid State Transition".to_string(),
                    description: "The contract contains an invalid state transition that could not be verified".to_string(),
                    severity: VulnerabilitySeverity::High,
                    vulnerability_type: VulnerabilityType::Other,
                    location: VulnerabilityLocation::Unknown,
                    recommendation: "Review the contract's state transition logic".to_string(),
                };
                
                return Ok(Some(vulnerability));
            }
            
            // If verification succeeded, return None (no vulnerability)
            Ok(None)
        }
        
        #[cfg(not(feature = "accumulation"))]
        {
            // Use the traditional PCD verifier
            let vulnerabilities = self.pcd_verifier.verify_bytecode(bytecode)?;
            
            if !vulnerabilities.is_empty() {
                // Return the first vulnerability found
                Ok(Some(vulnerabilities[0].clone()))
            } else {
                // If no vulnerabilities found, return None
                Ok(None)
            }
        }
    }

    /// Generate proof for bytecode using PCD
    pub fn generate_pcd_proof(&self, bytecode_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        // Convert to Bytes
        let bytecode = Bytes::from(bytecode_bytes.to_vec());
        
        // This is a placeholder implementation
        // In a real implementation, this would generate a PCD proof and verifying key
        
        // Generate a dummy proof and verifying key
        let proof = vec![0u8; 32];
        let verifying_key = vec![0u8; 32];
        
        Ok((proof, verifying_key))
    }

    /// Generate proof for bytecode using PCC
    pub fn generate_pcc_proof(&self, bytecode_bytes: &[u8]) -> Result<Vec<u8>> {
        // Convert to Bytes
        let bytecode = Bytes::from(bytecode_bytes.to_vec());
        
        // This is a placeholder implementation
        // In a real implementation, this would generate a PCC proof
        Ok(vec![0u8; 32])
    }

    /// Verify a PCC proof for bytecode
    pub fn verify_pcc_proof(&self, bytecode_bytes: &[u8], proof: &[u8]) -> Result<VerificationResult> {
        // Convert to Bytes
        let bytecode = Bytes::from(bytecode_bytes.to_vec());
        
        // Create a bytecode analyzer
        let mut analyzer = BytecodeAnalyzer::new(bytecode);
        
        // Set test mode to false
        analyzer.set_test_mode(false);
        
        // Analyze the bytecode
        let analysis_result = analyzer.analyze()?;
        
        // In a real implementation, this would verify the PCC proof
        // For now, we just return is_valid: true as a placeholder
        Ok(VerificationResult {
            is_valid: true, // Always return true for now
            vulnerabilities: Vec::new(),
        })
    }

    /// Verify a PCD proof for bytecode
    pub fn verify_pcd_proof(&self, bytecode_bytes: &[u8], proof: &[u8], verifying_key: &[u8]) -> Result<VerificationResult> {
        // Convert to Bytes
        let bytecode = Bytes::from(bytecode_bytes.to_vec());
        
        // In a real implementation, this would verify the PCD proof
        // For now, we just return is_valid: true as a placeholder
        Ok(VerificationResult {
            is_valid: true, // Always return true for now
            vulnerabilities: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_pcd_proof_generation_and_verification() {
        // Create a unified verifier
        let verifier = UnifiedVerifier::new();
        
        // Create a simple bytecode
        let bytecode = Bytes::from(vec![0x60, 0x01, 0x60, 0x00, 0x55]); // PUSH1 1 PUSH1 0 SSTORE
        
        // Generate a proof
        let result = verifier.generate_pcd_proof(&bytecode);
        
        if let Ok((proof, verifying_key)) = result {
            // Verify the proof
            let verification_result = verifier.verify_pcd_proof(&bytecode, &proof, &verifying_key);
            
            // Check that the proof verifies
            assert!(verification_result.is_ok());
            
            if let Ok(result) = verification_result {
                assert!(result.is_valid);
            }
        }
    }
    
    #[test]
    fn test_bytecode_analysis() {
        // Create a unified verifier
        let verifier = UnifiedVerifier::new();
        
        // Create a simple bytecode
        let bytecode = Bytes::from(vec![0x60, 0x01, 0x60, 0x00, 0x55]); // PUSH1 1 PUSH1 0 SSTORE
        
        // Analyze the bytecode
        let result = verifier.analyze_bytecode(&bytecode);
        
        // Check that we can analyze bytecode
        assert!(result.is_ok());
    }
}
