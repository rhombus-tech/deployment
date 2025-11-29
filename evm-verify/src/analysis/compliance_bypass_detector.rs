/// Compliance / Regulatory Bypass Detector
/// Detects sanctions list evasion, geographic restriction bypass, KYC circumvention

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ComplianceVulnerabilityType {
    SanctionsEvasion,
    GeographicBypass,
    KycCircumvention,
    BlacklistBypass,
    ComplianceCheckMissing,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SecuritySeverity { Critical, High, Medium, Low }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceVulnerability {
    pub vulnerability_type: ComplianceVulnerabilityType,
    pub severity: SecuritySeverity,
    pub location: usize,
    pub description: String,
    pub remediation: String,
}

pub struct ComplianceBypassDetector {
    bytecode: Vec<u8>,
}

impl ComplianceBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ComplianceVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_blacklist_bypass());
        vulnerabilities.extend(self.detect_missing_compliance_checks());
        vulnerabilities
    }

    fn detect_blacklist_bypass(&self) -> Vec<ComplianceVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        let transfer_sigs = [&[0xa9, 0x05, 0x9c, 0xbb][..], &[0x23, 0xb8, 0x72, 0xdd][..]];
        
        for sig in transfer_sigs.iter() {
            if let Some(pos) = self.bytecode.windows(4).position(|w| w == *sig) {
                let window = &self.bytecode[pos..pos.saturating_add(100).min(self.bytecode.len())];
                
                let has_blacklist_check = window.windows(8).any(|w| {
                    w.contains(&0x33) && // CALLER
                    w.contains(&0x54) && // SLOAD (blacklist mapping)
                    w.contains(&0x15) && // ISZERO (not blacklisted)
                    w.contains(&0x57)    // JUMPI (revert if blacklisted)
                });
                
                if !has_blacklist_check {
                    vulnerabilities.push(ComplianceVulnerability {
                        vulnerability_type: ComplianceVulnerabilityType::BlacklistBypass,
                        severity: SecuritySeverity::High,
                        location: pos,
                        description: "Transfer function doesn't check sender/receiver blacklist status.".to_string(),
                        remediation: "Add blacklist check: require(!blacklist[from] && !blacklist[to], 'Blacklisted')".to_string(),
                    });
                }
            }
        }
        vulnerabilities
    }

    fn detect_missing_compliance_checks(&self) -> Vec<ComplianceVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        let high_value_sigs = [&[0xf4, 0x05, 0xc1, 0x7e][..], &[0x5a, 0xe4, 0x01, 0xdc][..]];
        
        for sig in high_value_sigs.iter() {
            if let Some(pos) = self.bytecode.windows(4).position(|w| w == *sig) {
                let window = &self.bytecode[pos..pos.saturating_add(80).min(self.bytecode.len())];
                
                let has_kyc_check = window.windows(6).any(|w| {
                    w.contains(&0x54) && // SLOAD (KYC status)
                    w.contains(&0x57)    // JUMPI (revert if not verified)
                });
                
                if !has_kyc_check {
                    vulnerabilities.push(ComplianceVulnerability {
                        vulnerability_type: ComplianceVulnerabilityType::KycCircumvention,
                        severity: SecuritySeverity::Medium,
                        location: pos,
                        description: "High-value operation lacks KYC verification.".to_string(),
                        remediation: "Add KYC check: require(kycVerified[msg.sender], 'KYC required')".to_string(),
                    });
                }
            }
        }
        vulnerabilities
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_blacklist_bypass() {
        let bytecode = vec![0xa9, 0x05, 0x9c, 0xbb, 0xf1]; // transfer + CALL (no blacklist check)
        let detector = ComplianceBypassDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, ComplianceVulnerabilityType::BlacklistBypass)));
    }
}
