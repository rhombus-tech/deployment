// Compliance Token Transfer Restriction Detector
// Detects whitelist bypass and KYC verification bypass vulnerabilities

use crate::bytecode::security::{SecuritySeverity, SecurityWarning};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceTokenTransferVulnerability {
    pub location: usize,
    pub vulnerability_type: ComplianceRestrictionType,
    pub severity: SecuritySeverity,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComplianceRestrictionType {
    WhitelistBypass,                 // Bypass whitelist restrictions
    JurisdictionRestrictionBypass,   // Bypass geographical restrictions
    AccreditationCheckSkip,          // Skip accreditation verification
    TransferLimitExceeded,           // Exceed transfer amount limits
    LockupPeriodBypass,              // Transfer during lockup period
    KYCVerificationBypass,           // Bypass KYC/AML checks
}

pub struct ComplianceTokenTransferDetector {
    bytecode: Vec<u8>,
}

impl ComplianceTokenTransferDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<ComplianceTokenTransferVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_whitelist_bypass() {
            vulnerabilities.push(ComplianceTokenTransferVulnerability {
                location: loc,
                vulnerability_type: ComplianceRestrictionType::WhitelistBypass,
                severity: SecuritySeverity::Critical,
                description: "Whitelist check bypassable through alternative transfer path. \
                             Non-whitelisted addresses can receive tokens bypassing compliance.".to_string(),
                confidence: 0.92,
            });
        }

        if let Some(loc) = self.detect_jurisdiction_restriction_bypass() {
            vulnerabilities.push(ComplianceTokenTransferVulnerability {
                location: loc,
                vulnerability_type: ComplianceRestrictionType::JurisdictionRestrictionBypass,
                severity: SecuritySeverity::Critical,
                description: "Jurisdiction restrictions not enforced on all transfer methods. \
                             Restricted jurisdictions can access tokens through bypass routes.".to_string(),
                confidence: 0.90,
            });
        }

        if let Some(loc) = self.detect_accreditation_check_skip() {
            vulnerabilities.push(ComplianceTokenTransferVulnerability {
                location: loc,
                vulnerability_type: ComplianceRestrictionType::AccreditationCheckSkip,
                severity: SecuritySeverity::Critical,
                description: "Accreditation verification skippable. Non-accredited investors can \
                             acquire security tokens violating regulatory requirements.".to_string(),
                confidence: 0.91,
            });
        }

        if let Some(loc) = self.detect_transfer_limit_exceeded() {
            vulnerabilities.push(ComplianceTokenTransferVulnerability {
                location: loc,
                vulnerability_type: ComplianceRestrictionType::TransferLimitExceeded,
                severity: SecuritySeverity::High,
                description: "Transfer amount limits not enforced. Exceeds regulatory maximum \
                             transfer amounts per period or per transaction.".to_string(),
                confidence: 0.87,
            });
        }

        if let Some(loc) = self.detect_lockup_period_bypass() {
            vulnerabilities.push(ComplianceTokenTransferVulnerability {
                location: loc,
                vulnerability_type: ComplianceRestrictionType::LockupPeriodBypass,
                severity: SecuritySeverity::High,
                description: "Lockup period bypassable through proxy or alternative transfer. \
                             Tokens transferable during restricted period violating terms.".to_string(),
                confidence: 0.89,
            });
        }

        if let Some(loc) = self.detect_kyc_verification_bypass() {
            vulnerabilities.push(ComplianceTokenTransferVulnerability {
                location: loc,
                vulnerability_type: ComplianceRestrictionType::KYCVerificationBypass,
                severity: SecuritySeverity::Critical,
                description: "KYC verification not enforced on token receipt. Unverified addresses \
                             can hold tokens violating AML/KYC requirements.".to_string(),
                confidence: 0.93,
            });
        }

        vulnerabilities
    }

    fn detect_whitelist_bypass(&self) -> Option<usize> {
        // Pattern: Transfer without whitelist check on recipient
        // Balance update without verifying recipient whitelist status
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x55 {  // SSTORE (update balance)
                let mut is_transfer = false;
                let mut checks_whitelist = false;
                
                // Check if transfer (recipient balance increase)
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x01 {  // ADD (increase balance)
                        is_transfer = true;
                    }
                }
                
                // Check for whitelist verification
                for j in (i.saturating_sub(25))..i {
                    if self.bytecode[j] == 0x54 {  // SLOAD (whitelist status)
                        for k in j+1..(j+8).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x15 {  // ISZERO (check whitelisted)
                                checks_whitelist = true;
                            }
                        }
                    }
                }
                
                if is_transfer && !checks_whitelist {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_jurisdiction_restriction_bypass(&self) -> Option<usize> {
        // Pattern: Transfer without jurisdiction verification
        // No geographical restriction check on recipient
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x55 {  // SSTORE (transfer)
                let mut is_recipient_update = false;
                let mut checks_jurisdiction = false;
                
                // Check if recipient balance update
                for j in (i.saturating_sub(15))..i {
                    if self.bytecode[j] == 0x35 {  // CALLDATALOAD (recipient address)
                        is_recipient_update = true;
                    }
                }
                
                // Check for jurisdiction verification (oracle or registry call)
                for j in (i.saturating_sub(25))..i {
                    if self.bytecode[j] == 0xFA {  // STATICCALL (jurisdiction registry)
                        checks_jurisdiction = true;
                    }
                    if self.bytecode[j] == 0x54 {  // SLOAD (jurisdiction flag)
                        for k in j+1..(j+5).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x14 {  // EQ (verify allowed)
                                checks_jurisdiction = true;
                            }
                        }
                    }
                }
                
                if is_recipient_update && !checks_jurisdiction {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_accreditation_check_skip(&self) -> Option<usize> {
        // Pattern: Token acquisition without accreditation verification
        // Purchase or receive without investor status check
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x55 {  // SSTORE (acquire tokens)
                let mut is_acquisition = false;
                let mut verifies_accreditation = false;
                
                // Check if token acquisition (balance increase)
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x01 {  // ADD
                        is_acquisition = true;
                    }
                }
                
                // Check for accreditation verification
                for j in (i.saturating_sub(25))..i {
                    if self.bytecode[j] == 0x54 {  // SLOAD (accreditation status)
                        for k in j+1..(j+10).min(self.bytecode.len()) {
                            // Accreditation level check
                            if self.bytecode[k] == 0x10 || self.bytecode[k] == 0x11 {  // LT/GT
                                verifies_accreditation = true;
                            }
                        }
                    }
                }
                
                if is_acquisition && !verifies_accreditation {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_transfer_limit_exceeded(&self) -> Option<usize> {
        // Pattern: Transfer amount without limit enforcement
        // No maximum amount check per transaction or period
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x35 {  // CALLDATALOAD (transfer amount)
                let mut used_in_transfer = false;
                let mut checks_limit = false;
                
                // Check if amount used in transfer
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x55 {  // SSTORE (execute transfer)
                        used_in_transfer = true;
                    }
                }
                
                // Check for limit enforcement
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x10 {  // LT (amount < limit)
                        checks_limit = true;
                    }
                    
                    // Period-based limit (accumulator check)
                    if self.bytecode[j] == 0x54 {  // SLOAD (period total)
                        for k in j+1..(j+8).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x01 {  // ADD (accumulate)
                                for m in k+1..(k+5).min(self.bytecode.len()) {
                                    if self.bytecode[m] == 0x10 {  // LT (under period max)
                                        checks_limit = true;
                                    }
                                }
                            }
                        }
                    }
                }
                
                if used_in_transfer && !checks_limit {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_lockup_period_bypass(&self) -> Option<usize> {
        // Pattern: Transfer without lockup period verification
        // Token movement allowed during restricted period
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x55 {  // SSTORE (transfer)
                let mut is_transfer = false;
                let mut checks_lockup = false;
                
                // Check if transfer operation
                for j in (i.saturating_sub(15))..i {
                    if self.bytecode[j] == 0x03 {  // SUB (reduce sender balance)
                        is_transfer = true;
                    }
                }
                
                // Check for lockup period verification
                for j in (i.saturating_sub(25))..i {
                    if self.bytecode[j] == 0x42 {  // TIMESTAMP
                        for k in j+1..(j+15).min(self.bytecode.len()) {
                            // Compare against lockup end time
                            if self.bytecode[k] == 0x54 {  // SLOAD (lockup end)
                                for m in k+1..(k+5).min(self.bytecode.len()) {
                                    if self.bytecode[m] == 0x10 {  // LT (past lockup)
                                        checks_lockup = true;
                                    }
                                }
                            }
                        }
                    }
                }
                
                if is_transfer && !checks_lockup {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_kyc_verification_bypass(&self) -> Option<usize> {
        // Pattern: Recipient receives tokens without KYC check
        // Balance increase without identity verification
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x55 {  // SSTORE (update recipient balance)
                let mut is_receipt = false;
                let mut verifies_kyc = false;
                
                // Check if receiving tokens (balance increase)
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x01 {  // ADD (increase)
                        is_receipt = true;
                    }
                }
                
                // Check for KYC verification
                for j in (i.saturating_sub(25))..i {
                    if self.bytecode[j] == 0x54 {  // SLOAD (KYC status)
                        for k in j+1..(j+8).min(self.bytecode.len()) {
                            // KYC verified flag check
                            if self.bytecode[k] == 0x14 {  // EQ (verified)
                                verifies_kyc = true;
                            }
                        }
                    }
                    
                    // External KYC provider verification
                    if self.bytecode[j] == 0xFA {  // STATICCALL (KYC provider)
                        verifies_kyc = true;
                    }
                }
                
                if is_receipt && !verifies_kyc {
                    return Some(i);
                }
            }
        }
        None
    }

    pub fn to_security_warnings(&self) -> Vec<SecurityWarning> {
        self.detect()
            .into_iter()
            .map(|v| SecurityWarning {
                kind: crate::bytecode::security::SecurityWarningKind::Other(
                    format!("ComplianceTokenTransfer{:?}", v.vulnerability_type)
                ),
                severity: v.severity,
                pc: v.location as u64,
                description: format!(
                    "Compliance Token Transfer {:?}: {}",
                    v.vulnerability_type, v.description
                ),
                operations: Vec::new(),
                remediation: "Implement whitelist verification on all transfer paths, jurisdiction \
                             checks, accreditation verification, transfer amount limits with period \
                             tracking, lockup period enforcement, and KYC/AML verification".to_string(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_whitelist_bypass() {
        let bytecode = vec![
            0x60, 0x0A, // PUSH1 10
            0x01, // ADD (increase balance)
            0x60, 0x00, // PUSH1 0
            0x55, // SSTORE (without whitelist check)
        ];
        
        let detector = ComplianceTokenTransferDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, ComplianceRestrictionType::WhitelistBypass)));
    }

    #[test]
    fn test_kyc_verification_bypass() {
        let bytecode = vec![
            0x60, 0x64, // PUSH1 100
            0x01, // ADD (receive tokens)
            0x60, 0x00, // PUSH1 0
            0x55, // SSTORE (without KYC verification)
        ];
        
        let detector = ComplianceTokenTransferDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, ComplianceRestrictionType::KYCVerificationBypass)));
    }
}
