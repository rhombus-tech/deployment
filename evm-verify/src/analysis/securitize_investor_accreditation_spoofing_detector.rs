// Securitize Investor Accreditation Spoofing Detector
// Detects spoofing of investor accreditation status in digital securities

use crate::bytecode::security::{SecuritySeverity, SecurityWarning, SecurityWarningKind};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritizeVulnerability {
    pub location: usize,
    pub vulnerability_type: SecuritizeVulnerabilityType,
    pub severity: SecuritySeverity,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecuritizeVulnerabilityType {
    AccreditationSpoofing,          // Spoof accreditation credentials
    IdentityVerificationBypass,     // Bypass identity verification
    InvestorRegistryManipulation,   // Manipulate investor registry
    ComplianceOracleBypass,         // Bypass compliance oracle checks
    CrossBorderRestrictionBypass,   // Bypass cross-border restrictions
    AccreditationExpiryIgnored,     // Expired accreditation accepted
}

pub struct SecuritizeDetector {
    bytecode: Vec<u8>,
}

impl SecuritizeDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecuritizeVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_accreditation_spoofing() {
            vulnerabilities.push(SecuritizeVulnerability {
                location: loc,
                vulnerability_type: SecuritizeVulnerabilityType::AccreditationSpoofing,
                severity: SecuritySeverity::Critical,
                description: "Accreditation verification uses self-reported data without cryptographic \
                             proof. Investor can claim accredited status without validation.".to_string(),
                confidence: 0.90,
            });
        }

        if let Some(loc) = self.detect_identity_bypass() {
            vulnerabilities.push(SecuritizeVulnerability {
                location: loc,
                vulnerability_type: SecuritizeVulnerabilityType::IdentityVerificationBypass,
                severity: SecuritySeverity::Critical,
                description: "Identity verification signature not validated. Attacker can forge identity \
                             documents to pass KYC/AML checks.".to_string(),
                confidence: 0.88,
            });
        }

        if let Some(loc) = self.detect_registry_manipulation() {
            vulnerabilities.push(SecuritizeVulnerability {
                location: loc,
                vulnerability_type: SecuritizeVulnerabilityType::InvestorRegistryManipulation,
                severity: SecuritySeverity::High,
                description: "Investor registry update lacks access control. Unauthorized parties can \
                             modify registry entries to gain investment privileges.".to_string(),
                confidence: 0.85,
            });
        }

        if let Some(loc) = self.detect_oracle_bypass() {
            vulnerabilities.push(SecuritizeVulnerability {
                location: loc,
                vulnerability_type: SecuritizeVulnerabilityType::ComplianceOracleBypass,
                severity: SecuritySeverity::Critical,
                description: "Compliance oracle result not enforced. Transaction proceeds even when \
                             oracle indicates non-compliance.".to_string(),
                confidence: 0.89,
            });
        }

        if let Some(loc) = self.detect_crossborder_bypass() {
            vulnerabilities.push(SecuritizeVulnerability {
                location: loc,
                vulnerability_type: SecuritizeVulnerabilityType::CrossBorderRestrictionBypass,
                severity: SecuritySeverity::High,
                description: "Cross-border transfer restrictions not enforced on all transfer paths. \
                             Restricted jurisdictions can receive tokens via delegatecall.".to_string(),
                confidence: 0.83,
            });
        }

        if let Some(loc) = self.detect_expiry_ignored() {
            vulnerabilities.push(SecuritizeVulnerability {
                location: loc,
                vulnerability_type: SecuritizeVulnerabilityType::AccreditationExpiryIgnored,
                severity: SecuritySeverity::High,
                description: "Accreditation expiry timestamp not validated. Expired accreditation \
                             credentials still grant investment access.".to_string(),
                confidence: 0.86,
            });
        }

        vulnerabilities
    }

    fn detect_accreditation_spoofing(&self) -> Option<usize> {
        // Pattern: Accreditation check without cryptographic proof
        // CALLDATALOAD (accreditation claim) → use without signature verification
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x35 {  // CALLDATALOAD (accreditation data)
                let mut verifies_signature = false;
                
                // Check for signature verification (ECRECOVER)
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0xF1 || self.bytecode[j] == 0xFA {  // CALL (ecrecover)
                        verifies_signature = true;
                    }
                }
                
                // Accreditation stored without proof
                if !verifies_signature {
                    for j in i+1..(i+20).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x55 {  // SSTORE (accept claim)
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn detect_identity_bypass(&self) -> Option<usize> {
        // Pattern: Signature verification incomplete
        // ECRECOVER without checking signer against authorized list
        
        for i in 0..self.bytecode.len().saturating_sub(35) {
            if self.bytecode[i] == 0xF1 || self.bytecode[i] == 0xFA {  // CALL (ecrecover)
                let mut validates_signer = false;
                let mut checks_zero = false;
                
                for j in i+1..(i+30).min(self.bytecode.len()) {
                    // Check signer against authorized list
                    if self.bytecode[j] == 0x54 {  // SLOAD (check authorized)
                        for k in j+1..(j+5).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x14 {  // EQ
                                validates_signer = true;
                            }
                        }
                    }
                    
                    // Check for zero address (failed recovery)
                    if self.bytecode[j] == 0x15 {  // ISZERO
                        checks_zero = true;
                    }
                }
                
                if !validates_signer || !checks_zero {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_registry_manipulation(&self) -> Option<usize> {
        // Pattern: Registry update without access control
        // SSTORE (investor data) without CALLER check
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x55 {  // SSTORE (update registry)
                let mut has_access_control = false;
                
                // Check for access control
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x33 {  // CALLER
                        for k in j+1..(j+8).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x14 {  // EQ (check authorized)
                                has_access_control = true;
                            }
                        }
                    }
                }
                
                // Check if this looks like registry update (multiple SSTOREs)
                let mut sstore_count = 1;
                for j in i+1..(i+15).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x55 {
                        sstore_count += 1;
                    }
                }
                
                if sstore_count >= 2 && !has_access_control {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_oracle_bypass(&self) -> Option<usize> {
        // Pattern: Oracle result not enforced
        // STATICCALL (compliance check) → result ignored
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0xFA {  // STATICCALL (compliance oracle)
                let mut enforces_result = false;
                
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    // Enforcement: ISZERO → REVERT on failure
                    if self.bytecode[j] == 0x15 {  // ISZERO
                        for k in j+1..(j+3).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0xFD {  // REVERT
                                enforces_result = true;
                            }
                        }
                    }
                    
                    // Result popped (ignored)
                    if self.bytecode[j] == 0x50 && !enforces_result {  // POP
                        return Some(i);
                    }
                }
                
                if !enforces_result {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_crossborder_bypass(&self) -> Option<usize> {
        // Pattern: Jurisdiction check only on direct calls
        // DELEGATECALL path doesn't check jurisdiction
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0xF4 {  // DELEGATECALL
                let mut checks_jurisdiction = false;
                
                // Check for jurisdiction validation
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x54 {  // SLOAD (jurisdiction)
                        checks_jurisdiction = true;
                    }
                }
                
                // Check if transfer-related (token operations nearby)
                let mut is_transfer = false;
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x55 {  // SSTORE (balance update)
                        is_transfer = true;
                    }
                }
                
                if is_transfer && !checks_jurisdiction {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_expiry_ignored(&self) -> Option<usize> {
        // Pattern: Accreditation used without expiry check
        // SLOAD (accreditation) without TIMESTAMP comparison
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x54 {  // SLOAD (accreditation)
                let mut checks_expiry = false;
                
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    // Expiry check: TIMESTAMP → LT
                    if self.bytecode[j] == 0x42 {  // TIMESTAMP
                        for k in j+1..(j+5).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x10 {  // LT (not expired)
                                checks_expiry = true;
                            }
                        }
                    }
                }
                
                // Check if used for investment decision
                let mut is_accreditation_check = false;
                for j in i+1..(i+15).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x57 {  // JUMPI (gate on accreditation)
                        is_accreditation_check = true;
                    }
                }
                
                if is_accreditation_check && !checks_expiry {
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
                kind: SecurityWarningKind::Securitize,
                severity: v.severity,
                description: format!(
                    "Securitize {:?} at PC {}: {}",
                    v.vulnerability_type, v.location, v.description
                ),
                pc: v.location as u64,
                operations: Vec::new(),
                remediation: "Review protocol-specific security measures".to_string(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_accreditation_spoofing() {
        let bytecode = vec![
            0x35, // CALLDATALOAD (accreditation claim)
            0x60, 0x00, // PUSH1 0
            0x55, // SSTORE (accept without signature)
        ];
        
        let detector = SecuritizeDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, SecuritizeVulnerabilityType::AccreditationSpoofing)));
    }

    #[test]
    fn test_oracle_bypass() {
        let bytecode = vec![
            0xFA, // STATICCALL (compliance check)
            0x50, // POP (ignore result)
        ];
        
        let detector = SecuritizeDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, SecuritizeVulnerabilityType::ComplianceOracleBypass)));
    }
}
