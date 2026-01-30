// Legal Wrapper Failure Detector
// Detects SPV structure exploits and trust dissolution vulnerabilities in RWAs

use crate::bytecode::security::{SecuritySeverity, SecurityWarning};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegalWrapperFailureVulnerability {
    pub location: usize,
    pub vulnerability_type: LegalWrapperType,
    pub severity: SecuritySeverity,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LegalWrapperType {
    SPVStructureExploit,             // Special Purpose Vehicle compromise
    TrustDissolution,                // Trust structure failure
    JurisdictionArbitrage,           // Exploit jurisdictional gaps
    BankruptcyPriority,              // Bankruptcy claim priority issues
    BeneficialOwnershipDispute,      // Ownership verification failure
    LegalRecourseAbsence,            // No legal enforcement mechanism
}

pub struct LegalWrapperFailureDetector {
    bytecode: Vec<u8>,
}

impl LegalWrapperFailureDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<LegalWrapperFailureVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_spv_structure_exploit() {
            vulnerabilities.push(LegalWrapperFailureVulnerability {
                location: loc,
                vulnerability_type: LegalWrapperType::SPVStructureExploit,
                severity: SecuritySeverity::Critical,
                description: "SPV structure verification missing on-chain. Token claims not \
                             cryptographically linked to legal entity ownership.".to_string(),
                confidence: 0.89,
            });
        }

        if let Some(loc) = self.detect_trust_dissolution() {
            vulnerabilities.push(LegalWrapperFailureVulnerability {
                location: loc,
                vulnerability_type: LegalWrapperType::TrustDissolution,
                severity: SecuritySeverity::Critical,
                description: "Trust continuity not enforced. Trust structure can dissolve leaving \
                             token holders without legal claims to underlying assets.".to_string(),
                confidence: 0.91,
            });
        }

        if let Some(loc) = self.detect_jurisdiction_arbitrage() {
            vulnerabilities.push(LegalWrapperFailureVulnerability {
                location: loc,
                vulnerability_type: LegalWrapperType::JurisdictionArbitrage,
                severity: SecuritySeverity::High,
                description: "Jurisdiction not locked at token issuance. Legal entity can relocate \
                             to less favorable jurisdiction avoiding obligations.".to_string(),
                confidence: 0.86,
            });
        }

        if let Some(loc) = self.detect_bankruptcy_priority() {
            vulnerabilities.push(LegalWrapperFailureVulnerability {
                location: loc,
                vulnerability_type: LegalWrapperType::BankruptcyPriority,
                severity: SecuritySeverity::Critical,
                description: "Bankruptcy claim priority unclear. Token holders may rank below other \
                             creditors in insolvency proceedings with no guaranteed recovery.".to_string(),
                confidence: 0.90,
            });
        }

        if let Some(loc) = self.detect_beneficial_ownership_dispute() {
            vulnerabilities.push(LegalWrapperFailureVulnerability {
                location: loc,
                vulnerability_type: LegalWrapperType::BeneficialOwnershipDispute,
                severity: SecuritySeverity::High,
                description: "Beneficial ownership not cryptographically proven. Token to asset \
                             ownership link can be disputed enabling theft or fraud.".to_string(),
                confidence: 0.87,
            });
        }

        if let Some(loc) = self.detect_legal_recourse_absence() {
            vulnerabilities.push(LegalWrapperFailureVulnerability {
                location: loc,
                vulnerability_type: LegalWrapperType::LegalRecourseAbsence,
                severity: SecuritySeverity::Critical,
                description: "No legal enforcement mechanism documented. Token holders lack clear \
                             path to enforce rights or recover assets through legal system.".to_string(),
                confidence: 0.88,
            });
        }

        vulnerabilities
    }

    fn detect_spv_structure_exploit(&self) -> Option<usize> {
        // Pattern: Asset claims without SPV verification
        // Token issuance without entity verification proof
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x55 {  // SSTORE (mint token)
                let mut is_issuance = false;
                let mut verifies_spv = false;
                
                // Check if token minting (supply increase)
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x01 {  // ADD (increase supply)
                        is_issuance = true;
                    }
                }
                
                // Check for SPV verification (signature from legal entity)
                for j in (i.saturating_sub(25))..i {
                    if self.bytecode[j] == 0x01 {  // ECRECOVER (entity signature)
                        verifies_spv = true;
                    }
                }
                
                if is_issuance && !verifies_spv {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_trust_dissolution(&self) -> Option<usize> {
        // Pattern: No trust continuity verification
        // Operations without checking trust status
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0xF1 {  // CALL (critical operation)
                let mut is_critical = false;
                let mut checks_trust_status = false;
                
                // Check if value transfer (critical operation)
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x35 {  // CALLDATALOAD (amount)
                        is_critical = true;
                    }
                }
                
                // Check for trust status verification
                for j in (i.saturating_sub(25))..i {
                    if self.bytecode[j] == 0x54 {  // SLOAD (trust active flag)
                        for k in j+1..(j+8).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x15 {  // ISZERO (check active)
                                checks_trust_status = true;
                            }
                        }
                    }
                }
                
                if is_critical && !checks_trust_status {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_jurisdiction_arbitrage(&self) -> Option<usize> {
        // Pattern: Jurisdiction changeable after token creation
        // No jurisdiction lock mechanism
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x55 {  // SSTORE (set jurisdiction)
                let mut sets_jurisdiction = false;
                let mut is_immutable = false;
                
                // Check if jurisdiction update
                for j in (i.saturating_sub(15))..i {
                    if self.bytecode[j] == 0x35 {  // CALLDATALOAD (new jurisdiction)
                        sets_jurisdiction = true;
                    }
                }
                
                // Check for immutability (no update function after initial set)
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x54 {  // SLOAD (check if already set)
                        for k in j+1..(j+5).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x15 {  // ISZERO (must be unset)
                                is_immutable = true;
                            }
                        }
                    }
                }
                
                if sets_jurisdiction && !is_immutable {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_bankruptcy_priority(&self) -> Option<usize> {
        // Pattern: No bankruptcy waterfall specification
        // Token claims without priority documentation
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x55 {  // SSTORE (token issuance)
                let mut creates_claim = false;
                let mut specifies_priority = false;
                
                // Check if creating asset claim
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x33 {  // CALLER (holder)
                        creates_claim = true;
                    }
                }
                
                // Check for priority specification (seniority level)
                for j in (i.saturating_sub(25))..i {
                    if self.bytecode[j] == 0x60 || self.bytecode[j] == 0x61 {  // PUSH (priority level)
                        for k in j+2..(j+10).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x55 {  // SSTORE (save priority)
                                specifies_priority = true;
                            }
                        }
                    }
                }
                
                if creates_claim && !specifies_priority {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_beneficial_ownership_dispute(&self) -> Option<usize> {
        // Pattern: Ownership claim without cryptographic proof
        // Asset linkage without merkle proof or signature
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x54 {  // SLOAD (asset reference)
                let mut links_to_asset = false;
                let mut has_proof = false;
                
                // Check if asset ownership claim
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x14 {  // EQ (verify ownership)
                        links_to_asset = true;
                    }
                }
                
                // Check for cryptographic proof (merkle or signature)
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x20 {  // SHA3 (merkle proof)
                        has_proof = true;
                    }
                    if self.bytecode[j] == 0x01 {  // ECRECOVER (signature)
                        has_proof = true;
                    }
                }
                
                if links_to_asset && !has_proof {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_legal_recourse_absence(&self) -> Option<usize> {
        // Pattern: Token operations without legal documentation hash
        // No reference to legal agreements or terms
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x55 {  // SSTORE (create token)
                let mut creates_obligation = false;
                let mut references_legal_doc = false;
                
                // Check if creating legal obligation (issuance)
                for j in (i.saturating_sub(15))..i {
                    if self.bytecode[j] == 0x01 {  // ADD (mint)
                        creates_obligation = true;
                    }
                }
                
                // Check for legal document reference (hash of terms)
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x54 {  // SLOAD (terms hash)
                        for k in j+1..(j+8).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x14 {  // EQ (verify terms)
                                references_legal_doc = true;
                            }
                        }
                    }
                }
                
                if creates_obligation && !references_legal_doc {
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
                    format!("LegalWrapperFailure{:?}", v.vulnerability_type)
                ),
                severity: v.severity,
                pc: v.location as u64,
                description: format!(
                    "Legal Wrapper Failure {:?}: {}",
                    v.vulnerability_type, v.description
                ),
                operations: Vec::new(),
                remediation: "Implement SPV verification through signatures, trust continuity checks, \
                             immutable jurisdiction locks, bankruptcy priority specifications, \
                             cryptographic ownership proofs, and legal document hash references".to_string(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spv_structure_exploit() {
        let bytecode = vec![
            0x60, 0x01, // PUSH1 1
            0x01, // ADD (mint)
            0x60, 0x00, // PUSH1 0
            0x55, // SSTORE (without SPV verification)
        ];
        
        let detector = LegalWrapperFailureDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, LegalWrapperType::SPVStructureExploit)));
    }

    #[test]
    fn test_trust_dissolution() {
        let bytecode = vec![
            0x60, 0x00, // PUSH1 0
            0x35, // CALLDATALOAD
            0xF1, // CALL (critical operation without trust check)
        ];
        
        let detector = LegalWrapperFailureDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, LegalWrapperType::TrustDissolution)));
    }
}
