// Backed Fi Transfer Restriction Bypass Detector
// Detects bypasses in tokenized securities transfer restrictions

use crate::bytecode::security::{SecuritySeverity, SecurityWarning, SecurityWarningKind};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackedFiVulnerability {
    pub location: usize,
    pub vulnerability_type: BackedFiVulnerabilityType,
    pub severity: SecuritySeverity,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BackedFiVulnerabilityType {
    WhitelistBypass,                // Bypass transfer whitelist
    AccreditationCheckSkip,         // Skip accreditation verification
    JurisdictionRestrictionBypass,  // Bypass jurisdiction restrictions
    LockupPeriodBypass,             // Bypass lockup period enforcement
    TransferLimitExceeded,          // Exceed individual transfer limits
    KYCVerificationBypass,          // Bypass KYC verification
}

pub struct BackedFiDetector {
    bytecode: Vec<u8>,
}

impl BackedFiDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<BackedFiVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_whitelist_bypass() {
            vulnerabilities.push(BackedFiVulnerability {
                location: loc,
                vulnerability_type: BackedFiVulnerabilityType::WhitelistBypass,
                severity: SecuritySeverity::Critical,
                description: "Transfer whitelist check has logic error. Unwhitelisted addresses can \
                             receive tokens by exploiting check ordering.".to_string(),
                confidence: 0.89,
            });
        }

        if let Some(loc) = self.detect_accreditation_skip() {
            vulnerabilities.push(BackedFiVulnerability {
                location: loc,
                vulnerability_type: BackedFiVulnerabilityType::AccreditationCheckSkip,
                severity: SecuritySeverity::Critical,
                description: "Accreditation verification can be skipped. Non-accredited investors can \
                             acquire securities tokens bypassing regulatory requirements.".to_string(),
                confidence: 0.91,
            });
        }

        if let Some(loc) = self.detect_jurisdiction_bypass() {
            vulnerabilities.push(BackedFiVulnerability {
                location: loc,
                vulnerability_type: BackedFiVulnerabilityType::JurisdictionRestrictionBypass,
                severity: SecuritySeverity::High,
                description: "Jurisdiction restriction incomplete. Restricted jurisdictions can receive \
                             tokens through indirect transfer paths.".to_string(),
                confidence: 0.86,
            });
        }

        if let Some(loc) = self.detect_lockup_bypass() {
            vulnerabilities.push(BackedFiVulnerability {
                location: loc,
                vulnerability_type: BackedFiVulnerabilityType::LockupPeriodBypass,
                severity: SecuritySeverity::High,
                description: "Lockup period enforcement uses block.timestamp which can be manipulated. \
                             Validators can manipulate timestamp to enable premature transfers.".to_string(),
                confidence: 0.84,
            });
        }

        if let Some(loc) = self.detect_limit_exceeded() {
            vulnerabilities.push(BackedFiVulnerability {
                location: loc,
                vulnerability_type: BackedFiVulnerabilityType::TransferLimitExceeded,
                severity: SecuritySeverity::Medium,
                description: "Individual transfer limits not enforced cumulatively. Multiple small \
                             transfers can exceed intended limits.".to_string(),
                confidence: 0.78,
            });
        }

        if let Some(loc) = self.detect_kyc_bypass() {
            vulnerabilities.push(BackedFiVulnerability {
                location: loc,
                vulnerability_type: BackedFiVulnerabilityType::KYCVerificationBypass,
                severity: SecuritySeverity::Critical,
                description: "KYC verification result not properly validated. Expired or revoked KYC \
                             status still allows transfers.".to_string(),
                confidence: 0.87,
            });
        }

        vulnerabilities
    }

    fn detect_whitelist_bypass(&self) -> Option<usize> {
        // Pattern: Whitelist check with logic flaw
        // Check sender OR recipient instead of AND, or check happens after transfer
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x54 {  // SLOAD (whitelist)
                let mut checks_sender = false;
                let mut checks_recipient = false;
                let mut uses_or_logic = false;
                
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    // Check if both parties verified
                    if self.bytecode[j] == 0x54 {  // Second SLOAD (other party)
                        if checks_sender {
                            checks_recipient = true;
                        } else {
                            checks_sender = true;
                        }
                    }
                    
                    // OR logic (should be AND)
                    if self.bytecode[j] == 0x17 {  // OR
                        uses_or_logic = true;
                    }
                }
                
                // Flaw: OR instead of AND, or only one party checked
                if uses_or_logic || (checks_sender && !checks_recipient) {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_accreditation_skip(&self) -> Option<usize> {
        // Pattern: Transfer without accreditation check
        // CALL (transfer) without SLOAD (accreditation status)
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0xF1 {  // CALL (likely transfer)
                let mut checks_accreditation = false;
                
                // Check for accreditation verification before transfer
                for j in (i.saturating_sub(25))..i {
                    if self.bytecode[j] == 0x54 {  // SLOAD (accreditation)
                        checks_accreditation = true;
                    }
                }
                
                // Check if this is ERC20 transfer (function selector)
                let mut is_transfer = false;
                for j in (i.saturating_sub(15))..i {
                    if self.bytecode[j] == 0x63 {  // PUSH4 (selector)
                        is_transfer = true;
                    }
                }
                
                if is_transfer && !checks_accreditation {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_jurisdiction_bypass(&self) -> Option<usize> {
        // Pattern: Jurisdiction check only on direct transfers
        // No check on approve/transferFrom path
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Look for transferFrom without jurisdiction check
            if self.bytecode[i] == 0x23 {  // CALLDATALOAD (from address)
                let mut checks_jurisdiction = false;
                let mut is_transferfrom = false;
                
                // Check if transferFrom function
                for j in (i.saturating_sub(10))..i {
                    if self.bytecode[j] == 0x63 {  // PUSH4 (selector)
                        is_transferfrom = true;
                    }
                }
                
                // Check for jurisdiction validation
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x54 {  // SLOAD (jurisdiction)
                        checks_jurisdiction = true;
                    }
                }
                
                if is_transferfrom && !checks_jurisdiction {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_lockup_bypass(&self) -> Option<usize> {
        // Pattern: Lockup using timestamp without bounds
        // TIMESTAMP → LT without timestamp bounds validation
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x42 {  // TIMESTAMP
                let mut has_bounds_check = false;
                
                // Check for timestamp bounds (prevent manipulation)
                for j in i+1..(i+15).min(self.bytecode.len()) {
                    // Bounds: require timestamp within reasonable range of block.number
                    if self.bytecode[j] == 0x43 {  // NUMBER (for bounds check)
                        has_bounds_check = true;
                    }
                }
                
                // Check if used for lockup
                let mut is_lockup = false;
                for j in i+1..(i+12).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x10 {  // LT (lockup expired)
                        is_lockup = true;
                    }
                }
                
                if is_lockup && !has_bounds_check {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_limit_exceeded(&self) -> Option<usize> {
        // Pattern: Transfer limit without cumulative tracking
        // Amount check without SLOAD (cumulative amount)
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x10 {  // LT (amount < limit)
                let mut checks_cumulative = false;
                
                // Check for cumulative amount tracking
                for j in (i.saturating_sub(15))..i {
                    if self.bytecode[j] == 0x54 {  // SLOAD
                        // Check if added to current amount
                        for k in j+1..(j+8).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x01 {  // ADD (cumulative)
                                checks_cumulative = true;
                            }
                        }
                    }
                }
                
                // Check if this is transfer amount validation
                let mut is_amount_check = false;
                for j in (i.saturating_sub(10))..i {
                    if self.bytecode[j] == 0x35 {  // CALLDATALOAD (amount)
                        is_amount_check = true;
                    }
                }
                
                if is_amount_check && !checks_cumulative {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_kyc_bypass(&self) -> Option<usize> {
        // Pattern: KYC check without expiration validation
        // SLOAD (KYC status) without expiry timestamp check
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x54 {  // SLOAD (KYC status)
                let mut checks_expiry = false;
                let mut checks_status = false;
                
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    // Status check
                    if self.bytecode[j] == 0x15 || self.bytecode[j] == 0x14 {  // ISZERO/EQ
                        checks_status = true;
                    }
                    
                    // Expiry check: TIMESTAMP comparison
                    if self.bytecode[j] == 0x42 {  // TIMESTAMP
                        for k in j+1..(j+5).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x10 {  // LT (not expired)
                                checks_expiry = true;
                            }
                        }
                    }
                }
                
                // Status checked but not expiry
                if checks_status && !checks_expiry {
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
                kind: SecurityWarningKind::BackedFi,
                severity: v.severity,
                description: format!(
                    "Backed Fi {:?} at PC {}: {}",
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
    fn test_whitelist_bypass() {
        let bytecode = vec![
            0x54, // SLOAD (check sender)
            0x54, // SLOAD (check recipient)
            0x17, // OR (should be AND!)
        ];
        
        let detector = BackedFiDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, BackedFiVulnerabilityType::WhitelistBypass)));
    }

    #[test]
    fn test_accreditation_skip() {
        let bytecode = vec![
            0x63, 0x12, 0x34, 0x56, 0x78, // PUSH4 (transfer selector)
            0xF1, // CALL (transfer without accreditation check)
        ];
        
        let detector = BackedFiDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, BackedFiVulnerabilityType::AccreditationCheckSkip)));
    }
}
