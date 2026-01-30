// Cyberconnect Profile Ownership Dispute Detector
// Detects issues in decentralized social graph profile management

use crate::bytecode::security::{SecuritySeverity, SecurityWarning, SecurityWarningKind};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CyberconnectVulnerability {
    pub location: usize,
    pub vulnerability_type: CyberconnectVulnerabilityType,
    pub severity: SecuritySeverity,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CyberconnectVulnerabilityType {
    ProfileTransferRaceCondition,   // Race in profile ownership transfer
    NamespaceSquatting,             // Squat valuable namespaces/handles
    CrossChainOwnershipConflict,    // Ownership disputes across chains
    SubscriptionStateInconsistency, // Subscription state out of sync
    ContentVerificationBypass,      // Bypass content authenticity checks
    FollowListManipulation,         // Manipulate follower/following lists
    ProfileMetadataTampering,       // Tamper with profile metadata
}

pub struct CyberconnectDetector {
    bytecode: Vec<u8>,
}

impl CyberconnectDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<CyberconnectVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_transfer_race_condition() {
            vulnerabilities.push(CyberconnectVulnerability {
                location: loc,
                vulnerability_type: CyberconnectVulnerabilityType::ProfileTransferRaceCondition,
                severity: SecuritySeverity::High,
                description: "Profile transfer can be front-run during ownership change. Old owner \
                             can execute actions after transfer initiated but before finalized.".to_string(),
                confidence: 0.83,
            });
        }

        if let Some(loc) = self.detect_namespace_squatting() {
            vulnerabilities.push(CyberconnectVulnerability {
                location: loc,
                vulnerability_type: CyberconnectVulnerabilityType::NamespaceSquatting,
                severity: SecuritySeverity::Medium,
                description: "Namespace registration lacks anti-squatting measures. Bots can \
                             reserve valuable handles to resell at profit.".to_string(),
                confidence: 0.77,
            });
        }

        if let Some(loc) = self.detect_cross_chain_conflict() {
            vulnerabilities.push(CyberconnectVulnerability {
                location: loc,
                vulnerability_type: CyberconnectVulnerabilityType::CrossChainOwnershipConflict,
                severity: SecuritySeverity::High,
                description: "Cross-chain profile ownership not synchronized. Same profile can have \
                             different owners on different chains causing disputes.".to_string(),
                confidence: 0.81,
            });
        }

        if let Some(loc) = self.detect_subscription_inconsistency() {
            vulnerabilities.push(CyberconnectVulnerability {
                location: loc,
                vulnerability_type: CyberconnectVulnerabilityType::SubscriptionStateInconsistency,
                severity: SecuritySeverity::Medium,
                description: "Subscription state updates not atomic. User can access content after \
                             subscription expires due to state sync delays.".to_string(),
                confidence: 0.74,
            });
        }

        if let Some(loc) = self.detect_content_verification_bypass() {
            vulnerabilities.push(CyberconnectVulnerability {
                location: loc,
                vulnerability_type: CyberconnectVulnerabilityType::ContentVerificationBypass,
                severity: SecuritySeverity::High,
                description: "Content signature verification incomplete. Missing checks allow forged \
                             content to appear as authored by profile owner.".to_string(),
                confidence: 0.85,
            });
        }

        if let Some(loc) = self.detect_follow_list_manipulation() {
            vulnerabilities.push(CyberconnectVulnerability {
                location: loc,
                vulnerability_type: CyberconnectVulnerabilityType::FollowListManipulation,
                severity: SecuritySeverity::Medium,
                description: "Follow/unfollow operations lack proper validation. Attacker can \
                             manipulate follower counts through rapid follow/unfollow cycles.".to_string(),
                confidence: 0.72,
            });
        }

        if let Some(loc) = self.detect_metadata_tampering() {
            vulnerabilities.push(CyberconnectVulnerability {
                location: loc,
                vulnerability_type: CyberconnectVulnerabilityType::ProfileMetadataTampering,
                severity: SecuritySeverity::Medium,
                description: "Profile metadata not content-addressed. Owner can change metadata URI \
                             to alter historical profile information.".to_string(),
                confidence: 0.70,
            });
        }

        vulnerabilities
    }

    fn detect_transfer_race_condition(&self) -> Option<usize> {
        // Pattern: Transfer without atomic ownership change
        // CALLER check → state change without lock
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x33 {  // CALLER
                let mut has_ownership_check = false;
                let mut has_atomic_lock = false;
                
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x14 {  // EQ (check owner)
                        has_ownership_check = true;
                    }
                    
                    // Atomic lock: SSTORE transfer flag before actual transfer
                    if self.bytecode[j] == 0x55 {  // SSTORE
                        for k in j+1..(j+8).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x55 {  // Second SSTORE (actual transfer)
                                has_atomic_lock = true;
                            }
                        }
                    }
                    
                    // Transfer without atomicity
                    if has_ownership_check && !has_atomic_lock && self.bytecode[j] == 0x55 {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_namespace_squatting(&self) -> Option<usize> {
        // Pattern: Name registration without cost or holding period
        // SHA3 (hash name) → SSTORE without payment
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x20 {  // SHA3 (hash handle)
                let mut has_payment = false;
                let mut has_holding_period = false;
                
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    // Payment check
                    if self.bytecode[j] == 0xF1 {  // CALL (payment)
                        has_payment = true;
                    }
                    
                    // Holding period
                    if self.bytecode[j] == 0x42 || self.bytecode[j] == 0x43 {  // TIMESTAMP/NUMBER
                        has_holding_period = true;
                    }
                    
                    // Register without anti-squatting
                    if !has_payment && !has_holding_period && self.bytecode[j] == 0x55 {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_cross_chain_conflict(&self) -> Option<usize> {
        // Pattern: Ownership update without cross-chain sync check
        // SSTORE (owner) without STATICCALL (check other chains)
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x55 {  // SSTORE (set owner)
                let mut checks_other_chains = false;
                
                // Look for cross-chain verification before
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0xFA {  // STATICCALL (bridge/oracle)
                        checks_other_chains = true;
                    }
                }
                
                // Check if this looks like ownership change (CALLER nearby)
                let mut is_ownership_change = false;
                for j in (i.saturating_sub(15))..i {
                    if self.bytecode[j] == 0x33 {  // CALLER
                        is_ownership_change = true;
                    }
                }
                
                if is_ownership_change && !checks_other_chains {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_subscription_inconsistency(&self) -> Option<usize> {
        // Pattern: Subscription check without expiry validation
        // SLOAD (subscription) → use without TIMESTAMP comparison
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x54 {  // SLOAD (subscription state)
                let mut checks_expiry = false;
                
                for j in i+1..(i+15).min(self.bytecode.len()) {
                    // Expiry check: TIMESTAMP → LT
                    if self.bytecode[j] == 0x42 {  // TIMESTAMP
                        for k in j+1..(j+5).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x10 {  // LT (not expired)
                                checks_expiry = true;
                            }
                        }
                    }
                    
                    // Subscription used for access
                    if !checks_expiry && self.bytecode[j] == 0x57 {  // JUMPI (gate)
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_content_verification_bypass(&self) -> Option<usize> {
        // Pattern: Signature verification missing checks
        // ECRECOVER without full validation
        
        for i in 0..self.bytecode.len().saturating_sub(35) {
            if self.bytecode[i] == 0xF1 || self.bytecode[i] == 0xFA {  // CALL (ecrecover)
                let mut verifies_signer = false;
                let mut checks_zero_address = false;
                
                for j in i+1..(i+30).min(self.bytecode.len()) {
                    // Verify signer matches expected
                    if self.bytecode[j] == 0x14 {  // EQ (compare addresses)
                        verifies_signer = true;
                    }
                    
                    // Check for zero address (failed recovery)
                    if self.bytecode[j] == 0x15 {  // ISZERO
                        checks_zero_address = true;
                    }
                }
                
                if !verifies_signer || !checks_zero_address {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_follow_list_manipulation(&self) -> Option<usize> {
        // Pattern: Follow operation without rate limiting
        // SSTORE (follow) without time delta check
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x55 {  // SSTORE (follow state)
                let mut has_rate_limit = false;
                
                // Check for rate limiting
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x42 {  // TIMESTAMP
                        for k in j+1..(j+8).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x03 {  // SUB (time delta)
                                has_rate_limit = true;
                            }
                        }
                    }
                }
                
                // Check if this looks like follow (multiple SSTOREs)
                let mut sstore_count = 1;
                for j in i+1..(i+15).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x55 {
                        sstore_count += 1;
                    }
                }
                
                if sstore_count >= 2 && !has_rate_limit {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_metadata_tampering(&self) -> Option<usize> {
        // Pattern: Metadata URI update without content hash
        // SSTORE (URI) without SSTORE (hash)
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x55 {  // SSTORE (URI)
                let mut stores_hash = false;
                
                // Check if content hash also stored
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x20 {  // SHA3 (hash content)
                        for k in j+1..(j+8).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x55 {  // SSTORE (hash)
                                stores_hash = true;
                            }
                        }
                    }
                }
                
                // Check if this looks like metadata update (CALLDATALOAD nearby)
                let mut is_metadata_update = false;
                for j in (i.saturating_sub(10))..i {
                    if self.bytecode[j] == 0x35 {  // CALLDATALOAD
                        is_metadata_update = true;
                    }
                }
                
                if is_metadata_update && !stores_hash {
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
                kind: SecurityWarningKind::Cyberconnect,
                severity: v.severity,
                description: format!(
                    "Cyberconnect {:?} at PC {}: {}",
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
    fn test_transfer_race_condition() {
        let bytecode = vec![
            0x33, // CALLER
            0x60, 0x00, // PUSH1 0
            0x14, // EQ (check owner)
            0x60, 0x01, // PUSH1 1
            0x55, // SSTORE (transfer without lock)
        ];
        
        let detector = CyberconnectDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, CyberconnectVulnerabilityType::ProfileTransferRaceCondition)));
    }

    #[test]
    fn test_namespace_squatting() {
        let bytecode = vec![
            0x60, 0x00, // PUSH1 0
            0x20, // SHA3 (hash handle)
            0x60, 0x00, // PUSH1 0
            0x55, // SSTORE (register without payment)
        ];
        
        let detector = CyberconnectDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, CyberconnectVulnerabilityType::NamespaceSquatting)));
    }
}
