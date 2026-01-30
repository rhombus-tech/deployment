// Lens Protocol Follower NFT Manipulation Detector
// Detects manipulation of social graph NFTs and follow mechanics

use crate::bytecode::security::{SecuritySeverity, SecurityWarning, SecurityWarningKind};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LensProtocolVulnerability {
    pub location: usize,
    pub vulnerability_type: LensVulnerabilityType,
    pub severity: SecuritySeverity,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LensVulnerabilityType {
    FollowerNFTFrontRunning,        // Front-run follow NFT minting
    ProfileOwnershipDispute,        // Profile transfer/ownership manipulation
    CollectModuleBypass,            // Bypass collect fees/restrictions
    ReferenceModuleGaming,          // Game content mirroring/commenting
    HandleRegistrationSquatting,    // Squat valuable handles
    FollowModuleFeeManipulation,    // Manipulate follow fees/conditions
    PublicationMetadataForge,       // Forge publication metadata
}

pub struct LensProtocolDetector {
    bytecode: Vec<u8>,
}

impl LensProtocolDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<LensProtocolVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_follower_nft_frontrunning() {
            vulnerabilities.push(LensProtocolVulnerability {
                location: loc,
                vulnerability_type: LensVulnerabilityType::FollowerNFTFrontRunning,
                severity: SecuritySeverity::Medium,
                description: "Follower NFT minting can be front-run. MEV bot can observe follow \
                             transaction and mint follower NFT before user, stealing tokenID.".to_string(),
                confidence: 0.78,
            });
        }

        if let Some(loc) = self.detect_profile_ownership_dispute() {
            vulnerabilities.push(LensProtocolVulnerability {
                location: loc,
                vulnerability_type: LensVulnerabilityType::ProfileOwnershipDispute,
                severity: SecuritySeverity::High,
                description: "Profile transfer lacks proper ownership verification. Transfer can \
                             occur during delegation, causing ownership disputes.".to_string(),
                confidence: 0.82,
            });
        }

        if let Some(loc) = self.detect_collect_module_bypass() {
            vulnerabilities.push(LensProtocolVulnerability {
                location: loc,
                vulnerability_type: LensVulnerabilityType::CollectModuleBypass,
                severity: SecuritySeverity::High,
                description: "Collect module fee check uses weak validation. Attacker can bypass \
                             collect fees by manipulating payment token approval timing.".to_string(),
                confidence: 0.80,
            });
        }

        if let Some(loc) = self.detect_reference_module_gaming() {
            vulnerabilities.push(LensProtocolVulnerability {
                location: loc,
                vulnerability_type: LensVulnerabilityType::ReferenceModuleGaming,
                severity: SecuritySeverity::Medium,
                description: "Reference module allows unrestricted mirroring. Spammer can mirror \
                             content repeatedly to game engagement metrics.".to_string(),
                confidence: 0.74,
            });
        }

        if let Some(loc) = self.detect_handle_squatting() {
            vulnerabilities.push(LensProtocolVulnerability {
                location: loc,
                vulnerability_type: LensVulnerabilityType::HandleRegistrationSquatting,
                severity: SecuritySeverity::Medium,
                description: "Handle registration first-come-first-serve without protection. Bots \
                             can squat valuable handles and ransom them.".to_string(),
                confidence: 0.76,
            });
        }

        if let Some(loc) = self.detect_follow_fee_manipulation() {
            vulnerabilities.push(LensProtocolVulnerability {
                location: loc,
                vulnerability_type: LensVulnerabilityType::FollowModuleFeeManipulation,
                severity: SecuritySeverity::High,
                description: "Follow module fee can be changed retroactively. Profile owner can \
                             set high fee after users commit to follow.".to_string(),
                confidence: 0.79,
            });
        }

        if let Some(loc) = self.detect_metadata_forgery() {
            vulnerabilities.push(LensProtocolVulnerability {
                location: loc,
                vulnerability_type: LensVulnerabilityType::PublicationMetadataForge,
                severity: SecuritySeverity::Medium,
                description: "Publication metadata URI not validated. Attacker can change content \
                             after publication, breaking immutability.".to_string(),
                confidence: 0.72,
            });
        }

        vulnerabilities
    }

    fn detect_follower_nft_frontrunning(&self) -> Option<usize> {
        // Pattern: NFT mint without commit-reveal
        // CALL (mint follower NFT) without SLOAD (commitment hash check)
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0xF1 {  // CALL (likely mint)
                let mut has_commit_check = false;
                
                // Check for commitment verification before mint
                for j in (i.saturating_sub(15))..i {
                    if self.bytecode[j] == 0x54 {  // SLOAD
                        for k in j+1..(j+5).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x14 {  // EQ (hash verification)
                                has_commit_check = true;
                            }
                        }
                    }
                }
                
                // Check if this looks like NFT mint (ERC721 signature)
                let mut looks_like_mint = false;
                for j in (i.saturating_sub(10))..i {
                    if self.bytecode[j] == 0x63 {  // PUSH4 (function selector)
                        looks_like_mint = true;
                    }
                }
                
                if looks_like_mint && !has_commit_check {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_profile_ownership_dispute(&self) -> Option<usize> {
        // Pattern: Transfer without checking delegation state
        // CALLER → transferFrom without SLOAD (delegation check)
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x33 {  // CALLER
                let mut has_transfer = false;
                let mut checks_delegation = false;
                
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0xF1 {  // CALL (transfer)
                        has_transfer = true;
                    }
                    
                    // Check for delegation state verification
                    if self.bytecode[j] == 0x54 {  // SLOAD
                        for k in j+1..(j+5).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x15 {  // ISZERO (not delegated)
                                checks_delegation = true;
                            }
                        }
                    }
                    
                    if has_transfer && !checks_delegation {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_collect_module_bypass(&self) -> Option<usize> {
        // Pattern: Fee check with weak timing validation
        // SLOAD (fee) → comparison without SLOAD (approval timestamp)
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x54 {  // SLOAD (fee amount)
                let mut has_fee_check = false;
                let mut validates_approval = false;
                
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x11 || self.bytecode[j] == 0x10 {  // GT/LT
                        has_fee_check = true;
                    }
                    
                    // Approval validation
                    if self.bytecode[j] == 0x54 {  // SLOAD (approval state)
                        validates_approval = true;
                    }
                    
                    if has_fee_check && !validates_approval && self.bytecode[j] == 0xF1 {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_reference_module_gaming(&self) -> Option<usize> {
        // Pattern: Mirror/comment without rate limiting
        // Function without SLOAD (last action timestamp) or counter check
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Look for function that stores reference (SSTORE)
            if self.bytecode[i] == 0x55 {  // SSTORE (store reference)
                let mut has_rate_limit = false;
                
                // Check for rate limiting logic before
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x42 {  // TIMESTAMP
                        for k in j+1..(j+8).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x03 || self.bytecode[k] == 0x10 {  // SUB/LT
                                has_rate_limit = true;
                            }
                        }
                    }
                }
                
                // Check if multiple SSTOREs nearby (likely reference creation)
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

    fn detect_handle_squatting(&self) -> Option<usize> {
        // Pattern: Handle registration without anti-squatting measures
        // SSTORE (handle) without burn fee or holding period check
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x55 {  // SSTORE (register handle)
                let mut has_burn_fee = false;
                let mut has_holding_check = false;
                
                // Check for burn fee (token transfer or destroy)
                for j in (i.saturating_sub(15))..i {
                    if self.bytecode[j] == 0xF1 {  // CALL (payment)
                        has_burn_fee = true;
                    }
                }
                
                // Check for holding period
                for j in (i.saturating_sub(15))..i {
                    if self.bytecode[j] == 0x42 {  // TIMESTAMP
                        has_holding_check = true;
                    }
                }
                
                // Check if this looks like handle registration (hash operation nearby)
                let mut looks_like_handle = false;
                for j in (i.saturating_sub(10))..i {
                    if self.bytecode[j] == 0x20 {  // SHA3
                        looks_like_handle = true;
                    }
                }
                
                if looks_like_handle && !has_burn_fee && !has_holding_check {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_follow_fee_manipulation(&self) -> Option<usize> {
        // Pattern: Fee update without timelock or follower protection
        // SSTORE (follow fee) without delay mechanism
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x55 {  // SSTORE (update fee)
                let mut has_timelock = false;
                
                // Check for timelock pattern (TIMESTAMP + ADD + comparison)
                for j in (i.saturating_sub(15))..i {
                    if self.bytecode[j] == 0x42 {  // TIMESTAMP
                        for k in j+1..(j+8).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x01 {  // ADD (delay)
                                has_timelock = true;
                            }
                        }
                    }
                }
                
                // Check if multiple SLOADs before (fee update logic)
                let mut sload_count = 0;
                for j in (i.saturating_sub(10))..i {
                    if self.bytecode[j] == 0x54 {
                        sload_count += 1;
                    }
                }
                
                if sload_count >= 2 && !has_timelock {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_metadata_forgery(&self) -> Option<usize> {
        // Pattern: Metadata URI stored without hash commitment
        // SSTORE (URI) without SSTORE (content hash)
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x55 {  // SSTORE (URI)
                let mut has_hash_storage = false;
                
                // Check if hash is also stored (immutability)
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x20 {  // SHA3 (hash content)
                        for k in j+1..(j+8).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x55 {  // SSTORE (hash)
                                has_hash_storage = true;
                            }
                        }
                    }
                }
                
                // Check if this looks like publication (multiple SSTOREs)
                let mut sstore_count = 1;
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x55 {
                        sstore_count += 1;
                    }
                }
                
                if sstore_count >= 3 && !has_hash_storage {
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
                kind: SecurityWarningKind::LensProtocol,
                severity: v.severity,
                description: format!(
                    "Lens Protocol {:?} at PC {}: {}",
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
    fn test_follower_nft_frontrunning() {
        let bytecode = vec![
            0x63, 0x12, 0x34, 0x56, 0x78, // PUSH4 (mint selector)
            0xF1, // CALL (mint NFT without commit)
        ];
        
        let detector = LensProtocolDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, LensVulnerabilityType::FollowerNFTFrontRunning)));
    }

    #[test]
    fn test_handle_squatting() {
        let bytecode = vec![
            0x60, 0x00, // PUSH1 0
            0x20, // SHA3 (hash handle)
            0x60, 0x00, // PUSH1 0
            0x55, // SSTORE (register without fee/delay)
        ];
        
        let detector = LensProtocolDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, LensVulnerabilityType::HandleRegistrationSquatting)));
    }
}
