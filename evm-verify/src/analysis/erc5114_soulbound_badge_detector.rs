use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Erc5114SoulboundBadgeVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: String,
}

pub struct Erc5114SoulboundBadgeDetector {
    bytecode: Vec<u8>,
}

impl Erc5114SoulboundBadgeDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<Erc5114SoulboundBadgeVulnerability> {
        let mut vulnerabilities = Vec::new();

        // ERC-5114 defines soulbound tokens (non-transferable badges)
        // Detect transferability violation
        if let Some(location) = self.has_transfer_implementation() {
            vulnerabilities.push(Erc5114SoulboundBadgeVulnerability {
                vulnerability_type: "ERC-5114 Soulbound Transfer Violation".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "Soulbound badge has transfer implementation. ERC-5114 tokens must be non-transferable to preserve reputation binding. Remove transfer functions or always revert.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect approval implementation
        if let Some(location) = self.has_approval_implementation() {
            vulnerabilities.push(Erc5114SoulboundBadgeVulnerability {
                vulnerability_type: "ERC-5114 Approval Violation".to_string(),
                location,
                severity: "High".to_string(),
                description: "Soulbound badge allows approvals. Non-transferable tokens should not support approve() or setApprovalForAll(). Remove approval functionality.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        // Detect badge revocation without proper authority
        if let Some(location) = self.has_unauthorized_revocation() {
            vulnerabilities.push(Erc5114SoulboundBadgeVulnerability {
                vulnerability_type: "ERC-5114 Unauthorized Badge Revocation".to_string(),
                location,
                severity: "High".to_string(),
                description: "Badge can be revoked/burned without proper authority. Only authorized issuers or governance should revoke soulbound credentials. Implement proper revocation controls.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_transfer_implementation(&self) -> Option<usize> {
        // Pattern: Owner change (SSTORE) from transfer function
        // Soulbound tokens should revert on transfer attempts
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x55 { // SSTORE (owner change)
                // Check if this is from a transfer context
                // (has from/to addresses from calldata)
                let mut transfer_signature = 0;
                
                for j in i.saturating_sub(30)..i {
                    if self.bytecode[j] == 0x35 { // CALLDATALOAD
                        transfer_signature += 1;
                    }
                }
                
                // If multiple CALLDATALOAD (from, to, tokenId)
                if transfer_signature >= 2 {
                    // Check if there's a REVERT before SSTORE
                    let mut has_revert = false;
                    for j in i.saturating_sub(15)..i {
                        if self.bytecode[j] == 0xfd { // REVERT
                            has_revert = true;
                        }
                    }
                    
                    // If no REVERT, transfer is implemented
                    if !has_revert {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn has_approval_implementation(&self) -> Option<usize> {
        // Pattern: Approval storage write (SSTORE) without immediate REVERT
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x55 { // SSTORE (approval)
                // Check if this is approval-related (operator address stored)
                let mut looks_like_approval = false;
                
                for j in i.saturating_sub(20)..i {
                    // Approval typically involves two addresses (owner + operator)
                    if self.bytecode[j] == 0x33 { // CALLER (operator)
                        looks_like_approval = true;
                    }
                    // Or SHA3 for mapping key (operator mapping)
                    if self.bytecode[j] == 0x20 { // SHA3
                        looks_like_approval = true;
                    }
                }
                
                if looks_like_approval {
                    // Check if it REVERTs (proper soulbound behavior)
                    let mut has_revert = false;
                    for j in i.saturating_sub(10)..i+10.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0xfd { // REVERT
                            has_revert = true;
                        }
                    }
                    if !has_revert {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn has_unauthorized_revocation(&self) -> Option<usize> {
        // Pattern: Token burn/revocation without authority check
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x55 { // SSTORE (burning/revoking)
                // Check if setting owner to zero address (burn pattern)
                let mut is_burn = false;
                for j in i.saturating_sub(10)..i {
                    if self.bytecode[j] == 0x60 { // PUSH1
                        if j + 1 < self.bytecode.len() && self.bytecode[j + 1] == 0 {
                            is_burn = true;
                        }
                    }
                }
                
                if is_burn {
                    // Check for authority validation
                    let mut has_authority_check = false;
                    
                    for j in i.saturating_sub(30)..i {
                        // Check for CALLER comparison or role check
                        if self.bytecode[j] == 0x33 { // CALLER
                            for k in j+1..(j+10).min(self.bytecode.len()).min(self.bytecode.len()) {
                                if self.bytecode[k] == 0x14 { // EQ (authority check)
                                    has_authority_check = true;
                                    break;
                                }
                            }
                        }
                    }
                    
                    if !has_authority_check {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
