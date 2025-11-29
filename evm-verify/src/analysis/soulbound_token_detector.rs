/// Soulbound Token (SBT) Exploits Detector (EIP-5192)
/// Detects vulnerabilities in non-transferable token implementations
///
/// Issues: Fake transfers via wrapping, approval exploits, burn/remint loopholes

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoulboundTokenVulnerability {
    pub vulnerability_type: SBTIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SBTIssueType {
    TransferNotDisabled,           // Transfer functions not properly blocked
    ApprovalBypass,                // Can circumvent via approve() + transferFrom()
    WrapperBypass,                 // Can wrap SBT in transferable token
    BurnRemintLoophole,            // Can burn and remint to "transfer"
    InconsistentLocking,           // locked() returns wrong value
}

pub struct SoulboundTokenDetector {
    bytecode: Vec<u8>,
}

impl SoulboundTokenDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<SoulboundTokenVulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.is_soulbound_token() {
            return vulnerabilities;
        }

        vulnerabilities.extend(self.detect_transfer_not_disabled());
        vulnerabilities.extend(self.detect_approval_bypass());
        vulnerabilities.extend(self.detect_burn_remint_loophole());

        vulnerabilities
    }

    fn is_soulbound_token(&self) -> bool {
        // EIP-5192: locked(uint256) returns bool
        // Selector: 0xcf309012
        let locked_sig = [0xcf, 0x30, 0x90, 0x12];
        self.bytecode.windows(4).any(|w| w == locked_sig)
    }

    fn detect_transfer_not_disabled(&self) -> Vec<SoulboundTokenVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check if transfer/transferFrom exist and can execute
        let transfer_sig = [0xa9, 0x05, 0x9c, 0xbb]; // transfer
        let transfer_from_sig = [0x23, 0xb8, 0x72, 0xdd]; // transferFrom
        
        if let Some(transfer_pc) = self.bytecode.windows(4).position(|w| w == transfer_sig) {
            // Check if transfer actually reverts
            let reverts_immediately = self.has_immediate_revert(transfer_pc, 20);
            
            if !reverts_immediately {
                vulnerabilities.push(SoulboundTokenVulnerability {
                    vulnerability_type: SBTIssueType::TransferNotDisabled,
                    severity: SecuritySeverity::Critical,
                    confidence: 0.90,
                    description:
                        "Soulbound token has transfer() function that doesn't immediately revert. \
                        Token may be transferable despite being marked as soulbound.".to_string(),
                    exploit_scenario:
                        "Soulbound Bypass:\n\
                         1. SBT should be non-transferable\n\
                         2. transfer() exists but doesn't revert\n\
                         3. Attacker calls transfer() successfully\n\
                         4. \"Soulbound\" token gets transferred\n\
                         5. Breaks soulbound guarantee\n\n\
                         Fix: require(false, 'Soulbound') in transfer functions".to_string(),
                    location: transfer_pc,
                });
            }
        }

        vulnerabilities
    }

    fn detect_approval_bypass(&self) -> Vec<SoulboundTokenVulnerability> {
        let mut vulnerabilities = Vec::new();

        let approve_sig = [0x09, 0x5e, 0xa7, 0xb3]; // approve
        
        if let Some(approve_pc) = self.bytecode.windows(4).position(|w| w == approve_sig) {
            // If approve() works, transferFrom() might bypass soulbound
            let approve_works = !self.has_immediate_revert(approve_pc, 20);
            
            if approve_works {
                vulnerabilities.push(SoulboundTokenVulnerability {
                    vulnerability_type: SBTIssueType::ApprovalBypass,
                    severity: SecuritySeverity::High,
                    confidence: 0.75,
                    description:
                        "Soulbound token allows approve(). Combined with transferFrom(), \
                        this may bypass soulbound restrictions.".to_string(),
                    exploit_scenario:
                        "Approval Bypass:\n\
                         1. Owner calls approve(attacker, tokenId)\n\
                         2. Attacker calls transferFrom(owner, attacker, tokenId)\n\
                         3. If transferFrom checks approval but not soulbound status\n\
                         4. Transfer succeeds\n\
                         5. Soulbound token transferred\n\n\
                         Fix: Disable approve() for soulbound tokens".to_string(),
                    location: approve_pc,
                });
            }
        }

        vulnerabilities
    }

    fn detect_burn_remint_loophole(&self) -> Vec<SoulboundTokenVulnerability> {
        let mut vulnerabilities = Vec::new();

        let has_burn = self.has_burn_function();
        let has_mint = self.has_mint_function();
        
        if has_burn && has_mint {
            // Check if there's protection against burn+remint "transfer"
            let has_burn_protection = self.has_burn_cooldown_or_limit();
            
            if !has_burn_protection {
                vulnerabilities.push(SoulboundTokenVulnerability {
                    vulnerability_type: SBTIssueType::BurnRemintLoophole,
                    severity: SecuritySeverity::Medium,
                    confidence: 0.65,
                    description:
                        "Soulbound token allows burn and mint without cooldown. \
                        User could burn their SBT and remint to another address (pseudo-transfer).".to_string(),
                    exploit_scenario:
                        "Burn-Remint Transfer:\n\
                         1. User burns their SBT from address A\n\
                         2. Immediately mints same SBT to address B\n\
                         3. Effectively \"transferred\" the soulbound token\n\
                         4. Defeats purpose of soulbound\n\n\
                         Fix: Add cooldown period or prevent reminting same token ID".to_string(),
                    location: 0,
                });
            }
        }

        vulnerabilities
    }

    // Helper methods

    fn has_immediate_revert(&self, pc: usize, distance: usize) -> bool {
        let end = (pc + distance).min(self.bytecode.len());
        
        // Look for REVERT or INVALID soon after function start
        self.bytecode[pc..end].iter()
            .take(10)
            .any(|&op| op == 0xFD || op == 0xFE) // REVERT or INVALID
    }

    fn has_burn_function(&self) -> bool {
        // burn() selector: 0x42966c68
        let burn_sig = [0x42, 0x96, 0x6c, 0x68];
        self.bytecode.windows(4).any(|w| w == burn_sig)
    }

    fn has_mint_function(&self) -> bool {
        // mint() selector: 0x40c10f19
        // safeMint() selector: 0xd204c45e
        let mint_sigs = [
            [0x40, 0xc1, 0x0f, 0x19],
            [0xd2, 0x04, 0xc4, 0x5e],
        ];
        
        mint_sigs.iter().any(|sig| {
            self.bytecode.windows(4).any(|w| w == sig)
        })
    }

    fn has_burn_cooldown_or_limit(&self) -> bool {
        // Heuristic: Look for timestamp checks or counter limits
        let has_timestamp = self.bytecode.contains(&0x42); // TIMESTAMP
        let has_comparisons = self.bytecode.iter()
            .filter(|&&op| matches!(op, 0x10 | 0x11)) // LT, GT
            .count() >= 3;
        
        has_timestamp && has_comparisons
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_soulbound_token_transfer() {
        let bytecode = vec![
            0xcf, 0x30, 0x90, 0x12, // locked() selector
            0xa9, 0x05, 0x9c, 0xbb, // transfer() selector
            // No immediate revert
            0x55, // SSTORE (executes transfer)
        ];
        
        let detector = SoulboundTokenDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(!vulns.is_empty(), "Should detect transfer not disabled");
    }
}
