use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use ethers::types::U256;

/// Paraspace NFT Staking Reentrancy Detector
/// 
/// Detects reentrancy vulnerabilities specific to NFT staking protocols where
/// ERC721/ERC1155 callbacks during transfer can reenter staking logic.
/// 
/// **Attack Pattern**:
/// 1. Malicious NFT contract with onERC721Received callback
/// 2. During stake/unstake, NFT transfer triggers callback
/// 3. Callback reenters protocol before state updates complete
/// 4. Attacker manipulates rewards or duplicates stakes
/// 
/// **Detection Strategy**:
/// - Identifies NFT transfer operations (safeTransferFrom)
/// - Detects missing reentrancy guards on staking functions
/// - Flags state updates after NFT transfers
/// - Checks for CEI violations in NFT operations
pub struct ParaspaceNftStakingReentrancyDetector {
    bytecode: Vec<u8>,
}

impl ParaspaceNftStakingReentrancyDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityWarning> {
        let mut warnings = Vec::new();

        if self.has_unguarded_nft_transfer() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::Reentrancy,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "NFT safeTransferFrom without reentrancy guard - Paraspace vulnerability".to_string(),
                operations: Vec::new(),
                remediation: "Add reentrancy guard before NFT transfers with callbacks".to_string(),
            });
        }

        if self.has_state_update_after_nft_callback() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::Reentrancy,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "State updates after NFT transfer callback - CEI violation".to_string(),
                operations: Vec::new(),
                remediation: "Update state before NFT transfers to follow checks-effects-interactions".to_string(),
            });
        }

        if self.has_reward_calculation_reentrancy() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::Reentrancy,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Reward calculation vulnerable to reentrancy during NFT operations".to_string(),
                operations: Vec::new(),
                remediation: "Calculate and store rewards before any external NFT calls".to_string(),
            });
        }

        warnings
    }

    fn has_unguarded_nft_transfer(&self) -> bool {
        // safeTransferFrom selector: 0x42842e0e (ERC721) or 0xf242432a (ERC1155)
        let erc721_selector = [0x42, 0x84, 0x2e, 0x0e];
        let erc1155_selector = [0xf2, 0x42, 0x43, 0x2a];
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == erc721_selector || selector == erc1155_selector {
                    let window = &self.bytecode[i..i+30.min(self.bytecode.len())];
                    
                    // Check for reentrancy guard
                    let has_guard = window.windows(3).any(|w| {
                        w[0] == 0x54 && w[1] == 0x15 && w[2] == 0x57
                    });
                    
                    if !has_guard {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_state_update_after_nft_callback(&self) -> bool {
        // Pattern: safeTransferFrom -> CALL -> SSTORE
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == [0x42, 0x84, 0x2e, 0x0e] || // safeTransferFrom
                   selector == [0xf2, 0x42, 0x43, 0x2a]    // safeBatchTransferFrom
                {
                    let window = &self.bytecode[i..i+20.min(self.bytecode.len())];
                    
                    // Look for CALL (external) followed by SSTORE
                    if let Some(call_pos) = window.iter().position(|&op| op == 0xf1) {
                        let after_call = &window[call_pos+1..];
                        if after_call.contains(&0x55) { // SSTORE after callback
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    fn has_reward_calculation_reentrancy(&self) -> bool {
        // Pattern: NFT transfer -> reward calculation (MUL/DIV) -> SSTORE
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0xf1 { // CALL (NFT transfer callback)
                let window = &self.bytecode[i..i+25.min(self.bytecode.len())];
                
                // Check for arithmetic (reward calculation)
                let has_arithmetic = window.iter().any(|&op| {
                    op == 0x02 || op == 0x04 // MUL or DIV
                });
                
                // Check for SSTORE (updating rewards)
                let has_sstore = window.contains(&0x55);
                
                if has_arithmetic && has_sstore {
                    return true;
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_paraspace_nft_reentrancy() {
        let vulnerable_bytecode = vec![
            0x63, 0x42, 0x84, 0x2e, 0x0e, // safeTransferFrom
            0xf1, // CALL (triggers onERC721Received)
            0x02, // MUL (reward calculation)
            0x55, // SSTORE (update state)
        ];

        let detector = ParaspaceNftStakingReentrancyDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        assert!(!warnings.is_empty(), "Should detect NFT staking reentrancy");
    }
}
