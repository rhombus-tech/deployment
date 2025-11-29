/// Cross-Chain Replay Attack Detector
/// Detects missing chain ID validation that allows replaying transactions
/// across different chains (Ethereum, Polygon, Arbitrum, etc.)
///
/// Famous exploits: Multichain bridge, Wormhole, Nomad bridge

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossChainReplayVulnerability {
    pub vulnerability_type: CrossChainReplayType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CrossChainReplayType {
    MissingChainIdInSignature,     // Signature doesn't include chain ID
    NoChainIdValidation,           // No check against block.chainid
    BridgeMessageReplay,           // Bridge messages can be replayed
    CrossChainNonceReuse,          // Nonce not chain-specific
}

pub struct CrossChainReplayDetector {
    bytecode: Vec<u8>,
}

impl CrossChainReplayDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<CrossChainReplayVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern 1: Signature verification without chain ID
        vulnerabilities.extend(self.detect_signature_without_chain_id());

        // Pattern 2: Bridge message processing without chain validation
        vulnerabilities.extend(self.detect_bridge_message_replay());

        // Pattern 3: Cross-chain operations without chain ID check
        vulnerabilities.extend(self.detect_missing_chain_id_validation());

        vulnerabilities
    }

    /// Detect: ecrecover without CHAINID in hash
    fn detect_signature_without_chain_id(&self) -> Vec<CrossChainReplayVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        let has_ecrecover = self.has_ecrecover();
        let has_chain_id_check = self.has_chain_id_opcode();
        
        if has_ecrecover && !has_chain_id_check {
            vulnerabilities.push(CrossChainReplayVulnerability {
                vulnerability_type: CrossChainReplayType::MissingChainIdInSignature,
                severity: SecuritySeverity::Critical,
                confidence: 0.85,
                description:
                    "Contract uses ecrecover for signature verification but doesn't include \
                    CHAINID in the signed message. Signatures can be replayed across chains.".to_string(),
                exploit_scenario:
                    "Cross-Chain Replay Attack:\n\
                     1. User signs message on Ethereum mainnet\n\
                     2. Contract deployed at same address on Polygon\n\
                     3. Attacker replays same signature on Polygon\n\
                     4. Transaction executes on both chains\n\
                     5. User loses funds twice\n\n\
                     Fix: Include chain ID in EIP-712 domain:\n\
                     bytes32 domainSeparator = keccak256(abi.encode(\n\
                         TYPE_HASH, name, version, block.chainid, address(this)\n\
                     ));".to_string(),
                location: 0,
            });
        }

        vulnerabilities
    }

    /// Detect: Bridge message verification without chain validation
    fn detect_bridge_message_replay(&self) -> Vec<CrossChainReplayVulnerability> {
        let mut vulnerabilities = Vec::new();

        let is_bridge = self.looks_like_bridge_contract();
        
        if is_bridge {
            let has_chain_validation = self.has_chain_id_opcode();
            
            if !has_chain_validation {
                vulnerabilities.push(CrossChainReplayVulnerability {
                    vulnerability_type: CrossChainReplayType::BridgeMessageReplay,
                    severity: SecuritySeverity::Critical,
                    confidence: 0.80,
                    description:
                        "Contract appears to be a bridge but doesn't validate chain ID. \
                        Messages can be replayed on other chains.".to_string(),
                    exploit_scenario:
                        "Bridge Replay Attack (Nomad-style):\n\
                         1. Attacker observes message on Chain A\n\
                         2. Bridge deployed on Chain B with same logic\n\
                         3. Attacker submits same message on Chain B\n\
                         4. Bridge accepts it (no chain validation)\n\
                         5. Attacker double-spends bridge funds\n\n\
                         Real example: Nomad bridge $190M exploit\n\
                         Fix: Validate source/destination chain IDs".to_string(),
                    location: 0,
                });
            }
        }

        vulnerabilities
    }

    /// Detect: Operations that should check chain ID but don't
    fn detect_missing_chain_id_validation(&self) -> Vec<CrossChainReplayVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(50) {
            // Look for KECCAK256 (message hashing) without CHAINID nearby
            if self.bytecode[pc] == 0x20 { // KECCAK256
                let has_chain_id_before = self.has_chain_id_in_range(pc.saturating_sub(50), pc);
                let has_signature_check = self.has_signature_check_after(pc, 100);
                
                if has_signature_check && !has_chain_id_before {
                    vulnerabilities.push(CrossChainReplayVulnerability {
                        vulnerability_type: CrossChainReplayType::NoChainIdValidation,
                        severity: SecuritySeverity::High,
                        confidence: 0.70,
                        description: format!(
                            "Message hash at PC {} used for signature verification \
                            but doesn't include chain ID.",
                            pc
                        ),
                        exploit_scenario:
                            "Message Replay:\n\
                             1. User signs a message hash\n\
                             2. Hash doesn't include chain ID\n\
                             3. Same contract on different chain\n\
                             4. Signature valid on both chains\n\
                             5. Unintended cross-chain execution".to_string(),
                        location: pc,
                    });
                }
            }

            pc += 1;
        }

        vulnerabilities
    }

    // Helper methods

    fn has_ecrecover(&self) -> bool {
        // ecrecover is precompile at address 0x01
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x60 && // PUSH1
               self.bytecode[i + 1] == 0x01 { // 1 (ecrecover)
                // Check for STATICCALL nearby
                if self.bytecode[i..i+10].contains(&0xFA) {
                    return true;
                }
            }
        }
        false
    }

    fn has_chain_id_opcode(&self) -> bool {
        // CHAINID opcode: 0x46 (introduced in Istanbul)
        self.bytecode.contains(&0x46)
    }

    fn has_chain_id_in_range(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        self.bytecode[start..range_end].contains(&0x46)
    }

    fn has_signature_check_after(&self, pc: usize, distance: usize) -> bool {
        let end = (pc + distance).min(self.bytecode.len());
        
        // Look for comparison and JUMPI (signature validation)
        for i in pc..end.saturating_sub(2) {
            if self.bytecode[i] == 0x14 && // EQ
               self.bytecode[i + 1] == 0x57 { // JUMPI
                return true;
            }
        }
        false
    }

    fn looks_like_bridge_contract(&self) -> bool {
        // Bridge contracts typically:
        // 1. Have multiple external calls (to other chains)
        // 2. Have message validation logic
        // 3. Have token transfers
        
        let external_calls = self.bytecode.iter().filter(|&&op| op == 0xF1).count();
        let has_transfers = self.has_token_transfer_pattern();
        let has_validation = self.has_validation_pattern();
        
        external_calls >= 2 && has_transfers && has_validation
    }

    fn has_token_transfer_pattern(&self) -> bool {
        // Look for ERC20 transfer selector: 0xa9059cbb
        self.bytecode.windows(4).any(|w| w == [0xa9, 0x05, 0x9c, 0xbb])
    }

    fn has_validation_pattern(&self) -> bool {
        // Look for require-style checks (JUMPI after comparison)
        for i in 0..self.bytecode.len().saturating_sub(2) {
            if matches!(self.bytecode[i], 0x10 | 0x11 | 0x14) && // GT, LT, EQ
               self.bytecode[i + 1] == 0x57 { // JUMPI
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_missing_chain_id() {
        let bytecode = vec![
            0x01, // Some precompile setup
            0x60, 0x01, // PUSH1 1 (ecrecover address)
            0xFA, // STATICCALL (ecrecover)
            // No CHAINID (0x46) opcode present
            0x14, // EQ (signature check)
            0x57, // JUMPI
        ];
        
        let detector = CrossChainReplayDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(!vulns.is_empty(), "Should detect missing chain ID");
    }
}
