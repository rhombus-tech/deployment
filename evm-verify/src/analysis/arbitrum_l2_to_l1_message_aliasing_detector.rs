use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArbitrumL2ToL1MessageAliasingVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct ArbitrumL2ToL1MessageAliasingDetector {
    bytecode: Vec<u8>,
}

impl ArbitrumL2ToL1MessageAliasingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<ArbitrumL2ToL1MessageAliasingVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_missing_address_aliasing_check());
        vulnerabilities.extend(self.detect_l1_sender_impersonation());
        vulnerabilities.extend(self.detect_cross_chain_authentication_bypass());
        vulnerabilities
    }

    fn detect_missing_address_aliasing_check(&self) -> Vec<ArbitrumL2ToL1MessageAliasingVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x33 { // CALLER (checking msg.sender from L2)
                let window_end = (pc + 100).min(self.bytecode.len());
                let has_auth_check = self.bytecode[pc..window_end].iter().any(|&b| b == 0x14);
                if has_auth_check {
                    let unaliases_address = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x01).count() >= 1;
                    if !unaliases_address {
                        vulns.push(ArbitrumL2ToL1MessageAliasingVulnerability {
                            pc, vulnerability_type: "MissingAddressAliasingCheck".to_string(),
                            description: format!("L1 contract at PC {} checks msg.sender from L2 message without unaliasing, allowing impersonation. Attack: Arbitrum aliases L2 contract addresses when sending to L1 via ArbSys.sendTxToL1(), L1 contract trusts msg.sender directly, attacker spoofs. Real vulnerability: aliasing formula: L1_address = L2_address + 0x1111000000000000000000000000000000001111, L1 contract expects msg.sender == trustedL2Contract, but receives aliased version. Example: L2 contract 0x1234...5678 sends message, L1 receives from 0x2345...6789 (aliased), L1's require(msg.sender == 0x1234...5678) fails incorrectly, or attacker deploys at 0x0123...4567 which aliases to expected address. Missing: AddressAliasHelper.undoL1ToL2Alias(msg.sender) before comparison. Should implement: address l2Sender = undoL1ToL2Alias(msg.sender); require(l2Sender == trustedL2Contract). Fix: always unalias addresses from Arbitrum L2 messages before authentication checks.", pc),
                            confidence: 0.88,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_l1_sender_impersonation(&self) -> Vec<ArbitrumL2ToL1MessageAliasingVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x14 { // EQ (address comparison)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let compares_sender = self.bytecode[start..pc].iter().any(|&b| b == 0x33);
                if compares_sender {
                    let window_end = (pc + 60).min(self.bytecode.len());
                    let handles_alias_offset = self.bytecode[start..window_end].iter().filter(|&&b| b == 0x01 || b == 0x03).count() >= 2;
                    if !handles_alias_offset {
                        vulns.push(ArbitrumL2ToL1MessageAliasingVulnerability {
                            pc, vulnerability_type: "L1SenderImpersonation".to_string(),
                            description: format!("Address equality check at PC {} vulnerable to Arbitrum L1 sender impersonation via aliasing. Attack: L1 EOA sends tx to Arbitrum Inbox, becomes L2 tx with same sender, L2 contract sends message to L1, address gets aliased, different sender on L1. Real scenario: user 0xABCD...1234 on L1 deposits via Inbox, L2 sees tx from 0xABCD...1234, L2 contract withdraws to L1, L1 receives from 0xBCDE...2345 (aliased), authentication breaks. Example: multisig on L1 trusts specific L2 address, L2 sends withdrawal request, L1 receives from aliased address, require(msg.sender == trustedAddress) fails, funds locked. Missing: L1 contract must expect aliased address or unalias. Fix: if message from L2 contract, expect aliased = original + OFFSET, else expect unmodified for EOA. Implement: bool isAliased = uint160(msg.sender) > uint160(type(uint160).max) - OFFSET; if (isAliased) sender = undoAlias(msg.sender).", pc),
                            confidence: 0.85,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_cross_chain_authentication_bypass(&self) -> Vec<ArbitrumL2ToL1MessageAliasingVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x54 { // SLOAD (access control mapping)
                let window_end = (pc + 80).min(self.bytecode.len());
                let uses_for_auth = self.bytecode[pc..window_end].iter().any(|&b| b == 0x15);
                if uses_for_auth {
                    let start = if pc > 100 { pc - 100 } else { 0 };
                    let handles_aliasing = self.bytecode[start..window_end].iter().filter(|&&b| b == 0x01).count() >= 2;
                    if !handles_aliasing {
                        vulns.push(ArbitrumL2ToL1MessageAliasingVulnerability {
                            pc, vulnerability_type: "CrossChainAuthenticationBypass".to_string(),
                            description: format!("Access control check at PC {} uses msg.sender from L2 message without aliasing awareness, bypassable. Attack: L1 contract maintains mapping[address => bool] authorized, sets L2 contract address as authorized, but L2 messages arrive with aliased address failing lookup. Real vulnerability: contract grants role to 0x1234...5678 expecting L2 messages, L2 sends message, L1 receives from 0x2345...6789, mapping[0x2345...6789] == false, authorization denied incorrectly. Reverse attack: attacker finds address that when aliased matches authorized address, deploys malicious contract at that address. Example: authorized[0x2345...6789] = true, attacker calculates 0x2345...6789 - 0x1111...1111 = 0x1234...5678, deploys malicious contract at 0x1234...5678, messages alias to authorized address, bypass. Missing: store both original and aliased addresses, or unalias on check. Fix: when setting L2 authorized addresses, store applyL1ToL2Alias(address) for incoming message checks.", pc),
                            confidence: 0.81,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }
}
