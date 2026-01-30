use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtomicSwapRefundRaceVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct AtomicSwapRefundRaceConditionDetector {
    bytecode: Vec<u8>,
}

impl AtomicSwapRefundRaceConditionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<AtomicSwapRefundRaceVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_claim_refund_race());
        vulnerabilities.extend(self.detect_timelock_boundary_exploitation());
        vulnerabilities.extend(self.detect_missing_claim_atomicity());
        vulnerabilities
    }

    fn detect_claim_refund_race(&self) -> Vec<AtomicSwapRefundRaceVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x42 { // TIMESTAMP (timelock check)
                let window_end = (pc + 120).min(self.bytecode.len());
                let has_refund_path = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x57).count() >= 2;
                if has_refund_path {
                    let has_claim_exclusion = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x15).count() >= 1;
                    if !has_claim_exclusion {
                        vulns.push(AtomicSwapRefundRaceVulnerability {
                            pc,
                            vulnerability_type: "ClaimRefundRace".to_string(),
                            description: format!("HTLC timelock at PC {} allows concurrent claim and refund, enabling double-spend. Attack: at timelock expiry both claim() and refund() become valid, attacker submits both transactions, MEV bot orders refund before claim in same block, attacker gets refund while counterparty reveals secret thinking they'll claim. Real attack: swap expires at block N, attacker submits refund at block N with high gas, counterparty submits claim with secret, refund executes first, claim reverts, attacker keeps funds and learns secret for other chain. Example: cross-chain swap timelock expires, Alice reveals preimage in claim tx, Bob frontruns with refund, refund succeeds, Alice's claim fails but preimage public, Bob claims on other chain with preimage, double-spends. Missing: mutual exclusion between claim and refund, state flag. Should implement: bool claimed; require(!claimed) in refund. Fix: add state variable tracking claim status, set claimed=true atomically with claim, require !claimed in refund, ensure only one execution path possible.", pc),
                            confidence: 0.86,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_timelock_boundary_exploitation(&self) -> Vec<AtomicSwapRefundRaceVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x10 { // LT (timelock comparison)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let compares_timestamp = self.bytecode[start..pc].iter().any(|&b| b == 0x42);
                if compares_timestamp {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let has_buffer = self.bytecode[start..window_end].iter().filter(|&&b| b == 0x01).count() >= 1;
                    if !has_buffer {
                        vulns.push(AtomicSwapRefundRaceVulnerability {
                            pc,
                            vulnerability_type: "TimelockBoundaryExploitation".to_string(),
                            description: format!("Timelock comparison at PC {} uses exact boundary without buffer, enabling boundary exploitation. Attack: claim valid until block.timestamp < timelock, refund valid when block.timestamp >= timelock, at exact boundary both valid, creates race window. Real vulnerability: claim checks block.timestamp < expiry, refund checks block.timestamp >= expiry, at expiry second both conditions may be true in different transactions same block. Example: HTLC expires at timestamp T, block mined at timestamp T, claim tx checks T < T (false), refund tx checks T >= T (true), but if claim tx evaluated first it may succeed due to reorg or ordering, creates ambiguity. Missing: claim/refund buffer period, strict inequality. Should implement: claim valid until expiry - BUFFER, refund valid after expiry + BUFFER. Fix: add safety buffer, claim requires block.timestamp < expiry - 300, refund requires block.timestamp > expiry + 300, ensures no overlap.", pc),
                            confidence: 0.83,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_missing_claim_atomicity(&self) -> Vec<AtomicSwapRefundRaceVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x14 { // EQ (preimage verification)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let verifies_preimage = self.bytecode[start..pc].iter().filter(|&&b| b == 0x20).count() >= 1;
                if verifies_preimage {
                    let window_end = (pc + 100).min(self.bytecode.len());
                    let has_transfer = self.bytecode[pc..window_end].iter().any(|&b| b == 0xF1);
                    if has_transfer {
                        let atomic_state_update = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x55).count() >= 1;
                        if !atomic_state_update {
                            vulns.push(AtomicSwapRefundRaceVulnerability {
                                pc,
                                vulnerability_type: "MissingClaimAtomicity".to_string(),
                                description: format!("Claim execution at PC {} doesn't atomically update state before transfer, allowing refund during claim. Attack: claim() verifies preimage and transfers, but doesn't set claimed flag before transfer, if transfer reenters or fails, refund still possible, leads to fund loss. Real vulnerability: claim verifies hash, calls payable.transfer(amount), transfer reenters calling refund, claimed flag not yet set, refund succeeds, claim completes, double-payout. Example: Alice claims HTLC with correct preimage, transfer calls Alice's receive(), Alice reenters calling refund (since claimed not set), refund sends funds to Alice again, protocol loses 2x amount. Missing: state-before-interaction pattern, reentrancy guard. Should implement: claimed = true before transfer. Fix: use checks-effects-interactions, set all state variables before external calls, add nonReentrant modifier, emit events before state changes for audit trail.", pc),
                                confidence: 0.85,
                            });
                        }
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }
}
