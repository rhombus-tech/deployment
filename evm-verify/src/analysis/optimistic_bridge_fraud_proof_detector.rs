use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimisticBridgeVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct OptimisticBridgeFraudProofDetector {
    bytecode: Vec<u8>,
}

impl OptimisticBridgeFraudProofDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<OptimisticBridgeVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_challenge_period_bypass());
        vulnerabilities.extend(self.detect_fraud_proof_griefing());
        vulnerabilities.extend(self.detect_invalid_state_root_acceptance());

        vulnerabilities
    }

    fn detect_challenge_period_bypass(&self) -> Vec<OptimisticBridgeVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (withdrawal finalization)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_timestamp_check = window.iter().any(|&b| b == 0x42); // TIMESTAMP
                let has_withdrawal_logic = window.iter().any(|&b| b == 0xF1); // CALL
                
                if has_timestamp_check && has_withdrawal_logic {
                    let has_challenge_period = window.iter().filter(|&&b| b == 0x42).count() >= 2;
                    let has_state_verification = window.iter().any(|&b| b == 0x20); // KECCAK256
                    
                    if !has_challenge_period || !has_state_verification {
                        vulns.push(OptimisticBridgeVulnerability {
                            pc,
                            vulnerability_type: "ChallengePeriodBypass".to_string(),
                            description: format!(
                                "Optimistic bridge finalization at PC {} bypasses challenge period. Attack: bridge allows withdrawal finalization without enforcing \
                                7-day challenge period, proposer submits fraudulent state root, immediately finalizes withdrawals before fraud proof submitted, steals \
                                bridge funds. Optimistic bridges rely on fraud proofs during challenge window. Example: Optimism/Arbitrum bridges require 7-day wait, \
                                attacker finds bug allowing early finalization, withdraws stolen funds in hours. Missing: strict timestamp validation (current_time >= \
                                proposal_time + CHALLENGE_PERIOD), state root challenge verification, re-entrance protection on finalization. Should enforce: \
                                require(block.timestamp >= withdrawal.timestamp + 7 days, 'Challenge period not elapsed').",
                                pc
                            ),
                            confidence: 0.90,
                        });
                    }
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_fraud_proof_griefing(&self) -> Vec<OptimisticBridgeVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (challenge submission)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_challenge_bond = window.iter().any(|&b| b == 0x47); // SELFBALANCE (bond check)
                let has_challenge_validation = window.iter().filter(|&&b| b == 0x20).count() >= 1;
                
                if has_challenge_bond {
                    let has_frivolous_challenge_penalty = window.iter().filter(|&&b| b == 0x03).count() >= 2; // SUB (slashing)
                    let has_challenge_verification_cost = window.iter().any(|&b| b == 0x02); // MUL (gas cost)
                    
                    if !has_frivolous_challenge_penalty {
                        vulns.push(OptimisticBridgeVulnerability {
                            pc,
                            vulnerability_type: "FraudProofGriefing".to_string(),
                            description: format!(
                                "Fraud proof submission at PC {} vulnerable to griefing attacks. Attack: submitting fraud proofs is cheap or free, griefer repeatedly \
                                challenges valid state roots, forces proposers to defend against frivolous challenges, increases bridge operating costs and delays. DoS \
                                via spam challenges. Example: challenger posts small bond ($100), submits invalid challenge, proposer must spend $1000 in gas defending, \
                                challenger loses bond but caused $1000 damage, repeat. Missing: significant challenge bond (proportional to withdrawal size), bond slashing \
                                for invalid challenges, rate limiting on challenges per address. Should require: challenge_bond >= withdrawal_value * 0.1, slash entire \
                                bond if challenge proven frivolous, max 1 challenge per address per week.",
                                pc
                            ),
                            confidence: 0.85,
                        });
                    }
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_invalid_state_root_acceptance(&self) -> Vec<OptimisticBridgeVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (state root proposal)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_state_root = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                let has_proposer = window.iter().any(|&b| b == 0x33); // CALLER
                
                if has_state_root {
                    let has_validity_check = window.iter().filter(|&&b| b == 0x20).count() >= 2; // KECCAK256 checks
                    let has_sequencer_verification = window.iter().any(|&b| b == 0x14); // EQ (authorized sequencer)
                    
                    if !has_validity_check && !has_sequencer_verification {
                        vulns.push(OptimisticBridgeVulnerability {
                            pc,
                            vulnerability_type: "InvalidStateRootAcceptance".to_string(),
                            description: format!(
                                "State root proposal at PC {} accepts unvalidated roots. Attack: optimistic bridge accepts any state root proposal, attacker proposes \
                                invalid state root showing fraudulent balances, if fraud proof system broken or delayed, invalid root gets finalized, enables theft. \
                                Requires both proposer failure and challenger failure. Example: proposer submits root claiming 1000 ETH deposited when only 100 actually \
                                deposited, no one challenges within 7 days, invalid root finalizes, attacker withdraws 1000 ETH. Missing: state root format validation, \
                                authorized proposer whitelist, basic sanity checks (e.g., state root != 0x0), multiple independent proposers. Should enforce: only \
                                whitelisted sequencers can propose, state root must match expected format, require N independent proposers to agree.",
                                pc
                            ),
                            confidence: 0.87,
                        });
                    }
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }
}
