use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimisticRollupFraudProofWindowExpiryVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct OptimisticRollupFraudProofWindowExpiryDetector {
    bytecode: Vec<u8>,
}

impl OptimisticRollupFraudProofWindowExpiryDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<OptimisticRollupFraudProofWindowExpiryVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_challenge_period_too_short());
        vulnerabilities.extend(self.detect_no_fraud_proof_extension());
        vulnerabilities.extend(self.detect_state_finalization_before_challenge_end());
        vulnerabilities.extend(self.detect_timestamp_manipulation_in_challenge());
        vulnerabilities
    }

    fn detect_challenge_period_too_short(&self) -> Vec<OptimisticRollupFraudProofWindowExpiryVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x42 { // TIMESTAMP
                let window_end = (pc + 80).min(self.bytecode.len());
                let has_comparison = self.bytecode[pc..window_end].iter().any(|&b| matches!(b, 0x10 | 0x11));
                if has_comparison {
                    let start = if pc > 50 { pc - 50 } else { 0 };
                    let small_constant = self.bytecode[start..window_end].windows(2).any(|w| {
                        w[0] == 0x60 && w[1] > 0 && w[1] < 0x15
                    });
                    if small_constant {
                        vulns.push(OptimisticRollupFraudProofWindowExpiryVulnerability {
                            pc,
                            vulnerability_type: "ChallengePeriodTooShort".to_string(),
                            description: format!("Timestamp comparison at PC {} uses suspiciously short challenge period for optimistic rollup. Attack: challenge period (fraud proof window) set to very short duration (seconds/minutes instead of days), attacker submits invalid state root, honest challengers have insufficient time to detect fraud and submit proof, invalid state finalizes unchallenged. Real vulnerability: optimistic rollups rely on honest actors having enough time to verify off-chain computation and submit fraud proofs if incorrect, too short window makes censorship attacks viable (block fraud proof transactions until window expires). Example: Arbitrum/Optimism typically use 7 day challenge periods, vulnerable contract uses 1 hour, attacker coordinates with sequencer to censor fraud proofs for 60 minutes, withdraws funds based on fraudulent state. Missing: minimum challenge period enforcement (7+ days industry standard). Should implement: challenge_period >= 604800 (7 days). Fix: require minimum challenge period of 7 days (604800 seconds), add emergency extension mechanism if fraud proof submitted near deadline, implement multi-tiered finality (fast finality for small amounts, longer period for large withdrawals), add fraud proof queue system that guarantees inclusion.", pc),
                            confidence: 0.82,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_no_fraud_proof_extension(&self) -> Vec<OptimisticRollupFraudProofWindowExpiryVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x42 { // TIMESTAMP
                let window_end = (pc + 120).min(self.bytecode.len());
                let has_finalization = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x55).count() >= 2;
                if has_finalization {
                    let has_extension_logic = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x01 || b == 0x02).count() >= 3;
                    if !has_extension_logic {
                        vulns.push(OptimisticRollupFraudProofWindowExpiryVulnerability {
                            pc,
                            vulnerability_type: "NoFraudProofExtension".to_string(),
                            description: format!("State finalization at PC {} lacks fraud proof window extension mechanism. Attack: attacker submits invalid state, waits until near end of challenge period, submits valid-looking transaction that takes time to verify, honest verifier discovers fraud but challenge period expires before proof submitted, invalid state finalizes. Real attack: sophisticated fraud that requires complex verification (e.g., invalid merkle proof, state transition error in complex computation), honest challenger needs time to construct counter-proof, fixed deadline doesn't account for proof complexity. Example: invalid rollup batch submitted at T=0, challenger discovers fraud at T=6.9 days, needs 6 hours to generate fraud proof (heavy computation), challenge period ends at T=7 days, fraud proof arrives at T=7.25 days, rejected as late, attacker withdraws. Missing: deadline extension when fraud proof in progress, grace period for proof submission. Should implement: extend window by N hours when fraud proof initiated. Fix: implement fraud proof extension (if fraud proof submitted in last 24 hours of window, extend deadline by 48 hours), add proof-of-intent mechanism (allow challenger to claim intent to prove fraud, locking extension), implement tiered deadlines (initial 7 day window, automatic 2 day extension if challenge initiated), add priority queue for fraud proofs near deadline.", pc),
                            confidence: 0.80,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_state_finalization_before_challenge_end(&self) -> Vec<OptimisticRollupFraudProofWindowExpiryVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x55 { // SSTORE (state finalization)
                let start = if pc > 150 { pc - 150 } else { 0 };
                let has_timestamp_check = self.bytecode[start..pc].iter().any(|&b| b == 0x42);
                let has_comparison = self.bytecode[start..pc].iter().any(|&b| matches!(b, 0x10 | 0x11));
                if has_timestamp_check && !has_comparison {
                    vulns.push(OptimisticRollupFraudProofWindowExpiryVulnerability {
                        pc,
                        vulnerability_type: "StateFinalizationBeforeChallengeEnd".to_string(),
                        description: format!("State write at PC {} may finalize rollup state without proper challenge period verification. Attack: state root marked as finalized before challenge window expires, early finalization allows withdrawals based on unverified state, attacker submits invalid state and immediately withdraws, fraud proof arrives too late (state already finalized). Real vulnerability: optimistic rollups must NOT allow finalization until challenge period fully elapsed AND no pending fraud proofs, premature finalization defeats purpose of optimistic security model. Example: state submitted at block N, contract checks 'submitted_at + 1 day < now' but challenge period is 7 days, state finalizes after 1 day, attacker withdraws with invalid balance, fraud proof submitted on day 3 but state already finalized and withdrawals completed. Missing: strict challenge period enforcement, pending challenge check. Should verify: current_time >= submission_time + FULL_CHALLENGE_PERIOD AND no_pending_fraud_proofs. Fix: require challenge_period_end = submission_timestamp + 604800 (7 days), verify block.timestamp >= challenge_period_end before ANY finalization, add pending_challenges counter (increment on fraud proof start, decrement on resolution), require pending_challenges == 0 for finalization, implement immutable finalization delay (cannot be reduced by governance).", pc),
                        confidence: 0.85,
                    });
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_timestamp_manipulation_in_challenge(&self) -> Vec<OptimisticRollupFraudProofWindowExpiryVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x42 { // TIMESTAMP
                let window_end = (pc + 100).min(self.bytecode.len());
                let used_in_arithmetic = self.bytecode[pc..window_end].iter().any(|&b| matches!(b, 0x01 | 0x02 | 0x03));
                if used_in_arithmetic {
                    let has_block_number_check = self.bytecode[pc..window_end].iter().any(|&b| b == 0x43);
                    if !has_block_number_check {
                        vulns.push(OptimisticRollupFraudProofWindowExpiryVulnerability {
                            pc,
                            vulnerability_type: "TimestampManipulationInChallenge".to_string(),
                            description: format!("Challenge period calculation at PC {} relies solely on block.timestamp without block number verification. Attack: miner/validator manipulates block timestamp to artificially advance challenge deadline, submits invalid state at timestamp T, manipulates next block timestamp to T + 7 days + 1 second, challenge period appears expired in single block, state finalizes immediately. Real vulnerability: block.timestamp can be manipulated by miners within consensus rules (~15 second drift in Ethereum, larger in other chains), optimistic rollup deadlines based only on timestamp vulnerable to miner collusion. Example: attacker controls or bribes block producer, submits fraudulent state at block N (timestamp 1000000), block N+1 has timestamp 1604801 (7 days + 1 second later, but only 12 seconds real time), challenge period 'expired', fraud proof impossible. Missing: block number anchoring, timestamp drift detection. Should use: block.number AND block.timestamp for deadline verification. Fix: store submission_block_number and submission_timestamp, require BOTH conditions for finalization (block.number >= submission_block + 50400 blocks [~7 days at 12s/block] AND block.timestamp >= submission_timestamp + 604800), add maximum timestamp drift check (block.timestamp - previous_timestamp <= 900 [15 min max]), implement fraud proof grace period based on block count (not just time), add timestamp sanity checks comparing to previous blocks.", pc),
                            confidence: 0.78,
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
