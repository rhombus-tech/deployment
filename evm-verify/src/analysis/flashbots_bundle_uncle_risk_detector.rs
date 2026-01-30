use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlashbotsBundleUncleRiskVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct FlashbotsBundleUncleRiskDetector {
    bytecode: Vec<u8>,
}

impl FlashbotsBundleUncleRiskDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<FlashbotsBundleUncleRiskVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_bundle_atomicity_assumption());
        vulnerabilities.extend(self.detect_multi_block_bundle_race());
        vulnerabilities.extend(self.detect_uncle_bandit_protection_missing());
        vulnerabilities
    }

    fn detect_bundle_atomicity_assumption(&self) -> Vec<FlashbotsBundleUncleRiskVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x43 { // NUMBER (assuming bundle in same block)
                let window_end = (pc + 100).min(self.bytecode.len());
                let has_state_dependency = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x54).count() >= 2;
                if has_state_dependency {
                    let validates_block_inclusion = self.bytecode[pc..window_end].iter().any(|&b| b == 0x14);
                    if !validates_block_inclusion {
                        vulns.push(FlashbotsBundleUncleRiskVulnerability {
                            pc, vulnerability_type: "BundleAtomicityAssumption".to_string(),
                            description: format!("Block number dependency at PC {} assumes Flashbots bundle atomicity, vulnerable to uncle risk. Attack: Flashbots bundle with [txA, txB, txC] submitted, block becomes uncle, txA confirmed but txB/txC orphaned, state inconsistent. Real vulnerability: MEV searcher submits bundle loan+arbitrage+repay, block reorged, loan confirmed but repay orphaned, searcher insolvent. Example: bundle flash loans 1000 ETH (txA), swaps for profit (txB), repays loan (txC), miner includes bundle but block becomes uncle due to race, canonical chain has only txA creating bad debt. Missing: check bundle inclusion in canonical chain, implement fallback repayment. Should implement: store bundleId, after N confirmations verify all bundle txs in same canonical block, else trigger emergency repayment. Fix: never assume multi-tx atomicity, always include rollback logic for partial execution.", pc),
                            confidence: 0.84,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_multi_block_bundle_race(&self) -> Vec<FlashbotsBundleUncleRiskVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x55 { // SSTORE (bundle state transition)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let reads_previous_state = self.bytecode[start..pc].iter().any(|&b| b == 0x54);
                if reads_previous_state {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let has_block_validation = self.bytecode[start..window_end].iter().filter(|&&b| b == 0x43).count() >= 2;
                    if !has_block_validation {
                        vulns.push(FlashbotsBundleUncleRiskVulnerability {
                            pc, vulnerability_type: "MultiBlockBundleRace".to_string(),
                            description: format!("State transition at PC {} in multi-block bundle doesn't validate block progression, vulnerable to reorg race. Attack: Flashbots multi-block bundle spans blocks N and N+1, block N becomes uncle, state changes in N lost but bundle continues executing in N+1. Real attack: searcher plans 2-block MEV strategy: block N setup flash loan state, block N+1 execute arbitrage and repay, block N reorged, block N+1 executes with missing setup. Example: block 100 bundle sets storage slot for loan amount, block 101 bundle reads slot to determine repayment, reorg changes block 100, block 101 reads stale/missing value, repayment fails. Missing: validate block.number continuity, store block hash checkpoints. Fix: require(blockHash(blockNumber - 1) == expectedHash) to detect reorgs, implement checkpoint system.", pc),
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

    fn detect_uncle_bandit_protection_missing(&self) -> Vec<FlashbotsBundleUncleRiskVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0xF1 { // CALL (bundle transaction)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let has_value_transfer = self.bytecode[start..pc].iter().any(|&b| b == 0x34);
                if has_value_transfer {
                    let checks_bundle_validity = self.bytecode[start..pc].iter().filter(|&&b| b == 0x43).count() >= 1;
                    if !checks_bundle_validity {
                        vulns.push(FlashbotsBundleUncleRiskVulnerability {
                            pc, vulnerability_type: "UncleBanditProtectionMissing".to_string(),
                            description: format!("Value transfer at PC {} in Flashbots bundle lacks uncle bandit protection. Attack: uncle bandit attack where attacker submits competing bundle causing target bundle's block to become uncle, capturing uncle rewards. Real vulnerability: high-value MEV bundle submitted via Flashbots, attacker creates competing block with same parent, target block becomes uncle, attacker's block canonical, MEV opportunity stolen. Example: searcher's bundle extracts $100k MEV in block N, attacker sees bundle in Flashbots relay, creates competing block N with own MEV extraction, wins race making searcher's block uncle, steals $100k opportunity plus uncle reward. Missing: uncle detection, multi-block confirmation, or payment escrow. Should implement: payment to recipient only after 12 confirmations to ensure block canonicity. Fix: use time-lock contracts releasing funds only after sufficient confirmations, monitor for bundle reorg events.", pc),
                            confidence: 0.76,
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
