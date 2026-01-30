use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockNumberDependencyVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct BlockNumberDependencyManipulationDetector {
    bytecode: Vec<u8>,
}

impl BlockNumberDependencyManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<BlockNumberDependencyVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_block_height_race_condition());
        vulnerabilities.extend(self.detect_reorg_vulnerability());
        vulnerabilities.extend(self.detect_block_based_randomness());

        vulnerabilities
    }

    fn detect_block_height_race_condition(&self) -> Vec<BlockNumberDependencyVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x43 { // NUMBER
                let window_end = (pc + 80).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_state_change = window.iter().any(|&b| b == 0x55); // SSTORE
                let has_comparison = window.iter().any(|&b| b == 0x14); // EQ (exact block check)
                
                if has_state_change && has_comparison {
                    let has_range_check = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 2;
                    
                    if !has_range_check {
                        vulns.push(BlockNumberDependencyVulnerability {
                            pc,
                            vulnerability_type: "BlockHeightRaceCondition".to_string(),
                            description: format!(
                                "Exact block number check at PC {} creates race condition. Multiple transactions in same block compete \
                                for execution order. Attack: submit multiple transactions at target block, first to execute wins, \
                                creates MEV opportunity. Missing: block range instead of exact number, transaction ordering protection, \
                                deterministic execution order. Should not rely on exact block.number for critical logic.",
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

    fn detect_reorg_vulnerability(&self) -> Vec<BlockNumberDependencyVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x43 { // NUMBER
                let start = if pc > 80 { pc - 80 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_cross_chain = window.iter().any(|&b| matches!(b, 0xF1 | 0xFA)); // External call
                
                if has_cross_chain {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_finality_delay = forward.iter().any(|&b| b == 0x03); // SUB (checking confirmations)
                    let has_minimum_depth = forward.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    
                    if !has_finality_delay || !has_minimum_depth {
                        vulns.push(BlockNumberDependencyVulnerability {
                            pc,
                            vulnerability_type: "ReorgVulnerability".to_string(),
                            description: format!(
                                "Block number at PC {} used without reorg protection. Recent blocks can be reorganized, invalidating \
                                block-based logic. Attack: trigger action based on block N, chain reorgs, different block N appears with \
                                different state. Missing: minimum confirmation depth (e.g., 7+ blocks), finality wait period, reorg detection. \
                                Critical for cross-chain bridges and high-value operations.",
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

    fn detect_block_based_randomness(&self) -> Vec<BlockNumberDependencyVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x43 { // NUMBER
                let window_end = (pc + 60).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_hash = window.iter().any(|&b| b == 0x20); // KECCAK256
                let has_mod = window.iter().any(|&b| b == 0x06); // MOD (randomness generation)
                
                if has_hash && has_mod {
                    let has_vrf = window.iter().any(|&b| b == 0x01); // ECRECOVER (VRF verification)
                    let has_commit_reveal = window.iter().filter(|&&b| b == 0x20).count() >= 3;
                    
                    if !has_vrf && !has_commit_reveal {
                        vulns.push(BlockNumberDependencyVulnerability {
                            pc,
                            vulnerability_type: "BlockBasedRandomness".to_string(),
                            description: format!(
                                "Block number used for randomness at PC {}. Block numbers predictable and miner-influenceable. \
                                Attack: miner sees upcoming lottery based on next block number, chooses to mine or skip block to \
                                influence outcome. Missing: VRF (Verifiable Random Function), Chainlink VRF, commit-reveal with \
                                multiple participants. Block-based randomness is not secure for valuable outcomes.",
                                pc
                            ),
                            confidence: 0.88,
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
