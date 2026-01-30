use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UncleBanditVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct UncleBanditAttackDetector {
    bytecode: Vec<u8>,
}

impl UncleBanditAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<UncleBanditVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_block_timestamp_manipulation());
        vulnerabilities.extend(self.detect_uncle_rate_gaming());
        vulnerabilities.extend(self.detect_selfish_mining_incentive());

        vulnerabilities
    }

    fn detect_block_timestamp_manipulation(&self) -> Vec<UncleBanditVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x42 { // TIMESTAMP
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_reward_calculation = window.iter().any(|&b| b == 0x02); // MUL
                let has_conditional = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                
                if has_reward_calculation && has_conditional {
                    let has_timestamp_validation = window.iter().filter(|&&b| b == 0x42).count() >= 2;
                    let has_range_check = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 3;
                    
                    if !has_timestamp_validation {
                        vulns.push(UncleBanditVulnerability {
                            pc,
                            vulnerability_type: "BlockTimestampManipulation".to_string(),
                            description: format!(
                                "Timestamp-dependent logic at PC {} vulnerable to miner manipulation. Uncle bandit attack: miner sets block.timestamp strategically to \
                                maximize rewards or gaming outcomes. In Ethereum pre-Merge: miners could set timestamp ±15 seconds. Attack: time-locked rewards, lottery, \
                                or vesting contract uses block.timestamp for payout eligibility, miner adjusts timestamp to include/exclude own transactions for profit. \
                                Post-Merge: validators have less timestamp control but still ~12s tolerance. Missing: timestamp range validation, block.number for time \
                                instead, oracle-based time. Should use: block.number for intervals or tolerate ±15s manipulation.",
                                pc
                            ),
                            confidence: 0.82,
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

    fn detect_uncle_rate_gaming(&self) -> Vec<UncleBanditVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x43 { // NUMBER (block.number)
                let window_end = (pc + 80).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_modulo = window.iter().any(|&b| b == 0x06); // MOD (block.number % N)
                let has_reward_logic = window.iter().any(|&b| b == 0x02); // MUL
                
                if has_modulo && has_reward_logic {
                    let has_difficulty_check = window.iter().any(|&b| b == 0x44); // DIFFICULTY/PREVRANDAO
                    
                    if !has_difficulty_check {
                        vulns.push(UncleBanditVulnerability {
                            pc,
                            vulnerability_type: "UncleRateGaming".to_string(),
                            description: format!(
                                "Block.number modulo operation at PC {} for reward distribution. Uncle bandit strategy: miner withholds blocks to manipulate uncle rate \
                                and block.number timing. Attack: contract pays bonus every Nth block (e.g., block.number % 100 == 0), miner sees they'll mine block 999, \
                                withholds it to create uncle, causes someone else to mine block 1000, miner then publishes block 999 as uncle and mines block 1001 for \
                                bonus. Gaming block numbering. Missing: randomness source for rewards, uncle-resistant distribution, longer epoch intervals. Should use \
                                VRF or blockhash for unpredictable selection.",
                                pc
                            ),
                            confidence: 0.79,
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

    fn detect_selfish_mining_incentive(&self) -> Vec<UncleBanditVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x02 { // MUL (reward calculation)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_block_reference = window.iter().any(|&b| matches!(b, 0x40 | 0x43 | 0x44)); // BLOCKHASH, NUMBER, DIFFICULTY
                let has_payment = window.iter().any(|&b| b == 0xF1); // CALL (payment)
                
                if has_block_reference && has_payment {
                    let window_end = (pc + 60).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_uncle_detection = forward.iter().any(|&b| b == 0x40); // BLOCKHASH (check for reorg)
                    let has_confirmation_delay = window.iter().filter(|&&b| b == 0x43).count() >= 2;
                    
                    if !has_confirmation_delay {
                        vulns.push(UncleBanditVulnerability {
                            pc,
                            vulnerability_type: "SelfishMiningIncentive".to_string(),
                            description: format!(
                                "Block-based reward at PC {} incentivizes selfish mining. Attack: contract pays immediately upon block.number reaching target, miner \
                                performs selfish mining: mines blocks privately, maintains private chain, when contract reaches payout block on public chain, miner \
                                publishes longer private chain causing reorg, collects payout on their chain. Honest miners' blocks become uncles. Missing: \
                                confirmation depth requirement (e.g., must wait 12 blocks), reorg detection and reversal, oracle-based finality. Should require: \
                                payout only after N confirmations to make reorg economically unfeasible.",
                                pc
                            ),
                            confidence: 0.81,
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
