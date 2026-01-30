use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LidoStEthRebaseVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct LidoStethRebaseSandwichDetector {
    bytecode: Vec<u8>,
}

impl LidoStethRebaseSandwichDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<LidoStEthRebaseVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_rebase_frontrun_attack());
        vulnerabilities.extend(self.detect_share_price_manipulation());
        vulnerabilities.extend(self.detect_oracle_report_sandwich());

        vulnerabilities
    }

    fn detect_rebase_frontrun_attack(&self) -> Vec<LidoStEthRebaseVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (totalPooledEther update)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_rebase_logic = window.iter().any(|&b| b == 0x01); // ADD (rewards)
                let has_total_shares = window.iter().filter(|&&b| b == 0x54).count() >= 2;
                
                if has_rebase_logic {
                    let has_rebase_delay = window.iter().any(|&b| b == 0x42); // TIMESTAMP
                    let has_frontrun_protection = window.iter().filter(|&&b| b == 0x42).count() >= 2;
                    
                    if !has_frontrun_protection {
                        vulns.push(LidoStEthRebaseVulnerability {
                            pc,
                            vulnerability_type: "RebaseFrontrunAttack".to_string(),
                            description: format!(
                                "Lido stETH rebase at PC {} allows MEV sandwich. Attack: (1) observe oracle report tx in mempool (beacon chain rewards), \
                                (2) frontrun: deposit ETH to mint stETH at old exchange rate, (3) rebase executes, totalPooledEther increases, stETH price per \
                                share increases, (4) backrun: transfer stETH to exploit higher value. Predictable rebase timing enables profitable MEV. Missing: \
                                commit-reveal for oracle reports, randomized rebase timing, MEV-resistant rebase mechanism. Should delay rebase effects or use \
                                time-weighted averaging.",
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

    fn detect_share_price_manipulation(&self) -> Vec<LidoStEthRebaseVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x04 { // DIV (shares to stETH conversion)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_pooled_ether = window.iter().any(|&b| b == 0x54); // SLOAD (totalPooledEther)
                let has_total_shares = window.iter().filter(|&&b| b == 0x54).count() >= 2;
                
                if has_pooled_ether && has_total_shares {
                    let has_manipulation_check = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // Bounds
                    let has_rate_limit = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 2;
                    
                    if !has_rate_limit {
                        vulns.push(LidoStEthRebaseVulnerability {
                            pc,
                            vulnerability_type: "SharePriceManipulation".to_string(),
                            description: format!(
                                "Share price calculation at PC {} vulnerable to manipulation during rebase window. Attack: Lido rebases daily, exchange rate = \
                                totalPooledEther / totalShares changes. Attacker exploits: (1) deposit large amount right before positive rebase, (2) withdraw \
                                right after rebase capturing gains, (3) repeat daily. Or: manipulate totalPooledEther via slashing/penalty events. Missing: \
                                minimum hold period for rebase participation, deposit/withdrawal cooldown, gradual rebase distribution. Should enforce time-weighted \
                                rewards or lockup for rebase benefits.",
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

    fn detect_oracle_report_sandwich(&self) -> Vec<LidoStEthRebaseVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0xF1 { // CALL (oracle report submission)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_oracle_data = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_oracle_data {
                    let window_end = (pc + 100).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_immediate_rebase = forward.iter().any(|&b| b == 0x55); // SSTORE after report
                    let has_commit_delay = window.iter().filter(|&&b| b == 0x42).count() >= 2;
                    
                    if has_immediate_rebase && !has_commit_delay {
                        vulns.push(LidoStEthRebaseVulnerability {
                            pc,
                            vulnerability_type: "OracleReportSandwich".to_string(),
                            description: format!(
                                "Oracle report at PC {} triggers immediate rebase allowing sandwich. Lido oracles report beacon chain balance changes. Attack: \
                                MEV searcher monitors beacon chain, predicts oracle report value (positive/negative), observes oracle tx, sandwiches: (1) frontrun \
                                with large deposit if positive report, (2) oracle reports, rebase happens, (3) backrun with withdrawal/transfer at better rate. \
                                Missing: oracle report aggregation delay, commit-reveal scheme, encrypted oracle submissions. Should use: threshold decryption or \
                                time-locked oracle reveals to prevent frontrunning.",
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
