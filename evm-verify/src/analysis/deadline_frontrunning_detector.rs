use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadlineFrontrunVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct DeadlineFrontrunningDetector {
    bytecode: Vec<u8>,
}

impl DeadlineFrontrunningDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<DeadlineFrontrunVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_swap_deadline_bypass());
        vulnerabilities.extend(self.detect_auction_sniping());
        vulnerabilities.extend(self.detect_vesting_cliff_gaming());

        vulnerabilities
    }

    fn detect_swap_deadline_bypass(&self) -> Vec<DeadlineFrontrunVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x42 { // TIMESTAMP (deadline check)
                let start = if pc > 80 { pc - 80 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_deadline_param = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_deadline_param {
                    let window_end = (pc + 60).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_comparison = forward.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    let has_revert = forward.iter().any(|&b| b == 0xFD); // REVERT
                    
                    if has_comparison && has_revert {
                        let has_minimum_deadline = window.windows(2).any(|w| {
                            w[0] >= 0x60 && w[0] <= 0x7F && w[1] == 0x01 // PUSH + ADD (min duration)
                        });
                        
                        if !has_minimum_deadline {
                            vulns.push(DeadlineFrontrunVulnerability {
                                pc,
                                vulnerability_type: "SwapDeadlineBypass".to_string(),
                                description: format!(
                                    "Swap deadline at PC {} accepts arbitrary user-provided values. Attack: user sets deadline = \
                                    block.timestamp (or far future), defeating deadline protection. Frontrunner can delay transaction \
                                    inclusion, execute at unfavorable price within deadline. Missing: minimum deadline duration \
                                    (e.g., 20 minutes), maximum deadline limit, protocol-enforced deadline. Deadline should protect \
                                    against stale transactions, not be user-bypassable.",
                                    pc
                                ),
                                confidence: 0.89,
                            });
                        }
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

    fn detect_auction_sniping(&self) -> Vec<DeadlineFrontrunVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x42 { // TIMESTAMP (auction end)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_auction_data = window.iter().any(|&b| b == 0x54); // SLOAD (auction state)
                
                if has_auction_data {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_end_check = forward.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    
                    if has_end_check {
                        let has_extension = forward.iter().any(|&b| b == 0x01); // ADD (extending deadline)
                        let has_final_block = forward.iter().any(|&b| b == 0x43); // NUMBER
                        
                        if !has_extension && !has_final_block {
                            vulns.push(DeadlineFrontrunVulnerability {
                                pc,
                                vulnerability_type: "AuctionSniping".to_string(),
                                description: format!(
                                    "Auction end at PC {} allows last-second sniping without extension. Attack: wait until 1 second \
                                    before deadline, submit winning bid, other bidders have no time to respond. Missing: bid extension \
                                    mechanism (e.g., extend 10 min on late bids), anti-sniping buffer, Vickrey auction design. \
                                    Hard deadline enables unfair advantage to snipers monitoring close timing.",
                                    pc
                                ),
                                confidence: 0.86,
                            });
                        }
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

    fn detect_vesting_cliff_gaming(&self) -> Vec<DeadlineFrontrunVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x42 { // TIMESTAMP (vesting check)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_vesting_start = window.iter().any(|&b| b == 0x54); // SLOAD (vesting schedule)
                
                if has_vesting_start {
                    let window_end = (pc + 100).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_cliff_check = forward.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    let has_token_transfer = forward.iter().any(|&b| matches!(b, 0xF1 | 0x55)); // CALL or SSTORE
                    
                    if has_cliff_check && has_token_transfer {
                        let has_price_protection = window.iter().any(|&b| matches!(b, 0xFA | 0xF1)); // Oracle call
                        let has_gradual_unlock = forward.iter().any(|&b| b == 0x04); // DIV (proportional unlock)
                        
                        if !has_price_protection && !has_gradual_unlock {
                            vulns.push(DeadlineFrontrunVulnerability {
                                pc,
                                vulnerability_type: "VestingCliffGaming".to_string(),
                                description: format!(
                                    "Vesting cliff at PC {} unlocks tokens immediately without market protection. Attack: insider knows \
                                    exact cliff timestamp, frontrun with sell orders, dump entire vested amount at cliff, crashing price. \
                                    Missing: gradual unlock over period, price impact limits, market-aware release. Cliff vesting creates \
                                    predictable dump opportunity exploitable by insiders with timestamp knowledge.",
                                    pc
                                ),
                                confidence: 0.84,
                            });
                        }
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
