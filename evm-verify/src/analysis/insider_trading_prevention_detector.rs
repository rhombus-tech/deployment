use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InsiderTradingVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct InsiderTradingPreventionDetector {
    bytecode: Vec<u8>,
}

impl InsiderTradingPreventionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<InsiderTradingVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_privileged_information_trading());
        vulnerabilities.extend(self.detect_pre_announcement_frontrun());
        vulnerabilities.extend(self.detect_oracle_update_insider_trade());

        vulnerabilities
    }

    fn detect_privileged_information_trading(&self) -> Vec<InsiderTradingVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (privileged state change)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_admin_check = window.iter().any(|&b| b == 0x33); // CALLER
                let has_price_impact = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 2;
                
                if has_admin_check && has_price_impact {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_trading_blackout = window.iter().any(|&b| b == 0x42); // TIMESTAMP (lockout period)
                    let has_public_timelock = window.iter().filter(|&&b| b == 0x42).count() >= 2;
                    
                    if !has_trading_blackout && !has_public_timelock {
                        vulns.push(InsiderTradingVulnerability {
                            pc,
                            vulnerability_type: "PrivilegedInformationTrading".to_string(),
                            description: format!(
                                "Admin-controlled state change at PC {} without insider trading prevention. Attack: admin knows parameter change (fee adjustment, pool \
                                ratio, collateral requirements) will affect prices, trades on private information before public announcement, profits from price movement \
                                caused by their own action. Example: admin reduces protocol fee from 1% to 0.1%, knows this will pump token price, buys before announcing, \
                                sells after pump. Missing: trading blackout period for admins, public timelock on parameter changes (24-48 hours), commit-reveal for \
                                governance actions. Should require: all privileged actions announced 24h in advance with admin wallets restricted from trading.",
                                pc
                            ),
                            confidence: 0.86,
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

    fn detect_pre_announcement_frontrun(&self) -> Vec<InsiderTradingVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0xF1 { // CALL (external announcement)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_state_change = window.iter().any(|&b| b == 0x55); // SSTORE
                let has_privileged_caller = window.iter().any(|&b| b == 0x33);
                
                if has_state_change && has_privileged_caller {
                    let has_atomic_execution = window.iter().filter(|&&b| b == 0xF1).count() == 1;
                    let has_commit_reveal = window.iter().filter(|&&b| b == 0x20).count() >= 2; // KECCAK256
                    
                    if !has_atomic_execution && !has_commit_reveal {
                        vulns.push(InsiderTradingVulnerability {
                            pc,
                            vulnerability_type: "PreAnnouncementFrontrun".to_string(),
                            description: format!(
                                "Non-atomic announcement at PC {} enables pre-announcement insider trading. Attack: protocol plans to announce partnership/integration, \
                                insiders trade before announcement transaction is mined, transaction visible in mempool or shared privately, insiders frontrun with buys, \
                                announcement executes and pumps price, insiders sell. Gap between decision and public execution. Missing: atomic announcement+execution, \
                                encrypted announcements until block inclusion, simultaneous disclosure to all participants. Should use: single transaction that both \
                                executes change and emits announcement event, or commit hash N blocks before revealing.",
                                pc
                            ),
                            confidence: 0.84,
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

    fn detect_oracle_update_insider_trade(&self) -> Vec<InsiderTradingVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (oracle price update)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_oracle_role = window.iter().any(|&b| b == 0x14); // EQ (role check)
                let has_price_data = window.iter().filter(|&&b| b == 0x04).count() >= 1; // DIV (price calculation)
                
                if has_oracle_role {
                    let window_end = (pc + 60).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let oracle_can_trade = !window.iter().any(|&b| b == 0x42); // No TIMESTAMP lockout
                    
                    if oracle_can_trade {
                        vulns.push(InsiderTradingVulnerability {
                            pc,
                            vulnerability_type: "OracleUpdateInsiderTrade".to_string(),
                            description: format!(
                                "Oracle update at PC {} without oracle reporter trading restrictions. Attack: oracle reporter sees off-chain price (e.g., CEX shows ETH \
                                crashed to $1000), trades on protocol at old oracle price ($2000), then updates oracle to new price, profits from arbitrage using private \
                                timing advantage. Oracle updaters have seconds-to-minutes of price information lead time. Missing: oracle reporter address trading blackout, \
                                automatic TWAP updates instead of manual, delay between update submission and price activation. Should enforce: oracle reporters cannot \
                                interact with protocol for N blocks before/after price updates.",
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
