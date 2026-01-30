use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeefyVaultVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct BeefyVaultPanicWithdrawGriefingDetector {
    bytecode: Vec<u8>,
}

impl BeefyVaultPanicWithdrawGriefingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<BeefyVaultVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_panic_function_dos());
        vulnerabilities.extend(self.detect_emergency_withdrawal_frontrun());
        vulnerabilities.extend(self.detect_vault_pause_griefing());

        vulnerabilities
    }

    fn detect_panic_function_dos(&self) -> Vec<BeefyVaultVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0xF1 { // CALL (panic/emergency withdraw)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_owner_check = window.iter().any(|&b| b == 0x33); // CALLER
                let has_panic_logic = window.iter().filter(|&&b| matches!(b, 0xF1 | 0xF4)).count() >= 2;
                
                if has_owner_check && has_panic_logic {
                    let has_withdrawal_queue = window.iter().any(|&b| b == 0x20); // KECCAK256 (queue mapping)
                    let has_partial_withdrawal = window.iter().any(|&b| b == 0x04); // DIV (proportional)
                    
                    if !has_withdrawal_queue && !has_partial_withdrawal {
                        vulns.push(BeefyVaultVulnerability {
                            pc,
                            vulnerability_type: "PanicFunctionDoS".to_string(),
                            description: format!(
                                "Beefy panic() at PC {} withdraws all funds at once without queue. Attack: vault has $10M in strategy, panic() called, attempts to \
                                withdraw all $10M in single tx, strategy doesn't have sufficient liquidity, tx reverts, vault stuck. Or: gas limit exceeded trying \
                                to process all withdrawals. Griefing: attacker forces panic during illiquid conditions. Missing: withdrawal queue system, batch \
                                processing, partial emergency withdrawals. Should implement: emergency withdrawal over multiple txs with queue.",
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

    fn detect_emergency_withdrawal_frontrun(&self) -> Vec<BeefyVaultVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (withdrawal state)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_emergency_flag = window.iter().any(|&b| b == 0x54); // SLOAD (paused/emergency state)
                let has_withdraw_logic = window.iter().any(|&b| b == 0x03); // SUB (balance decrease)
                
                if has_emergency_flag {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_withdrawal_priority = window.iter().any(|&b| b == 0x42); // TIMESTAMP (order)
                    let has_fair_distribution = forward.iter().any(|&b| b == 0x04); // DIV (pro-rata)
                    
                    if !has_withdrawal_priority {
                        vulns.push(BeefyVaultVulnerability {
                            pc,
                            vulnerability_type: "EmergencyWithdrawalFrontrun".to_string(),
                            description: format!(
                                "Emergency withdrawal at PC {} allows frontrunning. Attack: keeper initiates panic() or emergency mode, sophisticated users observe \
                                tx in mempool, frontrun with withdraw() before panic completes, get out at full share price while remaining depositors bear loss. \
                                Unfair advantage to MEV-equipped users. Missing: withdrawal ordering system, timelock before emergency withdrawals active, snapshot-based \
                                fair withdrawal. Should enforce: FIFO withdrawal queue or pro-rata distribution to all depositors.",
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

    fn detect_vault_pause_griefing(&self) -> Vec<BeefyVaultVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (pause state)
                let start = if pc > 80 { pc - 80 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_pause_function = window.iter().any(|&b| b == 0x33); // CALLER (owner)
                
                if has_pause_function {
                    let has_timelock = window.iter().any(|&b| b == 0x42); // TIMESTAMP
                    let has_unpause_delay = window.iter().filter(|&&b| b == 0x42).count() >= 2;
                    let has_rate_limit = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    
                    if !has_timelock || !has_unpause_delay {
                        vulns.push(BeefyVaultVulnerability {
                            pc,
                            vulnerability_type: "VaultPauseGriefing".to_string(),
                            description: format!(
                                "Vault pause at PC {} allows instant freeze without safeguards. Attack: compromised keeper repeatedly pauses/unpauses vault, users \
                                can't deposit/withdraw during pauses, griefing attack disrupts vault operations. Or: pause during optimal harvest time to sabotage \
                                yields. Missing: pause cooldown period, multi-sig requirement for pause, automatic unpause after timeout, pause reason validation. \
                                Should require: 2-of-3 multisig for pause, 24hr minimum pause period, max consecutive pauses limit.",
                                pc
                            ),
                            confidence: 0.83,
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
