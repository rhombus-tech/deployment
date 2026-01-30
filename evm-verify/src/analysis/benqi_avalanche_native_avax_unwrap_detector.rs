use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenqiAvaxUnwrapVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct BenqiAvalancheNativeAvaxUnwrapDetector {
    bytecode: Vec<u8>,
}

impl BenqiAvalancheNativeAvaxUnwrapDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<BenqiAvaxUnwrapVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_qiavax_unwrap_reentrancy());
        vulnerabilities.extend(self.detect_exchange_rate_manipulation_during_unwrap());
        vulnerabilities.extend(self.detect_avalanche_c_chain_native_transfer_issue());

        vulnerabilities
    }

    fn detect_qiavax_unwrap_reentrancy(&self) -> Vec<BenqiAvaxUnwrapVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0xF1 { // CALL (native AVAX transfer)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_unwrap_logic = window.iter().any(|&b| b == 0x03); // SUB (burning qiAVAX)
                let has_native_transfer = window.iter().any(|&b| b == 0x34); // CALLVALUE
                
                if has_unwrap_logic {
                    let has_pre_call_state_update = window.iter().any(|&b| b == 0x55); // SSTORE before CALL
                    let has_reentrancy_guard = window.iter().filter(|&&b| b == 0x55).count() >= 2;
                    
                    if !has_pre_call_state_update || !has_reentrancy_guard {
                        vulns.push(BenqiAvaxUnwrapVulnerability {
                            pc,
                            vulnerability_type: "QiAVAXUnwrapReentrancy".to_string(),
                            description: format!(
                                "qiAVAX unwrap at PC {} sends native AVAX before updating state. Attack: unwrap qiAVAX, receive AVAX in fallback, \
                                reenter unwrap() before balance updated, withdraw same qiAVAX multiple times, drain protocol. Avalanche C-Chain native \
                                transfers can trigger fallback. Missing: state update before external call (checks-effects-interactions), reentrancy guard, \
                                pull payment pattern. Should burn qiAVAX balance BEFORE sending AVAX.",
                                pc
                            ),
                            confidence: 0.89,
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

    fn detect_exchange_rate_manipulation_during_unwrap(&self) -> Vec<BenqiAvaxUnwrapVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x04 { // DIV (exchange rate calculation)
                let start = if pc > 80 { pc - 80 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_total_supply = window.iter().any(|&b| b == 0x54); // SLOAD (totalSupply)
                let has_total_cash = window.iter().filter(|&&b| b == 0x54).count() >= 2;
                
                if has_total_supply && has_total_cash {
                    let window_end = (pc + 60).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_rate_lock = window.iter().any(|&b| b == 0x42); // TIMESTAMP (rate freeze)
                    let has_twap = window.iter().filter(|&&b| b == 0x02).count() >= 2; // Multiple MUL
                    
                    if !has_rate_lock && !has_twap {
                        vulns.push(BenqiAvaxUnwrapVulnerability {
                            pc,
                            vulnerability_type: "ExchangeRateManipulationDuringUnwrap".to_string(),
                            description: format!(
                                "Exchange rate at PC {} uses instant values during unwrap. Attack: (1) flashloan large AVAX, (2) deposit to inflate \
                                total cash, (3) exchange rate temporarily increases, (4) unwrap qiAVAX at inflated rate, (5) withdraw AVAX deposit, \
                                (6) repay flashloan, profit from rate manipulation. Missing: exchange rate TWAP, rate snapshot before tx, withdrawal \
                                uses rate from deposit time. Should use time-weighted or locked exchange rate for unwraps.",
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

    fn detect_avalanche_c_chain_native_transfer_issue(&self) -> Vec<BenqiAvaxUnwrapVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0xF1 { // CALL (AVAX transfer)
                let start = if pc > 60 { pc - 60 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_value = window.iter().any(|&b| b == 0x31); // BALANCE or value parameter
                
                if has_value {
                    let window_end = (pc + 30).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_success_check = forward.iter().any(|&b| b == 0x15); // ISZERO
                    let has_revert_on_fail = forward.iter().any(|&b| b == 0xFD); // REVERT
                    let has_fallback_handling = forward.iter().filter(|&&b| b == 0x57).count() >= 2;
                    
                    if has_success_check && !has_fallback_handling {
                        vulns.push(BenqiAvaxUnwrapVulnerability {
                            pc,
                            vulnerability_type: "AvalancheCChainNativeTransferIssue".to_string(),
                            description: format!(
                                "Native AVAX transfer at PC {} doesn't handle recipient contract rejection. Avalanche C-Chain allows contracts to reject \
                                native transfers. Attack: unwrap qiAVAX to contract that reverts on receive, unwrap fails but qiAVAX already burned in \
                                some implementations, funds lost. Or: griefing by forcing unwrap failures. Missing: pull payment pattern, transfer to \
                                escrow first, recipient success not required. Should use: sendValue() with try-catch or WAVAX intermediate.",
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
}
