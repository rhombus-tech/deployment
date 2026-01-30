use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompoundCtokenExchangeRateVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct CompoundCtokenExchangeRateStalenessDetector {
    bytecode: Vec<u8>,
}

impl CompoundCtokenExchangeRateStalenessDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<CompoundCtokenExchangeRateVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_cached_exchange_rate());
        vulnerabilities.extend(self.detect_accrual_block_number_stale());
        vulnerabilities.extend(self.detect_exchange_rate_manipulation_window());
        vulnerabilities
    }

    fn detect_cached_exchange_rate(&self) -> Vec<CompoundCtokenExchangeRateVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0xFA { // STATICCALL (exchangeRateCurrent)
                let window_end = (pc + 100).min(self.bytecode.len());
                let stores_result = self.bytecode[pc..window_end].iter().any(|&b| b == 0x55);
                if stores_result {
                    let next_usage = self.bytecode[window_end..(window_end + 200).min(self.bytecode.len())].iter().any(|&b| b == 0x54);
                    if next_usage {
                        vulns.push(CompoundCtokenExchangeRateVulnerability {
                            pc, vulnerability_type: "CachedExchangeRate".to_string(),
                            description: format!("Compound cToken exchange rate cached at PC {} without accrual, becomes stale. Attack: protocol caches exchangeRateStored() instead of calling exchangeRateCurrent(), interest accrues, cached rate outdated. Real example: exchange rate 0.02 (1 cToken = 0.02 DAI), protocol caches this, blocks pass, actual rate now 0.0205, protocol still uses 0.02 for calculations. Missing: call accrueInterest() before reading exchange rate, or use exchangeRateCurrent() which auto-accrues. Exploit: user redeems cTokens, gets less underlying due to stale rate, attacker front-runs with accrueInterest(), profits from rate difference. Fix: always call exchangeRateCurrent() or manually accrueInterest() + exchangeRateStored().", pc),
                            confidence: 0.87,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_accrual_block_number_stale(&self) -> Vec<CompoundCtokenExchangeRateVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x43 { // NUMBER (block.number)
                let window_end = (pc + 80).min(self.bytecode.len());
                let has_comparison = self.bytecode[pc..window_end].iter().any(|&b| b == 0x14);
                if has_comparison {
                    let has_accrual_call = self.bytecode[pc..window_end].iter().any(|&b| b == 0xF1);
                    if !has_accrual_call {
                        vulns.push(CompoundCtokenExchangeRateVulnerability {
                            pc, vulnerability_type: "AccrualBlockNumberStale".to_string(),
                            description: format!("Block number check at PC {} compares accrualBlockNumber but doesn't trigger accrual if stale. Attack: protocol checks if accrualBlockNumber < block.number, detects staleness, but doesn't call accrueInterest(), continues with stale state. Real vulnerability: Hundred Finance exploit involved stale interest accrual allowing over-borrowing. Missing: if (accrualBlockNumber < block.number) then call accrueInterest(). Should implement: require(accrueInterest() == 0) before any critical operation. Attack: manipulate timing to use stale rates for favorable borrow/redeem terms. Fix: enforce accrual before reads.", pc),
                            confidence: 0.83,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_exchange_rate_manipulation_window(&self) -> Vec<CompoundCtokenExchangeRateVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0xF1 { // CALL (mint/redeem)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let has_rate_read = self.bytecode[start..pc].iter().any(|&b| b == 0xFA);
                if has_rate_read {
                    let window_end = (pc + 60).min(self.bytecode.len());
                    let has_reentrancy_guard = self.bytecode[start..window_end].iter().filter(|&&b| b == 0x55).count() >= 2;
                    if !has_reentrancy_guard {
                        vulns.push(CompoundCtokenExchangeRateVulnerability {
                            pc, vulnerability_type: "ExchangeRateManipulationWindow".to_string(),
                            description: format!("cToken operation at PC {} reads exchange rate then executes, allowing rate manipulation between read and use. Attack: attacker reads exchangeRateCurrent(), deposits massive amount to cToken changing exchange rate, protocol's pending transaction executes with outdated rate assumption. Real attack: flash loan 100M DAI, mint cDAI inflating exchange rate, victim's redeem transaction executes expecting old rate, receives less. Missing: atomic rate read and use, or rate bounds checking. Fix: implement slippage protection, cache rate in same transaction as usage, add minimum output amount parameter.", pc),
                            confidence: 0.79,
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
