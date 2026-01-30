use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AaveAtokenRebasingVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct AaveAtokenRebasingIntegrationDetector {
    bytecode: Vec<u8>,
}

impl AaveAtokenRebasingIntegrationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<AaveAtokenRebasingVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_stale_balance_cache());
        vulnerabilities.extend(self.detect_rebasing_accounting_mismatch());
        vulnerabilities.extend(self.detect_transfer_after_index_update());
        vulnerabilities
    }

    fn detect_stale_balance_cache(&self) -> Vec<AaveAtokenRebasingVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x54 { // SLOAD (balance read)
                let window_end = (pc + 100).min(self.bytecode.len());
                let has_timestamp_check = self.bytecode[pc..window_end].iter().any(|&b| b == 0x42);
                if !has_timestamp_check && self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x54).count() >= 2 {
                    vulns.push(AaveAtokenRebasingVulnerability {
                        pc, vulnerability_type: "StaleBalanceCache".to_string(),
                        description: format!("Aave aToken balance read at PC {} caches scaled balance without checking latest liquidity index. Real attack: protocol integrates aTokens, reads balanceOf once, stores value, index updates (rebases), cached balance becomes stale. Example: user deposits 100 DAI, receives 100 aDAI (index=1.0), index updates to 1.1, real balance=110 aDAI, cached balance still 100. Missing: call scaledBalanceOf() and multiply by current index, or query balanceOf() fresh each time. Attack vector: arbitrage between stale cache and real balance, drain protocol by exploiting outdated values. Fix: never cache aToken balances, always read fresh with index multiplication.", pc),
                        confidence: 0.84,
                    });
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_rebasing_accounting_mismatch(&self) -> Vec<AaveAtokenRebasingVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x55 { // SSTORE (accounting update)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let has_external_call = self.bytecode[start..pc].iter().any(|&b| b == 0xFA);
                let has_mul = self.bytecode[start..pc].iter().any(|&b| b == 0x02);
                if has_external_call && !has_mul {
                    vulns.push(AaveAtokenRebasingVulnerability {
                        pc, vulnerability_type: "RebasingAccountingMismatch".to_string(),
                        description: format!("Accounting storage at PC {} treats aTokens as non-rebasing, causing mismatch. Attack: vault accepts aDAI deposits, stores amount directly (100 aDAI), index increases 10%, user withdraws, contract thinks they have 100 but actually 110, accounting breaks. Real exploit: Rari Capital Fuse hack involved improper aToken accounting. Missing: store scaled balance (rayDiv by index) or track deposits in underlying asset terms. Should implement: scaledBalance = balance.rayDiv(liquidityIndex), store scaledBalance, multiply by current index on withdrawal. Attack: deposit when index low, withdraw when index high, steal rebasing yield from other depositors.", pc),
                        confidence: 0.88,
                    });
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_transfer_after_index_update(&self) -> Vec<AaveAtokenRebasingVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0xF1 { // CALL (transfer)
                let start = if pc > 80 { pc - 80 } else { 0 };
                if self.bytecode[start..pc].iter().filter(|&&b| b == 0xF1).count() >= 2 {
                    let window_end = (pc + 60).min(self.bytecode.len());
                    let checks_balance_after = self.bytecode[pc..window_end].iter().any(|&b| b == 0xFA);
                    if !checks_balance_after {
                        vulns.push(AaveAtokenRebasingVulnerability {
                            pc, vulnerability_type: "TransferAfterIndexUpdate".to_string(),
                            description: format!("aToken transfer at PC {} doesn't re-check balance after index update, allowing front-run. Attack: attacker sees protocol transferring aTokens, frontruns with index update transaction, transfer executes with outdated balance calculation. Real scenario: protocol calls aDAI.transfer(user, calculatedAmount), attacker triggers LendingPool.deposit causing index update, calculatedAmount now incorrect. Missing: re-read balanceOf after any external call that could update index. Fix: use transfer-and-verify pattern, check recipient balance after transfer matches expected post-rebase amount.", pc),
                            confidence: 0.81,
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
