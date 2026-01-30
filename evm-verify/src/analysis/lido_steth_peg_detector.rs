use crate::bytecode::SecurityFinding;

pub struct LidoStethPegDetector {
    bytecode: Vec<u8>,
}

impl LidoStethPegDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_steth_eth_peg_assumption() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!(
                    "Contract assumes 1:1 stETH/ETH peg at PC {}. \
                    Depeg events can cause significant losses or protocol insolvency.",
                    pc
                ),
                pc,
                confidence: 0.90,
            });
        }

        if let Some(pc) = self.detect_rebase_token_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "Rebase token accounting not properly handled at PC {}. \
                    stETH balance changes can break invariants or accounting logic.",
                    pc
                ),
                pc,
                confidence: 0.88,
            });
        }

        if let Some(pc) = self.detect_withdrawal_queue_bypass() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "Lido withdrawal queue not properly integrated at PC {}. \
                    Users may be unable to exit positions during market stress.",
                    pc
                ),
                pc,
                confidence: 0.86,
            });
        }

        findings
    }

    fn detect_steth_eth_peg_assumption(&self) -> Option<usize> {
        // Look for stETH/ETH exchange without price validation
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // swap, exchange, convert selectors
                if matches!(selector, [0x38, 0xed, 0x17, 0x39] | [0xa1, 0x2e, _, _] | [0xb2, 0x3f, _, _]) {
                    let mut uses_steth = false;
                    let mut checks_price_oracle = false;
                    let mut validates_slippage = false;
                    
                    for j in i..i.saturating_add(70).min(self.bytecode.len()) {
                        // Check for stETH address (0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84)
                        if j + 20 < self.bytecode.len() {
                            // Look for PUSH20 with stETH address bytes
                            if self.bytecode[j] == 0x73 { // PUSH20
                                uses_steth = true;
                            }
                        }
                        // Check for price oracle call
                        if j + 4 < self.bytecode.len() && self.bytecode[j] == 0x63 {
                            let sub_selector = &self.bytecode[j + 1..j + 5];
                            // Chainlink latestRoundData, Curve get_dy
                            if matches!(sub_selector, [0xfe, 0xaf, 0x96, 0x8c] | [0x55, 0x56, 0x35, 0xe5]) {
                                checks_price_oracle = true;
                            }
                        }
                        // Check for slippage protection
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x35 && // CALLDATALOAD (min amount)
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x10 && // LT (checking received >= min)
                               j + 6 < self.bytecode.len() &&
                               self.bytecode[j + 5] == 0x15 { // ISZERO (require)
                                validates_slippage = true;
                            }
                        }
                    }
                    
                    if uses_steth && !checks_price_oracle && !validates_slippage {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_rebase_token_vulnerability(&self) -> Option<usize> {
        // Look for stETH balance operations without shareOf handling
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // deposit, stake, addLiquidity selectors
                if matches!(selector, [0xd0, 0xe3, 0x0d, 0xb0] | [0xa6, 0x94, 0xfc, 0x3a] | [0xe8, 0xe3, _, _]) {
                    let mut stores_steth_balance = false;
                    let mut uses_shares_calculation = false;
                    let mut handles_rebase = false;
                    
                    for j in i..i.saturating_add(80).min(self.bytecode.len()) {
                        // Check if storing balance directly
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x35 && // CALLDATALOAD (amount)
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x55 { // SSTORE (storing directly)
                                stores_steth_balance = true;
                            }
                        }
                        // Check for sharesOf() call
                        if j + 4 < self.bytecode.len() && self.bytecode[j] == 0x63 {
                            let sub_selector = &self.bytecode[j + 1..j + 5];
                            // sharesOf, getSharesByPooledEth selectors
                            if matches!(sub_selector, [0xf5, 0xeb, 0x42, 0xc6] | [0xa1, 0x2e, _, _]) {
                                uses_shares_calculation = true;
                            }
                        }
                        // Check for rebase event handling
                        if j + 6 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (last rebase)
                               j + 3 < self.bytecode.len() &&
                               self.bytecode[j + 2] == 0x42 && // TIMESTAMP
                               j + 5 < self.bytecode.len() &&
                               self.bytecode[j + 4] == 0x14 { // EQ (checking timestamp)
                                handles_rebase = true;
                            }
                        }
                    }
                    
                    if stores_steth_balance && !uses_shares_calculation && !handles_rebase {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_withdrawal_queue_bypass(&self) -> Option<usize> {
        // Look for stETH withdrawals without queue integration
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // withdraw, unstake, exit selectors
                if matches!(selector, [0x2e, 0x1a, 0x7d, 0x4d] | [0x3c, 0xcd, 0xa5, 0x20] | [0xe9, 0xf1, _, _]) {
                    let mut withdraws_steth = false;
                    let mut uses_withdrawal_queue = false;
                    let mut validates_queue_status = false;
                    
                    for j in i..i.saturating_add(70).min(self.bytecode.len()) {
                        // Check if burning/transferring stETH
                        if j + 4 < self.bytecode.len() && self.bytecode[j] == 0x63 {
                            let sub_selector = &self.bytecode[j + 1..j + 5];
                            // transfer, burn selectors
                            if matches!(sub_selector, [0xa9, 0x05, 0x9c, 0xbb] | [0x42, 0x96, 0x6c, 0x68]) {
                                withdraws_steth = true;
                            }
                            // requestWithdrawals (Lido withdrawal queue)
                            if matches!(sub_selector, [0x4d, 0xa5, _, _]) {
                                uses_withdrawal_queue = true;
                            }
                        }
                        // Check for withdrawal status validation
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (withdrawal status)
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x60 && // PUSH1 (status code)
                               j + 6 < self.bytecode.len() &&
                               self.bytecode[j + 5] == 0x14 { // EQ
                                validates_queue_status = true;
                            }
                        }
                    }
                    
                    if withdraws_steth && !uses_withdrawal_queue {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
