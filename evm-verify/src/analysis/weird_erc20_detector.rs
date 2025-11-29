/// Weird ERC20 Token Detector
/// Detects non-standard ERC20 behaviors: fee-on-transfer, rebasing, ERC-777 hooks

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeirdERC20Vulnerability {
    pub vulnerability_type: WeirdERC20Issue,
    pub severity: SecuritySeverity,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
    pub pc: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WeirdERC20Issue {
    /// Token takes fee on transfer (deflationary)
    FeeOnTransfer,
    /// Token balance changes over time (rebasing)
    RebasingToken,
    /// ERC-777 with reentrant hooks
    ERC777Hooks,
    /// Multiple tokens sent (e.g., stETH rewards)
    MultipleAddressReturn,
    /// Missing return value check
    MissingReturnValue,
}

pub struct WeirdERC20Detector {
    bytecode: Vec<u8>,
}

impl WeirdERC20Detector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<WeirdERC20Vulnerability> {
        let mut vulns = Vec::new();
        vulns.extend(self.detect_fee_on_transfer());
        vulns.extend(self.detect_rebasing_assumptions());
        vulns.extend(self.detect_erc777_hooks());
        vulns.extend(self.detect_missing_return_check());
        vulns
    }

    /// Detect unsafe fee-on-transfer token handling
    fn detect_fee_on_transfer(&self) -> Vec<WeirdERC20Vulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        // Pattern: transferFrom() followed by balance increment WITHOUT checking actual received amount
        while pc < self.bytecode.len() {
            // Look for CALL (external transferFrom)
            if self.bytecode[pc] == 0xF1 {
                // Check if followed by ADD to balance mapping (unsafe assumption)
                if self.has_balance_add_after(pc, 100) && !self.has_balance_check_between(pc, pc + 100) {
                    vulns.push(WeirdERC20Vulnerability {
                        vulnerability_type: WeirdERC20Issue::FeeOnTransfer,
                        severity: SecuritySeverity::Critical,
                        description: "Contract assumes transfer amount equals received amount - breaks with fee-on-transfer tokens".to_string(),
                        exploit_scenario: "Fee-on-transfer token exploit:\n\
                            1. Token takes 1% fee on transfer\n\
                            2. User deposits 100 tokens\n\
                            3. Contract receives 99 tokens\n\
                            4. Contract credits user 100 tokens\n\
                            5. User withdraws 100 tokens\n\
                            6. Profit: 1 token stolen from pool\n\
                            \n\
                            Real example: Balancer (2023)".to_string(),
                        remediation: "Check actual balance change:\n\
                            uint balanceBefore = token.balanceOf(address(this));\n\
                            token.transferFrom(msg.sender, address(this), amount);\n\
                            uint balanceAfter = token.balanceOf(address(this));\n\
                            uint actualReceived = balanceAfter - balanceBefore;\n\
                            balances[msg.sender] += actualReceived;".to_string(),
                        pc,
                    });
                }
            }
            pc += 1;
            if pc > 0 && self.bytecode[pc-1] >= 0x60 && self.bytecode[pc-1] <= 0x7F {
                pc += (self.bytecode[pc-1] - 0x5F) as usize;
            }
        }
        vulns
    }

    /// Detect rebasing token assumption violations
    fn detect_rebasing_assumptions(&self) -> Vec<WeirdERC20Vulnerability> {
        let mut vulns = Vec::new();
        
        // Look for: balanceOf() result stored, then used later without re-checking
        let has_balance_storage = self.has_pattern(&[0xF1, 0x55]); // CALL, SSTORE
        let has_balance_reuse = self.has_pattern(&[0x54]); // SLOAD of old balance
        
        if has_balance_storage && has_balance_reuse {
            vulns.push(WeirdERC20Vulnerability {
                vulnerability_type: WeirdERC20Issue::RebasingToken,
                severity: SecuritySeverity::High,
                description: "Contract stores token balance and reuses without re-checking - breaks with rebasing tokens".to_string(),
                exploit_scenario: "Rebasing token exploit:\n\
                    1. Contract stores: balance = stETH.balanceOf(this) = 100\n\
                    2. Positive rebase occurs: actual balance now 101\n\
                    3. Contract uses stored value: 100\n\
                    4. 1 stETH permanently locked/untracked\n\
                    \n\
                    Real example: Multiple stETH integrations".to_string(),
                remediation: "Always query balance fresh:\n\
                    // DON'T store balanceOf results\n\
                    // DO query each time:\n\
                    uint currentBalance = token.balanceOf(address(this));".to_string(),
                pc: 0,
            });
        }
        vulns
    }

    /// Detect ERC-777 hook reentrancy
    fn detect_erc777_hooks(&self) -> Vec<WeirdERC20Vulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        // Pattern: CALL followed by state change (unsafe for ERC-777)
        while pc < self.bytecode.len() {
            if self.bytecode[pc] == 0xF1 {  // CALL
                // If SSTORE comes AFTER call = vulnerable to ERC-777 reentrancy
                if self.has_sstore_after(pc, 50) {
                    vulns.push(WeirdERC20Vulnerability {
                        vulnerability_type: WeirdERC20Issue::ERC777Hooks,
                        severity: SecuritySeverity::Critical,
                        description: "State updated AFTER external call - vulnerable to ERC-777 reentrancy".to_string(),
                        exploit_scenario: "ERC-777 reentrancy:\n\
                            1. Contract calls token.transfer(attacker, amount)\n\
                            2. ERC-777 calls tokensReceived hook on attacker\n\
                            3. Attacker reenters before state is updated\n\
                            4. Withdraws again\n\
                            5. Double withdraw\n\
                            \n\
                            Real example: Uniswap/Lendf.me ($25M, 2020)".to_string(),
                        remediation: "Use Checks-Effects-Interactions:\n\
                            balances[msg.sender] = 0;  // Update state FIRST\n\
                            token.transfer(msg.sender, amount);  // External call LAST".to_string(),
                        pc,
                    });
                }
            }
            pc += 1;
            if pc > 0 && self.bytecode[pc-1] >= 0x60 && self.bytecode[pc-1] <= 0x7F {
                pc += (self.bytecode[pc-1] - 0x5F) as usize;
            }
        }
        vulns
    }

    /// Detect missing return value checks
    fn detect_missing_return_check(&self) -> Vec<WeirdERC20Vulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // CALL followed by POP (ignoring return value)
            if self.bytecode[pc] == 0xF1 {  // CALL
                if pc + 1 < self.bytecode.len() && self.bytecode[pc + 1] == 0x50 {  // POP
                    vulns.push(WeirdERC20Vulnerability {
                        vulnerability_type: WeirdERC20Issue::MissingReturnValue,
                        severity: SecuritySeverity::High,
                        description: "Transfer return value not checked - fails silently with non-standard tokens".to_string(),
                        exploit_scenario: "Silent failure:\n\
                            1. Token.transfer() returns false (insufficient balance)\n\
                            2. Contract ignores return value\n\
                            3. Contract assumes success\n\
                            4. User credited tokens they didn't receive\n\
                            5. Insolvency".to_string(),
                        remediation: "Check return values:\n\
                            require(token.transfer(to, amount), 'Transfer failed');\n\
                            // Or use SafeERC20:\n\
                            token.safeTransfer(to, amount);".to_string(),
                        pc,
                    });
                }
            }
            pc += 1;
            if pc > 0 && self.bytecode[pc-1] >= 0x60 && self.bytecode[pc-1] <= 0x7F {
                pc += (self.bytecode[pc-1] - 0x5F) as usize;
            }
        }
        vulns
    }

    fn has_balance_add_after(&self, start_pc: usize, window: usize) -> bool {
        let end = (start_pc + window).min(self.bytecode.len());
        self.bytecode[start_pc..end].windows(2).any(|w| 
            w[0] == 0x01  // ADD
        )
    }

    fn has_balance_check_between(&self, start: usize, end: usize) -> bool {
        let end = end.min(self.bytecode.len());
        self.bytecode[start..end].iter().any(|&b| 
            b == 0x03  // SUB (balance check pattern)
        )
    }

    fn has_pattern(&self, pattern: &[u8]) -> bool {
        self.bytecode.windows(pattern.len()).any(|w| w == pattern)
    }

    fn has_sstore_after(&self, pc: usize, window: usize) -> bool {
        let end = (pc + window).min(self.bytecode.len());
        self.bytecode[pc..end].iter().any(|&b| b == 0x55)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_fee_on_transfer() {
        let bytecode = vec![
            0xF1,        // CALL (transferFrom)
            0x60, 0x01,  // PUSH1 1
            0x01,        // ADD (balance += amount) - WRONG!
        ];
        let detector = WeirdERC20Detector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, WeirdERC20Issue::FeeOnTransfer)));
    }

    #[test]
    fn test_detect_erc777_reentrancy() {
        let bytecode = vec![
            0xF1,        // CALL (external)
            0x60, 0x00,  // PUSH1 0
            0x55,        // SSTORE (state change AFTER call - vulnerable!)
        ];
        let detector = WeirdERC20Detector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, WeirdERC20Issue::ERC777Hooks)));
    }
}
