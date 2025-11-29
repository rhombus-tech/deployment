/// Rebasing Token Analyzer
/// Detects vulnerabilities when contracts interact with rebasing/deflationary tokens
/// where balanceOf() can change without transfers
///
/// Examples: AMPL (rebasing), fee-on-transfer tokens, reflection tokens

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RebasingTokenVulnerability {
    pub vulnerability_type: RebasingIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RebasingIssueType {
    CachedBalanceRebase,           // Cached balance before rebase
    TransferAmountMismatch,        // Transfer amount != actual received
    FeeOnTransferNotHandled,       // Doesn't account for transfer fees
    RebaseAccountingError,         // Accounting breaks on rebase
    DeflationaryTokenLoss,         // Loses funds to deflation
}

pub struct RebasingTokenAnalyzer {
    bytecode: Vec<u8>,
}

impl RebasingTokenAnalyzer {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<RebasingTokenVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern 1: Cached balanceOf with arithmetic later
        vulnerabilities.extend(self.detect_cached_balance_rebase());

        // Pattern 2: transfer() without checking actual received amount
        vulnerabilities.extend(self.detect_transfer_amount_mismatch());

        // Pattern 3: Arithmetic on transfer amounts
        vulnerabilities.extend(self.detect_fee_on_transfer_issues());

        vulnerabilities
    }

    /// Detect: balanceOf cached, used later (breaks on rebase)
    fn detect_cached_balance_rebase(&self) -> Vec<RebasingTokenVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(100) {
            // Look for: balanceOf call, SSTORE, then later arithmetic
            if self.is_balance_of_call(pc) {
                if let Some(store_pc) = self.find_next_sstore(pc, 20) {
                    // Check if this stored balance is used in arithmetic
                    if self.has_arithmetic_on_stored_value(store_pc, 200) {
                        vulnerabilities.push(RebasingTokenVulnerability {
                            vulnerability_type: RebasingIssueType::CachedBalanceRebase,
                            severity: SecuritySeverity::High,
                            confidence: 0.80,
                            description: format!(
                                "Contract caches balanceOf at PC {} and uses it later. \
                                Vulnerable to rebasing tokens (AMPL, stETH) where balance \
                                changes without transfers.",
                                pc
                            ),
                            exploit_scenario:
                                "Rebasing Token Attack:\n\
                                 1. Contract: cachedBal = token.balanceOf(this)\n\
                                 2. Token rebases (positive or negative)\n\
                                 3. Contract uses cachedBal for calculations\n\
                                 4. Accounting is now wrong\n\
                                 5. User can exploit the discrepancy\n\n\
                                 Example: Deposit calculates shares based on old balance\n\
                                 Fix: Always call balanceOf() fresh, never cache".to_string(),
                            location: pc,
                        });
                    }
                }
            }

            pc += 1;
        }

        vulnerabilities
    }

    /// Detect: transfer() without verifying received amount
    fn detect_transfer_amount_mismatch(&self) -> Vec<RebasingTokenVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(150) {
            // Look for: transfer or transferFrom call
            if self.is_transfer_call(pc) {
                // Check if contract verifies actual received amount
                let checks_balance_before = self.has_balance_check_before(pc, 50);
                let checks_balance_after = self.has_balance_check_after(pc, 50);
                
                if !checks_balance_before || !checks_balance_after {
                    vulnerabilities.push(RebasingTokenVulnerability {
                        vulnerability_type: RebasingIssueType::TransferAmountMismatch,
                        severity: SecuritySeverity::Medium,
                        confidence: 0.70,
                        description: format!(
                            "Transfer at PC {} doesn't verify actual received amount. \
                            Vulnerable to fee-on-transfer and deflationary tokens.",
                            pc
                        ),
                        exploit_scenario:
                            "Fee-on-Transfer Attack:\n\
                             1. Contract expects: token.transfer(100)\n\
                             2. Token has 10% fee, only 90 received\n\
                             3. Contract credits user 100 (wrong!)\n\
                             4. User gets 10 free tokens per transaction\n\n\
                             Fix:\n\
                             uint256 balBefore = token.balanceOf(this);\n\
                             token.transferFrom(user, this, amount);\n\
                             uint256 balAfter = token.balanceOf(this);\n\
                             uint256 received = balAfter - balBefore;  // Use this!".to_string(),
                        location: pc,
                    });
                }
            }

            pc += 1;
        }

        vulnerabilities
    }

    /// Detect: Using transfer amount in arithmetic without adjustment
    fn detect_fee_on_transfer_issues(&self) -> Vec<RebasingTokenVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(100) {
            // Look for: transfer followed by arithmetic on the amount
            if self.is_transfer_call(pc) {
                // Check if arithmetic happens on the transfer amount
                if self.has_arithmetic_after(pc, 30) {
                    let has_balance_verification = self.has_balance_check_after(pc, 30);
                    
                    if !has_balance_verification {
                        vulnerabilities.push(RebasingTokenVulnerability {
                            vulnerability_type: RebasingIssueType::FeeOnTransferNotHandled,
                            severity: SecuritySeverity::Medium,
                            confidence: 0.65,
                            description: format!(
                                "Arithmetic on transfer amount at PC {} without balance verification. \
                                May incorrectly calculate with fee-on-transfer tokens.",
                                pc
                            ),
                            exploit_scenario:
                                "Accounting Error:\n\
                                 1. User deposits 1000 tokens with 5% fee\n\
                                 2. Contract receives 950, but credits 1000 shares\n\
                                 3. Over many transactions, mismatch accumulates\n\
                                 4. Protocol becomes insolvent\n\n\
                                 Examples: Many DeFi protocols have this bug with taxed tokens".to_string(),
                            location: pc,
                        });
                    }
                }
            }

            pc += 1;
        }

        vulnerabilities
    }

    // Helper methods

    fn is_balance_of_call(&self, pc: usize) -> bool {
        if pc + 4 >= self.bytecode.len() {
            return false;
        }
        
        // balanceOf selector: 0x70a08231
        self.bytecode[pc..pc+4].windows(4).any(|w| {
            w == [0x70, 0xa0, 0x82, 0x31]
        })
    }

    fn is_transfer_call(&self, pc: usize) -> bool {
        if pc + 4 >= self.bytecode.len() {
            return false;
        }
        
        // transfer: 0xa9059cbb, transferFrom: 0x23b872dd
        self.bytecode[pc..pc+4].windows(4).any(|w| {
            w == [0xa9, 0x05, 0x9c, 0xbb] || w == [0x23, 0xb8, 0x72, 0xdd]
        })
    }

    fn find_next_sstore(&self, start: usize, max_distance: usize) -> Option<usize> {
        let end = (start + max_distance).min(self.bytecode.len());
        
        self.bytecode[start..end]
            .iter()
            .position(|&op| op == 0x55)
            .map(|pos| start + pos)
    }

    fn has_arithmetic_on_stored_value(&self, sstore_pc: usize, distance: usize) -> bool {
        let end = (sstore_pc + distance).min(self.bytecode.len());
        
        // Look for SLOAD followed by arithmetic
        for i in (sstore_pc + 1)..end.saturating_sub(2) {
            if self.bytecode[i] == 0x54 { // SLOAD
                // Check if arithmetic happens nearby
                if self.bytecode[i..].windows(5).any(|w| {
                    matches!(w[0], 0x01 | 0x02 | 0x03 | 0x04) // ADD, MUL, SUB, DIV
                }) {
                    return true;
                }
            }
        }
        
        false
    }

    fn has_balance_check_before(&self, pc: usize, distance: usize) -> bool {
        let start = pc.saturating_sub(distance);
        
        for i in start..pc {
            if self.is_balance_of_call(i) {
                return true;
            }
        }
        false
    }

    fn has_balance_check_after(&self, pc: usize, distance: usize) -> bool {
        let end = (pc + distance).min(self.bytecode.len());
        
        for i in pc..end {
            if self.is_balance_of_call(i) {
                return true;
            }
        }
        false
    }

    fn has_arithmetic_after(&self, pc: usize, distance: usize) -> bool {
        let end = (pc + distance).min(self.bytecode.len());
        
        self.bytecode[pc..end].iter()
            .any(|&op| matches!(op, 0x01 | 0x02 | 0x03 | 0x04 | 0x05))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cached_balance_rebase() {
        let bytecode = vec![
            0x70, 0xa0, 0x82, 0x31, // balanceOf selector
            0xFA, // STATICCALL
            0x55, // SSTORE (cache)
            0x54, // SLOAD (load cached)
            0x02, // MUL (arithmetic on cached value)
        ];
        
        let analyzer = RebasingTokenAnalyzer::new(bytecode);
        let vulns = analyzer.detect_vulnerabilities();
        
        assert!(!vulns.is_empty(), "Should detect cached balance rebase issue");
    }
}
