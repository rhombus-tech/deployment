/// Rebase + Fee-on-Transfer Combo Detector
/// Detects vulnerabilities when contracts interact with tokens that both:
/// 1. Rebase (balance changes without transfers)
/// 2. Charge fees on transfer (received amount < sent amount)
///
/// This combination creates double accounting bugs that are extremely dangerous
/// Examples: Custom rebasing tokens with transfer fees, wrapped rebasing tokens with fees
///
/// Attack Vector: Exploiter deposits before rebase, withdraws after rebase,
/// and accounting fails to properly track both the rebase AND the transfer fee

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RebaseFeeComboVulnerability {
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
    pub issue_type: RebaseFeeIssueType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RebaseFeeIssueType {
    CachedBalanceWithFeeTransfer,      // Caches balance then does fee transfer
    RebaseAccountingWithFee,            // Accounting breaks on both rebase + fee
    DoubleDiscountVulnerable,           // Vulnerable to both discounts simultaneously
    ShareCalculationError,              // Share price calculation breaks
}

pub struct RebaseFeeComboDetector {
    bytecode: Vec<u8>,
}

impl RebaseFeeComboDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<RebaseFeeComboVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern 1: Cached balance + external transfer with no amount verification
        vulnerabilities.extend(self.detect_cached_balance_with_fee_transfer());

        // Pattern 2: Balance-based accounting without checking actual received
        vulnerabilities.extend(self.detect_rebase_accounting_with_fee());

        // Pattern 3: Share calculations vulnerable to both rebase and fees
        vulnerabilities.extend(self.detect_vulnerable_share_calculation());

        vulnerabilities
    }

    /// Detect: Contract caches balance, then transfers in/out without verifying amounts
    fn detect_cached_balance_with_fee_transfer(&self) -> Vec<RebaseFeeComboVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(200) {
            // Pattern: balanceOf -> SSTORE -> later transferFrom without balance check
            if self.is_balance_of_call(pc) {
                if let Some(store_pc) = self.find_next_sstore(pc, 30) {
                    // Look for transferFrom/transfer after the store
                    if let Some(transfer_pc) = self.find_next_transfer_call(store_pc, 150) {
                        // Check if there's no balance verification after transfer
                        if !self.has_balance_check_after(transfer_pc, 50) {
                            vulnerabilities.push(RebaseFeeComboVulnerability {
                                severity: SecuritySeverity::Critical,
                                confidence: 0.85,
                                description: format!(
                                    "CRITICAL: Contract at PC {} caches balance, then performs transfer \
                                    without verifying actual received amount. Vulnerable to BOTH \
                                    rebasing tokens (balance changes) AND fee-on-transfer tokens \
                                    (received < sent). This creates double-discount attack vector.",
                                    pc
                                ),
                                exploit_scenario:
                                    "Rebase + Fee-on-Transfer Attack:\n\
                                     1. Attacker deposits 100 tokens\n\
                                     2. Contract: cachedBal = balanceOf(this) = 100\n\
                                     3. Token rebases down 10% → actual balance = 90\n\
                                     4. Attacker withdraws 100 tokens\n\
                                     5. Transfer fee is 5% → contract receives 95\n\
                                     6. Contract thinks it has 100, actually has 90, sends 95\n\
                                     7. Net loss: 100 - 95 = 5 tokens stolen\n\n\
                                     The combination amplifies the loss!\n\n\
                                     Fix: ALWAYS check actual balance after any external call:\n\
                                     uint balBefore = token.balanceOf(this);\n\
                                     token.transferFrom(from, this, amount);\n\
                                     uint balAfter = token.balanceOf(this);\n\
                                     uint actualReceived = balAfter - balBefore;\n\
                                     // Use actualReceived, NOT amount!".to_string(),
                                location: pc,
                                issue_type: RebaseFeeIssueType::CachedBalanceWithFeeTransfer,
                            });
                        }
                    }
                }
            }

            pc += 1;
        }

        vulnerabilities
    }

    /// Detect: Arithmetic on balances without accounting for both rebase and fees
    fn detect_rebase_accounting_with_fee(&self) -> Vec<RebaseFeeComboVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(300) {
            // Pattern: Transfer call followed by arithmetic without balance delta check
            if self.is_transfer_from_call(pc) {
                // Check for arithmetic operations shortly after
                if self.has_arithmetic_without_balance_delta(pc, 100) {
                    vulnerabilities.push(RebaseFeeComboVulnerability {
                        severity: SecuritySeverity::Critical,
                        confidence: 0.75,
                        description: format!(
                            "Contract at PC {} performs transfer and uses amounts in calculations \
                            without measuring actual balance delta. Vulnerable to both rebasing \
                            (balance changes without transfer) and fee-on-transfer (received != sent).",
                            pc
                        ),
                        exploit_scenario:
                            "Double Accounting Bug:\n\
                             1. Contract logic: deposit(amount) -> shares = amount * totalShares / totalAssets\n\
                             2. User deposits 1000 tokens\n\
                             3. Token has 2% transfer fee → contract receives 980\n\
                             4. Token rebases +5% → contract now has 1029\n\
                             5. Contract calculates shares based on 1000, not 980\n\
                             6. User gets inflated shares\n\
                             7. User can withdraw more than they deposited\n\n\
                             Fix: Calculate shares based on ACTUAL balance change:\n\
                             uint balBefore = asset.balanceOf(this);\n\
                             asset.transferFrom(from, this, amount);\n\
                             uint balAfter = asset.balanceOf(this);\n\
                             uint received = balAfter - balBefore;  // Handles both rebase AND fees\n\
                             shares = received * totalShares / totalAssets;".to_string(),
                        location: pc,
                        issue_type: RebaseFeeIssueType::RebaseAccountingWithFee,
                    });
                }
            }

            pc += 1;
        }

        vulnerabilities
    }

    /// Detect: Share/vault calculations that don't account for balance changes
    fn detect_vulnerable_share_calculation(&self) -> Vec<RebaseFeeComboVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(250) {
            // Look for vault-like patterns: DIV operations with SLOAD (shares/totalAssets)
            if self.bytecode[pc] == 0x04 {  // DIV opcode
                // Check if there's share calculation pattern nearby
                if self.has_share_calculation_pattern(pc, 50) {
                    // Check if there's a preceding transfer without balance verification
                    if let Some(transfer_pc) = self.find_previous_transfer(pc, 100) {
                        if !self.has_balance_delta_check(transfer_pc, pc) {
                            vulnerabilities.push(RebaseFeeComboVulnerability {
                                severity: SecuritySeverity::Critical,
                                confidence: 0.80,
                                description: format!(
                                    "Vault-like share calculation at PC {} doesn't account for \
                                    actual received amounts. With rebase + fee-on-transfer tokens, \
                                    share price calculations will be incorrect.",
                                    pc
                                ),
                                exploit_scenario:
                                    "Share Price Manipulation:\n\
                                     1. Vault formula: shares = amount * totalShares / totalAssets\n\
                                     2. User deposits 10,000 REBASE_FEE_TOKEN\n\
                                     3. Token charges 3% fee → vault receives 9,700\n\
                                     4. Code calculates shares using 10,000 (wrong!)\n\
                                     5. Token rebases -8% → vault assets now 8,924\n\
                                     6. User has inflated shares worth more than deposit\n\
                                     7. First victim: withdraw drains the vault\n\n\
                                     This is CRITICAL for ERC-4626 vaults!\n\n\
                                     Fix: ERC-4626 compliant calculation:\n\
                                     function deposit(uint assets) returns (uint shares) {\n\
                                         uint balBefore = asset.balanceOf(this);\n\
                                         asset.transferFrom(msg.sender, this, assets);\n\
                                         uint balAfter = asset.balanceOf(this);\n\
                                         uint actualAssets = balAfter - balBefore;\n\
                                         shares = convertToShares(actualAssets);  // Use actual!\n\
                                     }".to_string(),
                                location: pc,
                                issue_type: RebaseFeeIssueType::ShareCalculationError,
                            });
                        }
                    }
                }
            }

            pc += 1;
        }

        vulnerabilities
    }

    // Helper methods

    fn is_balance_of_call(&self, pc: usize) -> bool {
        if pc + 40 >= self.bytecode.len() {
            return false;
        }
        // Look for balanceOf selector 0x70a08231
        self.bytecode[pc..].windows(4).take(40).any(|w| w == [0x70, 0xa0, 0x82, 0x31])
    }

    fn is_transfer_from_call(&self, pc: usize) -> bool {
        if pc + 40 >= self.bytecode.len() {
            return false;
        }
        // transferFrom selector 0x23b872dd
        self.bytecode[pc..].windows(4).take(40).any(|w| w == [0x23, 0xb8, 0x72, 0xdd])
    }

    fn find_next_sstore(&self, start: usize, range: usize) -> Option<usize> {
        let end = (start + range).min(self.bytecode.len());
        for i in start..end {
            if self.bytecode[i] == 0x55 {  // SSTORE
                return Some(i);
            }
        }
        None
    }

    fn find_next_transfer_call(&self, start: usize, range: usize) -> Option<usize> {
        let end = (start + range).min(self.bytecode.len());
        for i in start..end {
            if self.is_transfer_from_call(i) || self.is_transfer_call(i) {
                return Some(i);
            }
        }
        None
    }

    fn is_transfer_call(&self, pc: usize) -> bool {
        if pc + 40 >= self.bytecode.len() {
            return false;
        }
        // transfer selector 0xa9059cbb
        self.bytecode[pc..].windows(4).take(40).any(|w| w == [0xa9, 0x05, 0x9c, 0xbb])
    }

    fn has_balance_check_after(&self, pc: usize, range: usize) -> bool {
        let end = (pc + range).min(self.bytecode.len());
        // Look for another balanceOf call after the transfer
        for i in pc..end {
            if self.is_balance_of_call(i) {
                return true;
            }
        }
        false
    }

    fn has_arithmetic_without_balance_delta(&self, pc: usize, range: usize) -> bool {
        let end = (pc + range).min(self.bytecode.len());
        let mut has_arithmetic = false;
        let mut has_balance_delta = false;

        for i in pc..end {
            // Check for arithmetic: ADD, SUB, MUL, DIV
            if matches!(self.bytecode[i], 0x01 | 0x02 | 0x03 | 0x04) {
                has_arithmetic = true;
            }
            // Check for balance delta pattern (two balanceOf calls with SUB)
            if self.is_balance_of_call(i) {
                if let Some(j) = self.find_next_balance_of(i + 1, 50) {
                    if self.has_sub_between(i, j) {
                        has_balance_delta = true;
                    }
                }
            }
        }

        has_arithmetic && !has_balance_delta
    }

    fn find_next_balance_of(&self, start: usize, range: usize) -> Option<usize> {
        let end = (start + range).min(self.bytecode.len());
        for i in start..end {
            if self.is_balance_of_call(i) {
                return Some(i);
            }
        }
        None
    }

    fn has_sub_between(&self, start: usize, end: usize) -> bool {
        for i in start..end.min(self.bytecode.len()) {
            if self.bytecode[i] == 0x03 {  // SUB
                return true;
            }
        }
        false
    }

    fn has_share_calculation_pattern(&self, pc: usize, range: usize) -> bool {
        // Look for DIV with SLOAD operations nearby (typical vault math)
        let start = pc.saturating_sub(range);
        let end = (pc + range).min(self.bytecode.len());
        
        let mut has_sload = false;
        let mut has_mul = false;

        for i in start..end {
            if self.bytecode[i] == 0x54 {  // SLOAD
                has_sload = true;
            }
            if self.bytecode[i] == 0x02 {  // MUL
                has_mul = true;
            }
        }

        has_sload && has_mul
    }

    fn find_previous_transfer(&self, pc: usize, range: usize) -> Option<usize> {
        let start = pc.saturating_sub(range);
        for i in (start..pc).rev() {
            if self.is_transfer_from_call(i) || self.is_transfer_call(i) {
                return Some(i);
            }
        }
        None
    }

    fn has_balance_delta_check(&self, start: usize, end: usize) -> bool {
        // Look for pattern: balanceOf -> balanceOf -> SUB
        let mut balance_calls = Vec::new();
        
        for i in start..end.min(self.bytecode.len()) {
            if self.is_balance_of_call(i) {
                balance_calls.push(i);
            }
        }

        if balance_calls.len() >= 2 {
            // Check if there's a SUB between the balance calls
            return self.has_sub_between(balance_calls[0], balance_calls[1] + 50);
        }

        false
    }
}
