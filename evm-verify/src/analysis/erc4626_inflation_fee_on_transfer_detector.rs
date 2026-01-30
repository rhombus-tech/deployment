/// ERC4626 Inflation + Fee-on-Transfer Detector
/// Detects the combination of:
/// 1. First depositor inflation attack (deposit 1 wei, donate to inflate share price)
/// 2. Fee-on-transfer tokens (received amount < sent amount)
///
/// This combination is DEVASTATING for ERC-4626 vaults
/// Attack: First depositor donates to inflate shares, subsequent deposits with fee tokens lose funds
///
/// Real exploits: Numerous vault hacks totaling $50M+

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ERC4626InflationFeeVulnerability {
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
    pub issue_type: ERC4626IssueType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ERC4626IssueType {
    NoVirtualSharesProtection,         // No virtual shares/assets to prevent inflation
    NoMinSharesCheck,                  // Doesn't enforce minimum shares minted
    NoFeeOnTransferHandling,           // Doesn't check actual received vs requested
    FirstDepositUnprotected,           // First deposit can be 1 wei
    SharePriceManipulatable,           // Share price can be manipulated via donation
}

pub struct ERC4626InflationFeeDetector {
    bytecode: Vec<u8>,
}

impl ERC4626InflationFeeDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ERC4626InflationFeeVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern 1: Share calculation without virtual shares protection
        vulnerabilities.extend(self.detect_no_virtual_shares());

        // Pattern 2: Deposit without minimum shares check
        vulnerabilities.extend(self.detect_no_min_shares_check());

        // Pattern 3: Deposit without checking actual received amount
        vulnerabilities.extend(self.detect_no_fee_handling());

        // Pattern 4: convertToShares formula vulnerable to manipulation
        vulnerabilities.extend(self.detect_manipulable_share_price());

        vulnerabilities
    }

    /// Detect: convertToShares without virtual shares/assets protection
    fn detect_no_virtual_shares(&self) -> Vec<ERC4626InflationFeeVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(200) {
            // Look for share calculation: assets * totalShares / totalAssets
            if self.is_share_calculation(pc) {
                // Check if there's virtual shares/assets added (PUSH + ADD before DIV)
                if !self.has_virtual_offset_before_div(pc, 50) {
                    vulnerabilities.push(ERC4626InflationFeeVulnerability {
                        severity: SecuritySeverity::Critical,
                        confidence: 0.95,
                        description: format!(
                            "CRITICAL: ERC-4626 share calculation at PC {} doesn't use virtual \
                            shares/assets. Vulnerable to first depositor inflation attack + \
                            fee-on-transfer double whammy. This is one of the most exploited patterns!",
                            pc
                        ),
                        exploit_scenario:
                            "First Depositor Inflation + Fee-on-Transfer Attack:\n\
                             \n\
                             Setup:\n\
                             1. Attacker deposits 1 wei, gets 1 share\n\
                             2. Attacker directly transfers 10,000 tokens to vault (donation)\n\
                             3. Share price = 10,000 tokens / 1 share = 10,000:1\n\
                             \n\
                             Attack:\n\
                             4. Victim deposits 10,000 tokens (fee-on-transfer)\n\
                             5. Vault receives 9,500 tokens (5% fee)\n\
                             6. shares = 9,500 * 1 / 10,000 = 0.95 shares\n\
                             7. EVM rounds down → victim gets 0 shares!\n\
                             8. Victim's 9,500 tokens are stuck in vault\n\
                             9. Attacker redeems 1 share for all 19,500 tokens\n\
                             10. Attacker profit: 9,500 tokens (victim's entire deposit!)\n\
                             \n\
                             Why it's worse with fee tokens:\n\
                             - Normal tokens: victim might get 0 shares but could fix via higher deposit\n\
                             - Fee tokens: victim LOSES funds with each attempt\n\
                             - Attacker needs less capital for the same impact\n\
                             \n\
                             Fix (ERC-4626 best practice):\n\
                             // Add virtual shares/assets to prevent manipulation\n\
                             uint256 private constant VIRTUAL_SHARES = 1e3;  // 1000\n\
                             uint256 private constant VIRTUAL_ASSETS = 1;     // 1\n\
                             \n\
                             function convertToShares(uint256 assets) public view returns (uint256) {\n\
                                 uint256 supply = totalSupply();\n\
                                 return supply == 0 ? assets : assets * (supply + VIRTUAL_SHARES) / (totalAssets() + VIRTUAL_ASSETS);\n\
                             }\n\
                             \n\
                             // Also check actual received:\n\
                             function deposit(uint256 assets) public returns (uint256 shares) {\n\
                                 uint256 balBefore = asset.balanceOf(this);\n\
                                 asset.transferFrom(msg.sender, this, assets);\n\
                                 uint256 balAfter = asset.balanceOf(this);\n\
                                 uint256 actualAssets = balAfter - balBefore;  // Handles fee!\n\
                                 \n\
                                 shares = convertToShares(actualAssets);\n\
                                 require(shares > 0, 'ZERO_SHARES');\n\
                                 _mint(msg.sender, shares);\n\
                             }".to_string(),
                        location: pc,
                        issue_type: ERC4626IssueType::NoVirtualSharesProtection,
                    });
                }
            }

            pc += 1;
        }

        vulnerabilities
    }

    /// Detect: Deposit function without minimum shares check
    fn detect_no_min_shares_check(&self) -> Vec<ERC4626InflationFeeVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(300) {
            // Look for deposit-like pattern: transferFrom followed by mint
            if self.is_transfer_from_call(pc) {
                if let Some(mint_pc) = self.find_mint_operation(pc, 200) {
                    // Check if there's a zero-check on shares before mint
                    if !self.has_zero_shares_check_between(pc, mint_pc) {
                        vulnerabilities.push(ERC4626InflationFeeVulnerability {
                            severity: SecuritySeverity::Critical,
                            confidence: 0.85,
                            description: format!(
                                "Deposit function at PC {} doesn't check for zero shares minted. \
                                With fee-on-transfer tokens + inflation attack, users can deposit \
                                and receive 0 shares, permanently losing their funds.",
                                pc
                            ),
                            exploit_scenario:
                                "Zero Shares DoS + Fund Loss:\n\
                                 1. Share price inflated to 1 share = 10,000 tokens\n\
                                 2. User deposits 5,000 USDT (1% fee)\n\
                                 3. Vault receives 4,950 USDT\n\
                                 4. Calculation: 4,950 * 1 / 10,000 = 0.495 shares\n\
                                 5. EVM rounds to 0 shares minted\n\
                                 6. User's 4,950 USDT is stuck forever\n\
                                 7. Attacker can repeat to accumulate funds\n\n\
                                 Fix:\n\
                                 shares = convertToShares(actualAssets);\n\
                                 require(shares > 0, 'ZERO_SHARES');  // CRITICAL!\n\
                                 require(shares >= minShares, 'SLIPPAGE');  // Also add slippage\n\
                                 _mint(receiver, shares);".to_string(),
                            location: pc,
                            issue_type: ERC4626IssueType::NoMinSharesCheck,
                        });
                    }
                }
            }

            pc += 1;
        }

        vulnerabilities
    }

    /// Detect: Deposit using amount parameter instead of actual balance delta
    fn detect_no_fee_handling(&self) -> Vec<ERC4626InflationFeeVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(250) {
            if self.is_transfer_from_call(pc) {
                // Check if balance delta is calculated
                if !self.has_balance_delta_calculation(pc, 150) {
                    // But has share calculation after
                    if self.has_share_calc_after(pc, 150) {
                        vulnerabilities.push(ERC4626InflationFeeVulnerability {
                            severity: SecuritySeverity::Critical,
                            confidence: 0.80,
                            description: format!(
                                "Deposit at PC {} uses the input amount for share calculation \
                                instead of measuring actual received amount. Fee-on-transfer tokens \
                                will cause share calculation to be incorrect, amplifying inflation attack.",
                                pc
                            ),
                            exploit_scenario:
                                "Fee-on-Transfer Accounting Bug:\n\
                                 1. Function: deposit(uint256 assets)\n\
                                 2. User calls deposit(10000) with 5% fee token\n\
                                 3. Contract receives 9,500 tokens\n\
                                 4. But calculates: shares = convertToShares(10000)  // WRONG!\n\
                                 5. User gets shares for 10,000 but only deposited 9,500\n\
                                 6. 500 token discrepancy creates insolvency\n\
                                 7. With inflation attack, this compounds to total drain\n\n\
                                 Correct implementation:\n\
                                 function deposit(uint256 assets, address receiver) returns (uint256 shares) {\n\
                                     uint256 balBefore = asset.balanceOf(this);\n\
                                     asset.transferFrom(msg.sender, this, assets);\n\
                                     uint256 balAfter = asset.balanceOf(this);\n\
                                     \n\
                                     uint256 actualReceived = balAfter - balBefore;  // MUST USE THIS!\n\
                                     shares = convertToShares(actualReceived);\n\
                                     \n\
                                     require(shares > 0, 'ZERO_SHARES');\n\
                                     _mint(receiver, shares);\n\
                                     \n\
                                     emit Deposit(msg.sender, receiver, actualReceived, shares);\n\
                                 }".to_string(),
                            location: pc,
                            issue_type: ERC4626IssueType::NoFeeOnTransferHandling,
                        });
                    }
                }
            }

            pc += 1;
        }

        vulnerabilities
    }

    /// Detect: Share price calculation that can be manipulated
    fn detect_manipulable_share_price(&self) -> Vec<ERC4626InflationFeeVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(150) {
            // Look for totalAssets() or balanceOf call in share calc
            if self.is_balance_of_call(pc) && self.has_div_nearby(pc, 30) {
                // Check if this is part of share calculation
                if self.has_total_supply_nearby(pc, 50) {
                    // Check for protection against first deposit
                    if !self.has_first_deposit_protection(pc, 100) {
                        vulnerabilities.push(ERC4626InflationFeeVulnerability {
                            severity: SecuritySeverity::High,
                            confidence: 0.75,
                            description: format!(
                                "Share price calculation at PC {} is manipulatable via direct token \
                                transfers (donations). First depositor can inflate share price, then \
                                fee-on-transfer tokens cause subsequent depositors to get zero shares.",
                                pc
                            ),
                            exploit_scenario:
                                "Share Price Manipulation Flow:\n\
                                 1. totalAssets() = balanceOf(this)\n\
                                 2. Attacker deposits 1 wei\n\
                                 3. Attacker donates 1,000,000 tokens directly\n\
                                 4. totalAssets() = 1,000,000, totalSupply() = 1\n\
                                 5. sharePrice = 1,000,000:1\n\
                                 6. Victim deposits 100,000 fee-on-transfer (3% fee)\n\
                                 7. Contract receives 97,000\n\
                                 8. shares = 97,000 * 1 / 1,000,000 = 0.097 → rounds to 0\n\
                                 9. Victim loses 97,000 tokens\n\n\
                                 Mitigation strategies:\n\
                                 1. Virtual shares/assets (best)\n\
                                 2. Minimum first deposit requirement\n\
                                 3. Deadshares (mint initial shares to zero address)\n\
                                 4. Always check actualReceived vs amount".to_string(),
                            location: pc,
                            issue_type: ERC4626IssueType::SharePriceManipulatable,
                        });
                    }
                }
            }

            pc += 1;
        }

        vulnerabilities
    }

    // Helper methods

    fn is_share_calculation(&self, pc: usize) -> bool {
        // Pattern: MUL followed by DIV (typical share calculation)
        if pc + 10 >= self.bytecode.len() {
            return false;
        }
        
        for i in pc..(pc + 10) {
            if self.bytecode[i] == 0x02 {  // MUL
                for j in (i + 1)..(i + 10).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x04 {  // DIV
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_virtual_offset_before_div(&self, pc: usize, range: usize) -> bool {
        let start = pc.saturating_sub(range / 2);
        let end = (pc + range / 2).min(self.bytecode.len());
        
        // Look for pattern: PUSH (constant) -> ADD -> ... -> DIV
        let mut found_push_add = false;
        for i in start..end {
            if self.bytecode[i] >= 0x60 && self.bytecode[i] <= 0x7f {  // PUSH
                if i + 1 < self.bytecode.len() && self.bytecode[i + 1] == 0x01 {  // ADD
                    found_push_add = true;
                }
            }
        }
        
        found_push_add
    }

    fn is_transfer_from_call(&self, pc: usize) -> bool {
        if pc + 40 >= self.bytecode.len() {
            return false;
        }
        // transferFrom selector 0x23b872dd
        self.bytecode[pc..].windows(4).take(40).any(|w| w == [0x23, 0xb8, 0x72, 0xdd])
    }

    fn find_mint_operation(&self, start: usize, range: usize) -> Option<usize> {
        let end = (start + range).min(self.bytecode.len());
        
        // Look for mint selector 0x40c10f19 or LOG3 (Transfer event)
        for i in start..end {
            if self.bytecode[i] == 0xa2 {  // LOG3 (Transfer event)
                return Some(i);
            }
            if i + 4 < end && self.bytecode[i..i+4] == [0x40, 0xc1, 0x0f, 0x19] {
                return Some(i);
            }
        }
        
        None
    }

    fn has_zero_shares_check_between(&self, start: usize, end: usize) -> bool {
        let end = end.min(self.bytecode.len());
        
        // Look for ISZERO -> REVERT pattern (checking shares != 0)
        for i in start..end.saturating_sub(3) {
            if self.bytecode[i] == 0x15 {  // ISZERO
                for j in (i + 1)..(i + 10).min(end) {
                    if self.bytecode[j] == 0xfd {  // REVERT
                        return true;
                    }
                }
            }
        }
        
        false
    }

    fn has_balance_delta_calculation(&self, pc: usize, range: usize) -> bool {
        let end = (pc + range).min(self.bytecode.len());
        
        // Look for pattern: balanceOf -> store -> transfer -> balanceOf -> load -> SUB
        let mut balance_calls = 0;
        let mut has_sub = false;
        
        for i in pc..end {
            if self.is_balance_of_call(i) {
                balance_calls += 1;
            }
            if self.bytecode[i] == 0x03 {  // SUB
                has_sub = true;
            }
        }
        
        balance_calls >= 2 && has_sub
    }

    fn is_balance_of_call(&self, pc: usize) -> bool {
        if pc + 40 >= self.bytecode.len() {
            return false;
        }
        // balanceOf selector 0x70a08231
        self.bytecode[pc..].windows(4).take(40).any(|w| w == [0x70, 0xa0, 0x82, 0x31])
    }

    fn has_share_calc_after(&self, pc: usize, range: usize) -> bool {
        let end = (pc + range).min(self.bytecode.len());
        for i in pc..end {
            if self.is_share_calculation(i) {
                return true;
            }
        }
        false
    }

    fn has_div_nearby(&self, pc: usize, range: usize) -> bool {
        let start = pc.saturating_sub(range / 2);
        let end = (pc + range / 2).min(self.bytecode.len());
        
        for i in start..end {
            if self.bytecode[i] == 0x04 {  // DIV
                return true;
            }
        }
        false
    }

    fn has_total_supply_nearby(&self, pc: usize, range: usize) -> bool {
        let start = pc.saturating_sub(range / 2);
        let end = (pc + range / 2).min(self.bytecode.len());
        
        // totalSupply selector 0x18160ddd
        for i in start..end.saturating_sub(4) {
            if self.bytecode[i..i+4] == [0x18, 0x16, 0x0d, 0xdd] {
                return true;
            }
        }
        false
    }

    fn has_first_deposit_protection(&self, pc: usize, range: usize) -> bool {
        let start = pc.saturating_sub(range / 2);
        let end = (pc + range / 2).min(self.bytecode.len());
        
        // Look for totalSupply == 0 check or PUSH of large constant (virtual shares)
        for i in start..end {
            if self.bytecode[i] == 0x14 {  // EQ (checking if totalSupply == 0)
                return true;
            }
            // Look for PUSH of constant > 1000 (virtual shares pattern)
            if self.bytecode[i] >= 0x61 && self.bytecode[i] <= 0x63 {  // PUSH2-PUSH4
                return true;
            }
        }
        false
    }
}
