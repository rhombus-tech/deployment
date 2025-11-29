/// First Depositor Attack Detector (ERC-4626 Inflation Attack)
/// Detects share inflation vulnerabilities where first depositor can manipulate
/// share price to steal from subsequent depositors
///
/// Attack: deposit(1) → donate(1e18) → victim deposits → attacker profits

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirstDepositorVulnerability {
    pub vulnerability_type: FirstDepositorAttackType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub mitigation: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FirstDepositorAttackType {
    MissingVirtualShares,        // No virtual shares/assets to prevent inflation
    UnprotectedFirstDeposit,     // First deposit can be 1 wei
    MissingMinimumLiquidity,     // No minimum liquidity burn
    RoundingFavorAttacker,       // Rounding down helps attacker
    NoDeadSharesBurned,          // Doesn't burn initial shares to address(0)
}

pub struct FirstDepositorAttackDetector {
    bytecode: Vec<u8>,
}

impl FirstDepositorAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<FirstDepositorVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check if this is an ERC-4626 vault
        if !self.is_erc4626_vault() {
            return vulnerabilities;
        }

        // Pattern 1: shares = assets * totalSupply / totalAssets without protection
        vulnerabilities.extend(self.detect_unprotected_share_calculation());

        // Pattern 2: No minimum deposit check
        vulnerabilities.extend(self.detect_missing_minimum_deposit());

        // Pattern 3: No virtual shares mechanism
        vulnerabilities.extend(self.detect_missing_virtual_shares());

        // Pattern 4: No initial liquidity burn
        vulnerabilities.extend(self.detect_missing_liquidity_burn());

        vulnerabilities
    }

    /// Check if bytecode implements ERC-4626
    fn is_erc4626_vault(&self) -> bool {
        // Look for ERC-4626 function selectors
        let erc4626_selectors = [
            [0x38, 0xd5, 0x2e, 0x0f], // asset()
            [0x01, 0xe1, 0xd1, 0x14], // totalAssets()
            [0xc6, 0xe6, 0xf5, 0x92], // convertToShares()
            [0x07, 0xa2, 0x20, 0x3c], // convertToAssets()
            [0xb4, 0x60, 0xaf, 0x94], // deposit()
            [0xba, 0x08, 0x77, 0x65], // redeem()
        ];

        let mut matches = 0;
        for selector in &erc4626_selectors {
            if self.has_function_selector(selector) {
                matches += 1;
            }
        }

        matches >= 4 // If 4+ ERC-4626 functions present, likely a vault
    }

    /// Detect: shares = assets * totalSupply / totalAssets (vulnerable pattern)
    fn detect_unprotected_share_calculation(&self) -> Vec<FirstDepositorVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(50) {
            // Look for: MUL followed by DIV (shares calculation pattern)
            if self.bytecode[pc] == 0x02 { // MUL
                // Find next DIV
                if let Some(div_pc) = self.find_next_opcode(pc, 0x04, 20) {
                    // Check if there's protection (minimum shares, virtual assets, etc.)
                    let has_virtual_shares = self.has_virtual_shares_pattern(pc, div_pc);
                    let has_minimum_check = self.has_minimum_value_check(div_pc, 30);
                    
                    if !has_virtual_shares && !has_minimum_check {
                        vulnerabilities.push(FirstDepositorVulnerability {
                            vulnerability_type: FirstDepositorAttackType::MissingVirtualShares,
                            severity: SecuritySeverity::Critical,
                            confidence: 0.90,
                            description: format!(
                                "Share calculation at PC {} vulnerable to first depositor attack. \
                                Formula 'shares = assets * totalSupply / totalAssets' has no protection \
                                when totalSupply = 0.",
                                pc
                            ),
                            exploit_scenario:
                                "Attack Sequence:\n\
                                 1. Attacker: deposit(1 wei) → receives 1 share\n\
                                 2. Attacker: donate(1e18 tokens) directly to vault\n\
                                 3. Now: totalAssets = 1e18 + 1, totalSupply = 1\n\
                                 4. Victim: deposit(2e18) → shares = 2e18 * 1 / (1e18+1) = 1 share\n\
                                 5. Attacker: redeem(1 share) → gets ~1.5e18 tokens\n\
                                 6. Victim: redeem(1 share) → gets ~1.5e18 tokens\n\
                                 7. Attacker profit: 0.5e18 tokens stolen from victim".to_string(),
                            mitigation:
                                "Solutions:\n\
                                 1. Use virtual shares: shares = (assets * (totalSupply + 1)) / (totalAssets + 1)\n\
                                 2. Burn minimum liquidity on first deposit to address(0)\n\
                                 3. Enforce minimum first deposit (e.g., 1e6 wei)\n\
                                 4. Use OpenZeppelin ERC4626 with decimals offset".to_string(),
                            location: pc,
                        });
                    }
                }
            }

            pc += 1;
        }

        vulnerabilities
    }

    /// Detect: No minimum deposit enforcement
    fn detect_missing_minimum_deposit(&self) -> Vec<FirstDepositorVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for deposit() function
        let deposit_selector = [0xb4, 0x60, 0xaf, 0x94]; // deposit(uint256,address)
        
        if let Some(deposit_pc) = self.find_function_selector(&deposit_selector) {
            // Check if there's a minimum value check in first 100 bytes
            let has_minimum = self.has_minimum_value_check(deposit_pc, 100);
            
            if !has_minimum {
                vulnerabilities.push(FirstDepositorVulnerability {
                    vulnerability_type: FirstDepositorAttackType::UnprotectedFirstDeposit,
                    severity: SecuritySeverity::High,
                    confidence: 0.80,
                    description:
                        "deposit() function has no minimum deposit check. First depositor can \
                        deposit 1 wei and execute inflation attack.".to_string(),
                    exploit_scenario:
                        "1. Attacker deposits 1 wei (smallest possible amount)\n\
                         2. Receives 1 share\n\
                         3. Donates large amount to inflate share price\n\
                         4. Victims lose funds due to rounding".to_string(),
                    mitigation:
                        "Require minimum first deposit:\n\
                         if (totalSupply == 0) require(assets >= 1e6, 'MINIMUM_DEPOSIT');".to_string(),
                    location: deposit_pc,
                });
            }
        }

        vulnerabilities
    }

    /// Detect: Missing virtual shares mechanism
    fn detect_missing_virtual_shares(&self) -> Vec<FirstDepositorVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check if convertToShares uses virtual assets pattern
        let convert_selector = [0xc6, 0xe6, 0xf5, 0x92]; // convertToShares()
        
        if let Some(convert_pc) = self.find_function_selector(&convert_selector) {
            let has_virtual = self.has_virtual_shares_pattern(convert_pc, convert_pc + 200);
            
            if !has_virtual {
                vulnerabilities.push(FirstDepositorVulnerability {
                    vulnerability_type: FirstDepositorAttackType::MissingVirtualShares,
                    severity: SecuritySeverity::High,
                    confidence: 0.75,
                    description:
                        "convertToShares() lacks virtual shares/assets mechanism. \
                        Vulnerable to share price manipulation on first deposit.".to_string(),
                    exploit_scenario:
                        "Standard ERC-4626 formula without virtual shares allows attacker \
                        to manipulate rounding in their favor.".to_string(),
                    mitigation:
                        "Use OpenZeppelin's ERC4626 with _decimalsOffset() or implement:\n\
                         shares = assets * (totalSupply + 1) / (totalAssets + 1)".to_string(),
                    location: convert_pc,
                });
            }
        }

        vulnerabilities
    }

    /// Detect: No initial liquidity burn (Uniswap V2 style)
    fn detect_missing_liquidity_burn(&self) -> Vec<FirstDepositorVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for mint() or deposit() function
        if let Some(deposit_pc) = self.find_deposit_function() {
            // Check if there's a transfer to address(0) or MINIMUM_LIQUIDITY pattern
            let burns_liquidity = self.has_liquidity_burn_pattern(deposit_pc, 150);
            
            if !burns_liquidity {
                vulnerabilities.push(FirstDepositorVulnerability {
                    vulnerability_type: FirstDepositorAttackType::NoDeadSharesBurned,
                    severity: SecuritySeverity::Medium,
                    confidence: 0.70,
                    description:
                        "First deposit doesn't burn minimum liquidity. Consider Uniswap V2 \
                        pattern of burning MINIMUM_LIQUIDITY (1000 shares) to address(0).".to_string(),
                    exploit_scenario:
                        "Without burned liquidity, attacker can still manipulate share price \
                        with small initial deposit.".to_string(),
                    mitigation:
                        "On first mint:\n\
                         if (totalSupply == 0) {\n\
                             uint256 liquidity = shares - MINIMUM_LIQUIDITY;\n\
                             _mint(address(0), MINIMUM_LIQUIDITY);\n\
                             _mint(receiver, liquidity);\n\
                         }".to_string(),
                    location: deposit_pc,
                });
            }
        }

        vulnerabilities
    }

    // Helper methods

    fn has_function_selector(&self, selector: &[u8; 4]) -> bool {
        self.bytecode.windows(4).any(|w| w == selector)
    }

    fn find_function_selector(&self, selector: &[u8; 4]) -> Option<usize> {
        self.bytecode.windows(4)
            .position(|w| w == selector)
    }

    fn find_next_opcode(&self, start: usize, opcode: u8, max_distance: usize) -> Option<usize> {
        let end = (start + max_distance).min(self.bytecode.len());
        
        for i in start..end {
            if self.bytecode[i] == opcode {
                return Some(i);
            }
        }
        None
    }

    fn has_virtual_shares_pattern(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Look for: ADD(totalSupply, 1) or ADD(totalAssets, 1)
        // Pattern: PUSH1 1, ADD
        for i in start..range_end.saturating_sub(2) {
            if self.bytecode[i] == 0x60 && // PUSH1
               self.bytecode[i + 1] == 0x01 && // 1
               self.bytecode[i + 2] == 0x01 { // ADD
                return true;
            }
        }
        
        false
    }

    fn has_minimum_value_check(&self, start: usize, distance: usize) -> bool {
        let end = (start + distance).min(self.bytecode.len());
        
        // Look for: GT/LT followed by JUMPI (minimum check pattern)
        for i in start..end.saturating_sub(2) {
            if (self.bytecode[i] == 0x10 || self.bytecode[i] == 0x11) && // GT or LT
               self.bytecode[i + 1] == 0x57 { // JUMPI
                return true;
            }
        }
        
        false
    }

    fn find_deposit_function(&self) -> Option<usize> {
        let deposit_selectors = [
            [0xb4, 0x60, 0xaf, 0x94], // deposit(uint256,address)
            [0x60, 0x05, 0xb4, 0x60], // mint(uint256,address)
        ];
        
        for selector in &deposit_selectors {
            if let Some(pc) = self.find_function_selector(selector) {
                return Some(pc);
            }
        }
        
        None
    }

    fn has_liquidity_burn_pattern(&self, start: usize, distance: usize) -> bool {
        let end = (start + distance).min(self.bytecode.len());
        
        // Look for transfer to address(0) - PUSH20 0x0000...0000
        for i in start..end.saturating_sub(20) {
            if self.bytecode[i] == 0x73 { // PUSH20
                // Check if next 20 bytes are all zeros
                if self.bytecode[i+1..i+21].iter().all(|&b| b == 0x00) {
                    return true;
                }
            }
        }
        
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vulnerable_erc4626() {
        // Simplified vulnerable ERC-4626 pattern
        let bytecode = vec![
            // convertToShares selector
            0x63, 0xc6, 0xe6, 0xf5, 0x92,
            // ... share calculation
            0x02, // MUL: assets * totalSupply
            0x04, // DIV: / totalAssets
            // No virtual shares (missing PUSH1 1, ADD)
        ];
        
        let detector = FirstDepositorAttackDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(!vulns.is_empty(), "Should detect first depositor vulnerability");
    }
}
