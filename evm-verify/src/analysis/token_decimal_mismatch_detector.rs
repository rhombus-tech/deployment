/// Token Decimal Mismatch Detector
/// 
/// Detects when tokens with different decimals are used incorrectly
/// USDC=6 decimals, DAI=18 decimals, WBTC=8 decimals
/// 
/// Example:
/// ```solidity
/// function swap(address tokenIn, address tokenOut, uint amount) {
///     // USDC (6 decimals) to DAI (18 decimals)
///     uint daiAmount = amount; // Wrong! Should be amount * 1e12
///     IERC20(tokenOut).transfer(msg.sender, daiAmount);
/// }
/// ```

use crate::bytecode::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenDecimalMismatchVulnerability {
    pub location: usize,
    pub severity: SecuritySeverity,
    pub mismatch_type: DecimalMismatchType,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DecimalMismatchType {
    SwapWithoutConversion,       // Swap tokens without decimal adjustment
    PriceCalculationMismatch,    // Price calc assumes same decimals
    RewardDistributionMismatch,  // Rewards calculated with wrong decimals
    CollateralValueMismatch,     // Collateral value uses wrong decimals
    SharePriceMismatch,          // Share price assumes 18 decimals
    LiquidityPoolMismatch,       // LP tokens with different decimals
}

pub struct TokenDecimalMismatchDetector {
    bytecode: Vec<u8>,
}

impl TokenDecimalMismatchDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<TokenDecimalMismatchVulnerability> {
        let mut vulnerabilities = Vec::new();

        // 1. Swap without decimal conversion
        vulnerabilities.extend(self.detect_swap_mismatch());

        // 2. Price calculation without decimal adjustment
        vulnerabilities.extend(self.detect_price_calculation_mismatch());

        // 3. Reward distribution with wrong decimals
        vulnerabilities.extend(self.detect_reward_mismatch());

        // 4. Share price assumes all tokens are 18 decimals
        vulnerabilities.extend(self.detect_share_price_mismatch());

        // 5. Missing decimals() call before math
        vulnerabilities.extend(self.detect_missing_decimals_call());

        vulnerabilities
    }

    fn detect_swap_mismatch(&self) -> Vec<TokenDecimalMismatchVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: Token transfer without decimal adjustment
            // Look for: transfer call without 1e18, 1e12, 1e6 constants
            if self.has_transfer_without_decimal_conversion(pc) {
                vulns.push(TokenDecimalMismatchVulnerability {
                    location: pc,
                    severity: SecuritySeverity::Critical,
                    mismatch_type: DecimalMismatchType::SwapWithoutConversion,
                    description: "Token swap/transfer without decimal conversion".to_string(),
                    exploit_scenario: "function swap(uint usdcAmount) {\n\
                        // USDC has 6 decimals, DAI has 18\n\
                        uint daiAmount = usdcAmount; // No conversion!\n\
                        // User deposits 1000 USDC (1000e6)\n\
                        // Gets 1000 DAI (should be 1000e18)\n\
                        // User loses 1000e12 in value (99.9999% loss)\n\
                        dai.transfer(msg.sender, daiAmount);\n\
                        }".to_string(),
                    remediation: "Convert between decimals: daiAmount = usdcAmount * 1e12 (for 6→18 decimals)".to_string(),
                    confidence: 0.70,
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_price_calculation_mismatch(&self) -> Vec<TokenDecimalMismatchVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: Price = amount * price without decimal normalization
            if self.has_price_calc_without_normalization(pc) {
                vulns.push(TokenDecimalMismatchVulnerability {
                    location: pc,
                    severity: SecuritySeverity::High,
                    mismatch_type: DecimalMismatchType::PriceCalculationMismatch,
                    description: "Price calculation assumes all tokens have same decimals".to_string(),
                    exploit_scenario: "function calculateValue(uint usdcAmount) {\n\
                        // Oracle returns price in 18 decimals\n\
                        uint price = oracle.getPrice(USDC); // Returns 1e18 for $1\n\
                        // USDC has 6 decimals\n\
                        uint value = usdcAmount * price;    // Wrong!\n\
                        // 1000 USDC (1000e6) * 1e18 = 1000e24 (instead of 1000e18)\n\
                        // Value inflated by 1e12 (1 trillion times)\n\
                        }".to_string(),
                    remediation: "Normalize: value = usdcAmount * price / 1e6 (adjust for USDC decimals)".to_string(),
                    confidence: 0.75,
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_reward_mismatch(&self) -> Vec<TokenDecimalMismatchVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: Reward calculation without decimal consideration
            if self.has_reward_calc_mismatch(pc) {
                vulns.push(TokenDecimalMismatchVulnerability {
                    location: pc,
                    severity: SecuritySeverity::High,
                    mismatch_type: DecimalMismatchType::RewardDistributionMismatch,
                    description: "Reward distribution uses wrong token decimals".to_string(),
                    exploit_scenario: "function distributeRewards(address rewardToken) {\n\
                        // Calculate rewards assuming 18 decimals\n\
                        uint rewardPerShare = totalReward * 1e18 / totalShares;\n\
                        // But rewardToken is USDC (6 decimals)\n\
                        // Users receive 1e12 less rewards than expected\n\
                        // Protocol loses/gains funds due to miscalculation\n\
                        }".to_string(),
                    remediation: "Query token decimals: uint decimals = IERC20Metadata(token).decimals()".to_string(),
                    confidence: 0.68,
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_share_price_mismatch(&self) -> Vec<TokenDecimalMismatchVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: Share price calculation hardcoded to 1e18
            if self.has_hardcoded_decimal_assumption(pc) {
                vulns.push(TokenDecimalMismatchVulnerability {
                    location: pc,
                    severity: SecuritySeverity::Critical,
                    mismatch_type: DecimalMismatchType::SharePriceMismatch,
                    description: "Share price calculation assumes 18 decimals for underlying".to_string(),
                    exploit_scenario: "function convertToShares(uint assets) {\n\
                        // Hardcoded 1e18 precision\n\
                        return assets * totalSupply / totalAssets * 1e18;\n\
                        // But if asset is USDC (6 decimals):\n\
                        // Depositing 1000 USDC (1000e6)\n\
                        // Gets 1000e24 shares (inflated by 1e18)\n\
                        // Can drain entire vault with small deposit\n\
                        }".to_string(),
                    remediation: "Use asset decimals: return assets * totalSupply * 10**decimals / totalAssets".to_string(),
                    confidence: 0.80,
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_missing_decimals_call(&self) -> Vec<TokenDecimalMismatchVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: Math operations without checking decimals
            if self.has_math_without_decimals_check(pc) {
                vulns.push(TokenDecimalMismatchVulnerability {
                    location: pc,
                    severity: SecuritySeverity::Medium,
                    mismatch_type: DecimalMismatchType::SwapWithoutConversion,
                    description: "Math operations on token amounts without checking decimals".to_string(),
                    exploit_scenario: "function addLiquidity(address tokenA, address tokenB, uint amountA, uint amountB) {\n\
                        // No decimals() call\n\
                        uint lpTokens = sqrt(amountA * amountB); // Assumes same decimals\n\
                        // If tokenA=WETH (18 decimals), tokenB=USDC (6 decimals)\n\
                        // Math is completely wrong, LP tokens mispriced\n\
                        }".to_string(),
                    remediation: "Call decimals() on both tokens and normalize before math".to_string(),
                    confidence: 0.65,
                });
            }

            pc += 1;
        }

        vulns
    }

    // Helper functions

    fn has_transfer_without_decimal_conversion(&self, start: usize) -> bool {
        if start + 40 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 40];

        // Look for transfer/transferFrom without decimal constants
        let has_transfer = self.has_erc20_transfer(window);
        
        // Common decimal conversion constants
        let decimal_constants = [
            0x0de0b6b3a7640000u64, // 1e18
            0x00038d7ea4c68000u64, // 1e15
            0x000000e8d4a51000u64, // 1e12
            0x00000002540be400u64, // 1e9
            0x0000000000989680u64, // 1e6
        ];

        if has_transfer {
            // Check if any decimal conversion constant appears nearby
            !self.has_any_decimal_constant(window, &decimal_constants)
        } else {
            false
        }
    }

    fn has_price_calc_without_normalization(&self, start: usize) -> bool {
        if start + 35 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 35];

        // Pattern: MUL → DIV without decimal adjustment
        // Price calculations often look like: amount * price / something
        let has_mul = window.iter().any(|&b| b == 0x02); // MUL
        let has_div = window.iter().any(|&b| b == 0x04); // DIV

        if has_mul && has_div {
            // Check if there's no decimal constant for normalization
            !self.has_decimal_normalization(window)
        } else {
            false
        }
    }

    fn has_reward_calc_mismatch(&self, start: usize) -> bool {
        if start + 40 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 40];

        // Pattern: Reward calculation (MUL/DIV) with hardcoded 1e18
        let has_math = window.iter().any(|&b| b == 0x02 || b == 0x04); // MUL or DIV
        let has_1e18 = self.has_constant(window, 0x0de0b6b3a7640000u64); // 1e18

        // If using 1e18 but also doing token transfer (might be wrong decimals)
        has_math && has_1e18 && self.has_erc20_transfer(window)
    }

    fn has_hardcoded_decimal_assumption(&self, start: usize) -> bool {
        if start + 45 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 45];

        // Look for vault-style calculations with hardcoded 1e18
        // Pattern: assets * totalSupply / totalAssets with 1e18
        let mul_count = window.iter().filter(|&&b| b == 0x02).count(); // MUL
        let div_count = window.iter().filter(|&&b| b == 0x04).count(); // DIV
        let has_1e18 = self.has_constant(window, 0x0de0b6b3a7640000u64);

        mul_count >= 2 && div_count >= 1 && has_1e18
    }

    fn has_math_without_decimals_check(&self, start: usize) -> bool {
        if start + 50 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 50];

        // Look for math operations without decimals() function call
        // decimals() selector: 0x313ce567
        let has_math = window.iter().any(|&b| b == 0x02 || b == 0x04 || b == 0x0a); // MUL, DIV, EXP
        let has_decimals_call = window.windows(4).any(|w| {
            w == [0x31, 0x3c, 0xe5, 0x67] // decimals() selector
        });

        has_math && !has_decimals_call
    }

    fn has_erc20_transfer(&self, window: &[u8]) -> bool {
        // ERC20 transfer selector: 0xa9059cbb
        // transferFrom selector: 0x23b872dd
        window.windows(4).any(|w| {
            w == [0xa9, 0x05, 0x9c, 0xbb] || // transfer
            w == [0x23, 0xb8, 0x72, 0xdd]    // transferFrom
        })
    }

    fn has_any_decimal_constant(&self, window: &[u8], constants: &[u64]) -> bool {
        for &constant in constants {
            if self.has_constant(window, constant) {
                return true;
            }
        }
        false
    }

    fn has_constant(&self, window: &[u8], constant: u64) -> bool {
        let bytes = constant.to_be_bytes();
        window.windows(8).any(|w| w == bytes)
    }

    fn has_decimal_normalization(&self, window: &[u8]) -> bool {
        // Common normalization: division by 1e6, 1e12, 1e18
        let normalization_constants = [
            0x0de0b6b3a7640000u64, // 1e18
            0x000000e8d4a51000u64, // 1e12
            0x0000000000989680u64, // 1e6
        ];

        self.has_any_decimal_constant(window, &normalization_constants)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_swap_without_conversion() {
        // Transfer without decimal adjustment
        let mut bytecode = vec![0xa9, 0x05, 0x9c, 0xbb]; // transfer()
        bytecode.extend_from_slice(&[0x02, 0x04]); // MUL, DIV
        // No 1e18 or 1e12 constant
        
        let detector = TokenDecimalMismatchDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(!vulns.is_empty());
    }
}
