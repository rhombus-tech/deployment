/// Token Decimal Mismatch Detector
///
/// Detects hardcoded decimal assumptions (e.g., always 18 decimals).
/// Different tokens have different decimals: USDC=6, WBTC=8, DAI=18.
///
/// Why dangerous:
/// - Assuming 18 decimals for all tokens
/// - Price calculations off by 10^12 for USDC
/// - Devastating for cross-token protocols
/// - Silent accounting errors
///
/// Real exploits:
/// - **$15M+ in DEX decimal bugs**
/// - Price oracle manipulation via decimals
/// - Vault share calculation errors
/// - Cross-chain decimal mismatches
///
/// Example vulnerability:
/// ```solidity
/// contract DecimalBug {
///     function swap(IERC20 tokenA, IERC20 tokenB, uint256 amount) external {
///         // ❌ WRONG: Assumes both have 18 decimals!
///         uint256 price = oracle.getPrice(tokenA, tokenB);
///         uint256 amountOut = amount * price / 1e18;
///         
///         // If tokenA = USDC (6 decimals), tokenB = WETH (18 decimals):
///         // User sends 1000 USDC ($1000)
///         // Gets 1000 * 1e12 more ETH than they should!
///     }
/// }
/// ```

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecimalMismatchVulnerability {
    pub vulnerability_type: DecimalIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DecimalIssueType {
    HardcodedDecimals,             // 1e18 hardcoded without decimals() check
    MissingDecimalsCall,           // Token interaction without checking decimals
    CrossTokenCalculation,         // Calculation between tokens without scaling
    AssumedEighteenDecimals,       // Explicit 18 decimal assumption
}

pub struct DecimalMismatchDetector {
    bytecode: Vec<u8>,
}

impl DecimalMismatchDetector {
    const DECIMALS_SELECTOR: [u8; 4] = [0x31, 0x3c, 0xe5, 0x67]; // decimals()
    
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<DecimalMismatchVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_hardcoded_1e18());
        vulnerabilities.extend(self.detect_missing_decimals_call());

        vulnerabilities
    }

    fn detect_hardcoded_1e18(&self) -> Vec<DecimalMismatchVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for 1e18 constant (0xDE0B6B3A7640000 in hex)
        let one_e18_bytes = 0x0DE0B6B3A7640000u64.to_be_bytes();
        
        for i in 0..self.bytecode.len().saturating_sub(8) {
            if &self.bytecode[i..i+8] == &one_e18_bytes {
                vulnerabilities.push(DecimalMismatchVulnerability {
                    vulnerability_type: DecimalIssueType::HardcodedDecimals,
                    severity: SecuritySeverity::High,
                    confidence: 0.75,
                    description: "Hardcoded 1e18 detected - verify decimal handling".to_string(),
                    exploit_scenario: format!(
                        "HARDCODED 1e18 at position {}:\n\
                        \n\
                        Hardcoded 1e18 (18 decimals) detected.\n\
                        This breaks with tokens that have different decimals!\n\
                        \n\
                        COMMON TOKEN DECIMALS:\n\
                        - USDC: 6 decimals\n\
                        - USDT: 6 decimals  \n\
                        - WBTC: 8 decimals\n\
                        - DAI: 18 decimals\n\
                        - WETH: 18 decimals\n\
                        \n\
                        ATTACK EXAMPLE:\n\
                        ```solidity\n\
                        function calculateValue(IERC20 token, uint256 amount)\n\
                            returns (uint256)\n\
                        {{\n\
                            // ❌ Assumes 18 decimals!\n\
                            return amount * price / 1e18;\n\
                            \n\
                            // If token is USDC (6 decimals):\n\
                            // 1000 USDC = 1000 * 10^6 = 1,000,000,000\n\
                            // Calculation: 1,000,000,000 * price / 10^18\n\
                            // Result off by 10^12! \n\
                        }}\n\
                        ```\n\
                        \n\
                        SAFE IMPLEMENTATION:\n\
                        ```solidity\n\
                        function calculateValue(IERC20 token, uint256 amount)\n\
                            returns (uint256)\n\
                        {{\n\
                            uint8 decimals = token.decimals();\n\
                            uint256 scaleFactor = 10 ** decimals;\n\
                            return amount * price / scaleFactor;\n\
                        }}\n\
                        ```\n\
                        \n\
                        REAL EXPLOIT:\n\
                        Multiple DEXes lost $15M+ from decimal bugs.",
                        i
                    ),
                    location: i,
                });
            }
        }

        vulnerabilities
    }

    fn detect_missing_decimals_call(&self) -> Vec<DecimalMismatchVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check if contract has token interactions but never calls decimals()
        let has_transfer = self.has_erc20_transfer();
        let has_decimals_call = self.bytecode.windows(4).any(|w| w == &Self::DECIMALS_SELECTOR);

        if has_transfer && !has_decimals_call {
            vulnerabilities.push(DecimalMismatchVulnerability {
                vulnerability_type: DecimalIssueType::MissingDecimalsCall,
                severity: SecuritySeverity::Medium,
                confidence: 0.65,
                description: "ERC-20 interactions without decimals() call".to_string(),
                exploit_scenario: "Contract interacts with ERC-20 tokens but never calls decimals(). Verify decimal handling is correct.".to_string(),
                location: 0,
            });
        }

        vulnerabilities
    }

    fn has_erc20_transfer(&self) -> bool {
        const TRANSFER: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb]; // transfer(address,uint256)
        const TRANSFER_FROM: [u8; 4] = [0x23, 0xb8, 0x72, 0xdd]; // transferFrom
        
        self.bytecode.windows(4).any(|w| w == &TRANSFER || w == &TRANSFER_FROM)
    }
}
