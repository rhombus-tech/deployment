/// Fixed-Point Arithmetic Vulnerability Detector
///
/// Detects precision loss and scaling errors in fixed-point math (WAD/RAY).
/// DeFi protocols use fixed-point arithmetic - wrong scaling = fund loss.
///
/// Why dangerous:
/// - WAD = 1e18 (18 decimals), RAY = 1e27 (27 decimals)
/// - Mixing WAD and RAY causes 1e9 precision loss
/// - Division before multiplication loses precision
/// - Rounding errors accumulate in loops
///
/// Common patterns:
/// - WAD: Standard ERC20 precision (1e18)
/// - RAY: High-precision rates (1e27)
/// - Percentage: Often 1e4 or 1e6
/// - Confusion = catastrophic loss
///
/// Real exploits:
/// - $10M+ in precision loss bugs
/// - Compound interest calculation errors
/// - Aave rate manipulation
/// - Yearn vault accounting bugs
///
/// Example vulnerability:
/// ```solidity
/// contract FixedPointBug {
///     uint256 constant WAD = 1e18;
///     uint256 constant RAY = 1e27;
///     
///     function calculateInterest(uint256 principal) public pure returns (uint256) {
///         uint256 rate = 5 * RAY / 100;  // 5% in RAY
///         
///         // ❌ WRONG: Mixing WAD and RAY!
///         uint256 interest = principal * rate / WAD;
///         // Should divide by RAY, not WAD
///         // Off by 1 billion (1e9)!
///         
///         return interest;
///     }
/// }
/// ```

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixedPointVulnerability {
    pub vulnerability_type: FixedPointIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FixedPointIssueType {
    WADRAYMixup,                   // Mixing WAD (1e18) and RAY (1e27)
    PrecisionLoss,                 // Division before multiplication
    ScalingFactorError,            // Wrong scaling factor used
    RoundingInLoop,                // Rounding errors accumulate
    PercentageConfusion,           // Different percentage bases mixed
}

pub struct FixedPointArithmeticDetector {
    bytecode: Vec<u8>,
}

impl FixedPointArithmeticDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<FixedPointVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_division_multiplication_pattern());
        vulnerabilities.extend(self.detect_complex_math());

        vulnerabilities
    }

    fn detect_division_multiplication_pattern(&self) -> Vec<FixedPointVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for DIV followed by MUL (precision loss pattern)
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x04 { // DIV
                // Check if followed by MUL
                for j in i+1..i.saturating_add(15).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x02 { // MUL
                        vulnerabilities.push(FixedPointVulnerability {
                            vulnerability_type: FixedPointIssueType::PrecisionLoss,
                            severity: SecuritySeverity::Medium,
                            confidence: 0.65,
                            description: "Division before multiplication detected - precision loss risk".to_string(),
                            exploit_scenario: format!(
                                "DIVISION BEFORE MULTIPLICATION at position {}:\n\
                                \n\
                                Pattern: a / b * c\n\
                                This loses precision! Should be: a * c / b\n\
                                \n\
                                EXAMPLE:\n\
                                ```solidity\n\
                                uint256 a = 100;\n\
                                uint256 b = 3;\n\
                                uint256 c = 5;\n\
                                \n\
                                // ❌ WRONG: Loses precision\n\
                                uint256 result1 = a / b * c;\n\
                                // = (100 / 3) * 5\n\
                                // = 33 * 5  (lost 0.333...)\n\
                                // = 165\n\
                                \n\
                                // ✓ CORRECT: Preserves precision\n\
                                uint256 result2 = a * c / b;\n\
                                // = (100 * 5) / 3\n\
                                // = 500 / 3\n\
                                // = 166\n\
                                ```\n\
                                \n\
                                FIX: Always multiply before divide",
                                i
                            ),
                            location: i,
                        });
                        break;
                    }
                }
            }
        }

        vulnerabilities
    }

    fn detect_complex_math(&self) -> Vec<FixedPointVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Count math operations
        let mut math_ops = 0;
        for &byte in &self.bytecode {
            if byte == 0x01 || byte == 0x02 || byte == 0x03 || byte == 0x04 {
                math_ops += 1;
            }
        }

        if math_ops > 20 {
            vulnerabilities.push(FixedPointVulnerability {
                vulnerability_type: FixedPointIssueType::ScalingFactorError,
                severity: SecuritySeverity::Medium,
                confidence: 0.50,
                description: format!("Complex math operations ({}) - verify fixed-point scaling", math_ops),
                exploit_scenario: 
                    "FIXED-POINT ARITHMETIC RISKS:\n\
                    \n\
                    Common scaling factors in DeFi:\n\
                    - WAD = 1e18 (standard ERC20)\n\
                    - RAY = 1e27 (high precision rates)\n\
                    - Percentage = 1e4 or 1e6\n\
                    \n\
                    CRITICAL MISTAKES:\n\
                    \n\
                    1. WAD/RAY CONFUSION:\n\
                    ```solidity\n\
                    uint256 WAD = 1e18;\n\
                    uint256 RAY = 1e27;\n\
                    \n\
                    uint256 rate = 5 * RAY / 100;  // 5% in RAY\n\
                    uint256 principal = 1000 * WAD; // 1000 tokens\n\
                    \n\
                    // ❌ WRONG: Mixed WAD and RAY\n\
                    uint256 interest = principal * rate / WAD;\n\
                    // Off by 1e9 (billion)!\n\
                    \n\
                    // ✓ CORRECT:\n\
                    uint256 interest = principal * rate / RAY;\n\
                    ```\n\
                    \n\
                    2. PERCENTAGE BASE CONFUSION:\n\
                    ```solidity\n\
                    // ❌ WRONG: Inconsistent bases\n\
                    uint256 fee1 = amount * 25 / 10000;  // 0.25% (basis points)\n\
                    uint256 fee2 = amount * 5 / 100;     // 5% (percentage)\n\
                    // Different bases cause bugs!\n\
                    \n\
                    // ✓ CORRECT: Consistent base\n\
                    uint256 FEE_BASE = 10000;\n\
                    uint256 fee1 = amount * 25 / FEE_BASE;   // 0.25%\n\
                    uint256 fee2 = amount * 500 / FEE_BASE;  // 5%\n\
                    ```\n\
                    \n\
                    3. ROUNDING IN LOOPS:\n\
                    ```solidity\n\
                    // ❌ WRONG: Rounding errors accumulate\n\
                    for (uint i = 0; i < 100; i++) {\n\
                        shares[i] = totalShares / 100;\n\
                        // Loses precision each iteration!\n\
                    }\n\
                    \n\
                    // ✓ CORRECT: Calculate precisely\n\
                    uint256 remaining = totalShares;\n\
                    for (uint i = 0; i < 99; i++) {\n\
                        shares[i] = totalShares / 100;\n\
                        remaining -= shares[i];\n\
                    }\n\
                    shares[99] = remaining; // Last gets remainder\n\
                    ```\n\
                    \n\
                    AAVE EXAMPLE (SAFE):\n\
                    ```solidity\n\
                    function calculateInterest(\n\
                        uint256 principal,\n\
                        uint256 rate,\n\
                        uint256 time\n\
                    ) pure returns (uint256) {\n\
                        // rate in RAY (1e27)\n\
                        // time in seconds\n\
                        // result in WAD (1e18)\n\
                        return principal\n\
                            .rayMul(rate)           // RAY precision\n\
                            .rayMul(time)           // Keep RAY\n\
                            .rayDiv(365 days)       // Still RAY\n\
                            .rayToWad();            // Convert to WAD\n\
                    }\n\
                    ```\n\
                    \n\
                    RECOMMENDATIONS:\n\
                    ✓ Use consistent scaling (WAD or RAY)\n\
                    ✓ Multiply before divide\n\
                    ✓ Document all scaling factors\n\
                    ✓ Use library functions (rayMul, wadDiv)\n\
                    ✓ Test with extreme values".to_string(),
                location: 0,
            });
        }

        vulnerabilities
    }
}
