/// Redundant SafeMath Detector (Post Solidity 0.8.0)
///
/// Detects usage of SafeMath library in Solidity >= 0.8.0.
/// Solidity 0.8.0+ has built-in overflow/underflow checks - SafeMath is redundant.
///
/// Why it matters:
/// - Wastes gas (double-checking)
/// - Unnecessary code bloat
/// - Shows outdated practices
/// - Not a security issue, but optimization issue
///
/// Background:
/// - Pre-0.8.0: No overflow checks, SafeMath required
/// - Post-0.8.0: Built-in checks, SafeMath redundant
/// - Using SafeMath in 0.8.0+ = paying twice for same check
///
/// Example:
/// ```solidity
/// // Solidity 0.8.0+
/// import "@openzeppelin/contracts/utils/math/SafeMath.sol";
///
/// contract RedundantSafeMath {
///     using SafeMath for uint256;
///     
///     function add(uint256 a, uint256 b) external pure returns (uint256) {
///         // ❌ Redundant! Compiler already checks overflow
///         return a.add(b);
///         
///         // ✓ Just use: return a + b;
///     }
/// }
/// ```

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedundantSafeMathVulnerability {
    pub vulnerability_type: SafeMathIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SafeMathIssueType {
    SafeMathInModernSolidity,      // SafeMath used in 0.8.0+
    DoubleChecking,                // Redundant overflow checks
}

pub struct RedundantSafeMathDetector {
    bytecode: Vec<u8>,
}

impl RedundantSafeMathDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<RedundantSafeMathVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for patterns that might indicate SafeMath usage
        // SafeMath typically has checked operations followed by reverts
        vulnerabilities.extend(self.detect_safemath_patterns());

        vulnerabilities
    }

    fn detect_safemath_patterns(&self) -> Vec<RedundantSafeMathVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Bytecode-level detection is limited - this provides awareness
        // Look for multiple overflow check patterns (builtin + SafeMath)
        let mut check_count = 0;
        
        for i in 0..self.bytecode.len().saturating_sub(3) {
            // Pattern: operation + overflow check + revert
            if self.bytecode[i] == 0x10 { // LT (less than - used in overflow checks)
                if self.has_revert_nearby(i) {
                    check_count += 1;
                }
            }
        }

        if check_count > 10 {
            vulnerabilities.push(RedundantSafeMathVulnerability {
                vulnerability_type: SafeMathIssueType::DoubleChecking,
                severity: SecuritySeverity::Low,
                confidence: 0.35,
                description: format!("Multiple overflow checks detected ({}) - verify SafeMath not redundant", check_count),
                exploit_scenario: 
                    "POTENTIAL REDUNDANT SAFEMATH:\n\
                    \n\
                    If this contract is compiled with Solidity 0.8.0+,\n\
                    using SafeMath is redundant and wastes gas.\n\
                    \n\
                    SOLIDITY VERSION CHANGES:\n\
                    - Before 0.8.0: Overflow wraps around (need SafeMath)\n\
                    - After 0.8.0: Overflow reverts automatically\n\
                    \n\
                    GAS COMPARISON:\n\
                    ```solidity\n\
                    // Solidity 0.7.6 (before built-in checks)\n\
                    import '@openzeppelin/contracts/utils/math/SafeMath.sol';\n\
                    using SafeMath for uint256;\n\
                    \n\
                    function add(uint256 a, uint256 b) returns (uint256) {\n\
                        return a.add(b); // ✓ Necessary\n\
                    }\n\
                    \n\
                    // Solidity 0.8.0+ (built-in checks)\n\
                    function add(uint256 a, uint256 b) returns (uint256) {\n\
                        return a + b; // ✓ Same safety, less gas\n\
                    }\n\
                    \n\
                    function addRedundant(uint256 a, uint256 b) returns (uint256) {\n\
                        return a.add(b); // ❌ Double-checking, wastes gas\n\
                    }\n\
                    ```\n\
                    \n\
                    RECOMMENDATION:\n\
                    If using Solidity >= 0.8.0:\n\
                    ✓ Remove SafeMath imports\n\
                    ✓ Use native operators (+, -, *, /)\n\
                    ✓ Use 'unchecked' only when needed\n\
                    \n\
                    NOTE: This is a gas optimization, not a security issue.".to_string(),
                location: 0,
            });
        }

        vulnerabilities
    }

    fn has_revert_nearby(&self, pos: usize) -> bool {
        for i in pos..pos.saturating_add(10).min(self.bytecode.len()) {
            if self.bytecode[i] == 0xFD { // REVERT
                return true;
            }
        }
        false
    }
}
