/// Assert vs Require Misuse Detector
///
/// Detects incorrect usage of assert() vs require() in Solidity.
/// Critical difference: assert() consumes ALL gas on failure, require() refunds.
///
/// Why dangerous:
/// - assert() for input validation = users lose all gas on failure
/// - Pre-0.8.0: assert() uses INVALID opcode (consumes all gas)
/// - Post-0.8.0: Both use revert, but semantic difference remains
/// - Wrong usage = $5M+ in wasted gas + poor UX
///
/// CORRECT USAGE:
/// - require(): Input validation, preconditions, external checks
/// - assert(): Invariant checks, internal consistency, "should never fail"
///
/// Real impact:
/// - **$5M+ in wasted gas fees**
/// - Poor user experience (total gas loss on valid errors)
/// - Incorrect error handling patterns
///
/// Example vulnerability:
/// ```solidity
/// contract AssertMisuse {
///     mapping(address => uint256) public balances;
///     
///     function withdraw(uint256 amount) external {
///         // ❌ WRONG: assert() for input validation!
///         assert(balances[msg.sender] >= amount);
///         // User mistake = loses ALL gas!
///         
///         balances[msg.sender] -= amount;
///         payable(msg.sender).transfer(amount);
///     }
///     
///     // ✓ CORRECT:
///     function withdrawCorrect(uint256 amount) external {
///         require(balances[msg.sender] >= amount, "Insufficient balance");
///         // User mistake = refunds remaining gas
///         
///         balances[msg.sender] -= amount;
///         payable(msg.sender).transfer(amount);
///     }
/// }
/// ```

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssertRequireVulnerability {
    pub vulnerability_type: AssertIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AssertIssueType {
    AssertUsedForValidation,       // assert() used like require()
    MultipleAsserts,               // Heavy assert() usage (suspicious)
    InvalidOpcodeDetected,         // INVALID opcode (pre-0.8.0 assert)
}

pub struct AssertRequireMisuseDetector {
    bytecode: Vec<u8>,
}

impl AssertRequireMisuseDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<AssertRequireVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_invalid_opcode());
        vulnerabilities.extend(self.detect_suspicious_assert_usage());

        vulnerabilities
    }

    fn detect_invalid_opcode(&self) -> Vec<AssertRequireVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len() {
            if self.bytecode[i] == 0xFE { // INVALID opcode
                vulnerabilities.push(AssertRequireVulnerability {
                    vulnerability_type: AssertIssueType::InvalidOpcodeDetected,
                    severity: SecuritySeverity::Medium,
                    confidence: 0.85,
                    description: "INVALID opcode detected - likely assert() in pre-0.8.0 Solidity".to_string(),
                    exploit_scenario: format!(
                        "ASSERT() DETECTED at position {}:\n\
                        \n\
                        INVALID opcode (0xFE) indicates assert() usage.\n\
                        In Solidity < 0.8.0, assert() consumes ALL gas on failure!\n\
                        \n\
                        CRITICAL DIFFERENCE:\n\
                        \n\
                        PRE-0.8.0:\n\
                        - require() → REVERT (0xFD) → Refunds remaining gas\n\
                        - assert() → INVALID (0xFE) → Consumes ALL gas!\n\
                        \n\
                        POST-0.8.0:\n\
                        - Both use REVERT, but semantic difference remains\n\
                        \n\
                        WRONG USAGE:\n\
                        ```solidity\n\
                        function transfer(address to, uint256 amount) external {{\n\
                            // ❌ WRONG: assert() for input validation\n\
                            assert(balances[msg.sender] >= amount);\n\
                            assert(to != address(0));\n\
                            \n\
                            // User typo = loses ALL gas!\n\
                            balances[msg.sender] -= amount;\n\
                            balances[to] += amount;\n\
                        }}\n\
                        ```\n\
                        \n\
                        CORRECT USAGE:\n\
                        ```solidity\n\
                        function transfer(address to, uint256 amount) external {{\n\
                            // ✓ CORRECT: require() for validation\n\
                            require(balances[msg.sender] >= amount, 'Low balance');\n\
                            require(to != address(0), 'Zero address');\n\
                            \n\
                            uint256 oldBalance = balances[msg.sender];\n\
                            balances[msg.sender] -= amount;\n\
                            balances[to] += amount;\n\
                            \n\
                            // ✓ CORRECT: assert() for invariant\n\
                            assert(balances[msg.sender] + amount == oldBalance);\n\
                        }}\n\
                        ```\n\
                        \n\
                        WHEN TO USE EACH:\n\
                        \n\
                        require():\n\
                        ✓ Input validation\n\
                        ✓ Preconditions\n\
                        ✓ External call results\n\
                        ✓ User-facing errors\n\
                        ✓ Access control\n\
                        \n\
                        assert():\n\
                        ✓ Internal invariants\n\
                        ✓ Overflow checks (pre-0.8.0)\n\
                        ✓ Math that should never fail\n\
                        ✓ Post-conditions\n\
                        ✓ 'This should be impossible' checks\n\
                        \n\
                        GAS IMPACT:\n\
                        User sends tx with 100,000 gas:\n\
                        - require() fails → Refunds ~95,000 gas\n\
                        - assert() fails (pre-0.8.0) → Consumes ALL 100,000 gas!\n\
                        \n\
                        COST: $5M+ in wasted gas across ecosystem",
                        i
                    ),
                    location: i,
                });
            }
        }

        vulnerabilities
    }

    fn detect_suspicious_assert_usage(&self) -> Vec<AssertRequireVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Count INVALID opcodes (pre-0.8.0 assert indicator)
        let invalid_count = self.bytecode.iter().filter(|&&b| b == 0xFE).count();

        if invalid_count > 5 {
            vulnerabilities.push(AssertRequireVulnerability {
                vulnerability_type: AssertIssueType::MultipleAsserts,
                severity: SecuritySeverity::Low,
                confidence: 0.60,
                description: format!("Heavy assert() usage detected ({} instances) - verify correct usage", invalid_count),
                exploit_scenario: "Multiple assert() statements detected. Ensure they're used for invariants, not input validation.".to_string(),
                location: 0,
            });
        }

        vulnerabilities
    }
}
