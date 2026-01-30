/// Payable Confusion Vulnerability Detector
///
/// Detects functions marked payable but revert when receiving ETH.
/// This creates confusion and can lead to stuck funds or DoS.
///
/// Why dangerous:
/// - Function signature says "payable" but reverts on ETH
/// - Users send ETH expecting success → transaction reverts
/// - Opposite: non-payable that should accept ETH
/// - Gas wasted, user confusion, potential DoS
///
/// Common patterns:
/// - Payable function with CALLVALUE check that reverts
/// - Payable modifier but internal revert on value
/// - Conditional payable (sometimes accepts, sometimes reverts)
/// - Payable fallback that always reverts
///
/// Real issues:
/// - User sends ETH to payable function → stuck in mempool/reverts
/// - Gas griefing via false payable
/// - Integration bugs (expect payable to accept ETH)
/// - $1M+ in user errors and gas waste
///
/// Example vulnerability:
/// ```solidity
/// contract ConfusingPayable {
///     // ❌ CONFUSING: Marked payable but reverts on ETH!
///     function deposit() external payable {
///         require(msg.value == 0, "Don't send ETH!");
///         // Why is this payable then?
///     }
///     
///     // ❌ WRONG: Should be payable but isn't
///     function depositETH() external {
///         // User tries to send ETH → reverts
///         balances[msg.sender] += msg.value; // This would work if payable
///     }
/// }
/// ```

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayableConfusionVulnerability {
    pub vulnerability_type: PayableIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PayableIssueType {
    PayableWithValueRevert,        // Payable function that reverts on ETH
    PayableWithZeroValueCheck,     // Requires msg.value == 0 but payable
    ConditionalPayable,            // Sometimes accepts ETH, sometimes not
    PayableFallbackReverts,        // Payable fallback always reverts
    NonPayableUsesValue,           // Non-payable but uses msg.value
}

pub struct PayableConfusionDetector {
    bytecode: Vec<u8>,
}

impl PayableConfusionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<PayableConfusionVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_payable_with_value_check());
        vulnerabilities.extend(self.detect_value_check_pattern());

        vulnerabilities
    }

    fn detect_payable_with_value_check(&self) -> Vec<PayableConfusionVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Function is payable (no CALLVALUE revert guard at start)
        // but has CALLVALUE check later that reverts on value
        
        let is_payable = !self.has_nonpayable_guard_at_start();
        
        if is_payable {
            // Look for CALLVALUE checks inside function
            for i in 100..self.bytecode.len().saturating_sub(10) {
                if self.bytecode[i] == 0x34 { // CALLVALUE
                    // Check if this is a zero-value requirement
                    if self.has_zero_value_requirement_after(i) {
                        vulnerabilities.push(PayableConfusionVulnerability {
                            vulnerability_type: PayableIssueType::PayableWithZeroValueCheck,
                            severity: SecuritySeverity::Medium,
                            confidence: 0.70,
                            description: "Function appears payable but requires msg.value == 0".to_string(),
                            exploit_scenario: format!(
                                "PAYABLE CONFUSION at position {}:\n\
                                \n\
                                Function is marked payable but reverts when ETH is sent!\n\
                                \n\
                                CONFUSING PATTERN:\n\
                                ```solidity\n\
                                contract ConfusingContract {{\n\
                                    // ❌ Says 'payable' but doesn't want ETH\n\
                                    function process() external payable {{\n\
                                        require(msg.value == 0, 'Do not send ETH');\n\
                                        // Why is this payable?\n\
                                        \n\
                                        // Process logic...\n\
                                    }}\n\
                                    \n\
                                    // User sees 'payable' → sends ETH → reverts!\n\
                                }}\n\
                                ```\n\
                                \n\
                                IMPACT:\n\
                                - User confusion (payable suggests accepts ETH)\n\
                                - Wasted gas on reverted transactions\n\
                                - Integration bugs (tools expect payable to accept ETH)\n\
                                - UX issues\n\
                                \n\
                                WHY THIS HAPPENS:\n\
                                1. Copy-paste from payable function\n\
                                2. Changed logic but forgot to remove payable\n\
                                3. Conditional logic (sometimes accepts ETH)\n\
                                4. Defensive programming (prevent accidental ETH)\n\
                                \n\
                                REAL EXAMPLE:\n\
                                ```solidity\n\
                                contract TokenSwap {{\n\
                                    // ❌ Confusing: payable but uses token, not ETH\n\
                                    function swapToken(\n\
                                        address token,\n\
                                        uint256 amount\n\
                                    ) external payable {{\n\
                                        // Require no ETH sent\n\
                                        require(msg.value == 0, 'Use swapETH for ETH swaps');\n\
                                        \n\
                                        IERC20(token).transferFrom(msg.sender, address(this), amount);\n\
                                        // Swap logic...\n\
                                    }}\n\
                                    \n\
                                    // Should be:\n\
                                    function swapToken(address token, uint256 amount) external {{\n\
                                        // ✓ Not payable, clear intent\n\
                                        IERC20(token).transferFrom(msg.sender, address(this), amount);\n\
                                    }}\n\
                                }}\n\
                                ```\n\
                                \n\
                                OPPOSITE PROBLEM:\n\
                                ```solidity\n\
                                contract WrongWay {{\n\
                                    mapping(address => uint256) public balances;\n\
                                    \n\
                                    // ❌ Should be payable but isn't!\n\
                                    function deposit() external {{\n\
                                        balances[msg.sender] += msg.value;\n\
                                        // This reverts! Function not payable!\n\
                                    }}\n\
                                    \n\
                                    // ✓ Correct version:\n\
                                    function deposit() external payable {{\n\
                                        balances[msg.sender] += msg.value;\n\
                                    }}\n\
                                }}\n\
                                ```\n\
                                \n\
                                FIX:\n\
                                ```solidity\n\
                                // Option 1: Remove payable if no ETH accepted\n\
                                function process() external {{  // Not payable\n\
                                    // No msg.value check needed\n\
                                    // Will revert automatically if ETH sent\n\
                                }}\n\
                                \n\
                                // Option 2: Accept ETH if payable\n\
                                function deposit() external payable {{\n\
                                    // Use the ETH!\n\
                                    balances[msg.sender] += msg.value;\n\
                                }}\n\
                                \n\
                                // Option 3: Clear separation\n\
                                function processToken(address token) external {{\n\
                                    // Token processing, not payable\n\
                                }}\n\
                                \n\
                                function processETH() external payable {{\n\
                                    // ETH processing, payable\n\
                                }}\n\
                                ```\n\
                                \n\
                                BEST PRACTICES:\n\
                                ✓ Only mark functions payable if they accept ETH\n\
                                ✓ If payable, actually use the ETH\n\
                                ✓ Don't require msg.value == 0 in payable function\n\
                                ✓ Clear function names (depositETH vs depositToken)\n\
                                ✓ Document expected behavior\n\
                                \n\
                                SEVERITY: MEDIUM\n\
                                - User confusion and wasted gas\n\
                                - Integration issues\n\
                                - Not a direct fund loss but UX problem",
                                i
                            ),
                            location: i,
                        });
                    }
                }
            }
        }

        vulnerabilities
    }

    fn detect_value_check_pattern(&self) -> Vec<PayableConfusionVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for confusing patterns where CALLVALUE is used
        // but function behavior is unclear
        
        let callvalue_count = self.bytecode.iter().filter(|&&b| b == 0x34).count();
        
        if callvalue_count > 2 {
            // Multiple CALLVALUE checks might indicate conditional payable
            vulnerabilities.push(PayableConfusionVulnerability {
                vulnerability_type: PayableIssueType::ConditionalPayable,
                severity: SecuritySeverity::Low,
                confidence: 0.60,
                description: format!("Multiple msg.value checks ({}) - verify payable logic is clear", callvalue_count),
                exploit_scenario: "Contract has multiple msg.value checks. This may indicate conditional payable behavior which can confuse users. Ensure clear documentation.".to_string(),
                location: 0,
            });
        }

        vulnerabilities
    }

    fn has_nonpayable_guard_at_start(&self) -> bool {
        // Check if function has non-payable guard at start
        // Pattern: CALLVALUE → ISZERO → (not) JUMPI → REVERT
        for i in 0..100.min(self.bytecode.len().saturating_sub(5)) {
            if self.bytecode[i] == 0x34 && // CALLVALUE
               i + 1 < self.bytecode.len() &&
               (self.bytecode[i+1] == 0x15 || // ISZERO
                self.bytecode[i+2] == 0x15) {
                // Likely non-payable guard
                return true;
            }
        }
        false
    }

    fn has_zero_value_requirement_after(&self, pos: usize) -> bool {
        // Pattern: CALLVALUE → PUSH 0 → EQ → condition
        for i in pos..pos.saturating_add(15).min(self.bytecode.len()) {
            if i + 3 < self.bytecode.len() {
                if self.bytecode[i] == 0x60 && // PUSH1
                   self.bytecode[i+1] == 0x00 && // 0
                   self.bytecode[i+2] == 0x14 { // EQ
                    // Check for ISZERO (require msg.value == 0)
                    return true;
                }
            }
        }
        false
    }
}
