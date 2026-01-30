/// Internal Function Visibility Vulnerability Detector
///
/// Detects internal functions that may be exposed through public interfaces.
/// In bytecode, "internal" and "private" are identical - only matter at call sites.
///
/// Why dangerous:
/// - Internal functions can be called by any derived contract
/// - "Private" in Solidity is not truly private in bytecode
/// - Sensitive logic exposed through inheritance
/// - Cross-function attacks via unexpected paths
///
/// Key insights:
/// - Internal = callable by derived contracts
/// - Private = only callable within same contract
/// - Both compiled to same bytecode (JUMP, not CALL)
/// - Inheritance can expose "internal" logic
///
/// Real risks:
/// - Sensitive functions accessible via inheritance
/// - State manipulation through derived contracts
/// - Authorization bypass chains
/// - $2M+ in visibility bugs
///
/// Example vulnerability:
/// ```solidity
/// contract Base {
///     // ❌ DANGER: Internal means derived contracts can call!
///     function _unsafeTransfer(address to, uint256 amount) internal {
///         // No auth checks - assumes caller did them
///         balances[to] += amount;
///         balances[msg.sender] -= amount;
///     }
/// }
///
/// contract Derived is Base {
///     // ❌ Exposes base's internal function!
///     function exploit(address to, uint256 amount) external {
///         _unsafeTransfer(to, amount);
///         // No authorization check!
///     }
/// }
/// ```

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalVisibilityVulnerability {
    pub vulnerability_type: InternalVisibilityIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InternalVisibilityIssueType {
    InternalFunctionExposed,       // Internal function called from public
    PrivateNotReallyPrivate,       // Misunderstanding of "private"
    InheritanceExposure,           // Derived contract exposes base internals
    CrossFunctionAccess,           // Internal accessed from unexpected path
}

pub struct InternalFunctionVisibilityDetector {
    bytecode: Vec<u8>,
}

impl InternalFunctionVisibilityDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<InternalVisibilityVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Detect complex jump patterns that might indicate internal calls
        vulnerabilities.extend(self.detect_internal_jump_patterns());

        vulnerabilities
    }

    fn detect_internal_jump_patterns(&self) -> Vec<InternalVisibilityVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Count JUMP opcodes (internal calls use JUMP, not CALL)
        let jump_count = self.bytecode.iter().filter(|&&b| b == 0x56).count();

        if jump_count > 10 {
            vulnerabilities.push(InternalVisibilityVulnerability {
                vulnerability_type: InternalVisibilityIssueType::InternalFunctionExposed,
                severity: SecuritySeverity::Medium,
                confidence: 0.45,
                description: format!("Complex internal call structure ({} JUMPs) - verify function visibility", jump_count),
                exploit_scenario: 
                    "INTERNAL FUNCTION VISIBILITY:\n\
                    \n\
                    Critical visibility concepts:\n\
                    \n\
                    1. INTERNAL vs PRIVATE:\n\
                    ```solidity\n\
                    contract Example {\n\
                        // Internal: Derived contracts CAN call\n\
                        function _internal() internal { }\n\
                        \n\
                        // Private: Only this contract can call\n\
                        function _private() private { }\n\
                        \n\
                        // Both use JUMP in bytecode (not CALL)\n\
                        // Difference enforced at compile time only!\n\
                    }\n\
                    ```\n\
                    \n\
                    2. EXPOSURE VIA INHERITANCE:\n\
                    ```solidity\n\
                    contract Base {\n\
                        function _mint(address to) internal {\n\
                            balances[to] += 1000;\n\
                        }\n\
                    }\n\
                    \n\
                    contract Exploit is Base {\n\
                        // ❌ Exposes _mint to anyone!\n\
                        function getMoney() external {\n\
                            _mint(msg.sender);\n\
                        }\n\
                    }\n\
                    ```\n\
                    \n\
                    3. PRIVATE IS NOT PRIVATE:\n\
                    ```solidity\n\
                    contract Secrets {\n\
                        // ❌ WRONG: 'private' doesn't hide data!\n\
                        uint256 private secretKey = 12345;\n\
                        \n\
                        // Still visible:\n\
                        // - In blockchain storage\n\
                        // - In contract bytecode\n\
                        // - Via eth_getStorageAt\n\
                    }\n\
                    ```\n\
                    \n\
                    RECOMMENDATIONS:\n\
                    ✓ Use private for sensitive helpers\n\
                    ✓ Add auth to internal functions\n\
                    ✓ Review inheritance chain\n\
                    ✓ Never store secrets in 'private' vars".to_string(),
                location: 0,
            });
        }

        vulnerabilities
    }
}
