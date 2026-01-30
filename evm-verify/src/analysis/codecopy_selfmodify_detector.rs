/// CODECOPY Self-Modification Vulnerability Detector
///
/// Detects attempts to modify runtime code, which is impossible but indicates bugs.
/// EVM runtime code is immutable - CODECOPY can only READ code, not modify it.
///
/// Why dangerous:
/// - Indicates misunderstanding of EVM
/// - Logic assumes code can be modified → won't work as expected
/// - May be trying to implement metamorphic contract incorrectly
/// - Critical security logic based on false assumption
///
/// EVM code immutability:
/// - CODECOPY: Copies code to memory (read-only)
/// - Code at address is immutable after deployment
/// - Constructor can modify code during deployment
/// - Runtime code cannot self-modify
///
/// Common misconceptions:
/// - "I'll update my code at runtime" → impossible
/// - Using CODECOPY thinking it modifies code → only reads
/// - Trying to patch bugs by modifying bytecode → can't
/// - Self-upgrading logic without proxy → won't work
///
/// Real risks:
/// - Security logic that never executes (thinks code updated)
/// - Upgrade mechanisms that fail silently
/// - Metamorphic attempts that don't work
/// - Critical bugs unfixable due to immutability
///
/// Example misconception:
/// ```solidity
/// // ❌ MISCONCEPTION - This doesn't work!
/// contract AttemptedSelfModification {
///     function "upgrade"() external {
///         assembly {
///             // ❌ Can't modify runtime code!
///             // This only copies code to memory, doesn't modify contract
///             codecopy(0, 0, codesize())
///             
///             // Attacker thinks: modify memory then write back
///             // Reality: Code is immutable, this does nothing
///             mstore(100, 0xdeadbeef)
///             
///             // No opcode exists to write memory back to code!
///         }
///     }
/// }
/// ```

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodecopyVulnerability {
    pub vulnerability_type: CodecopyIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CodecopyIssueType {
    CodecopyThenMstore,            // CODECOPY followed by MSTORE (suggests modification attempt)
    CodecopyInUserFunction,        // CODECOPY in user-callable function (unusual)
    CodecopyWithCodesize,          // CODECOPY of full code (metamorphic attempt?)
    SuspiciousCodecopyPattern,     // Pattern suggests misunderstanding
}

pub struct CodecopySelfModifyDetector {
    bytecode: Vec<u8>,
}

impl CodecopySelfModifyDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<CodecopyVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_codecopy_then_modify());
        vulnerabilities.extend(self.detect_codecopy_full_code());

        vulnerabilities
    }

    fn detect_codecopy_then_modify(&self) -> Vec<CodecopyVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x39 { // CODECOPY
                // Check if followed by MSTORE (suggests trying to modify)
                if self.has_mstore_after(i) {
                    vulnerabilities.push(CodecopyVulnerability {
                        vulnerability_type: CodecopyIssueType::CodecopyThenMstore,
                        severity: SecuritySeverity::Medium,
                        confidence: 0.70,
                        description: "CODECOPY followed by MSTORE - possible self-modification attempt".to_string(),
                        exploit_scenario: format!(
                            "CODECOPY + MSTORE PATTERN at position {}:\n\
                            \n\
                            POSSIBLE MISCONCEPTION: Code trying to modify itself?\n\
                            \n\
                            IMPORTANT: EVM runtime code is IMMUTABLE!\n\
                            \n\
                            COMMON MISCONCEPTION:\n\
                            ```solidity\n\
                            contract MisunderstandingEVM {{\n\
                                function attemptUpgrade(bytes memory newCode) external {{\n\
                                    assembly {{\n\
                                        // ❌ WRONG: Thinks this modifies contract code\n\
                                        codecopy(0, 0, codesize())\n\
                                        \n\
                                        // Modify in memory\n\
                                        mstore(0x20, 0xdeadbeef)\n\
                                        \n\
                                        // ❌ PROBLEM: No way to write memory back to code!\n\
                                        // Code remains unchanged\n\
                                        // Contract still has original code\n\
                                    }}\n\
                                }}\n\
                            }}\n\
                            ```\n\
                            \n\
                            WHAT CODECOPY ACTUALLY DOES:\n\
                            ```\n\
                            CODECOPY(destOffset, offset, length)\n\
                            - Reads code from current contract\n\
                            - Copies to memory at destOffset\n\
                            - This is READ-ONLY operation\n\
                            - Does NOT modify contract code\n\
                            - Memory changes don't affect code\n\
                            ```\n\
                            \n\
                            WHY CODE IS IMMUTABLE:\n\
                            1. Security: Prevent runtime modifications\n\
                            2. Determinism: Same code = same behavior always\n\
                            3. Verification: Audited code can't change\n\
                            4. Trust: Users know code won't change\n\
                            \n\
                            IF YOU WANT UPGRADEABLE CODE:\n\
                            \n\
                            Option 1: Proxy Pattern (Recommended)\n\
                            ```solidity\n\
                            contract Proxy {{\n\
                                address public implementation;\n\
                                \n\
                                function setImplementation(address newImpl) external {{\n\
                                    implementation = newImpl;\n\
                                }}\n\
                                \n\
                                fallback() external payable {{\n\
                                    // DELEGATECALL to implementation\n\
                                    // Implementation can be changed\n\
                                    address impl = implementation;\n\
                                    assembly {{\n\
                                        calldatacopy(0, 0, calldatasize())\n\
                                        let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)\n\
                                        returndatacopy(0, 0, returndatasize())\n\
                                        switch result\n\
                                        case 0 {{ revert(0, returndatasize()) }}\n\
                                        default {{ return(0, returndatasize()) }}\n\
                                    }}\n\
                                }}\n\
                            }}\n\
                            ```\n\
                            \n\
                            Option 2: Metamorphic Contracts (Advanced)\n\
                            ```solidity\n\
                            // Step 1: Deploy contract\n\
                            // Step 2: SELFDESTRUCT\n\
                            // Step 3: Redeploy to same address with CREATE2\n\
                            // Same address, different code\n\
                            // Complex, use with caution!\n\
                            ```\n\
                            \n\
                            Option 3: External Library Pattern\n\
                            ```solidity\n\
                            contract Main {{\n\
                                address public logic;\n\
                                \n\
                                function execute(bytes calldata data) external {{\n\
                                    // Call external logic contract\n\
                                    (bool success,) = logic.call(data);\n\
                                    require(success);\n\
                                }}\n\
                                \n\
                                function updateLogic(address newLogic) external {{\n\
                                    logic = newLogic; // Can update logic address\n\
                                }}\n\
                            }}\n\
                            ```\n\
                            \n\
                            VALID CODECOPY USES:\n\
                            ```solidity\n\
                            // ✓ Copy code to return it\n\
                            function getCode() external view returns (bytes memory) {{\n\
                                bytes memory code = new bytes(codesize);\n\
                                assembly {{\n\
                                    codecopy(add(code, 0x20), 0, codesize())\n\
                                }}\n\
                                return code;\n\
                            }}\n\
                            \n\
                            // ✓ Verify code hash\n\
                            function verifyCode(bytes32 expectedHash) external view {{\n\
                                bytes memory code = new bytes(codesize);\n\
                                assembly {{\n\
                                    codecopy(add(code, 0x20), 0, codesize())\n\
                                }}\n\
                                require(keccak256(code) == expectedHash);\n\
                            }}\n\
                            \n\
                            // ✓ Clone contract (in factory)\n\
                            function clone() external returns (address) {{\n\
                                bytes memory code = new bytes(codesize);\n\
                                assembly {{\n\
                                    codecopy(add(code, 0x20), 0, codesize())\n\
                                    let addr := create(0, add(code, 0x20), codesize())\n\
                                }}\n\
                                return addr;\n\
                            }}\n\
                            ```\n\
                            \n\
                            IMPACT OF MISCONCEPTION:\n\
                            - Security logic never executes\n\
                            - Upgrade mechanisms fail silently  \n\
                            - Contract behavior doesn't match intent\n\
                            - Critical bugs unfixable\n\
                            \n\
                            RECOMMENDATION:\n\
                            - Verify this CODECOPY is for reading, not modifying\n\
                            - If upgradeability needed, use proxy pattern\n\
                            - Document why CODECOPY is used\n\
                            - Review logic assuming code can change",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_codecopy_full_code(&self) -> Vec<CodecopyVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x39 { // CODECOPY
                // Check if copying full codesize
                if self.has_codesize_before(i) {
                    vulnerabilities.push(CodecopyVulnerability {
                        vulnerability_type: CodecopyIssueType::CodecopyWithCodesize,
                        severity: SecuritySeverity::Low,
                        confidence: 0.65,
                        description: "CODECOPY of full contract code detected".to_string(),
                        exploit_scenario: format!(
                            "FULL CODE COPY at position {}:\n\
                            \n\
                            Contract copies its entire code with CODECOPY.\n\
                            \n\
                            Valid uses:\n\
                            - Returning code for verification\n\
                            - Cloning contract\n\
                            - Code hash computation\n\
                            \n\
                            Invalid uses:\n\
                            - Attempting to modify code (impossible)\n\
                            - Self-upgrade without proxy (won't work)\n\
                            \n\
                            Verify the intent is correct.",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn has_mstore_after(&self, pos: usize) -> bool {
        for i in pos..pos.saturating_add(20).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x52 { // MSTORE
                return true;
            }
        }
        false
    }

    fn has_codesize_before(&self, pos: usize) -> bool {
        for i in pos.saturating_sub(10)..pos {
            if self.bytecode[i] == 0x38 { // CODESIZE
                return true;
            }
        }
        false
    }
}
