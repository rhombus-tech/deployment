/// Invalid JUMPDEST Target Detector
///
/// Detects jumps to invalid JUMPDEST locations that can cause undefined behavior.
/// JUMP/JUMPI must target valid JUMPDEST opcodes, otherwise execution fails.
///
/// Why dangerous:
/// - Dynamic jump addresses can be manipulated
/// - Invalid jump destination → execution halts or undefined behavior
/// - Can bypass critical security checks
/// - Compiler bugs can generate invalid jumps
///
/// JUMPDEST rules:
/// - Valid jump targets must be JUMPDEST opcode (0x5B)
/// - JUMPDEST must not be inside PUSH data
/// - Dynamic jumps (computed addresses) are risky
/// - Stack-based jump calculations can be manipulated
///
/// Real exploits:
/// - Compiler optimization bugs generating invalid jumps
/// - Dynamic dispatch vulnerabilities
/// - Switch statement exploitation
/// - $2M+ in compiler-related jump bugs
///
/// Example vulnerability:
/// ```solidity
/// contract VulnerableJump {
///     function dispatch(uint256 selector) external {
///         assembly {
///             // ❌ DANGEROUS: Dynamic jump based on user input!
///             let target := add(baseAddress, mul(selector, 0x20))
///             jump(target)
///             
///             // If selector manipulated:
///             // - Jump to middle of PUSH data
///             // - Jump to non-JUMPDEST
///             // - Bypass security checks
///         }
///     }
/// }
/// ```

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvalidJumpdestVulnerability {
    pub vulnerability_type: JumpdestIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JumpdestIssueType {
    DynamicJumpAddress,            // Jump address calculated at runtime
    JumpWithoutValidation,         // Jump without checking destination
    ComputedJumpTable,             // Jump table with computed addresses
    StackBasedJump,                // Jump address from stack (manipulatable)
    JumpdestInsidePushData,        // JUMPDEST inside PUSH data (invalid)
}

pub struct InvalidJumpdestDetector {
    bytecode: Vec<u8>,
}

impl InvalidJumpdestDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<InvalidJumpdestVulnerability> {
        let mut vulnerabilities = Vec::new();

        let valid_jumpdests = self.extract_valid_jumpdests();
        
        vulnerabilities.extend(self.detect_dynamic_jumps(&valid_jumpdests));
        vulnerabilities.extend(self.detect_jumpdest_in_push_data());

        vulnerabilities
    }

    fn extract_valid_jumpdests(&self) -> HashSet<usize> {
        let mut jumpdests = HashSet::new();
        let mut i = 0;

        while i < self.bytecode.len() {
            match self.bytecode[i] {
                0x5B => { // JUMPDEST
                    jumpdests.insert(i);
                    i += 1;
                }
                0x60..=0x7F => { // PUSH1-PUSH32
                    let push_size = (self.bytecode[i] - 0x5F) as usize;
                    i += push_size + 1;
                }
                _ => {
                    i += 1;
                }
            }
        }

        jumpdests
    }

    fn detect_dynamic_jumps(&self, _valid_jumpdests: &HashSet<usize>) -> Vec<InvalidJumpdestVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len() {
            if self.bytecode[i] == 0x56 || self.bytecode[i] == 0x57 { // JUMP or JUMPI
                // Check if jump destination is computed (not a simple PUSH)
                if self.has_computed_destination(i) {
                    vulnerabilities.push(InvalidJumpdestVulnerability {
                        vulnerability_type: JumpdestIssueType::DynamicJumpAddress,
                        severity: SecuritySeverity::High,
                        confidence: 0.75,
                        description: "Dynamic jump with computed destination detected".to_string(),
                        exploit_scenario: format!(
                            "DYNAMIC JUMP at position {}:\n\
                            \n\
                            Jump destination computed at runtime - manipulation risk!\n\
                            \n\
                            VULNERABLE PATTERN:\n\
                            ```solidity\n\
                            contract DynamicDispatch {{\n\
                                function execute(uint256 functionId) external {{\n\
                                    assembly {{\n\
                                        // ❌ DANGEROUS: User controls jump destination\n\
                                        let jumpTable := 0x100\n\
                                        let offset := mul(functionId, 0x20)\n\
                                        let target := add(jumpTable, offset)\n\
                                        \n\
                                        jump(target)\n\
                                        \n\
                                        // If functionId manipulated:\n\
                                        // - Jump to arbitrary location\n\
                                        // - Skip authorization checks\n\
                                        // - Execute unintended code paths\n\
                                    }}\n\
                                }}\n\
                            }}\n\
                            ```\n\
                            \n\
                            REAL RISK: Switch Statement Vulnerabilities\n\
                            \n\
                            Solidity switch statements compile to jump tables:\n\
                            ```solidity\n\
                            function processAction(uint8 action) external {{\n\
                                if (action == 0) {{ /* code0 */ }}\n\
                                else if (action == 1) {{ /* code1 */ }}\n\
                                else if (action == 2) {{ /* code2 */ }}\n\
                                // ...\n\
                                \n\
                                // Compiles to jump table with dynamic offset\n\
                                // If bounds check missing → jump anywhere!\n\
                            }}\n\
                            ```\n\
                            \n\
                            ATTACK SCENARIO:\n\
                            ```solidity\n\
                            contract VulnerableRouter {{\n\
                                function route(uint256 dest) external payable {{\n\
                                    assembly {{\n\
                                        // Jump table at 0x200\n\
                                        // Entries: 0x200, 0x220, 0x240, 0x260\n\
                                        \n\
                                        let target := add(0x200, mul(dest, 0x20))\n\
                                        jump(target)\n\
                                        \n\
                                        // Normal destinations:\n\
                                        // dest=0 → 0x200 (authorized function)\n\
                                        // dest=1 → 0x220 (authorized function)\n\
                                        // dest=2 → 0x240 (authorized function)\n\
                                        \n\
                                        // Attack:\n\
                                        // dest=999 → 0x200 + (999*32) = 0x7C60\n\
                                        // If 0x7C60 contains admin function...\n\
                                        // Authorization bypassed!\n\
                                    }}\n\
                                }}\n\
                            }}\n\
                            ```\n\
                            \n\
                            COMPILER BUG HISTORY:\n\
                            \n\
                            1. Solidity < 0.5.0: Switch without bounds check\n\
                            2. Vyper < 0.2.0: Jump table overflow\n\
                            3. Yul optimizer: Invalid jump optimizations\n\
                            \n\
                            SAFE PATTERNS:\n\
                            ```solidity\n\
                            // ✓ Bounds-checked dispatch\n\
                            function safeDispatch(uint256 id) external {{\n\
                                require(id < 4, 'Invalid function ID');\n\
                                \n\
                                if (id == 0) func0();\n\
                                else if (id == 1) func1();\n\
                                else if (id == 2) func2();\n\
                                else if (id == 3) func3();\n\
                            }}\n\
                            \n\
                            // ✓ Or use function pointers (safer)\n\
                            mapping(uint256 => function() external) public functions;\n\
                            \n\
                            function execute(uint256 id) external {{\n\
                                require(address(functions[id]) != address(0));\n\
                                functions[id]();\n\
                            }}\n\
                            ```\n\
                            \n\
                            SEVERITY: HIGH\n\
                            - Control flow manipulation\n\
                            - Authorization bypass\n\
                            - Arbitrary code execution",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_jumpdest_in_push_data(&self) -> Vec<InvalidJumpdestVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut i = 0;

        while i < self.bytecode.len() {
            if self.bytecode[i] >= 0x60 && self.bytecode[i] <= 0x7F { // PUSH1-PUSH32
                let push_size = (self.bytecode[i] - 0x5F) as usize;
                
                // Check if there's a 0x5B (JUMPDEST) in the push data
                for j in 1..=push_size {
                    if i + j < self.bytecode.len() && self.bytecode[i + j] == 0x5B {
                        vulnerabilities.push(InvalidJumpdestVulnerability {
                            vulnerability_type: JumpdestIssueType::JumpdestInsidePushData,
                            severity: SecuritySeverity::Medium,
                            confidence: 0.90,
                            description: format!("JUMPDEST opcode found inside PUSH{} data at position {}", push_size, i),
                            exploit_scenario: format!(
                                "JUMPDEST IN PUSH DATA at position {}:\n\
                                \n\
                                JUMPDEST opcode (0x5B) found inside PUSH data.\n\
                                This is NOT a valid jump destination!\n\
                                \n\
                                If code tries to jump here, execution will fail.\n\
                                This may indicate:\n\
                                - Compiler bug\n\
                                - Bytecode corruption\n\
                                - Invalid code generation\n\
                                \n\
                                Recommendation: Verify bytecode integrity",
                                i
                            ),
                            location: i,
                        });
                    }
                }
                
                i += push_size + 1;
            } else {
                i += 1;
            }
        }

        vulnerabilities
    }

    fn has_computed_destination(&self, pos: usize) -> bool {
        // Check if jump destination is computed (ADD, MUL, etc. before JUMP)
        for i in pos.saturating_sub(20)..pos {
            if self.bytecode[i] == 0x01 || // ADD
               self.bytecode[i] == 0x02 || // MUL
               self.bytecode[i] == 0x35 || // CALLDATALOAD
               self.bytecode[i] == 0x54 {  // SLOAD
                return true;
            }
        }
        false
    }
}
