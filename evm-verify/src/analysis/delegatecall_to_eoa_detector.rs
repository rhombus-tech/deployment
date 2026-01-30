/// DELEGATECALL to EOA Vulnerability Detector
///
/// Detects delegatecall to externally owned accounts (no code).
/// DELEGATECALL to EOA succeeds but does nothing - returns success=true with empty returndata.
///
/// Why dangerous:
/// - Delegatecall to address with no code succeeds silently
/// - Logic assumes delegatecall executed code → bypassed
/// - Authorization checks in delegated contract → skipped
/// - State changes expected → don't happen
///
/// DELEGATECALL behavior:
/// - To contract: Executes code in current context
/// - To EOA (no code): Returns success=true, returndata=empty
/// - To destroyed contract: Same as EOA
///
/// Real risks:
/// - Proxy pointing to EOA → all calls succeed but do nothing
/// - Authorization bypass if checks in delegated code
/// - Critical logic skipped
/// - Silent failures
///
/// Example vulnerability:
/// ```solidity
/// contract VulnerableProxy {
///     address public implementation;
///     
///     fallback() external payable {
///         address impl = implementation;
///         
///         assembly {
///             calldatacopy(0, 0, calldatasize())
///             
///             // ❌ No check if impl has code!
///             let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
///             
///             // If impl = EOA, result = 1 (success) but nothing executed!
///             
///             returndatacopy(0, 0, returndatasize())
///             
///             switch result
///             case 0 { revert(0, returndatasize()) }
///             default { return(0, returndatasize()) }
///         }
///     }
/// }
///
/// // Attack: Set implementation to EOA
/// // All function calls succeed but do nothing
/// // Authorization checks bypassed!
/// ```

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegatecallToEOAVulnerability {
    pub vulnerability_type: DelegatecallEOAIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DelegatecallEOAIssueType {
    DelegatecallWithoutCodeCheck,  // DELEGATECALL without EXTCODESIZE check
    DelegatecallToVariable,        // DELEGATECALL to variable address
    ProxyWithoutCodeCheck,         // Proxy pattern without code validation
    DelegatecallInLoop,            // Multiple delegatecalls without validation
}

pub struct DelegatecallToEOADetector {
    bytecode: Vec<u8>,
}

impl DelegatecallToEOADetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<DelegatecallToEOAVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_delegatecall_without_code_check());
        vulnerabilities.extend(self.detect_delegatecall_to_variable());

        vulnerabilities
    }

    fn detect_delegatecall_without_code_check(&self) -> Vec<DelegatecallToEOAVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len() {
            if self.bytecode[i] == 0xF4 { // DELEGATECALL
                // Check if there's an EXTCODESIZE check before
                if !self.has_extcodesize_check_before(i) {
                    vulnerabilities.push(DelegatecallToEOAVulnerability {
                        vulnerability_type: DelegatecallEOAIssueType::DelegatecallWithoutCodeCheck,
                        severity: SecuritySeverity::High,
                        confidence: 0.80,
                        description: "DELEGATECALL without code existence check".to_string(),
                        exploit_scenario: format!(
                            "DELEGATECALL WITHOUT CODE CHECK at position {}:\n\
                            \n\
                            CRITICAL: DELEGATECALL to address without verifying code exists!\n\
                            \n\
                            VULNERABLE PATTERN:\n\
                            ```solidity\n\
                            contract VulnerableProxy {{\n\
                                address public implementation;\n\
                                \n\
                                function setImplementation(address newImpl) external {{\n\
                                    // ❌ No check if newImpl has code!\n\
                                    implementation = newImpl;\n\
                                }}\n\
                                \n\
                                fallback() external payable {{\n\
                                    address impl = implementation;\n\
                                    \n\
                                    assembly {{\n\
                                        calldatacopy(0, 0, calldatasize())\n\
                                        \n\
                                        // ❌ DELEGATECALL without EXTCODESIZE check\n\
                                        let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)\n\
                                        \n\
                                        // If impl is EOA or destroyed contract:\n\
                                        // result = 1 (success!)\n\
                                        // returndatasize = 0\n\
                                        // Nothing was executed!\n\
                                        \n\
                                        returndatacopy(0, 0, returndatasize())\n\
                                        \n\
                                        switch result\n\
                                        case 0 {{ revert(0, returndatasize()) }}\n\
                                        default {{ return(0, returndatasize()) }}\n\
                                    }}\n\
                                }}\n\
                            }}\n\
                            ```\n\
                            \n\
                            ATTACK SCENARIOS:\n\
                            \n\
                            1. AUTHORIZATION BYPASS:\n\
                            ```solidity\n\
                            // Implementation contract (expected):\n\
                            contract Implementation {{\n\
                                address public owner;\n\
                                \n\
                                function withdraw() external {{\n\
                                    require(msg.sender == owner, 'Not owner');\n\
                                    // Withdraw funds\n\
                                }}\n\
                            }}\n\
                            \n\
                            // Attack:\n\
                            // 1. Set implementation to EOA (address with no code)\n\
                            // 2. Call proxy.withdraw()\n\
                            // 3. DELEGATECALL to EOA succeeds (returns true)\n\
                            // 4. No require(msg.sender == owner) executed!\n\
                            // 5. Funds withdrawn without authorization!\n\
                            ```\n\
                            \n\
                            2. SELFDESTRUCT THEN EXPLOIT:\n\
                            ```solidity\n\
                            contract MaliciousImpl {{\n\
                                function backdoor() external {{\n\
                                    // Step 1: Destroy implementation\n\
                                    selfdestruct(payable(msg.sender));\n\
                                }}\n\
                            }}\n\
                            \n\
                            // Attack:\n\
                            // 1. Implementation is MaliciousImpl\n\
                            // 2. Call backdoor() → implementation self-destructs\n\
                            // 3. Now implementation address has no code (EOA-like)\n\
                            // 4. All future calls succeed but do nothing\n\
                            // 5. Authorization bypassed, logic skipped\n\
                            ```\n\
                            \n\
                            3. UNINITIALIZED PROXY:\n\
                            ```solidity\n\
                            contract UninitializedProxy {{\n\
                                address public implementation; // Default: address(0)\n\
                                \n\
                                fallback() external payable {{\n\
                                    // implementation = address(0)\n\
                                    // DELEGATECALL to address(0)\n\
                                    // Succeeds! Returns true!\n\
                                    // All function calls work but do nothing\n\
                                }}\n\
                            }}\n\
                            ```\n\
                            \n\
                            REAL-WORLD EXAMPLE:\n\
                            ```solidity\n\
                            contract Vault {{\n\
                                address public logic;\n\
                                mapping(address => uint256) public balances;\n\
                                \n\
                                function deposit() external payable {{\n\
                                    // Expected: delegatecall to logic contract\n\
                                    // Logic contract has: balances[msg.sender] += msg.value\n\
                                    (bool success,) = logic.delegatecall(\n\
                                        abi.encodeWithSignature('_deposit()')\n\
                                    );\n\
                                    require(success);\n\
                                }}\n\
                                \n\
                                function withdraw() external {{\n\
                                    // Expected: delegatecall checks balance\n\
                                    (bool success,) = logic.delegatecall(\n\
                                        abi.encodeWithSignature('_withdraw()')\n\
                                    );\n\
                                    require(success);\n\
                                }}\n\
                            }}\n\
                            \n\
                            // If logic points to EOA:\n\
                            // - deposit() succeeds but doesn't update balances\n\
                            // - withdraw() succeeds but doesn't check balances\n\
                            // - Anyone can withdraw all funds!\n\
                            ```\n\
                            \n\
                            SAFE IMPLEMENTATION:\n\
                            ```solidity\n\
                            contract SafeProxy {{\n\
                                address public implementation;\n\
                                \n\
                                function setImplementation(address newImpl) external {{\n\
                                    // ✓ Verify code exists\n\
                                    require(newImpl.code.length > 0, 'Not a contract');\n\
                                    \n\
                                    implementation = newImpl;\n\
                                }}\n\
                                \n\
                                fallback() external payable {{\n\
                                    address impl = implementation;\n\
                                    \n\
                                    assembly {{\n\
                                        // ✓ Check code exists\n\
                                        if iszero(extcodesize(impl)) {{\n\
                                            revert(0, 0)\n\
                                        }}\n\
                                        \n\
                                        calldatacopy(0, 0, calldatasize())\n\
                                        let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)\n\
                                        returndatacopy(0, 0, returndatasize())\n\
                                        \n\
                                        switch result\n\
                                        case 0 {{ revert(0, returndatasize()) }}\n\
                                        default {{ return(0, returndatasize()) }}\n\
                                    }}\n\
                                }}\n\
                            }}\n\
                            ```\n\
                            \n\
                            OPENZEPPELIN PATTERN:\n\
                            ```solidity\n\
                            function _setImplementation(address newImplementation) private {{\n\
                                require(\n\
                                    Address.isContract(newImplementation),\n\
                                    'ERC1967: new implementation is not a contract'\n\
                                );\n\
                                // ...\n\
                            }}\n\
                            ```\n\
                            \n\
                            FIX CHECKLIST:\n\
                            ✓ Always check EXTCODESIZE > 0 before DELEGATECALL\n\
                            ✓ Validate implementation address in setter\n\
                            ✓ Prevent address(0) as implementation\n\
                            ✓ Consider using OpenZeppelin's proxy contracts\n\
                            ✓ Add initialization checks\n\
                            \n\
                            SEVERITY: HIGH\n\
                            - Silent failures\n\
                            - Authorization bypass\n\
                            - Complete loss of contract logic",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_delegatecall_to_variable(&self) -> Vec<DelegatecallToEOAVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0xF4 { // DELEGATECALL
                // Check if target address is from storage/variable
                if self.has_variable_address_before(i) {
                    vulnerabilities.push(DelegatecallToEOAVulnerability {
                        vulnerability_type: DelegatecallEOAIssueType::DelegatecallToVariable,
                        severity: SecuritySeverity::Medium,
                        confidence: 0.75,
                        description: "DELEGATECALL to variable address - verify code check exists".to_string(),
                        exploit_scenario: format!(
                            "DELEGATECALL TO VARIABLE at position {}:\n\
                            \n\
                            DELEGATECALL target is a variable (from storage or parameter).\n\
                            \n\
                            Risk: If variable can be set to EOA, delegatecall succeeds but does nothing.\n\
                            \n\
                            Recommendation:\n\
                            - Validate address has code before delegatecall\n\
                            - Use: require(target.code.length > 0)",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn has_extcodesize_check_before(&self, pos: usize) -> bool {
        // Look for EXTCODESIZE in preceding bytecode
        for i in pos.saturating_sub(30)..pos {
            if self.bytecode[i] == 0x3B { // EXTCODESIZE
                // Check if followed by ISZERO and JUMPI/REVERT (validation pattern)
                for j in i..i.saturating_add(5).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x15 || // ISZERO
                       self.bytecode[j] == 0x57 || // JUMPI
                       self.bytecode[j] == 0xFD {  // REVERT
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_variable_address_before(&self, pos: usize) -> bool {
        // Check if address comes from SLOAD (storage) or CALLDATALOAD
        for i in pos.saturating_sub(15)..pos {
            if self.bytecode[i] == 0x54 || // SLOAD
               self.bytecode[i] == 0x35 {  // CALLDATALOAD
                return true;
            }
        }
        false
    }
}
