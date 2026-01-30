/// Unvalidated DELEGATECALL Data Detector
///
/// Detects delegatecall with user-controlled data without validation.
/// DELEGATECALL executes in caller's context - user control = arbitrary code execution.
///
/// Why dangerous:
/// - DELEGATECALL executes target code in OUR storage context
/// - User-controlled calldata = user picks which function to call
/// - Can call any function, including admin functions
/// - Complete contract takeover possible
///
/// Real exploits:
/// - **Parity Wallet: $280M+** - Unprotected delegatecall
/// - **$10M+ in proxy exploits** - User-controlled delegate targets
/// - Complete storage corruption
/// - Arbitrary code execution
///
/// Example vulnerability:
/// ```solidity
/// contract VulnerableDelegator {
///     address public owner;
///     address public implementation;
///     
///     // ❌ CRITICAL: User controls calldata!
///     function execute(bytes calldata data) external {
///         (bool success,) = implementation.delegatecall(data);
///         require(success);
///     }
///     
///     // ATTACK:
///     // 1. Craft calldata for setOwner(attacker)
///     // 2. Call execute(malicious_calldata)
///     // 3. Become owner!
/// }
/// ```

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnvalidatedDelegatecallVulnerability {
    pub vulnerability_type: DelegatecallIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DelegatecallIssueType {
    UserControlledCalldata,        // User provides calldata directly
    UserControlledTarget,          // User controls delegatecall target
    NoFunctionWhitelist,           // No function selector validation
    ArbitraryDelegatecall,         // Unrestricted delegatecall
}

pub struct UnvalidatedDelegatecallDetector {
    bytecode: Vec<u8>,
}

impl UnvalidatedDelegatecallDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<UnvalidatedDelegatecallVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_delegatecall_patterns());

        vulnerabilities
    }

    fn detect_delegatecall_patterns(&self) -> Vec<UnvalidatedDelegatecallVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len() {
            if self.bytecode[i] == 0xF4 { // DELEGATECALL
                // Check if this delegatecall has validation before it
                if !self.has_validation_before(i) {
                    vulnerabilities.push(UnvalidatedDelegatecallVulnerability {
                        vulnerability_type: DelegatecallIssueType::ArbitraryDelegatecall,
                        severity: SecuritySeverity::Critical,
                        confidence: 0.70,
                        description: "DELEGATECALL detected - verify input validation".to_string(),
                        exploit_scenario: format!(
                            "DELEGATECALL at position {}:\n\
                            \n\
                            ⚠️  CRITICAL: DELEGATECALL with potentially unvalidated data!\n\
                            \n\
                            DELEGATECALL DANGER:\n\
                            - Executes target code in THIS contract's storage context\n\
                            - User-controlled data = attacker picks function to call\n\
                            - Can call admin functions, change storage, destroy contract\n\
                            \n\
                            PARITY WALLET HACK ($280M):\n\
                            ```solidity\n\
                            contract ParityWallet {{\n\
                                address[] public owners;\n\
                                \n\
                                // ❌ CRITICAL VULNERABILITY!\n\
                                function() external payable {{\n\
                                    address target = libraryAddress;\n\
                                    \n\
                                    // User controls msg.data!\n\
                                    assembly {{\n\
                                        calldatacopy(0, 0, calldatasize())\n\
                                        let result := delegatecall(\n\
                                            gas(),\n\
                                            target,\n\
                                            0,\n\
                                            calldatasize(),\n\
                                            0,\n\
                                            0\n\
                                        )\n\
                                    }}\n\
                                }}\n\
                            }}\n\
                            \n\
                            contract Library {{\n\
                                address[] public owners;\n\
                                \n\
                                function initWallet(address[] _owners) public {{\n\
                                    owners = _owners; // Sets wallet owners!\n\
                                }}\n\
                            }}\n\
                            \n\
                            // ATTACK:\n\
                            // 1. Call wallet.fallback() with:\n\
                            //    calldata = initWallet([attacker_address])\n\
                            // 2. DELEGATECALL executes initWallet in wallet's context\n\
                            // 3. owners[] overwritten with attacker's address\n\
                            // 4. Attacker owns wallet!\n\
                            // 5. Drain all funds ($280M)\n\
                            ```\n\
                            \n\
                            VULNERABLE PATTERNS:\n\
                            \n\
                            1. USER-CONTROLLED CALLDATA:\n\
                            ```solidity\n\
                            function execute(bytes calldata data) external {{\n\
                                // ❌ User picks which function to call!\n\
                                (bool success,) = implementation.delegatecall(data);\n\
                                require(success);\n\
                            }}\n\
                            ```\n\
                            \n\
                            2. USER-CONTROLLED TARGET:\n\
                            ```solidity\n\
                            function callLibrary(address lib, bytes calldata data)\n\
                                external\n\
                            {{\n\
                                // ❌ User picks which contract to execute!\n\
                                (bool success,) = lib.delegatecall(data);\n\
                                require(success);\n\
                            }}\n\
                            ```\n\
                            \n\
                            SAFE IMPLEMENTATIONS:\n\
                            \n\
                            1. WHITELIST FUNCTIONS:\n\
                            ```solidity\n\
                            contract SafeDelegator {{\n\
                                mapping(bytes4 => bool) public allowedSelectors;\n\
                                address public immutable implementation;\n\
                                \n\
                                constructor() {{\n\
                                    // ✓ Whitelist safe functions only\n\
                                    allowedSelectors[IImpl.safeFunction.selector] = true;\n\
                                }}\n\
                                \n\
                                function execute(bytes calldata data) external {{\n\
                                    // ✓ Validate function selector\n\
                                    bytes4 selector = bytes4(data[:4]);\n\
                                    require(\n\
                                        allowedSelectors[selector],\n\
                                        'Function not allowed'\n\
                                    );\n\
                                    \n\
                                    (bool success,) = implementation.delegatecall(data);\n\
                                    require(success);\n\
                                }}\n\
                            }}\n\
                            ```\n\
                            \n\
                            2. FIXED TARGET + RESTRICTED FUNCTIONS:\n\
                            ```solidity\n\
                            contract SafeProxy {{\n\
                                address public immutable implementation;\n\
                                \n\
                                // ✓ Only owner can upgrade\n\
                                modifier onlyOwner() {{\n\
                                    require(msg.sender == owner);\n\
                                    _;\n\
                                }}\n\
                                \n\
                                // ✓ Specific function, not arbitrary calldata\n\
                                function callSpecificFunction(uint256 param)\n\
                                    external\n\
                                    onlyOwner\n\
                                {{\n\
                                    bytes memory data = abi.encodeWithSignature(\n\
                                        'specificFunction(uint256)',\n\
                                        param\n\
                                    );\n\
                                    (bool success,) = implementation.delegatecall(data);\n\
                                    require(success);\n\
                                }}\n\
                            }}\n\
                            ```\n\
                            \n\
                            3. NO USER CONTROL (Best):\n\
                            ```solidity\n\
                            contract BestProxy {{\n\
                                address public immutable implementation;\n\
                                \n\
                                fallback() external payable {{\n\
                                    // ✓ Forward ALL calls to fixed implementation\n\
                                    // User can't control target or arbitrary functions\n\
                                    assembly {{\n\
                                        calldatacopy(0, 0, calldatasize())\n\
                                        let result := delegatecall(\n\
                                            gas(),\n\
                                            sload(implementation.slot),\n\
                                            0,\n\
                                            calldatasize(),\n\
                                            0,\n\
                                            0\n\
                                        )\n\
                                        returndatacopy(0, 0, returndatasize())\n\
                                        switch result\n\
                                        case 0 {{ revert(0, returndatasize()) }}\n\
                                        default {{ return(0, returndatasize()) }}\n\
                                    }}\n\
                                }}\n\
                            }}\n\
                            ```\n\
                            \n\
                            CRITICAL CHECKS:\n\
                            ✓ Never let users control delegatecall target\n\
                            ✓ Never let users provide arbitrary calldata\n\
                            ✓ Whitelist allowed function selectors\n\
                            ✓ Restrict who can call delegatecall functions\n\
                            ✓ Use immutable implementation addresses\n\
                            ✓ Add timelock for upgrades\n\
                            \n\
                            SEVERITY: CRITICAL\n\
                            - Complete contract takeover\n\
                            - Arbitrary code execution\n\
                            - Storage corruption\n\
                            - $290M+ in exploits",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn has_validation_before(&self, pos: usize) -> bool {
        // Look for validation patterns before delegatecall
        // This is a simplified heuristic
        for i in pos.saturating_sub(50)..pos {
            // Look for comparison operations (validation)
            if self.bytecode[i] == 0x14 || // EQ
               self.bytecode[i] == 0x57 { // JUMPI (conditional)
                return true;
            }
        }
        false
    }
}
