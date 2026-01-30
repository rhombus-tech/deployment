/// Proxy Selector Shadowing Vulnerability Detector
///
/// Detects when implementation contract functions shadow proxy admin functions.
/// Function selectors are 4-byte identifiers - collisions make admin functions inaccessible.
///
/// Why dangerous:
/// - Proxy has admin functions (upgrade, changeAdmin, etc.)
/// - Implementation has business logic functions
/// - If implementation function has SAME selector as proxy admin function
/// - Implementation function is called instead → admin function inaccessible!
/// - Contract upgrade mechanism permanently broken
///
/// Real exploits:
/// - Multiple proxy upgrades locked
/// - Admin access lost permanently
/// - $10M+ in locked contracts
/// - OpenZeppelin proxy issues
///
/// Example vulnerability:
/// ```solidity
/// // Proxy contract
/// contract TransparentProxy {
///     address public admin;
///     address public implementation;
///     
///     function upgradeTo(address newImpl) external {
///         require(msg.sender == admin);
///         implementation = newImpl;
///     }
///     // upgradeTo selector: 0x3659cfe6
///     
///     fallback() external {
///         address impl = implementation;
///         assembly {
///             calldatacopy(0, 0, calldatasize())
///             let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
///             returndatacopy(0, 0, returndatasize())
///             switch result
///             case 0 { revert(0, returndatasize()) }
///             default { return(0, returndatasize()) }
///         }
///     }
/// }
///
/// // Implementation contract
/// contract Implementation {
///     // ❌ CRITICAL: Same selector as proxy's upgradeTo!
///     function collide_3659cfe6() external {
///         // Business logic...
///     }
///     // This shadows proxy's upgradeTo!
///     // Admin can never upgrade contract!
/// }
/// ```

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxySelectorShadowingVulnerability {
    pub vulnerability_type: SelectorShadowingIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
    pub selector: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SelectorShadowingIssueType {
    UpgradeToShadowed,             // upgradeTo(address) - 0x3659cfe6
    ChangeAdminShadowed,           // changeAdmin(address) - 0x8f283970
    AdminShadowed,                 // admin() - 0xf851a440
    ImplementationShadowed,        // implementation() - 0x5c60da1b
    ProxyAdminFunctionShadowed,    // Other proxy admin function
}

pub struct ProxySelectorShadowingDetector {
    bytecode: Vec<u8>,
}

impl ProxySelectorShadowingDetector {
    // Critical proxy admin function selectors
    const UPGRADE_TO: &'static [u8] = &[0x36, 0x59, 0xcf, 0xe6];           // upgradeTo(address)
    const CHANGE_ADMIN: &'static [u8] = &[0x8f, 0x28, 0x39, 0x70];         // changeAdmin(address)
    const ADMIN: &'static [u8] = &[0xf8, 0x51, 0xa4, 0x40];                // admin()
    const IMPLEMENTATION: &'static [u8] = &[0x5c, 0x60, 0xda, 0x1b];       // implementation()
    const UPGRADE_TO_AND_CALL: &'static [u8] = &[0x4f, 0x1e, 0xf2, 0x86];  // upgradeToAndCall(address,bytes)

    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ProxySelectorShadowingVulnerability> {
        let mut vulnerabilities = Vec::new();

        let selectors = self.extract_function_selectors();
        
        vulnerabilities.extend(self.detect_critical_selector_shadows(&selectors));

        vulnerabilities
    }

    fn extract_function_selectors(&self) -> HashSet<Vec<u8>> {
        let mut selectors = HashSet::new();

        // Look for PUSH4 followed by EQ (function selector matching pattern)
        for i in 0..self.bytecode.len().saturating_sub(6) {
            if self.bytecode[i] == 0x63 { // PUSH4
                if i + 4 < self.bytecode.len() {
                    let selector = self.bytecode[i+1..i+5].to_vec();
                    selectors.insert(selector);
                }
            }
        }

        selectors
    }

    fn detect_critical_selector_shadows(&self, selectors: &HashSet<Vec<u8>>) -> Vec<ProxySelectorShadowingVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for upgradeTo selector
        if selectors.contains(&Self::UPGRADE_TO.to_vec()) {
            vulnerabilities.push(ProxySelectorShadowingVulnerability {
                vulnerability_type: SelectorShadowingIssueType::UpgradeToShadowed,
                severity: SecuritySeverity::Critical,
                confidence: 0.95,
                description: "Function with selector 0x3659cfe6 (upgradeTo) detected - may shadow proxy admin function".to_string(),
                exploit_scenario: format!(
                    "SELECTOR SHADOWING: upgradeTo (0x3659cfe6)\n\
                    \n\
                    CRITICAL: Contract has function with selector 0x3659cfe6!\n\
                    This is the selector for upgradeTo(address) in proxy contracts.\n\
                    \n\
                    VULNERABLE PATTERN:\n\
                    ```solidity\n\
                    // Transparent Proxy\n\
                    contract TransparentUpgradeableProxy {{\n\
                        address private _admin;\n\
                        address private _implementation;\n\
                        \n\
                        // Admin function: selector = 0x3659cfe6\n\
                        function upgradeTo(address newImplementation) external ifAdmin {{\n\
                            _implementation = newImplementation;\n\
                        }}\n\
                        \n\
                        fallback() external payable {{\n\
                            // Delegate to implementation\n\
                            _delegate(_implementation);\n\
                        }}\n\
                    }}\n\
                    \n\
                    // Implementation contract\n\
                    contract MyContract {{\n\
                        // ❌ DISASTER: Same selector as proxy's upgradeTo!\n\
                        function myFunction_3659cfe6() external {{\n\
                            // Regular business logic\n\
                        }}\n\
                        \n\
                        // When called, this executes instead of proxy's upgradeTo\n\
                        // Admin can NEVER upgrade the contract!\n\
                        // Contract permanently locked!\n\
                    }}\n\
                    ```\n\
                    \n\
                    REAL WORLD SCENARIO:\n\
                    \n\
                    Timeline:\n\
                    ```\n\
                    Day 1:   Deploy proxy + implementation\n\
                    Day 30:  Critical bug found in implementation\n\
                    Day 31:  Admin tries to upgrade:\n\
                             proxy.upgradeTo(newImplementation)\n\
                             \n\
                             Result: Calls implementation.myFunction_3659cfe6()\n\
                             Not proxy.upgradeTo()!\n\
                             \n\
                    Day 32:  Realize upgrade mechanism is broken\n\
                             Cannot fix the bug\n\
                             Cannot upgrade\n\
                             Contract permanently vulnerable\n\
                             \n\
                    Day 33:  Exploit happens\n\
                             Total loss\n\
                    ```\n\
                    \n\
                    HOW SHADOWING HAPPENS:\n\
                    \n\
                    Proxy dispatch logic:\n\
                    ```solidity\n\
                    fallback() external payable {{\n\
                        if (msg.sender == admin) {{\n\
                            // Route to proxy admin functions\n\
                            // upgradeTo, changeAdmin, etc.\n\
                        }} else {{\n\
                            // Delegate to implementation\n\
                            _delegate(implementation);\n\
                        }}\n\
                    }}\n\
                    ```\n\
                    \n\
                    But in Transparent Proxy:\n\
                    ```solidity\n\
                    fallback() external payable {{\n\
                        // Admin calls go to proxy functions\n\
                        // Non-admin calls delegated to implementation\n\
                        \n\
                        if (msg.sender == admin) {{\n\
                            // Handle admin functions locally\n\
                        }} else {{\n\
                            // If implementation has matching selector,\n\
                            // it executes instead of proxy function!\n\
                            _delegate(implementation);\n\
                        }}\n\
                    }}\n\
                    ```\n\
                    \n\
                    SELECTOR COLLISION TYPES:\n\
                    \n\
                    1. Accidental Collision:\n\
                    ```solidity\n\
                    // Random function happens to have same selector\n\
                    function processData_3659cfe6() external {{\n\
                        // Accidentally collides with upgradeTo\n\
                    }}\n\
                    ```\n\
                    \n\
                    2. Intentional Attack:\n\
                    ```solidity\n\
                    // Malicious implementation\n\
                    function _3659cfe6() external {{\n\
                        // Deliberately shadows upgradeTo\n\
                        // Admin cannot upgrade to fix this!\n\
                    }}\n\
                    ```\n\
                    \n\
                    3. Function Name Collision:\n\
                    ```solidity\n\
                    // If implementation also has upgradeTo\n\
                    function upgradeTo(address addr) external {{\n\
                        // Different purpose but same selector\n\
                        // Shadows proxy's upgradeTo\n\
                    }}\n\
                    ```\n\
                    \n\
                    OPENZEPPELIN TRANSPARENT PROXY PROTECTION:\n\
                    ```solidity\n\
                    contract TransparentUpgradeableProxy {{\n\
                        modifier ifAdmin() {{\n\
                            if (msg.sender == _admin()) {{\n\
                                _;\n\
                            }} else {{\n\
                                _fallback();\n\
                            }}\n\
                        }}\n\
                        \n\
                        function upgradeTo(address newImplementation) external ifAdmin {{\n\
                            _upgradeTo(newImplementation);\n\
                        }}\n\
                        \n\
                        function _fallback() internal virtual {{\n\
                            // Only delegates if NOT admin\n\
                            // This prevents admin from calling shadowed functions\n\
                            _delegate(_implementation());\n\
                        }}\n\
                    }}\n\
                    ```\n\
                    \n\
                    But this means:\n\
                    - Admin CANNOT call implementation functions\n\
                    - Need separate account to use implementation\n\
                    - Still risk if selector collision exists\n\
                    \n\
                    UUPS PROXY (SAFER):\n\
                    ```solidity\n\
                    // Implementation contains upgrade logic\n\
                    contract UUPSUpgradeable {{\n\
                        function upgradeTo(address newImplementation) external onlyOwner {{\n\
                            _upgradeTo(newImplementation);\n\
                        }}\n\
                    }}\n\
                    \n\
                    // Proxy just delegates\n\
                    contract UUPSProxy {{\n\
                        fallback() external payable {{\n\
                            _delegate(implementation);\n\
                        }}\n\
                    }}\n\
                    \n\
                    // No admin functions in proxy → no shadowing risk\n\
                    ```\n\
                    \n\
                    DETECTION & PREVENTION:\n\
                    \n\
                    Before deployment:\n\
                    ```javascript\n\
                    // Check implementation selectors\n\
                    const implSelectors = getSelectors(implementation);\n\
                    const proxySelectors = [\n\
                        '0x3659cfe6', // upgradeTo\n\
                        '0x8f283970', // changeAdmin\n\
                        '0xf851a440', // admin\n\
                        '0x5c60da1b', // implementation\n\
                    ];\n\
                    \n\
                    for (const selector of implSelectors) {{\n\
                        if (proxySelectors.includes(selector)) {{\n\
                            throw new Error(`Selector collision: ${{selector}}`);\n\
                        }}\n\
                    }}\n\
                    ```\n\
                    \n\
                    SEVERITY: CRITICAL\n\
                    - Permanent upgrade mechanism lock\n\
                    - Cannot fix bugs\n\
                    - Contract stuck forever\n\
                    - Total loss if vulnerability exists\n\
                    \n\
                    RECOMMENDATION:\n\
                    - Use UUPS instead of Transparent Proxy\n\
                    - Verify no selector collisions before deployment\n\
                    - Use OpenZeppelin's defender to check\n\
                    - Consider Beacon Proxy pattern\n\
                    - Never use function names that might collide"
                ),
                location: 0,
                selector: Self::UPGRADE_TO.to_vec(),
            });
        }

        // Check for changeAdmin selector
        if selectors.contains(&Self::CHANGE_ADMIN.to_vec()) {
            vulnerabilities.push(ProxySelectorShadowingVulnerability {
                vulnerability_type: SelectorShadowingIssueType::ChangeAdminShadowed,
                severity: SecuritySeverity::Critical,
                confidence: 0.95,
                description: "Function with selector 0x8f283970 (changeAdmin) detected - may shadow proxy admin function".to_string(),
                exploit_scenario: "SELECTOR SHADOWING: changeAdmin (0x8f283970)\n\nImplementation function shadows proxy's changeAdmin. Admin transfer mechanism broken.".to_string(),
                location: 0,
                selector: Self::CHANGE_ADMIN.to_vec(),
            });
        }

        // Check for admin() selector
        if selectors.contains(&Self::ADMIN.to_vec()) {
            vulnerabilities.push(ProxySelectorShadowingVulnerability {
                vulnerability_type: SelectorShadowingIssueType::AdminShadowed,
                severity: SecuritySeverity::High,
                confidence: 0.90,
                description: "Function with selector 0xf851a440 (admin) detected - may shadow proxy admin getter".to_string(),
                exploit_scenario: "SELECTOR SHADOWING: admin() (0xf851a440)\n\nImplementation function shadows proxy's admin getter. Cannot query admin address.".to_string(),
                location: 0,
                selector: Self::ADMIN.to_vec(),
            });
        }

        // Check for implementation() selector
        if selectors.contains(&Self::IMPLEMENTATION.to_vec()) {
            vulnerabilities.push(ProxySelectorShadowingVulnerability {
                vulnerability_type: SelectorShadowingIssueType::ImplementationShadowed,
                severity: SecuritySeverity::High,
                confidence: 0.90,
                description: "Function with selector 0x5c60da1b (implementation) detected - may shadow proxy implementation getter".to_string(),
                exploit_scenario: "SELECTOR SHADOWING: implementation() (0x5c60da1b)\n\nImplementation function shadows proxy's implementation getter. Cannot query current implementation.".to_string(),
                location: 0,
                selector: Self::IMPLEMENTATION.to_vec(),
            });
        }

        // Check for upgradeToAndCall selector
        if selectors.contains(&Self::UPGRADE_TO_AND_CALL.to_vec()) {
            vulnerabilities.push(ProxySelectorShadowingVulnerability {
                vulnerability_type: SelectorShadowingIssueType::UpgradeToShadowed,
                severity: SecuritySeverity::Critical,
                confidence: 0.95,
                description: "Function with selector 0x4f1ef286 (upgradeToAndCall) detected - may shadow proxy upgrade function".to_string(),
                exploit_scenario: "SELECTOR SHADOWING: upgradeToAndCall (0x4f1ef286)\n\nImplementation function shadows proxy's upgradeToAndCall. Atomic upgrade + initialization broken.".to_string(),
                location: 0,
                selector: Self::UPGRADE_TO_AND_CALL.to_vec(),
            });
        }

        vulnerabilities
    }
}
