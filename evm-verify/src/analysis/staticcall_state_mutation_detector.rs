/// STATICCALL State Mutation Vulnerability Detector
///
/// Detects view/pure functions that can change state despite STATICCALL protection.
/// STATICCALL prevents direct state changes but can be bypassed via delegatecall.
///
/// Why dangerous:
/// - View functions marked "read-only" but actually change state
/// - Off-chain integrations assume view functions are safe
/// - Oracles, frontends, subgraphs all trust view functions
/// - State change in view function breaks assumptions
///
/// STATICCALL protection:
/// - Reverts on SSTORE, LOG, CREATE, SELFDESTRUCT, CALL with value
/// - BUT: DELEGATECALL is allowed!
/// - Delegated contract can change state in caller's context
///
/// Real exploits:
/// - Read-only reentrancy attacks
/// - Oracle manipulation via view functions
/// - Frontend state corruption
/// - Multiple protocols: $50M+ in view function exploits
///
/// Example vulnerability:
/// ```solidity
/// contract VulnerableView {
///     address public implementation;
///     uint256 public balance;
///     
///     // ❌ Marked 'view' but can change state!
///     function getBalance() external view returns (uint256) {
///         // STATICCALL allows delegatecall!
///         (bool success, bytes memory data) = implementation.delegatecall(
///             abi.encodeWithSignature("_getBalance()")
///         );
///         require(success);
///         return abi.decode(data, (uint256));
///     }
/// }
///
/// contract MaliciousImplementation {
///     uint256 public balance; // Same storage layout
///     
///     function _getBalance() external returns (uint256) {
///         // This executes in VulnerableView's context!
///         balance = 1000000; // Changes VulnerableView's balance!
///         return balance;
///     }
/// }
/// ```

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticCallMutationVulnerability {
    pub vulnerability_type: StaticCallIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StaticCallIssueType {
    DelegatecallInView,            // DELEGATECALL inside view function
    StaticCallToDelegatecall,      // STATICCALL to function that does delegatecall
    ViewFunctionStateChange,       // View function that changes state via proxy
    ReadOnlyReentrancy,            // Read-only reentrancy pattern
}

pub struct StaticCallStateMutationDetector {
    bytecode: Vec<u8>,
}

impl StaticCallStateMutationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<StaticCallMutationVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_delegatecall_in_view());
        vulnerabilities.extend(self.detect_staticcall_with_delegatecall());

        vulnerabilities
    }

    fn detect_delegatecall_in_view(&self) -> Vec<StaticCallMutationVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: DELEGATECALL in context that might be STATICCALL
        for i in 0..self.bytecode.len() {
            if self.bytecode[i] == 0xF4 { // DELEGATECALL
                vulnerabilities.push(StaticCallMutationVulnerability {
                    vulnerability_type: StaticCallIssueType::DelegatecallInView,
                    severity: SecuritySeverity::High,
                    confidence: 0.75,
                    description: "DELEGATECALL detected - may bypass STATICCALL protection in view functions".to_string(),
                    exploit_scenario: format!(
                        "DELEGATECALL IN VIEW CONTEXT at position {}:\n\
                        \n\
                        CRITICAL: DELEGATECALL can bypass STATICCALL protection!\n\
                        If this is inside a view function, state can be mutated.\n\
                        \n\
                        VULNERABLE PATTERN:\n\
                        ```solidity\n\
                        contract CurvePool {{\n\
                            address public implementation;\n\
                            uint256 public virtualPrice; // Cached value\n\
                            \n\
                            // ❌ CRITICAL: View function with delegatecall\n\
                            function get_virtual_price() external view returns (uint256) {{\n\
                                // This is marked 'view' so called via STATICCALL\n\
                                // But STATICCALL allows delegatecall!\n\
                                \n\
                                (bool success, bytes memory data) = implementation.delegatecall(\n\
                                    abi.encodeWithSignature('_get_virtual_price()')\n\
                                );\n\
                                \n\
                                require(success);\n\
                                return abi.decode(data, (uint256));\n\
                            }}\n\
                        }}\n\
                        \n\
                        contract MaliciousImplementation {{\n\
                            uint256 public virtualPrice; // Same storage slot\n\
                            \n\
                            function _get_virtual_price() external returns (uint256) {{\n\
                                // Executes in CurvePool's context!\n\
                                // Can modify CurvePool's storage!\n\
                                virtualPrice = 999999999; // Corrupt cached value\n\
                                return virtualPrice;\n\
                            }}\n\
                        }}\n\
                        ```\n\
                        \n\
                        REAL EXPLOIT: CURVE READ-ONLY REENTRANCY ($100M+ RISK)\n\
                        \n\
                        Attack flow:\n\
                        ```solidity\n\
                        contract ReadOnlyReentrancy {{\n\
                            CurvePool public pool;\n\
                            LendingProtocol public lending;\n\
                            \n\
                            function exploit() external {{\n\
                                // Step 1: Remove liquidity from Curve\n\
                                pool.remove_liquidity();\n\
                                \n\
                                // During removal, Curve calls back to attacker\n\
                                // Curve state is inconsistent (mid-withdrawal)\n\
                            }}\n\
                            \n\
                            // Curve calls this during remove_liquidity\n\
                            receive() external payable {{\n\
                                // Step 2: Query Curve price (via view function)\n\
                                // Curve is in inconsistent state!\n\
                                uint256 manipulatedPrice = pool.get_virtual_price();\n\
                                \n\
                                // Step 3: Use manipulated price in lending protocol\n\
                                // Borrow maximum based on inflated collateral value\n\
                                lending.borrow(calculateMaxBorrow(manipulatedPrice));\n\
                                \n\
                                // Step 4: Price returns to normal\n\
                                // Attacker overborrowed, protocol insolvent\n\
                            }}\n\
                        }}\n\
                        ```\n\
                        \n\
                        WHY STATICCALL DOESN'T PREVENT THIS:\n\
                        \n\
                        STATICCALL restrictions:\n\
                        ```\n\
                        Blocked:\n\
                        - SSTORE (direct state write)\n\
                        - LOG* (event emission)\n\
                        - CREATE/CREATE2 (contract creation)\n\
                        - SELFDESTRUCT\n\
                        - CALL with value > 0\n\
                        \n\
                        Allowed:\n\
                        - DELEGATECALL ✓ (!!)\n\
                        - STATICCALL ✓\n\
                        - Pure computation\n\
                        - Storage reads\n\
                        ```\n\
                        \n\
                        Attack via DELEGATECALL:\n\
                        ```solidity\n\
                        // External view function\n\
                        function query() external view returns (uint256) {{\n\
                            // Called via STATICCALL\n\
                            \n\
                            // This DELEGATECALL is allowed!\n\
                            (bool s, bytes memory d) = impl.delegatecall(...);\n\
                            \n\
                            // Delegated code executes in THIS contract's context\n\
                            // Can modify THIS contract's storage!\n\
                            // STATICCALL only protects the view function itself\n\
                            // Not the delegated execution!\n\
                        }}\n\
                        ```\n\
                        \n\
                        CURVE FINANCE SPECIFIC:\n\
                        ```python\n\
                        # Vyper view function\n\
                        @view\n\
                        @external\n\
                        def get_virtual_price() -> uint256:\n\
                            # This is 'view' so EVM uses STATICCALL\n\
                            \n\
                            # But implementation uses delegatecall to library\n\
                            return self._get_virtual_price()  # delegatecall!\n\
                        \n\
                        # During remove_liquidity:\n\
                        # 1. Balances updated\n\
                        # 2. Transfer ETH (calls attacker)\n\
                        # 3. Attacker calls get_virtual_price\n\
                        # 4. Price calculated with inconsistent state\n\
                        # 5. Attacker uses inflated price\n\
                        ```\n\
                        \n\
                        AFFECTED PROTOCOLS:\n\
                        - Curve pools with reentrancy\n\
                        - Balancer weighted pools\n\
                        - Any lending protocol using pool prices\n\
                        - Yield aggregators\n\
                        - Oracles querying during callbacks\n\
                        \n\
                        IMPACT: $100M+ AT RISK\n\
                        - Euler Finance: $197M (read-only reentrancy component)\n\
                        - Multiple Curve integrations vulnerable\n\
                        - Lending protocols using manipulated prices\n\
                        - Cascading liquidations\n\
                        \n\
                        CORRECT IMPLEMENTATIONS:\n\
                        \n\
                        Option 1: Reentrancy Guard on View Functions\n\
                        ```solidity\n\
                        contract SafePool {{\n\
                            uint256 private _status;\n\
                            \n\
                            modifier nonReentrant() {{\n\
                                require(_status == 0, 'Reentrant call');\n\
                                _status = 1;\n\
                                _;\n\
                                _status = 0;\n\
                            }}\n\
                            \n\
                            // ✓ Protected view function\n\
                            function get_virtual_price() \n\
                                external \n\
                                view \n\
                                nonReentrant  // View + nonReentrant!\n\
                                returns (uint256) \n\
                            {{\n\
                                return calculatePrice();\n\
                            }}\n\
                        }}\n\
                        ```\n\
                        \n\
                        Option 2: Snapshot State Before External Calls\n\
                        ```solidity\n\
                        contract SafeWithdrawal {{\n\
                            function remove_liquidity() external {{\n\
                                // ✓ Update state BEFORE external call\n\
                                uint256 amount = calculateRemoval();\n\
                                balances[msg.sender] = 0;  // Update first\n\
                                totalSupply -= amount;\n\
                                \n\
                                // Now state is consistent\n\
                                // Even if receiver calls view functions\n\
                                (bool s,) = msg.sender.call{{value: amount}}('');\n\
                                require(s);\n\
                            }}\n\
                        }}\n\
                        ```\n\
                        \n\
                        Option 3: Read-Only State Flag\n\
                        ```solidity\n\
                        contract SafePrice {{\n\
                            bool private _readOnly;\n\
                            \n\
                            function withdraw() external {{\n\
                                _readOnly = true;  // Set flag before callback\n\
                                (bool s,) = msg.sender.call{{value: amt}}('');\n\
                                _readOnly = false;\n\
                                require(s);\n\
                            }}\n\
                            \n\
                            function get_price() external view returns (uint256) {{\n\
                                require(!_readOnly, 'Price locked during withdrawal');\n\
                                return calculatePrice();\n\
                            }}\n\
                        }}\n\
                        ```\n\
                        \n\
                        PREVENTION CHECKLIST:\n\
                        ✓ No delegatecall in view functions\n\
                        ✓ Reentrancy guards on view functions\n\
                        ✓ Update state before external calls\n\
                        ✓ Read-only flags during sensitive operations\n\
                        ✓ Consistent state in all view functions\n\
                        ✓ Test with reentrancy scenarios\n\
                        \n\
                        SEVERITY: HIGH\n\
                        - Bypasses view function safety assumption\n\
                        - Enables read-only reentrancy\n\
                        - Oracle manipulation\n\
                        - Protocol insolvency",
                        i
                    ),
                    location: i,
                });
            }
        }

        vulnerabilities
    }

    fn detect_staticcall_with_delegatecall(&self) -> Vec<StaticCallMutationVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: STATICCALL followed later by DELEGATECALL
        let mut has_staticcall = false;
        let mut has_delegatecall = false;

        for &byte in &self.bytecode {
            if byte == 0xFA { // STATICCALL
                has_staticcall = true;
            }
            if byte == 0xF4 { // DELEGATECALL
                has_delegatecall = true;
            }
        }

        if has_staticcall && has_delegatecall {
            vulnerabilities.push(StaticCallMutationVulnerability {
                vulnerability_type: StaticCallIssueType::StaticCallToDelegatecall,
                severity: SecuritySeverity::Medium,
                confidence: 0.65,
                description: "Contract has both STATICCALL and DELEGATECALL - verify view function safety".to_string(),
                exploit_scenario: "Contract uses STATICCALL (view functions) and DELEGATECALL (proxy pattern). Verify view functions cannot change state via delegatecall chain.".to_string(),
                location: 0,
            });
        }

        vulnerabilities
    }
}
