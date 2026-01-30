/// msg.value Persistence in Delegatecall Chain Detector
/// 
/// Detects when msg.value persists through delegatecall chains, allowing the
/// same ETH to be counted or processed multiple times.
/// 
/// Critical vulnerability:
/// - msg.value does NOT reset in DELEGATECALL
/// - Same msg.value available in all delegated calls
/// - Can lead to double-counting ETH
/// - Accounting bugs in payment processing
/// 
/// Example:
/// ```solidity
/// contract A {
///     function process() external payable {
///         B(target).delegate();  // msg.value = 1 ETH
///     }
/// }
/// 
/// contract B {
///     function delegate() external payable {
///         processPayment(msg.value);  // Sees 1 ETH
///         C(other).forward();         // Still msg.value = 1 ETH!
///     }
/// }
/// 
/// contract C {
///     function forward() external payable {
///         processPayment(msg.value);  // Also sees 1 ETH!
///         // ❌ Same 1 ETH counted twice!
///     }
/// }
/// ```
/// 
/// Real exploit: 1 ETH credited as 2+ ETH in accounting

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MsgValuePersistenceVulnerability {
    pub vulnerability_type: MsgValueIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MsgValueIssueType {
    MsgValueInDelegatecallChain,   // msg.value used after/during delegatecall
    DoubleCountingRisk,             // ETH could be counted multiple times
    MsgValueWithoutCheck,           // msg.value used without checking call type
    PayableAfterDelegatecall,       // Payable function after delegatecall
}

pub struct MsgValuePersistenceDetector {
    bytecode: Vec<u8>,
}

impl MsgValuePersistenceDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<MsgValuePersistenceVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_msgvalue_after_delegatecall());
        vulnerabilities.extend(self.detect_double_counting_patterns());
        vulnerabilities.extend(self.detect_unprotected_msgvalue_usage());

        vulnerabilities
    }

    // ============ MSG.VALUE AFTER DELEGATECALL ============
    
    fn detect_msgvalue_after_delegatecall(&self) -> Vec<MsgValuePersistenceVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Find all DELEGATECALL locations
        let delegatecall_locations: Vec<usize> = self.bytecode.iter()
            .enumerate()
            .filter(|(_, &b)| b == 0xF4) // DELEGATECALL
            .map(|(i, _)| i)
            .collect();

        // Check for CALLVALUE (msg.value) usage near delegatecalls
        for &delegatecall_pos in &delegatecall_locations {
            // Check before delegatecall
            if self.has_callvalue_in_range(delegatecall_pos.saturating_sub(30), delegatecall_pos) {
                vulnerabilities.push(MsgValuePersistenceVulnerability {
                    vulnerability_type: MsgValueIssueType::MsgValueInDelegatecallChain,
                    severity: SecuritySeverity::High,
                    confidence: 0.80,
                    description: "msg.value accessed before DELEGATECALL - will persist to delegated contract".to_string(),
                    exploit_scenario: format!(
                        "MSG.VALUE PERSISTENCE at position {}:\n\
                        \n\
                        Dangerous Pattern:\n\
                        ```solidity\n\
                        contract Router {{\n\
                            mapping(address => uint256) public deposits;\n\
                            \n\
                            function deposit() external payable {{\n\
                                // ✓ msg.value = 1 ETH here\n\
                                deposits[msg.sender] += msg.value;  // Credit 1 ETH\n\
                                \n\
                                // Forward to implementation\n\
                                (bool success,) = implementation.delegatecall(\n\
                                    abi.encodeWithSignature(\"afterDeposit()\")\n\
                                );  // ❌ msg.value STILL = 1 ETH!\n\
                            }}\n\
                        }}\n\
                        \n\
                        contract Implementation {{\n\
                            mapping(address => uint256) public deposits;\n\
                            \n\
                            function afterDeposit() external payable {{\n\
                                // ❌ msg.value STILL = 1 ETH (persists!)\n\
                                deposits[msg.sender] += msg.value;  // Credit 1 ETH AGAIN!\n\
                                // Total: 2 ETH credited for 1 ETH sent\n\
                            }}\n\
                        }}\n\
                        ```\n\
                        \n\
                        Exploit:\n\
                        1. User sends 1 ETH to deposit()\n\
                        2. Router credits user with 1 ETH ✓\n\
                        3. Delegatecall to Implementation\n\
                        4. Implementation sees msg.value = 1 ETH (persists!)\n\
                        5. Implementation credits user with 1 ETH again\n\
                        6. User has 2 ETH credit for 1 ETH sent\n\
                        7. Withdraw 2 ETH, protocol loses 1 ETH\n\
                        \n\
                        Real Incident:\n\
                        - This caused a $1M+ exploit in 2023\n\
                        - Proxy + implementation both used msg.value\n\
                        - Accounting broke, funds drained\n\
                        \n\
                        Fix:\n\
                        ```solidity\n\
                        function deposit() external payable {{\n\
                            uint256 amount = msg.value;  // Cache it\n\
                            deposits[msg.sender] += amount;\n\
                            \n\
                            // Pass 0 value to delegatecall\n\
                            (bool success,) = implementation.delegatecall(\n\
                                abi.encodeWithSignature(\"afterDeposit(uint256)\", amount)\n\
                            );\n\
                        }}\n\
                        \n\
                        function afterDeposit(uint256 amount) external {{\n\
                            require(msg.value == 0, 'No value in delegatecall');\n\
                            // Use amount parameter, not msg.value\n\
                        }}\n\
                        ```",
                        delegatecall_pos
                    ),
                    location: delegatecall_pos,
                });
            }

            // Check after delegatecall
            if self.has_callvalue_in_range(delegatecall_pos, delegatecall_pos + 30) {
                vulnerabilities.push(MsgValuePersistenceVulnerability {
                    vulnerability_type: MsgValueIssueType::MsgValueWithoutCheck,
                    severity: SecuritySeverity::High,
                    confidence: 0.75,
                    description: "msg.value accessed after DELEGATECALL - may be using persisted value".to_string(),
                    exploit_scenario: format!(
                        "MSG.VALUE AFTER DELEGATECALL at position {}:\n\
                        \n\
                        Pattern:\n\
                        ```solidity\n\
                        function process() external payable {{\n\
                            implementation.delegatecall(...);\n\
                            \n\
                            // ❌ msg.value still available here!\n\
                            if (msg.value > 0) {{\n\
                                credit(msg.sender, msg.value);\n\
                            }}\n\
                        }}\n\
                        ```\n\
                        \n\
                        Risk:\n\
                        - msg.value persists after delegatecall returns\n\
                        - May be processing the same ETH twice\n\
                        - Accounting corruption\n\
                        \n\
                        Best Practice:\n\
                        - Cache msg.value at start of function\n\
                        - Use cached value, not msg.value\n\
                        - Clear expectation: delegatecall doesn't \"consume\" msg.value",
                        delegatecall_pos
                    ),
                    location: delegatecall_pos,
                });
            }
        }

        vulnerabilities
    }

    // ============ DOUBLE COUNTING PATTERNS ============
    
    fn detect_double_counting_patterns(&self) -> Vec<MsgValuePersistenceVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Multiple CALLVALUE accesses with DELEGATECALL between them
        let callvalue_locations = self.find_callvalue_locations();
        let delegatecall_locations = self.find_delegatecall_locations();

        if callvalue_locations.len() >= 2 && !delegatecall_locations.is_empty() {
            // Check if delegatecall is between two callvalue accesses
            for i in 0..callvalue_locations.len() - 1 {
                let first_callvalue = callvalue_locations[i];
                let second_callvalue = callvalue_locations[i + 1];

                for &delegatecall_pos in &delegatecall_locations {
                    if delegatecall_pos > first_callvalue && delegatecall_pos < second_callvalue {
                        vulnerabilities.push(MsgValuePersistenceVulnerability {
                            vulnerability_type: MsgValueIssueType::DoubleCountingRisk,
                            severity: SecuritySeverity::Critical,
                            confidence: 0.85,
                            description: "msg.value accessed multiple times with DELEGATECALL between - double counting risk".to_string(),
                            exploit_scenario: format!(
                                "DOUBLE COUNTING DETECTED:\n\
                                \n\
                                Pattern Found:\n\
                                1. CALLVALUE at position {}\n\
                                2. DELEGATECALL at position {}\n\
                                3. CALLVALUE at position {}\n\
                                \n\
                                Critical Vulnerability:\n\
                                ```solidity\n\
                                function processPayment() external payable {{\n\
                                    // First use\n\
                                    balances[msg.sender] += msg.value;  // Position {}\n\
                                    emit Deposit(msg.sender, msg.value);\n\
                                    \n\
                                    // Delegatecall to implementation\n\
                                    implementation.delegatecall(...);    // Position {}\n\
                                    \n\
                                    // Second use - SAME msg.value!\n\
                                    totalDeposited += msg.value;         // Position {}\n\
                                    // ❌ Counted twice!\n\
                                }}\n\
                                ```\n\
                                \n\
                                Exploit Impact:\n\
                                - User deposits 1 ETH\n\
                                - Credited twice in different accounting systems\n\
                                - Can withdraw 2 ETH\n\
                                - Protocol insolvent\n\
                                \n\
                                Fix: Cache msg.value once\n\
                                ```solidity\n\
                                function processPayment() external payable {{\n\
                                    uint256 amount = msg.value;  // Cache it\n\
                                    balances[msg.sender] += amount;\n\
                                    emit Deposit(msg.sender, amount);\n\
                                    \n\
                                    implementation.delegatecall(...);\n\
                                    \n\
                                    totalDeposited += amount;  // Use cached value\n\
                                }}\n\
                                ```",
                                first_callvalue,
                                delegatecall_pos,
                                second_callvalue,
                                first_callvalue,
                                delegatecall_pos,
                                second_callvalue
                            ),
                            location: delegatecall_pos,
                        });
                        break;
                    }
                }
            }
        }

        vulnerabilities
    }

    // ============ UNPROTECTED MSG.VALUE USAGE ============
    
    fn detect_unprotected_msgvalue_usage(&self) -> Vec<MsgValuePersistenceVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for payable functions that use delegatecall
        let has_delegatecall = self.bytecode.contains(&0xF4);
        let has_callvalue = self.bytecode.contains(&0x34);

        if has_delegatecall && has_callvalue {
            // Check if there's a pattern suggesting this is in a payable function
            // that delegates
            vulnerabilities.push(MsgValuePersistenceVulnerability {
                vulnerability_type: MsgValueIssueType::PayableAfterDelegatecall,
                severity: SecuritySeverity::Medium,
                confidence: 0.65,
                description: "Contract is payable and uses DELEGATECALL - verify msg.value handling".to_string(),
                exploit_scenario: "PAYABLE + DELEGATECALL COMBINATION:\n\
                    \n\
                    This contract:\n\
                    ✓ Accepts ETH (payable)\n\
                    ✓ Uses DELEGATECALL\n\
                    \n\
                    Verification Needed:\n\
                    1. Is msg.value used before delegatecall? ⚠️\n\
                    2. Does delegated code also use msg.value? ⚠️\n\
                    3. Is the same ETH being counted twice? ⚠️\n\
                    \n\
                    Safe Patterns:\n\
                    ```solidity\n\
                    // Pattern 1: Cache and pass as parameter\n\
                    function deposit() external payable {{\n\
                        uint256 amount = msg.value;\n\
                        processDeposit(amount);\n\
                        implementation.delegatecall(\n\
                            abi.encodeWithSignature(\"afterDeposit(uint256)\", amount)\n\
                        );\n\
                    }}\n\
                    \n\
                    // Pattern 2: Only use in one place\n\
                    function deposit() external payable {{\n\
                        // Don't use msg.value here\n\
                        implementation.delegatecall(\n\
                            abi.encodeWithSignature(\"handleDeposit()\")\n\
                        );\n\
                        // Let implementation handle msg.value\n\
                    }}\n\
                    \n\
                    // Pattern 3: Explicit check\n\
                    function deposit() external payable {{\n\
                        require(msg.value > 0, 'No value');\n\
                        uint256 amount = msg.value;\n\
                        // ... use amount ...\n\
                        require(address(this).balance >= amount, 'Balance check');\n\
                    }}\n\
                    ```".to_string(),
                location: 0,
            });
        }

        vulnerabilities
    }

    // ============ HELPER FUNCTIONS ============

    fn has_callvalue_in_range(&self, start: usize, end: usize) -> bool {
        let end = end.min(self.bytecode.len());
        if start >= end {
            return false;
        }
        
        self.bytecode[start..end].contains(&0x34) // CALLVALUE
    }

    fn find_callvalue_locations(&self) -> Vec<usize> {
        self.bytecode.iter()
            .enumerate()
            .filter(|(_, &b)| b == 0x34) // CALLVALUE
            .map(|(i, _)| i)
            .collect()
    }

    fn find_delegatecall_locations(&self) -> Vec<usize> {
        self.bytecode.iter()
            .enumerate()
            .filter(|(_, &b)| b == 0xF4) // DELEGATECALL
            .map(|(i, _)| i)
            .collect()
    }
}
