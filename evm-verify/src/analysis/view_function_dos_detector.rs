/// View Function Denial of Service Detector
/// 
/// Detects view/pure functions with unbounded operations that can revert or
/// consume excessive gas, breaking integrations that expect view functions
/// to always succeed.
/// 
/// Critical patterns:
/// - Unbounded loops in view functions
/// - Large array iterations in view/pure
/// - Recursive calls without bounds
/// - Out-of-gas in readonly operations
/// 
/// Real impact:
/// - DeFi aggregators fail to fetch prices
/// - UIs break when calling view functions
/// - Oracle integrations timeout
/// - Third-party contracts can't read state
/// 
/// Example vulnerability:
/// ```solidity
/// contract Token {
///     address[] public holders;  // Grows unbounded
///     
///     function getAllHolders() external view returns (address[] memory) {
///         return holders;  // ❌ Reverts after 10k+ holders
///     }
///     
///     function totalBalance() external view returns (uint256) {
///         uint256 total;
///         for (uint i = 0; i < holders.length; i++) {  // ❌ Unbounded loop
///             total += balanceOf(holders[i]);
///         }
///         return total;  // Out of gas!
///     }
/// }
/// ```

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewFunctionDosVulnerability {
    pub vulnerability_type: ViewDosType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ViewDosType {
    UnboundedLoopInView,          // Loop without fixed bound in view
    LargeArrayReturnInView,       // Returning unbounded array
    RecursiveViewFunction,        // Recursive calls in view
    ExpensiveComputationInView,   // Heavy computation in view
    ExternalCallInView,           // External call that might revert
}

pub struct ViewFunctionDosDetector {
    bytecode: Vec<u8>,
}

impl ViewFunctionDosDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ViewFunctionDosVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_unbounded_loops());
        vulnerabilities.extend(self.detect_large_array_operations());
        vulnerabilities.extend(self.detect_recursive_patterns());
        vulnerabilities.extend(self.detect_expensive_view_operations());

        vulnerabilities
    }

    // ============ UNBOUNDED LOOPS IN VIEW FUNCTIONS ============
    
    fn detect_unbounded_loops(&self) -> Vec<ViewFunctionDosVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Find all STATICCALL locations (view/pure external calls)
        let staticcall_locations: Vec<usize> = self.bytecode.iter()
            .enumerate()
            .filter(|(_, &b)| b == 0xFA) // STATICCALL
            .map(|(i, _)| i)
            .collect();

        // Find loop patterns (JUMPDEST + counter + JUMPI back)
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.is_loop_start(i) {
                // Check if loop bound is dynamic (loaded from storage)
                if self.is_unbounded_loop(i) {
                    // Check if this is likely in a view function
                    let near_staticcall = staticcall_locations.iter()
                        .any(|&pos| pos.abs_diff(i) < 100);
                    
                    if near_staticcall || self.is_in_view_context(i) {
                        vulnerabilities.push(ViewFunctionDosVulnerability {
                            vulnerability_type: ViewDosType::UnboundedLoopInView,
                            severity: SecuritySeverity::High,
                            confidence: 0.75,
                            description: "Unbounded loop detected in view function context".to_string(),
                            exploit_scenario: format!(
                                "UNBOUNDED LOOP IN VIEW FUNCTION at position {}:\n\
                                \n\
                                Dangerous Pattern:\n\
                                ```solidity\n\
                                contract Vault {{\n\
                                    address[] public depositors;  // Grows over time\n\
                                    mapping(address => uint256) public balances;\n\
                                    \n\
                                    // ❌ Will fail after ~1000 depositors\n\
                                    function getTotalDeposited() external view returns (uint256) {{\n\
                                        uint256 total;\n\
                                        for (uint i = 0; i < depositors.length; i++) {{\n\
                                            total += balances[depositors[i]];\n\
                                        }}\n\
                                        return total;\n\
                                    }}\n\
                                    \n\
                                    // ❌ Breaks DeFi integrations\n\
                                    function getAllDepositors() external view returns (address[] memory) {{\n\
                                        return depositors;  // Reverts with 10k+ entries\n\
                                    }}\n\
                                }}\n\
                                ```\n\
                                \n\
                                Real Impact:\n\
                                1. User count grows: 100 → 1,000 → 10,000\n\
                                2. getTotalDeposited() starts reverting (out of gas)\n\
                                3. DeFi aggregator: vault.getTotalDeposited() → REVERT\n\
                                4. Aggregator marks vault as broken\n\
                                5. Vault loses TVL, users can't see stats\n\
                                6. Frontend breaks, no total displayed\n\
                                \n\
                                Real Incidents:\n\
                                - Dozens of protocols hit this in 2023-2024\n\
                                - View functions that worked with 100 users fail at 1000\n\
                                - No recovery - contract can't be fixed\n\
                                \n\
                                Fix Patterns:\n\
                                ```solidity\n\
                                // Pattern 1: Pagination\n\
                                function getDepositors(\n\
                                    uint256 offset,\n\
                                    uint256 limit\n\
                                ) external view returns (address[] memory) {{\n\
                                    require(limit <= 100, 'Max 100 per call');\n\
                                    uint256 end = (offset + limit).min(depositors.length);\n\
                                    address[] memory result = new address[](end - offset);\n\
                                    for (uint i = 0; i < result.length; i++) {{\n\
                                        result[i] = depositors[offset + i];\n\
                                    }}\n\
                                    return result;\n\
                                }}\n\
                                \n\
                                // Pattern 2: Cached aggregates\n\
                                uint256 public totalDeposited;  // Updated on each deposit\n\
                                \n\
                                function deposit() external payable {{\n\
                                    balances[msg.sender] += msg.value;\n\
                                    totalDeposited += msg.value;  // Update cache\n\
                                }}\n\
                                \n\
                                // Pattern 3: Off-chain computation\n\
                                // Move heavy computation to off-chain indexer\n\
                                // Expose simple view functions for critical data only\n\
                                ```",
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

    // ============ LARGE ARRAY OPERATIONS ============
    
    fn detect_large_array_operations(&self) -> Vec<ViewFunctionDosVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: SLOAD (array length) + MSTORE (allocate) + loop to copy
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.is_array_return_pattern(i) {
                vulnerabilities.push(ViewFunctionDosVulnerability {
                    vulnerability_type: ViewDosType::LargeArrayReturnInView,
                    severity: SecuritySeverity::High,
                    confidence: 0.70,
                    description: "View function returns dynamically-sized array - potential DoS".to_string(),
                    exploit_scenario: format!(
                        "LARGE ARRAY RETURN at position {}:\n\
                        \n\
                        Pattern:\n\
                        ```solidity\n\
                        contract Registry {{\n\
                            address[] public registeredUsers;\n\
                            \n\
                            // ❌ Fails when array > 5k-10k entries\n\
                            function getAllUsers() external view returns (address[] memory) {{\n\
                                return registeredUsers;\n\
                            }}\n\
                        }}\n\
                        ```\n\
                        \n\
                        Gas Limits:\n\
                        - Block gas limit: 30M gas\n\
                        - SLOAD: 2,100 gas per slot\n\
                        - 10,000 addresses = 10,000 * 2,100 = 21M gas\n\
                        - Plus memory allocation = hits gas limit\n\
                        \n\
                        Breaking Points:\n\
                        - ~5,000 entries: Starts failing on some nodes\n\
                        - ~10,000 entries: Consistently reverts\n\
                        - ~100,000 entries: Impossible to call\n\
                        \n\
                        Affected Integrations:\n\
                        - Etherscan contract page breaks\n\
                        - DeFi aggregators can't read data\n\
                        - Wallets can't display info\n\
                        - Subgraph indexers fail\n\
                        \n\
                        Fix: Use pagination (see above)",
                        i
                    ),
                    location: i,
                });
            }
        }

        vulnerabilities
    }

    // ============ RECURSIVE PATTERNS ============
    
    fn detect_recursive_patterns(&self) -> Vec<ViewFunctionDosVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for STATICCALL to self (recursive view function)
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0xFA { // STATICCALL
                if self.is_recursive_call_pattern(i) {
                    vulnerabilities.push(ViewFunctionDosVulnerability {
                        vulnerability_type: ViewDosType::RecursiveViewFunction,
                        severity: SecuritySeverity::Medium,
                        confidence: 0.65,
                        description: "Recursive call pattern in view function - stack depth limit risk".to_string(),
                        exploit_scenario: format!(
                            "RECURSIVE VIEW FUNCTION at position {}:\n\
                            \n\
                            Pattern:\n\
                            ```solidity\n\
                            contract Tree {{\n\
                                mapping(uint => uint[]) public children;\n\
                                \n\
                                function getTreeSize(uint nodeId) external view returns (uint) {{\n\
                                    uint size = 1;\n\
                                    for (uint i = 0; i < children[nodeId].length; i++) {{\n\
                                        size += this.getTreeSize(children[nodeId][i]);  // Recursive!\n\
                                    }}\n\
                                    return size;\n\
                                }}\n\
                            }}\n\
                            ```\n\
                            \n\
                            Risk:\n\
                            - Stack depth limit: 1024 calls\n\
                            - Deep recursion causes revert\n\
                            - No way to query large trees\n\
                            \n\
                            Better: Iterative with manual stack",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    // ============ EXPENSIVE VIEW OPERATIONS ============
    
    fn detect_expensive_view_operations(&self) -> Vec<ViewFunctionDosVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for expensive operations in what might be view functions
        // Pattern: Many SLOAD operations in sequence
        let sload_clusters = self.find_sload_clusters();
        
        for (start, count) in sload_clusters {
            if count > 50 {
                vulnerabilities.push(ViewFunctionDosVulnerability {
                    vulnerability_type: ViewDosType::ExpensiveComputationInView,
                    severity: SecuritySeverity::Medium,
                    confidence: 0.60,
                    description: format!("{} SLOAD operations in sequence - expensive view function", count),
                    exploit_scenario: format!(
                        "EXPENSIVE VIEW COMPUTATION at position {}:\n\
                        \n\
                        Detected: {} storage reads in sequence\n\
                        \n\
                        Gas Cost: ~{} gas\n\
                        \n\
                        Pattern:\n\
                        ```solidity\n\
                        function calculateRewards() external view returns (uint256) {{\n\
                            uint256 total;\n\
                            // ❌ Reading many storage slots\n\
                            for (uint i = 0; i < 100; i++) {{\n\
                                total += stakingData[i].amount * stakingData[i].rate;\n\
                                // Each iteration: 2 SLOADs + computation\n\
                            }}\n\
                            return total;\n\
                        }}\n\
                        ```\n\
                        \n\
                        Impact:\n\
                        - Slow response times (> 1 second)\n\
                        - RPC node timeouts\n\
                        - Rate limiting issues\n\
                        \n\
                        Better:\n\
                        - Cache aggregates\n\
                        - Limit computation scope\n\
                        - Use events + off-chain indexing",
                        start,
                        count,
                        count * 2100
                    ),
                    location: start,
                });
            }
        }

        vulnerabilities
    }

    // ============ HELPER FUNCTIONS ============

    fn is_loop_start(&self, pos: usize) -> bool {
        // Loop pattern: JUMPDEST at start
        self.bytecode.get(pos) == Some(&0x5B)
    }

    fn is_unbounded_loop(&self, pos: usize) -> bool {
        // Check if loop counter comes from storage (SLOAD)
        // vs hardcoded constant (PUSH)
        
        for i in pos..pos.saturating_add(30).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x54 { // SLOAD (dynamic bound)
                // Check if this is used in loop condition
                if i + 10 < self.bytecode.len() {
                    let has_comparison = self.bytecode[i..i+10].iter()
                        .any(|&b| b == 0x10 || b == 0x11); // LT or GT
                    if has_comparison {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn is_in_view_context(&self, _pos: usize) -> bool {
        // Heuristic: No SSTORE operations = likely view/pure
        !self.bytecode.contains(&0x55) // No SSTORE
    }

    fn is_array_return_pattern(&self, pos: usize) -> bool {
        // Pattern for returning array:
        // SLOAD (get length) + MSIZE/MSTORE (allocate) + loop (copy)
        
        if pos + 15 > self.bytecode.len() {
            return false;
        }
        
        let window = &self.bytecode[pos..pos + 15];
        window.contains(&0x54) &&  // SLOAD
        window.contains(&0x52) &&  // MSTORE
        window.contains(&0x59)     // MSIZE
    }

    fn is_recursive_call_pattern(&self, pos: usize) -> bool {
        // Check if STATICCALL address is ADDRESS (self)
        for i in pos.saturating_sub(10)..pos {
            if i < self.bytecode.len() && self.bytecode[i] == 0x30 { // ADDRESS
                return true;
            }
        }
        false
    }

    fn find_sload_clusters(&self) -> Vec<(usize, usize)> {
        let mut clusters = Vec::new();
        let mut current_start = None;
        let mut count = 0;

        for (i, &byte) in self.bytecode.iter().enumerate() {
            if byte == 0x54 { // SLOAD
                if current_start.is_none() {
                    current_start = Some(i);
                    count = 1;
                } else {
                    count += 1;
                }
            } else if let Some(start) = current_start {
                // End of cluster if gap > 10 bytes
                if i - start - count > 10 {
                    if count > 5 {
                        clusters.push((start, count));
                    }
                    current_start = None;
                    count = 0;
                }
            }
        }

        if let Some(start) = current_start {
            if count > 5 {
                clusters.push((start, count));
            }
        }

        clusters
    }
}
