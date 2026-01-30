/// Memory Expansion DoS Detector
///
/// Detects unbounded memory growth that can cause out-of-gas errors.
/// EVM memory is dynamically allocated and gas cost increases quadratically.
///
/// Memory gas cost formula:
/// - Linear part: 3 gas per word
/// - Quadratic part: (size_in_words)² / 512
/// - Expanding from 0 to 1MB costs ~350k gas
/// - Expanding from 0 to 10MB costs ~35M gas (exceeds block limit!)
///
/// Why dangerous:
/// - Attacker controls memory expansion via input data
/// - View/pure functions can DoS if unbounded
/// - Off-chain calls fail, breaking integrations
/// - Oracles, subgraphs, frontends all affected
///
/// Common patterns:
/// - abi.decode(unbounded calldata)
/// - Dynamic array allocation in loops
/// - Large return data from external calls
/// - Unchecked memory copy operations
///
/// Real exploits:
/// - Multiple DeFi protocols: view function DoS
/// - Oracle failures due to large return data
/// - Subgraph indexing failures
/// - Frontend crashes from contract calls
///
/// Example vulnerability:
/// ```solidity
/// contract VulnerableAggregator {
///     function getAllPrices(address[] calldata tokens) 
///         external view returns (uint256[] memory prices) 
///     {
///         // ❌ Unbounded array allocation
///         // Attacker passes 100k tokens → massive memory allocation
///         prices = new uint256[](tokens.length);
///         
///         for (uint i = 0; i < tokens.length; i++) {
///             prices[i] = getPriceFor(tokens[i]);
///         }
///         // If tokens.length = 100,000:
///         // Memory needed = 100,000 * 32 bytes = 3.2 MB
///         // Gas cost = millions → out of gas
///     }
/// }
/// ```

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryExpansionVulnerability {
    pub vulnerability_type: MemoryExpansionIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MemoryExpansionIssueType {
    UnboundedMemoryAllocation,     // Dynamic allocation without bounds
    UnboundedMemoryCopy,           // CALLDATACOPY/RETURNDATACOPY unbounded
    LargeReturnDataCopy,           // Copying large return data to memory
    LoopMemoryExpansion,           // Memory grows in unbounded loop
    ViewFunctionMemoryDoS,         // View function with unbounded memory
}

pub struct MemoryExpansionDoSDetector {
    bytecode: Vec<u8>,
}

impl MemoryExpansionDoSDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<MemoryExpansionVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_unbounded_calldatacopy());
        vulnerabilities.extend(self.detect_unbounded_returndatacopy());
        vulnerabilities.extend(self.detect_loop_memory_expansion());
        vulnerabilities.extend(self.detect_large_memory_allocation());

        vulnerabilities
    }

    // ============ UNBOUNDED CALLDATACOPY ============
    
    fn detect_unbounded_calldatacopy(&self) -> Vec<MemoryExpansionVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: CALLDATACOPY with size from CALLDATASIZE (unbounded)
        for i in 0..self.bytecode.len().saturating_sub(15) {
            if self.bytecode[i] == 0x37 { // CALLDATACOPY
                // Check if size comes directly from CALLDATASIZE without bounds
                if self.has_unbounded_size_before(i) {
                    vulnerabilities.push(MemoryExpansionVulnerability {
                        vulnerability_type: MemoryExpansionIssueType::UnboundedMemoryCopy,
                        severity: SecuritySeverity::High,
                        confidence: 0.80,
                        description: "Unbounded CALLDATACOPY - attacker controls memory expansion".to_string(),
                        exploit_scenario: format!(
                            "UNBOUNDED CALLDATACOPY at position {}:\n\
                            \n\
                            VULNERABLE PATTERN:\n\
                            Memory expansion controlled by calldata size without bounds check.\n\
                            \n\
                            ```solidity\n\
                            contract VulnerableBatchProcessor {{\n\
                                struct Batch {{\n\
                                    address[] targets;\n\
                                    bytes[] calldatas;\n\
                                }}\n\
                                \n\
                                function processBatch(Batch calldata batch) external {{\n\
                                    // ❌ Unbounded abi.decode\n\
                                    // Internally uses CALLDATACOPY with size = calldata length\n\
                                    \n\
                                    for (uint i = 0; i < batch.targets.length; i++) {{\n\
                                        batch.targets[i].call(batch.calldatas[i]);\n\
                                    }}\n\
                                }}\n\
                            }}\n\
                            ```\n\
                            \n\
                            ATTACK:\n\
                            ```javascript\n\
                            // Attacker creates calldata with 100k addresses\n\
                            const hugeBatch = {{\n\
                                targets: new Array(100000).fill(attackerAddress),\n\
                                calldatas: new Array(100000).fill('0x')\n\
                            }};\n\
                            \n\
                            // Call processBatch(hugeBatch)\n\
                            // Memory allocation for 100k addresses:\n\
                            // 100,000 * 32 bytes = 3.2 MB\n\
                            // Quadratic gas cost → out of gas!\n\
                            ```\n\
                            \n\
                            IMPACT:\n\
                            - View function DoS (external integrations break)\n\
                            - Oracle price feed failures\n\
                            - Subgraph indexing stops\n\
                            - Frontend crashes\n\
                            - Griefing attack (wastes validator resources)\n\
                            \n\
                            REAL WORLD:\n\
                            Multiple DeFi protocols had view functions that accepted unbounded arrays:\n\
                            - getBalances(address[] users) → DoS with 10k users\n\
                            - getPrices(address[] tokens) → DoS with massive token list\n\
                            - batchTransfer(address[] recipients, uint256[] amounts) → DoS\n\
                            \n\
                            FIX:\n\
                            ```solidity\n\
                            uint256 constant MAX_BATCH_SIZE = 100;\n\
                            \n\
                            function processBatch(Batch calldata batch) external {{\n\
                                require(batch.targets.length <= MAX_BATCH_SIZE, 'Batch too large');\n\
                                require(batch.calldatas.length <= MAX_BATCH_SIZE, 'Batch too large');\n\
                                \n\
                                for (uint i = 0; i < batch.targets.length; i++) {{\n\
                                    batch.targets[i].call(batch.calldatas[i]);\n\
                                }}\n\
                            }}\n\
                            ```\n\
                            \n\
                            BEST PRACTICES:\n\
                            ✓ Always limit array sizes from calldata\n\
                            ✓ Max 100-1000 elements for view functions\n\
                            ✓ Use pagination for large datasets\n\
                            ✓ Test with gas limit simulation\n\
                            ✓ Add explicit bounds checking",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    // ============ UNBOUNDED RETURNDATACOPY ============
    
    fn detect_unbounded_returndatacopy(&self) -> Vec<MemoryExpansionVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: RETURNDATACOPY with size from RETURNDATASIZE (unbounded)
        for i in 0..self.bytecode.len().saturating_sub(15) {
            if self.bytecode[i] == 0x3E { // RETURNDATACOPY
                // Check if copying entire return data without size check
                if self.has_unbounded_returndata_size(i) {
                    vulnerabilities.push(MemoryExpansionVulnerability {
                        vulnerability_type: MemoryExpansionIssueType::LargeReturnDataCopy,
                        severity: SecuritySeverity::High,
                        confidence: 0.75,
                        description: "Unbounded RETURNDATACOPY - malicious contract can cause DoS".to_string(),
                        exploit_scenario: format!(
                            "UNBOUNDED RETURNDATACOPY at position {}:\n\
                            \n\
                            External call returns massive data → memory explosion.\n\
                            \n\
                            ```solidity\n\
                            contract VulnerableProxy {{\n\
                                address public implementation;\n\
                                \n\
                                fallback() external payable {{\n\
                                    address impl = implementation;\n\
                                    \n\
                                    assembly {{\n\
                                        calldatacopy(0, 0, calldatasize())\n\
                                        let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)\n\
                                        \n\
                                        // ❌ Copies ALL return data without bounds\n\
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
                            ATTACK:\n\
                            ```solidity\n\
                            contract MaliciousImplementation {{\n\
                                function attack() external returns (bytes memory) {{\n\
                                    // Return 10 MB of data\n\
                                    return new bytes(10_000_000);\n\
                                }}\n\
                            }}\n\
                            \n\
                            // Set implementation to MaliciousImplementation\n\
                            // Call any function → returndatasize() = 10 MB\n\
                            // RETURNDATACOPY tries to allocate 10 MB\n\
                            // Gas cost exceeds block limit → DoS\n\
                            ```\n\
                            \n\
                            FIX:\n\
                            ```solidity\n\
                            uint256 constant MAX_RETURN_SIZE = 10000; // 10 KB\n\
                            \n\
                            assembly {{\n\
                                let size := returndatasize()\n\
                                \n\
                                // ✓ Limit return data size\n\
                                if gt(size, MAX_RETURN_SIZE) {{\n\
                                    revert(0, 0)\n\
                                }}\n\
                                \n\
                                returndatacopy(0, 0, size)\n\
                                return(0, size)\n\
                            }}\n\
                            ```",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    // ============ LOOP MEMORY EXPANSION ============
    
    fn detect_loop_memory_expansion(&self) -> Vec<MemoryExpansionVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Memory operations (MSTORE/MLOAD) inside loops
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.is_in_loop(i) {
                // Check for memory operations that expand memory
                if self.bytecode[i] == 0x52 || // MSTORE
                   self.bytecode[i] == 0x51 {  // MLOAD
                    
                    // Check if offset grows with loop iteration
                    if self.has_growing_memory_offset(i) {
                        vulnerabilities.push(MemoryExpansionVulnerability {
                            vulnerability_type: MemoryExpansionIssueType::LoopMemoryExpansion,
                            severity: SecuritySeverity::Medium,
                            confidence: 0.70,
                            description: "Memory expansion in loop - potential DoS".to_string(),
                            exploit_scenario: format!(
                                "LOOP MEMORY EXPANSION at position {}:\n\
                                \n\
                                Memory grows with each loop iteration.\n\
                                If loop count is unbounded, memory cost can exceed gas limit.\n\
                                \n\
                                ```solidity\n\
                                function processAll(uint256[] calldata items) external view {{\n\
                                    bytes[] memory results = new bytes[](items.length);\n\
                                    \n\
                                    for (uint i = 0; i < items.length; i++) {{\n\
                                        // Each iteration allocates more memory\n\
                                        results[i] = process(items[i]);\n\
                                    }}\n\
                                }}\n\
                                ```\n\
                                \n\
                                Fix: Limit array length or use pagination",
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

    // ============ LARGE MEMORY ALLOCATION ============
    
    fn detect_large_memory_allocation(&self) -> Vec<MemoryExpansionVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Large memory allocations (MSTORE to high offset)
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x52 { // MSTORE
                // Check if offset is very large or computed from input
                if self.has_large_or_dynamic_offset_before(i) {
                    vulnerabilities.push(MemoryExpansionVulnerability {
                        vulnerability_type: MemoryExpansionIssueType::UnboundedMemoryAllocation,
                        severity: SecuritySeverity::Medium,
                        confidence: 0.65,
                        description: "Large or dynamic memory allocation detected".to_string(),
                        exploit_scenario: format!(
                            "LARGE MEMORY ALLOCATION at position {}:\n\
                            \n\
                            Memory allocated at dynamic or very high offset.\n\
                            Could lead to excessive gas consumption.\n\
                            \n\
                            Recommendation: Validate memory allocation sizes",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    // ============ HELPER FUNCTIONS ============

    fn has_unbounded_size_before(&self, pos: usize) -> bool {
        // Check if CALLDATASIZE appears before CALLDATACOPY without bounds check
        for i in pos.saturating_sub(10)..pos {
            if self.bytecode[i] == 0x36 { // CALLDATASIZE
                // Check if there's a comparison/bounds check
                if !self.has_size_check_between(i, pos) {
                    return true;
                }
            }
        }
        false
    }

    fn has_unbounded_returndata_size(&self, pos: usize) -> bool {
        // Check if RETURNDATASIZE appears before RETURNDATACOPY without check
        for i in pos.saturating_sub(10)..pos {
            if self.bytecode[i] == 0x3D { // RETURNDATASIZE
                if !self.has_size_check_between(i, pos) {
                    return true;
                }
            }
        }
        false
    }

    fn has_size_check_between(&self, start: usize, end: usize) -> bool {
        // Look for comparison operations (GT, LT, EQ) between start and end
        for i in start..end {
            if self.bytecode[i] == 0x10 || // LT
               self.bytecode[i] == 0x11 || // GT
               self.bytecode[i] == 0x14 {  // EQ
                return true;
            }
        }
        false
    }

    fn is_in_loop(&self, pos: usize) -> bool {
        // Simple heuristic: Check for JUMPDEST before and JUMPI after
        let has_jumpdest_before = self.bytecode[..pos]
            .iter()
            .rev()
            .take(50)
            .any(|&b| b == 0x5B); // JUMPDEST
        
        let has_jumpi_after = self.bytecode[pos..]
            .iter()
            .take(50)
            .any(|&b| b == 0x57); // JUMPI
        
        has_jumpdest_before && has_jumpi_after
    }

    fn has_growing_memory_offset(&self, _pos: usize) -> bool {
        // Complex to detect reliably - would need symbolic execution
        // For now, conservative assumption
        true
    }

    fn has_large_or_dynamic_offset_before(&self, pos: usize) -> bool {
        // Check for MSTORE offset that's large or computed
        for i in pos.saturating_sub(10)..pos {
            // Large constant offset (> 10000 bytes)
            if self.bytecode[i] >= 0x60 && self.bytecode[i] <= 0x7F {
                // PUSH operation
                let push_size = (self.bytecode[i] - 0x5F) as usize;
                if i + push_size < self.bytecode.len() {
                    let mut value: u64 = 0;
                    for j in 0..push_size.min(8) {
                        value = (value << 8) | self.bytecode[i + 1 + j] as u64;
                    }
                    if value > 10000 {
                        return true;
                    }
                }
            }
            
            // Dynamic offset (from CALLDATALOAD, SLOAD, etc.)
            if self.bytecode[i] == 0x35 || // CALLDATALOAD
               self.bytecode[i] == 0x54 {  // SLOAD
                return true;
            }
        }
        false
    }
}
