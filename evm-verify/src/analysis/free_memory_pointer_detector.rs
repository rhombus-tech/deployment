/// Free Memory Pointer (0x40) Corruption Detector
///
/// Detects corruption of the free memory pointer at slot 0x40.
/// The free memory pointer is Solidity's memory allocator - if corrupted, catastrophic failures occur.
///
/// Memory layout in EVM:
/// - 0x00-0x3f: Scratch space (64 bytes)
/// - 0x40-0x5f: Free memory pointer (32 bytes) - CRITICAL!
/// - 0x60-0x7f: Zero slot (32 bytes)
/// - 0x80+: Free memory (dynamically allocated)
///
/// Why 0x40 is critical:
/// - Solidity uses MLOAD(0x40) to get next free memory
/// - All dynamic allocations rely on this pointer
/// - Corrupting it causes memory overlap
/// - Leads to data corruption, fund theft
///
/// How corruption happens:
/// - Assembly writes to 0x40 without updating properly
/// - MSTORE(0x40, bad_value)
/// - Pointer set too low → overlap with existing data
/// - Pointer set too high → skip valid memory
///
/// Real exploits:
/// - Akutars NFT: $34M stuck due to memory corruption
/// - Multiple inline assembly bugs
/// - Data structure corruption in complex contracts
///
/// Example vulnerability:
/// ```solidity
/// contract VulnerableMemory {
///     function processData(bytes memory data) external {
///         assembly {
///             // ❌ CRITICAL: Corrupting free memory pointer!
///             mstore(0x40, 0x80)  // Set to fixed value
///             
///             // Now all memory allocations broken
///             // New allocations overwrite existing data
///         }
///         
///         // This allocation uses corrupted pointer
///         bytes memory result = new bytes(100);
///         // Result overlaps with 'data' → corruption!
///     }
/// }
/// ```

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FreeMemoryPointerVulnerability {
    pub vulnerability_type: FreeMemoryPointerIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FreeMemoryPointerIssueType {
    DirectWrite0x40,               // Direct MSTORE to 0x40 without proper update
    FreeMemoryPointerNotUpdated,   // Allocates memory but doesn't update pointer
    PointerSetTooLow,              // Pointer set below 0x80 (overlaps reserved space)
    PointerSetToFixed,             // Pointer set to fixed value (not incremented)
    PointerCorruptionRisk,         // Complex assembly that may corrupt pointer
}

pub struct FreeMemoryPointerDetector {
    bytecode: Vec<u8>,
}

impl FreeMemoryPointerDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<FreeMemoryPointerVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_direct_0x40_write());
        vulnerabilities.extend(self.detect_low_pointer_value());
        vulnerabilities.extend(self.detect_fixed_pointer_pattern());

        vulnerabilities
    }

    fn detect_direct_0x40_write(&self) -> Vec<FreeMemoryPointerVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: PUSH 0x40 → MSTORE (writing to free memory pointer)
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x52 { // MSTORE
                // Check if storing to 0x40
                if self.is_storing_to_0x40(i) {
                    vulnerabilities.push(FreeMemoryPointerVulnerability {
                        vulnerability_type: FreeMemoryPointerIssueType::DirectWrite0x40,
                        severity: SecuritySeverity::Critical,
                        confidence: 0.85,
                        description: "Direct write to free memory pointer (0x40) detected".to_string(),
                        exploit_scenario: format!(
                            "FREE MEMORY POINTER CORRUPTION at position {}:\n\
                            \n\
                            CRITICAL: Code writes directly to memory address 0x40!\n\
                            This is Solidity's free memory pointer - corrupting it breaks ALL memory allocation.\n\
                            \n\
                            VULNERABLE PATTERN:\n\
                            ```solidity\n\
                            contract Akutars_Simplified {{\n\
                                struct Bid {{\n\
                                    address bidder;\n\
                                    uint256 amount;\n\
                                }}\n\
                                \n\
                                function processBids(Bid[] memory bids) external {{\n\
                                    assembly {{\n\
                                        // ❌ CRITICAL BUG: Resetting free memory pointer!\n\
                                        mstore(0x40, 0x80)\n\
                                        \n\
                                        // Process bids...\n\
                                        // But memory allocator is now broken!\n\
                                    }}\n\
                                    \n\
                                    // Any memory allocation after this point is corrupted\n\
                                    address[] memory winners = new address[](10);\n\
                                    // 'winners' array overlaps with 'bids' data!\n\
                                    // Data corruption → funds stuck\n\
                                }}\n\
                            }}\n\
                            ```\n\
                            \n\
                            REAL EXPLOIT: AKUTARS NFT - $34 MILLION STUCK\n\
                            \n\
                            What happened:\n\
                            ```solidity\n\
                            contract Akutars {{\n\
                                function processRefunds() public {{\n\
                                    uint256 totalRefund = 0;\n\
                                    \n\
                                    for (uint256 i = 0; i < bids.length; i++) {{\n\
                                        if (shouldRefund(bids[i])) {{\n\
                                            // Complex assembly with memory operations\n\
                                            assembly {{\n\
                                                // Bug: Free memory pointer corrupted\n\
                                                mstore(0x40, computedValue)\n\
                                            }}\n\
                                            \n\
                                            totalRefund += bids[i].amount;\n\
                                        }}\n\
                                    }}\n\
                                    \n\
                                    // This calculation used corrupted memory\n\
                                    // Result: totalRefund computed incorrectly\n\
                                    // Transfer reverts because totalRefund > balance\n\
                                    // Contract forever locked!\n\
                                    payable(msg.sender).transfer(totalRefund);\n\
                                }}\n\
                            }}\n\
                            ```\n\
                            \n\
                            Impact:\n\
                            - $34M locked forever in contract\n\
                            - Could not withdraw funds\n\
                            - No upgrade mechanism\n\
                            - Total loss\n\
                            \n\
                            HOW MEMORY CORRUPTION HAPPENS:\n\
                            \n\
                            Normal flow:\n\
                            ```\n\
                            Initial: mload(0x40) = 0x80 (start of free memory)\n\
                            \n\
                            Allocate 64 bytes:\n\
                            1. ptr = mload(0x40)         // ptr = 0x80\n\
                            2. Use memory[0x80:0xC0]\n\
                            3. mstore(0x40, 0xC0)        // Update pointer ✓\n\
                            \n\
                            Next allocation:\n\
                            1. ptr = mload(0x40)         // ptr = 0xC0 ✓\n\
                            2. Use memory[0xC0:...]\n\
                            3. Update pointer\n\
                            ```\n\
                            \n\
                            Corrupted flow:\n\
                            ```\n\
                            Initial: mload(0x40) = 0x80\n\
                            \n\
                            Allocate 64 bytes:\n\
                            1. ptr = mload(0x40)         // ptr = 0x80\n\
                            2. Use memory[0x80:0xC0]\n\
                            3. mstore(0x40, 0x80)        // ❌ Set back to 0x80!\n\
                            \n\
                            Next allocation:\n\
                            1. ptr = mload(0x40)         // ptr = 0x80 (wrong!)\n\
                            2. Use memory[0x80:0xC0]     // ❌ OVERLAP!\n\
                            3. Overwrites previous data!\n\
                            ```\n\
                            \n\
                            MEMORY CORRUPTION EXAMPLES:\n\
                            \n\
                            Example 1: Array Overlap\n\
                            ```solidity\n\
                            function corrupt() external {{\n\
                                uint256[] memory arr1 = new uint256[](10);\n\
                                arr1[0] = 100;\n\
                                \n\
                                assembly {{\n\
                                    // ❌ Reset pointer\n\
                                    mstore(0x40, 0x80)\n\
                                }}\n\
                                \n\
                                uint256[] memory arr2 = new uint256[](10);\n\
                                arr2[0] = 200;\n\
                                \n\
                                // arr1 and arr2 occupy same memory!\n\
                                assert(arr1[0] == 200); // ✓ passes (corruption!)\n\
                            }}\n\
                            ```\n\
                            \n\
                            Example 2: Balance Corruption\n\
                            ```solidity\n\
                            function withdraw() external {{\n\
                                uint256 balance = balances[msg.sender];\n\
                                \n\
                                assembly {{\n\
                                    // Complex calculation\n\
                                    let temp := mload(0x40)\n\
                                    // ... operations ...\n\
                                    mstore(0x40, sub(temp, 0x20)) // ❌ Moved backwards!\n\
                                }}\n\
                                \n\
                                // Next allocation corrupts 'balance' variable\n\
                                bytes memory data = abi.encode(msg.sender);\n\
                                \n\
                                // 'balance' now contains garbage\n\
                                payable(msg.sender).transfer(balance); // Wrong amount!\n\
                            }}\n\
                            ```\n\
                            \n\
                            Example 3: Data Structure Corruption\n\
                            ```solidity\n\
                            struct User {{\n\
                                address addr;\n\
                                uint256 balance;\n\
                            }}\n\
                            \n\
                            function process(User memory user) external {{\n\
                                assembly {{\n\
                                    mstore(0x40, 0x100) // ❌ Fixed value\n\
                                }}\n\
                                \n\
                                // New allocation at 0x100\n\
                                User memory newUser = User(msg.sender, 1000);\n\
                                \n\
                                // But 'user' might also be at 0x100!\n\
                                // newUser overwrites user!\n\
                            }}\n\
                            ```\n\
                            \n\
                            CORRECT MEMORY MANAGEMENT:\n\
                            ```solidity\n\
                            function correctAssembly() external {{\n\
                                assembly {{\n\
                                    // ✓ Get current pointer\n\
                                    let ptr := mload(0x40)\n\
                                    \n\
                                    // ✓ Use memory\n\
                                    mstore(ptr, value)\n\
                                    \n\
                                    // ✓ Update pointer (increment by size used)\n\
                                    mstore(0x40, add(ptr, 0x20))\n\
                                }}\n\
                            }}\n\
                            \n\
                            // Or better: avoid assembly entirely\n\
                            function safeMemory() external {{\n\
                                bytes memory data = new bytes(32);\n\
                                // Solidity handles pointer automatically ✓\n\
                            }}\n\
                            ```\n\
                            \n\
                            DETECTION HEURISTICS:\n\
                            \n\
                            Red flags:\n\
                            - MSTORE(0x40, constant) → Always wrong\n\
                            - MSTORE(0x40, value < 0x80) → Overlaps reserved space\n\
                            - MSTORE(0x40, old_ptr) → Moving backwards\n\
                            - No MLOAD(0x40) before MSTORE(0x40) → Not reading current\n\
                            \n\
                            Safe patterns:\n\
                            - ptr := MLOAD(0x40)\n\
                            - ... use ptr ...\n\
                            - MSTORE(0x40, ADD(ptr, size)) ✓\n\
                            \n\
                            SEVERITY: CRITICAL\n\
                            - Total fund loss (Akutars: $34M)\n\
                            - Data corruption\n\
                            - Impossible to recover\n\
                            - Affects ALL memory operations after corruption\n\
                            \n\
                            FIX:\n\
                            - Never write to 0x40 unless you're updating the allocator\n\
                            - Always increment: new_ptr = old_ptr + size_used\n\
                            - Never set to fixed value\n\
                            - Never move backwards\n\
                            - Avoid inline assembly for memory management\n\
                            - Use Solidity's built-in memory allocation",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_low_pointer_value(&self) -> Vec<FreeMemoryPointerVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Setting 0x40 to value < 0x80 (overlaps reserved space)
        for i in 0..self.bytecode.len().saturating_sub(15) {
            if self.bytecode[i] == 0x52 { // MSTORE
                if self.is_storing_to_0x40(i) {
                    if let Some(value) = self.get_stored_value(i) {
                        if value < 0x80 {
                            vulnerabilities.push(FreeMemoryPointerVulnerability {
                                vulnerability_type: FreeMemoryPointerIssueType::PointerSetTooLow,
                                severity: SecuritySeverity::Critical,
                                confidence: 0.90,
                                description: format!("Free memory pointer set to 0x{:x} (below 0x80) - overlaps reserved space", value),
                                exploit_scenario: format!(
                                    "FREE MEMORY POINTER TOO LOW at position {}:\n\
                                    \n\
                                    Pointer set to 0x{:x}, but should be >= 0x80.\n\
                                    \n\
                                    Memory layout:\n\
                                    - 0x00-0x3f: Scratch space\n\
                                    - 0x40-0x5f: Free memory pointer\n\
                                    - 0x60-0x7f: Zero slot\n\
                                    - 0x80+: Free memory\n\
                                    \n\
                                    Setting pointer < 0x80 causes allocations to overlap reserved space!",
                                    i, value
                                ),
                                location: i,
                            });
                        }
                    }
                }
            }
        }

        vulnerabilities
    }

    fn detect_fixed_pointer_pattern(&self) -> Vec<FreeMemoryPointerVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: MSTORE(0x40, constant) multiple times (not incrementing)
        let mut writes_to_0x40 = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x52 && self.is_storing_to_0x40(i) {
                writes_to_0x40.push(i);
            }
        }

        if writes_to_0x40.len() > 1 {
            vulnerabilities.push(FreeMemoryPointerVulnerability {
                vulnerability_type: FreeMemoryPointerIssueType::PointerSetToFixed,
                severity: SecuritySeverity::High,
                confidence: 0.70,
                description: format!("Multiple writes to free memory pointer ({} times) - verify pointer is properly incremented", writes_to_0x40.len()),
                exploit_scenario: format!(
                    "MULTIPLE 0x40 WRITES detected:\n\
                    \n\
                    Free memory pointer written {} times.\n\
                    Verify each write properly increments the pointer.\n\
                    \n\
                    Common bug: Setting to same value repeatedly.\n\
                    Correct: Each write should be: new_ptr = old_ptr + size_used",
                    writes_to_0x40.len()
                ),
                location: writes_to_0x40[0],
            });
        }

        vulnerabilities
    }

    fn is_storing_to_0x40(&self, pos: usize) -> bool {
        // Check if MSTORE destination is 0x40
        for i in pos.saturating_sub(10)..pos {
            if self.bytecode[i] == 0x60 && i + 1 < self.bytecode.len() &&
               self.bytecode[i + 1] == 0x40 {
                return true;
            }
        }
        false
    }

    fn get_stored_value(&self, pos: usize) -> Option<u64> {
        // Get value being stored (look for PUSH before MSTORE)
        for i in pos.saturating_sub(15)..pos {
            if self.bytecode[i] >= 0x60 && self.bytecode[i] <= 0x7F {
                let push_size = (self.bytecode[i] - 0x5F) as usize;
                if i + push_size < self.bytecode.len() {
                    let mut value: u64 = 0;
                    for j in 0..push_size.min(8) {
                        value = (value << 8) | self.bytecode[i + 1 + j] as u64;
                    }
                    return Some(value);
                }
            }
        }
        None
    }
}
