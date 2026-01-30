/// Storage Slot Calculation Vulnerability Detector
///
/// Detects errors in storage slot calculations for mappings, arrays, and structs.
/// Incorrect slot calculation leads to storage collisions and data corruption.
///
/// Storage layout rules:
/// - State variables: Sequential slots starting at 0
/// - Mappings: keccak256(key . slot)
/// - Dynamic arrays: keccak256(slot) for length, keccak256(slot) + index for elements
/// - Structs: Members packed sequentially
///
/// Why dangerous:
/// - Wrong slot calculation → write to wrong location
/// - Storage collision → overwrite critical data
/// - Array length manipulation → arbitrary storage write
/// - Mapping collision → access control bypass
///
/// Real exploits:
/// - Multiple storage collision bugs
/// - Array length overflow attacks
/// - Mapping key collision exploits
/// - $20M+ in storage corruption vulnerabilities
///
/// Example vulnerability:
/// ```solidity
/// contract VulnerableStorage {
///     uint256[] public items;  // slot 0
///     mapping(address => uint256) public balances;  // slot 1
///     
///     function addItem(uint256 item) external {
///         items.push(item);
///     }
///     
///     function exploit() external {
///         // ❌ BUG: Manipulate array length to overlap with mapping
///         assembly {
///             // items length is at slot 0
///             // Set length to huge value
///             sstore(0, 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
///         }
///         
///         // Now items[i] can access ANY storage slot!
///         // Calculate index to hit balances mapping
///         uint256 maliciousIndex = uint256(keccak256(abi.encode(1))) - uint256(keccak256(abi.encode(0)));
///         
///         // Write to balances[msg.sender] through items array!
///         items[maliciousIndex] = 1000000 ether;
///     }
/// }
/// ```

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageSlotVulnerability {
    pub vulnerability_type: StorageSlotIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageSlotIssueType {
    ArrayLengthManipulation,       // Array length can be manipulated
    MappingSlotCollision,          // Mapping slot calculation may collide
    StructPackingError,            // Struct packing may cause overlap
    DynamicArraySlotCalculation,   // Dynamic array slot calculation risk
    ArbitraryStorageWrite,         // Calculated slot allows arbitrary write
}

pub struct StorageSlotCalculationDetector {
    bytecode: Vec<u8>,
}

impl StorageSlotCalculationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<StorageSlotVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_array_length_manipulation());
        vulnerabilities.extend(self.detect_mapping_slot_calculation());
        vulnerabilities.extend(self.detect_computed_storage_access());

        vulnerabilities
    }

    fn detect_array_length_manipulation(&self) -> Vec<StorageSlotVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: SSTORE to low slot (array length location)
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x55 { // SSTORE
                // Check if storing to low slot (0-10) which are typically array lengths
                if self.is_storing_to_low_slot(i) {
                    vulnerabilities.push(StorageSlotVulnerability {
                        vulnerability_type: StorageSlotIssueType::ArrayLengthManipulation,
                        severity: SecuritySeverity::Critical,
                        confidence: 0.75,
                        description: "Storage write to low slot - potential array length manipulation".to_string(),
                        exploit_scenario: format!(
                            "ARRAY LENGTH MANIPULATION at position {}:\n\
                            \n\
                            CRITICAL: Write to low storage slot detected!\n\
                            If this is an array length, manipulation allows arbitrary storage access.\n\
                            \n\
                            VULNERABLE PATTERN:\n\
                            ```solidity\n\
                            contract VulnerableArrayAccess {{\n\
                                uint256[] public data;  // Length at slot 0\n\
                                                        // Elements at keccak256(0) + index\n\
                                address public owner;   // slot 1\n\
                                \n\
                                function unsafeSetLength(uint256 newLength) external {{\n\
                                    // ❌ CRITICAL: Allows setting array length!\n\
                                    assembly {{\n\
                                        sstore(0, newLength)\n\
                                    }}\n\
                                }}\n\
                                \n\
                                function setValue(uint256 index, uint256 value) external {{\n\
                                    data[index] = value;\n\
                                    // No bounds check because length was manipulated!\n\
                                }}\n\
                            }}\n\
                            \n\
                            // ATTACK:\n\
                            contract Attacker {{\n\
                                function exploit(VulnerableArrayAccess target) external {{\n\
                                    // Step 1: Set array length to max\n\
                                    target.unsafeSetLength(2**256 - 1);\n\
                                    \n\
                                    // Step 2: Calculate index to access 'owner' (slot 1)\n\
                                    // data elements start at keccak256(0)\n\
                                    uint256 dataStart = uint256(keccak256(abi.encode(uint256(0))));\n\
                                    \n\
                                    // To access slot 1 (owner):\n\
                                    // dataStart + index = 1\n\
                                    // index = 1 - dataStart (mod 2^256)\n\
                                    uint256 maliciousIndex = uint256(1) - dataStart;\n\
                                    \n\
                                    // Step 3: Overwrite owner!\n\
                                    target.setValue(maliciousIndex, uint256(uint160(address(this))));\n\
                                    \n\
                                    // Now attacker is owner!\n\
                                }}\n\
                            }}\n\
                            ```\n\
                            \n\
                            REAL EXPLOIT: ARRAY LENGTH OVERFLOW\n\
                            \n\
                            Historical bug (pre-0.6.0):\n\
                            ```solidity\n\
                            contract OldVulnerable {{\n\
                                uint256[] public data;\n\
                                \n\
                                function pop() external {{\n\
                                    // ❌ BUG: No underflow check!\n\
                                    data.length--;\n\
                                    \n\
                                    // If data.length = 0, this underflows to 2^256-1\n\
                                    // Now all storage accessible via data array!\n\
                                }}\n\
                            }}\n\
                            ```\n\
                            \n\
                            STORAGE LAYOUT:\n\
                            ```\n\
                            Slot 0: data.length\n\
                            Slot 1: owner\n\
                            Slot 2: balance\n\
                            ...\n\
                            \n\
                            data[0] location: keccak256(0x00...00) = 0x290d...\n\
                            data[1] location: keccak256(0x00...00) + 1 = 0x290d... + 1\n\
                            data[i] location: keccak256(0x00...00) + i\n\
                            ```\n\
                            \n\
                            ARBITRARY STORAGE ACCESS:\n\
                            ```solidity\n\
                            // To write to ANY slot S:\n\
                            // Need: keccak256(arraySlot) + index = S\n\
                            // So: index = S - keccak256(arraySlot)\n\
                            \n\
                            function writeToAnySlot(uint256 slot, uint256 value) internal {{\n\
                                uint256[] storage arr; // Assume at slot 0\n\
                                uint256 arrStart = uint256(keccak256(abi.encode(uint256(0))));\n\
                                \n\
                                // Calculate wraparound index\n\
                                uint256 index = slot - arrStart; // Wraps if slot < arrStart\n\
                                \n\
                                arr[index] = value; // Writes to arbitrary slot!\n\
                            }}\n\
                            ```\n\
                            \n\
                            IMPACT EXAMPLES:\n\
                            \n\
                            1. Owner Takeover:\n\
                            ```solidity\n\
                            // Overwrite owner variable\n\
                            writeToSlot(ownerSlot, uint256(uint160(attacker)));\n\
                            ```\n\
                            \n\
                            2. Balance Manipulation:\n\
                            ```solidity\n\
                            // Overwrite balance mapping\n\
                            uint256 balanceSlot = uint256(keccak256(abi.encode(attacker, balancesSlot)));\n\
                            writeToSlot(balanceSlot, 1000000 ether);\n\
                            ```\n\
                            \n\
                            3. Authorization Bypass:\n\
                            ```solidity\n\
                            // Set isAdmin[attacker] = true\n\
                            uint256 adminSlot = uint256(keccak256(abi.encode(attacker, isAdminSlot)));\n\
                            writeToSlot(adminSlot, 1);\n\
                            ```\n\
                            \n\
                            SOLIDITY 0.6.0+ PROTECTION:\n\
                            ```solidity\n\
                            // Modern Solidity prevents this:\n\
                            function safePop() external {{\n\
                                data.pop(); // ✓ Has underflow check\n\
                                // Reverts if length = 0\n\
                            }}\n\
                            \n\
                            function safeAccess(uint256 index) external {{\n\
                                require(index < data.length); // ✓ Bounds check\n\
                                return data[index];\n\
                            }}\n\
                            ```\n\
                            \n\
                            MANUAL ASSEMBLY RISKS:\n\
                            ```solidity\n\
                            function dangerousAssembly(uint256 index) external {{\n\
                                assembly {{\n\
                                    // ❌ No bounds check in assembly!\n\
                                    let slot := 0 // array slot\n\
                                    mstore(0, slot)\n\
                                    let loc := add(keccak256(0, 0x20), index)\n\
                                    sstore(loc, 123)\n\
                                    // If index malicious → arbitrary write\n\
                                }}\n\
                            }}\n\
                            ```\n\
                            \n\
                            SAFE PATTERNS:\n\
                            ```solidity\n\
                            // ✓ Use Solidity's built-in array operations\n\
                            function safe() external {{\n\
                                data.push(value);   // Safe\n\
                                data.pop();         // Safe (reverts on underflow)\n\
                                data[index] = val;  // Safe (bounds checked)\n\
                            }}\n\
                            \n\
                            // ✓ If using assembly, add bounds checks\n\
                            function safeAssembly(uint256 index, uint256 value) external {{\n\
                                require(index < data.length, 'Out of bounds');\n\
                                \n\
                                assembly {{\n\
                                    let slot := 0\n\
                                    mstore(0, slot)\n\
                                    let loc := add(keccak256(0, 0x20), index)\n\
                                    sstore(loc, value)\n\
                                }}\n\
                            }}\n\
                            ```\n\
                            \n\
                            SEVERITY: CRITICAL\n\
                            - Arbitrary storage write\n\
                            - Complete contract takeover\n\
                            - Fund theft\n\
                            - Authorization bypass",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_mapping_slot_calculation(&self) -> Vec<StorageSlotVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: SHA3 followed by SLOAD/SSTORE (mapping access)
        for i in 0..self.bytecode.len().saturating_sub(5) {
            if self.bytecode[i] == 0x20 { // SHA3/KECCAK256
                // Check if followed by storage operation
                for j in i..i.saturating_add(10).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x54 || self.bytecode[j] == 0x55 {
                        vulnerabilities.push(StorageSlotVulnerability {
                            vulnerability_type: StorageSlotIssueType::MappingSlotCollision,
                            severity: SecuritySeverity::Medium,
                            confidence: 0.65,
                            description: "Keccak256-based storage access detected - verify mapping slot calculation".to_string(),
                            exploit_scenario: format!(
                                "MAPPING SLOT CALCULATION at position {}:\n\
                                \n\
                                SHA3 followed by storage operation.\n\
                                Typical of mapping access: slot = keccak256(key . mappingSlot)\n\
                                \n\
                                Verify:\n\
                                - Correct key encoding (abi.encode vs abi.encodePacked)\n\
                                - No collision between different mappings\n\
                                - Nested mapping keys in correct order",
                                i
                            ),
                            location: i,
                        });
                        break;
                    }
                }
            }
        }

        vulnerabilities
    }

    fn detect_computed_storage_access(&self) -> Vec<StorageSlotVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: ADD/SUB before SSTORE (computed slot)
        for i in 0..self.bytecode.len().saturating_sub(5) {
            if self.bytecode[i] == 0x55 { // SSTORE
                // Check if slot is computed (ADD/SUB before SSTORE)
                if self.has_arithmetic_before(i) {
                    vulnerabilities.push(StorageSlotVulnerability {
                        vulnerability_type: StorageSlotIssueType::ArbitraryStorageWrite,
                        severity: SecuritySeverity::High,
                        confidence: 0.60,
                        description: "Computed storage slot access - verify bounds and collision safety".to_string(),
                        exploit_scenario: format!(
                            "COMPUTED STORAGE ACCESS at position {}:\n\
                            \n\
                            Storage slot calculated via arithmetic operations.\n\
                            Risk: If calculation user-controlled → arbitrary storage write.\n\
                            \n\
                            Ensure:\n\
                            - Slot calculation cannot overflow/underflow\n\
                            - User input properly validated\n\
                            - Cannot access unintended slots",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn is_storing_to_low_slot(&self, pos: usize) -> bool {
        // Check if SSTORE destination is low slot (0-10)
        for i in pos.saturating_sub(10)..pos {
            if self.bytecode[i] == 0x60 && i + 1 < self.bytecode.len() {
                let slot = self.bytecode[i + 1];
                if slot < 10 {
                    return true;
                }
            }
        }
        false
    }

    fn has_arithmetic_before(&self, pos: usize) -> bool {
        // Check for ADD/SUB before SSTORE
        for i in pos.saturating_sub(10)..pos {
            if self.bytecode[i] == 0x01 || // ADD
               self.bytecode[i] == 0x03 {  // SUB
                return true;
            }
        }
        false
    }
}
