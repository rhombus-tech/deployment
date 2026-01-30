/// Library Delegatecall State Mutation Detector
/// 
/// Detects when Solidity libraries use delegatecall to execute code that
/// unexpectedly modifies the caller's storage, leading to storage collisions.
/// 
/// Critical patterns:
/// - Library uses DELEGATECALL instead of CALL
/// - Library modifies storage via SSTORE
/// - Library's storage layout conflicts with caller
/// - "Pure" or "view" library functions that actually mutate state
/// 
/// Real risks:
/// - Storage slot collisions between library and contract
/// - Unexpected state mutations from "safe" library calls
/// - Libraries that should be stateless but aren't
/// 
/// Example vulnerability:
/// ```solidity
/// library Math {
///     uint256 private temp; // Storage slot 0
///     
///     function calculate(uint x, uint y) internal returns (uint) {
///         temp = x;  // ❌ Writes to CALLER's slot 0!
///         return temp * y;
///     }
/// }
/// 
/// contract Vault {
///     address public owner;  // Storage slot 0
///     
///     function compute(uint a, uint b) external {
///         Math.calculate(a, b);  // Overwrites owner!
///     }
/// }
/// ```

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LibraryDelegatecallVulnerability {
    pub vulnerability_type: LibraryIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LibraryIssueType {
    LibraryModifiesStorage,        // Library with SSTORE operations
    DelegatecallToLibrary,         // DELEGATECALL to library code
    StorageCollisionRisk,          // Storage layout conflicts
    StatefulLibraryFunction,       // Library function should be pure/view but isn't
}

pub struct LibraryDelegatecallDetector {
    bytecode: Vec<u8>,
}

impl LibraryDelegatecallDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<LibraryDelegatecallVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_library_storage_mutations());
        vulnerabilities.extend(self.detect_delegatecall_to_library());
        vulnerabilities.extend(self.detect_storage_collision_patterns());

        vulnerabilities
    }

    // ============ LIBRARY STORAGE MUTATIONS ============
    
    fn detect_library_storage_mutations(&self) -> Vec<LibraryDelegatecallVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check if bytecode is a library (no constructor, uses DELEGATECALL internally)
        if !self.is_library_pattern() {
            return vulnerabilities;
        }

        // Pattern: Library contains SSTORE (modifies storage)
        for (i, &byte) in self.bytecode.iter().enumerate() {
            if byte == 0x55 { // SSTORE
                vulnerabilities.push(LibraryDelegatecallVulnerability {
                    vulnerability_type: LibraryIssueType::LibraryModifiesStorage,
                    severity: SecuritySeverity::High,
                    confidence: 0.85,
                    description: "Library contains SSTORE - will modify caller's storage".to_string(),
                    exploit_scenario: format!(
                        "LIBRARY STORAGE MUTATION at position {}:\n\
                        \n\
                        Dangerous Pattern:\n\
                        ```solidity\n\
                        library UnsafeLib {{\n\
                            uint256 private temp;  // ❌ Storage slot 0\n\
                            \n\
                            function process(uint256 value) internal returns (uint256) {{\n\
                                temp = value;  // SSTORE to slot 0\n\
                                return temp * 2;\n\
                            }}\n\
                        }}\n\
                        \n\
                        contract Victim {{\n\
                            address public owner;  // Slot 0\n\
                            uint256 public balance; // Slot 1\n\
                            \n\
                            function calculate(uint256 x) external {{\n\
                                uint256 result = UnsafeLib.process(x);\n\
                                // owner has been overwritten by library!\n\
                            }}\n\
                        }}\n\
                        ```\n\
                        \n\
                        What Happens:\n\
                        1. User calls calculate(123456)\n\
                        2. Library executes: temp = 123456\n\
                        3. SSTORE writes to slot 0 in CALLER's storage\n\
                        4. owner = address(123456) - corrupted!\n\
                        5. Access control broken\n\
                        \n\
                        Real Incident:\n\
                        - This pattern has caused multiple storage corruption bugs\n\
                        - Libraries should NEVER use storage variables\n\
                        - Use memory or calldata instead\n\
                        \n\
                        Fix:\n\
                        ```solidity\n\
                        library SafeLib {{\n\
                            function process(uint256 value) internal pure returns (uint256) {{\n\
                                return value * 2;  // No storage!\n\
                            }}\n\
                        }}\n\
                        ```",
                        i
                    ),
                    location: i,
                });
            }
        }

        vulnerabilities
    }

    // ============ DELEGATECALL TO LIBRARY ============
    
    fn detect_delegatecall_to_library(&self) -> Vec<LibraryDelegatecallVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: DELEGATECALL that might be to a library
        for i in 0..self.bytecode.len() {
            if self.bytecode[i] == 0xF4 { // DELEGATECALL
                // Check if this is an internal library call pattern
                if self.is_library_delegatecall_pattern(i) {
                    vulnerabilities.push(LibraryDelegatecallVulnerability {
                        vulnerability_type: LibraryIssueType::DelegatecallToLibrary,
                        severity: SecuritySeverity::Medium,
                        confidence: 0.70,
                        description: "DELEGATECALL to library - ensure library is stateless".to_string(),
                        exploit_scenario: format!(
                            "DELEGATECALL TO LIBRARY at position {}:\n\
                            \n\
                            Pattern Detected:\n\
                            ```solidity\n\
                            library LibraryCode {{\n\
                                function doSomething() internal {{\n\
                                    // Library code executes in caller context\n\
                                }}\n\
                            }}\n\
                            \n\
                            contract Main {{\n\
                                function execute() external {{\n\
                                    LibraryCode.doSomething();\n\
                                    // Compiles to: DELEGATECALL to library address\n\
                                }}\n\
                            }}\n\
                            ```\n\
                            \n\
                            Risk Assessment:\n\
                            ✓ OK if library is truly stateless (pure/view)\n\
                            ❌ DANGEROUS if library uses storage\n\
                            ❌ DANGEROUS if library has state variables\n\
                            \n\
                            Verify:\n\
                            1. Check if library has any state variables\n\
                            2. Ensure all library functions are pure/view\n\
                            3. No SSTORE operations in library\n\
                            \n\
                            Safe Pattern:\n\
                            ```solidity\n\
                            library SafeMath {{\n\
                                function add(uint a, uint b) internal pure returns (uint) {{\n\
                                    return a + b;  // Pure function, no storage\n\
                                }}\n\
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

    // ============ STORAGE COLLISION PATTERNS ============
    
    fn detect_storage_collision_patterns(&self) -> Vec<LibraryDelegatecallVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for patterns that indicate potential storage collisions
        let sstore_locations = self.find_sstore_locations();
        let sload_locations = self.find_sload_locations();

        if sstore_locations.len() > 2 && sload_locations.len() > 2 {
            // Check if storage access uses low slot numbers (0-10)
            for &loc in &sstore_locations {
                if self.accesses_low_storage_slot(loc) {
                    vulnerabilities.push(LibraryDelegatecallVulnerability {
                        vulnerability_type: LibraryIssueType::StorageCollisionRisk,
                        severity: SecuritySeverity::High,
                        confidence: 0.65,
                        description: "Storage operations on low slots - collision risk with caller".to_string(),
                        exploit_scenario: format!(
                            "STORAGE COLLISION RISK at position {}:\n\
                            \n\
                            Vulnerability:\n\
                            Library accesses storage slots 0-10, which are typically used for:\n\
                            - Slot 0: owner, admin, or first state variable\n\
                            - Slot 1: balances, status flags\n\
                            - Slot 2-10: other critical state\n\
                            \n\
                            Example Collision:\n\
                            ```solidity\n\
                            library DataStore {{\n\
                                struct Data {{\n\
                                    uint256 value;    // Slot 0 when used\n\
                                    address owner;     // Slot 1 when used\n\
                                }}\n\
                                \n\
                                function store(Data storage data, uint256 val) internal {{\n\
                                    data.value = val;  // Writes to slot 0!\n\
                                }}\n\
                            }}\n\
                            \n\
                            contract Vault {{\n\
                                address public owner;      // Slot 0\n\
                                uint256 public balance;    // Slot 1\n\
                                \n\
                                DataStore.Data private data;  // Also starts at slot 0!\n\
                                \n\
                                function update(uint256 val) external {{\n\
                                    DataStore.store(data, val);\n\
                                    // owner corrupted!\n\
                                }}\n\
                            }}\n\
                            ```\n\
                            \n\
                            Impact:\n\
                            - Critical state variables overwritten\n\
                            - Access control bypassed\n\
                            - Funds at risk\n\
                            \n\
                            Prevention:\n\
                            1. Libraries should not use storage\n\
                            2. If absolutely necessary, use high slot numbers\n\
                            3. Use unstructured storage pattern\n\
                            4. Thorough storage layout analysis",
                            loc
                        ),
                        location: loc,
                    });
                    break; // Report once per contract
                }
            }
        }

        vulnerabilities
    }

    // ============ HELPER FUNCTIONS ============

    fn is_library_pattern(&self) -> bool {
        // Libraries typically:
        // 1. Don't have payable constructors
        // 2. Use DELEGATECALL for internal library calls
        // 3. Have specific bytecode patterns
        
        // Check for absence of constructor (library marker)
        let has_constructor = self.bytecode.windows(4).any(|w| {
            w[0] == 0x39 && // CODECOPY
            w.contains(&0xF3) // RETURN nearby
        });
        
        // Check for DELEGATECALL usage (library internal calls)
        let has_delegatecall = self.bytecode.contains(&0xF4);
        
        has_delegatecall || !has_constructor
    }

    fn is_library_delegatecall_pattern(&self, pos: usize) -> bool {
        // Library delegatecall pattern:
        // PUSH library_address, ..., DELEGATECALL
        
        // Look backwards for PUSH of address
        for i in pos.saturating_sub(25)..pos {
            if i + 1 < self.bytecode.len() {
                if self.bytecode[i] == 0x73 { // PUSH20 (address)
                    return true;
                }
            }
        }
        false
    }

    fn find_sstore_locations(&self) -> Vec<usize> {
        self.bytecode.iter()
            .enumerate()
            .filter(|(_, &b)| b == 0x55) // SSTORE
            .map(|(i, _)| i)
            .collect()
    }

    fn find_sload_locations(&self) -> Vec<usize> {
        self.bytecode.iter()
            .enumerate()
            .filter(|(_, &b)| b == 0x54) // SLOAD
            .map(|(i, _)| i)
            .collect()
    }

    fn accesses_low_storage_slot(&self, pos: usize) -> bool {
        // Check if SSTORE is preceded by PUSH of low value (0-10)
        for i in pos.saturating_sub(5)..pos {
            if i + 1 < self.bytecode.len() {
                if self.bytecode[i] == 0x60 { // PUSH1
                    let value = self.bytecode[i + 1];
                    if value <= 10 {
                        return true;
                    }
                }
            }
        }
        false
    }
}
