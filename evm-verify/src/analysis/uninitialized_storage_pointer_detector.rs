/// Uninitialized Storage Pointer Detector
/// 
/// In Solidity <0.5.0, uninitialized storage variables point to slot 0,
/// potentially overwriting critical state (e.g., owner, balances)
/// 
/// Example:
/// struct User { address addr; uint bal; }
/// function bug() {
///     User user; // Uninitialized! Points to storage slot 0
///     user.addr = msg.sender; // Overwrites storage[0]!
/// }

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UninitializedStoragePointer {
    pub vulnerability_type: String,
    pub severity: String,
    pub location: usize,
    pub description: String,
    pub affected_slot: String,
    pub exploit_scenario: String,
    pub remediation: String,
}

pub struct UninitializedStoragePointerDetector {
    bytecode: Vec<u8>,
}

impl UninitializedStoragePointerDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect(&self) -> Vec<UninitializedStoragePointer> {
        let mut vulnerabilities = Vec::new();
        
        vulnerabilities.extend(self.detect_storage_access_without_initialization());
        vulnerabilities.extend(self.detect_struct_pointer_bugs());
        vulnerabilities.extend(self.detect_array_pointer_bugs());
        
        vulnerabilities
    }
    
    fn detect_storage_access_without_initialization(&self) -> Vec<UninitializedStoragePointer> {
        let mut vulns = Vec::new();
        
        // Pattern: SSTORE to slot 0 or low slots without prior initialization
        // This happens when uninitialized storage variable is used
        
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x55 { // SSTORE
                // Check if storing to a constant low slot (0-10)
                let stores_to_low_slot = self.check_stores_to_low_slot(i);
                
                if stores_to_low_slot {
                    // Check if this is within a function (not constructor)
                    let in_function = self.is_in_function_body(i);
                    
                    // Check if there's no prior SLOAD from this slot (uninitialized)
                    let has_prior_load = self.has_prior_sload_from_slot(i);
                    
                    if in_function && !has_prior_load {
                        vulns.push(UninitializedStoragePointer {
                            vulnerability_type: "Uninitialized Storage Pointer".to_string(),
                            severity: "Critical".to_string(),
                            location: i,
                            description: "Storage write to low slot without initialization - likely uninitialized struct/array".to_string(),
                            affected_slot: "Storage slot 0 or other critical slots".to_string(),
                            exploit_scenario: 
                                "Uninitialized storage variable points to slot 0:\n\
                                 1. Contract state: owner = storage[0]\n\
                                 2. Function creates uninitialized User struct\n\
                                 3. user.addr = attacker overwrites storage[0]\n\
                                 4. Attacker is now owner!".to_string(),
                            remediation: 
                                "Initialize storage variables:\n\
                                 - Use 'memory' keyword for temporary variables\n\
                                 - Or explicitly initialize: User storage user = users[id];\n\
                                 - Upgrade to Solidity >=0.5.0 (enforces initialization)".to_string(),
                        });
                    }
                }
            }
        }
        
        vulns
    }
    
    fn detect_struct_pointer_bugs(&self) -> Vec<UninitializedStoragePointer> {
        let mut vulns = Vec::new();
        
        // Pattern for struct access: SHA3 (for struct field offset) + SSTORE
        // Without initialization, SHA3 operates on zero, writing to wrong location
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x20 { // SHA3 (used for struct field calculation)
                // Look for SSTORE shortly after
                for j in i+1..i+15.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x55 { // SSTORE
                        // Check if SHA3 input includes a zero (uninitialized base)
                        let has_zero_input = self.bytecode[i.saturating_sub(10)..i]
                            .windows(2)
                            .any(|w| w[0] == 0x60 && w[1] == 0x00); // PUSH1 0
                        
                        if has_zero_input {
                            vulns.push(UninitializedStoragePointer {
                                vulnerability_type: "Uninitialized Struct Pointer".to_string(),
                                severity: "Critical".to_string(),
                                location: i,
                                description: "Struct field access with uninitialized base pointer".to_string(),
                                affected_slot: "keccak256(0 + field_offset) - unpredictable slots".to_string(),
                                exploit_scenario: "Struct fields write to arbitrary storage locations".to_string(),
                                remediation: "Initialize struct: MyStruct storage s = structMapping[key];".to_string(),
                            });
                        }
                        break;
                    }
                }
            }
        }
        
        vulns
    }
    
    fn detect_array_pointer_bugs(&self) -> Vec<UninitializedStoragePointer> {
        let mut vulns = Vec::new();
        
        // Pattern: Array access (index calculation + SSTORE) without initialization
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Array access pattern: ADD (base + index) -> SSTORE
            if self.bytecode[i] == 0x01 { // ADD (for array indexing)
                for j in i+1..i+10.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x55 { // SSTORE
                        // Check if ADD operates on zero base (uninitialized)
                        let uses_zero_base = self.bytecode[i.saturating_sub(5)..i]
                            .windows(2)
                            .any(|w| w[0] == 0x60 && w[1] == 0x00);
                        
                        if uses_zero_base {
                            vulns.push(UninitializedStoragePointer {
                                vulnerability_type: "Uninitialized Array Pointer".to_string(),
                                severity: "High".to_string(),
                                location: i,
                                description: "Array element access with uninitialized base".to_string(),
                                affected_slot: "Storage slots starting from 0 + index".to_string(),
                                exploit_scenario: "Array writes overwrite beginning of storage".to_string(),
                                remediation: "Initialize array: uint[] storage arr = myArray;".to_string(),
                            });
                        }
                        break;
                    }
                }
            }
        }
        
        vulns
    }
    
    fn check_stores_to_low_slot(&self, sstore_pc: usize) -> bool {
        // Check if SSTORE writes to slot 0-10 (critical slots)
        // Look backwards for PUSH that specifies the slot
        
        for i in (sstore_pc.saturating_sub(10)..sstore_pc).rev() {
            if self.bytecode[i] >= 0x60 && self.bytecode[i] <= 0x7F { // PUSH
                let push_size = (self.bytecode[i] - 0x60 + 1) as usize;
                if i + push_size < self.bytecode.len() {
                    // Check if pushed value is small (0-10)
                    let all_zeros = self.bytecode[i+1..i+push_size]
                        .iter()
                        .all(|&b| b == 0);
                    let last_byte = self.bytecode[i+push_size.min(self.bytecode.len()-i-1)];
                    
                    if all_zeros && last_byte <= 10 {
                        return true;
                    }
                }
            }
        }
        
        false
    }
    
    fn is_in_function_body(&self, pc: usize) -> bool {
        // Check if PC is in function body (not constructor)
        // Constructor typically at beginning, functions have JUMPDEST markers
        
        let has_jumpdest_before = self.bytecode[..pc]
            .iter()
            .any(|&op| op == 0x5B);
        
        has_jumpdest_before && pc > 100 // After constructor code
    }
    
    fn has_prior_sload_from_slot(&self, sstore_pc: usize) -> bool {
        // Check if there's an SLOAD before this SSTORE in the same function
        
        let function_start = self.bytecode[..sstore_pc]
            .iter()
            .rposition(|&op| op == 0x5B)
            .unwrap_or(0);
        
        self.bytecode[function_start..sstore_pc]
            .iter()
            .any(|&op| op == 0x54) // SLOAD
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_uninitialized_storage_write() {
        // Uninitialized storage: writes to slot 0
        let bytecode = vec![
            0x5B,              // JUMPDEST (function marker)
            0x60, 0x00,        // PUSH1 0 (slot 0 - CRITICAL!)
            0x33,              // CALLER
            0x55,              // SSTORE (writes caller to slot 0)
        ];
        
        let detector = UninitializedStoragePointerDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.len() > 0);
    }
    
    #[test]
    fn test_initialized_storage_access() {
        // Safe: loads then stores
        let bytecode = vec![
            0x60, 0x00,        // PUSH1 0
            0x54,              // SLOAD (load first)
            0x60, 0x00,        // PUSH1 0
            0x55,              // SSTORE (then store - OK)
        ];
        
        let detector = UninitializedStoragePointerDetector::new(bytecode);
        let vulns = detector.detect_storage_access_without_initialization();
        
        // Should have prior SLOAD, so safe
        assert_eq!(vulns.len(), 0);
    }
}
