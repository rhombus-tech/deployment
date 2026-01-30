/// Shadowed State Variable Detector
/// 
/// Detects state variable shadowing in contract inheritance:
/// - Child contract variable shadows parent variable
/// - Can cause confusion about which variable is being modified
/// - Storage layout issues in upgradeable contracts
///
/// Example:
/// contract Parent { uint public value; }
/// contract Child is Parent { uint public value; } // SHADOWS parent.value!

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowedVariable {
    pub vulnerability_type: String,
    pub severity: String,
    pub location: usize,
    pub description: String,
    pub variable_name: String,
    pub exploit_scenario: String,
    pub remediation: String,
}

pub struct ShadowedStateVariableDetector {
    bytecode: Vec<u8>,
}

impl ShadowedStateVariableDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect(&self) -> Vec<ShadowedVariable> {
        let mut vulnerabilities = Vec::new();
        
        // Detect shadowing via storage layout analysis
        vulnerabilities.extend(self.detect_duplicate_slot_access());
        vulnerabilities.extend(self.detect_ambiguous_storage_writes());
        
        vulnerabilities
    }
    
    fn detect_duplicate_slot_access(&self) -> Vec<ShadowedVariable> {
        let mut vulns = Vec::new();
        
        // Pattern: Multiple different code paths accessing the same storage slot
        // This can indicate shadowing where child and parent both access same slot
        
        let mut slot_accesses: std::collections::HashMap<u8, Vec<usize>> = std::collections::HashMap::new();
        
        // Find all storage slot accesses
        for i in 0..self.bytecode.len().saturating_sub(5) {
            if self.bytecode[i] == 0x54 || self.bytecode[i] == 0x55 { // SLOAD or SSTORE
                // Look for preceding PUSH that specifies slot
                for j in (i.saturating_sub(10)..i).rev() {
                    if self.bytecode[j] == 0x60 && j+1 < self.bytecode.len() { // PUSH1
                        let slot = self.bytecode[j+1];
                        slot_accesses.entry(slot).or_insert_with(Vec::new).push(i);
                        break;
                    }
                }
            }
        }
        
        // Check for slots accessed from multiple functions
        for (slot, access_points) in slot_accesses {
            if access_points.len() >= 3 { // Multiple accesses
                // Check if accesses are from different functions
                if self.are_in_different_functions(&access_points) {
                    vulns.push(ShadowedVariable {
                        vulnerability_type: "Potential Variable Shadowing".to_string(),
                        severity: "Medium".to_string(),
                        location: access_points[0],
                        description: format!("Storage slot {} accessed from multiple functions - possible shadowing", slot),
                        variable_name: format!("storage[{}]", slot),
                        exploit_scenario: 
                            "Shadowed variable causes confusion:\n\
                             1. Parent sets value to 100\n\
                             2. Child thinks it's setting its own value to 200\n\
                             3. Both modify same storage slot\n\
                             4. Unexpected behavior and bugs".to_string(),
                        remediation: "Rename variables to avoid shadowing, use different storage slots".to_string(),
                    });
                }
            }
        }
        
        vulns
    }
    
    fn detect_ambiguous_storage_writes(&self) -> Vec<ShadowedVariable> {
        let mut vulns = Vec::new();
        
        // Pattern: Same slot written in different contexts with different meanings
        // Indicates possible shadowing
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x55 { // SSTORE
                // Check if this looks like a state variable write
                if self.is_state_variable_write(i) {
                    // Check if there's another write to same slot elsewhere
                    if self.has_duplicate_writes_to_same_slot(i) {
                        vulns.push(ShadowedVariable {
                            vulnerability_type: "Ambiguous Storage Write".to_string(),
                            severity: "Low".to_string(),
                            location: i,
                            description: "Multiple writes to same storage slot in different contexts".to_string(),
                            variable_name: "Unknown".to_string(),
                            exploit_scenario: "Variable shadowing can cause parent and child to unknowingly share state".to_string(),
                            remediation: "Review inheritance hierarchy for shadowed variables".to_string(),
                        });
                    }
                }
            }
        }
        
        vulns
    }
    
    fn are_in_different_functions(&self, pcs: &[usize]) -> bool {
        // Check if PCs are in different functions (separated by JUMPDEST)
        if pcs.len() < 2 {
            return false;
        }
        
        for i in 0..pcs.len()-1 {
            let pc1 = pcs[i];
            let pc2 = pcs[i+1];
            
            // Check if there's a JUMPDEST between them
            if self.bytecode[pc1..pc2].iter().any(|&op| op == 0x5B) {
                return true;
            }
        }
        
        false
    }
    
    fn is_state_variable_write(&self, sstore_pc: usize) -> bool {
        // State variable writes typically:
        // - Use constant slot (PUSH1 X)
        // - Not in constructor (after some code)
        
        sstore_pc > 100 && // Not in constructor
        self.bytecode[sstore_pc.saturating_sub(5)..sstore_pc]
            .iter()
            .any(|&op| op == 0x60) // Has PUSH1 (constant slot)
    }
    
    fn has_duplicate_writes_to_same_slot(&self, sstore_pc: usize) -> bool {
        // Find the slot being written
        let slot = self.get_storage_slot_at(sstore_pc);
        
        if let Some(slot_value) = slot {
            // Look for other SSTORE to same slot
            for i in 0..self.bytecode.len() {
                if i != sstore_pc && self.bytecode[i] == 0x55 {
                    if let Some(other_slot) = self.get_storage_slot_at(i) {
                        if other_slot == slot_value && self.are_in_different_contexts(sstore_pc, i) {
                            return true;
                        }
                    }
                }
            }
        }
        
        false
    }
    
    fn get_storage_slot_at(&self, sstore_pc: usize) -> Option<u8> {
        // Get the storage slot being accessed at this SSTORE
        for i in (sstore_pc.saturating_sub(10)..sstore_pc).rev() {
            if self.bytecode[i] == 0x60 && i+1 < self.bytecode.len() { // PUSH1
                return Some(self.bytecode[i+1]);
            }
        }
        None
    }
    
    fn are_in_different_contexts(&self, pc1: usize, pc2: usize) -> bool {
        // Check if two PCs are in different function contexts
        let min_pc = pc1.min(pc2);
        let max_pc = pc1.max(pc2);
        
        // Different if separated by JUMPDEST (function boundary)
        self.bytecode[min_pc..max_pc]
            .iter()
            .filter(|&&op| op == 0x5B)
            .count() >= 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_shadowing_detection() {
        // Two functions accessing same slot
        let bytecode = vec![
            0x5B,              // JUMPDEST (function 1)
            0x60, 0x00,        // PUSH1 0 (slot 0)
            0x55,              // SSTORE
            0x5B,              // JUMPDEST (function 2)  
            0x60, 0x00,        // PUSH1 0 (same slot!)
            0x55,              // SSTORE (shadowing!)
        ];
        
        let detector = ShadowedStateVariableDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.len() > 0);
    }
}
