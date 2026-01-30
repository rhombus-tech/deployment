use serde::{Serialize, Deserialize};

/// Transient Storage Attack Detection (EIP-1153)
/// 
/// EIP-1153 introduces TSTORE/TLOAD opcodes for transaction-scoped storage.
/// New attack vectors:
/// 
/// 1. Transient storage not cleared on reentrancy
/// 2. Cross-contract transient state confusion
/// 3. Transient storage used for critical security
/// 4. Gas-optimized reentrancy attacks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransientStorageAttackVulnerability {
    /// Critical: Transient storage used for reentrancy guard
    TransientReentrancyGuard {
        description: String,
        location: usize,
        confidence: f32,
    },
    /// Critical: Transient state not isolated
    NonIsolatedTransientState {
        description: String,
        location: usize,
    },
    /// High: Transient storage in cross-contract calls
    CrossContractTransientRisk {
        description: String,
        location: usize,
    },
    /// High: Critical data in transient storage
    CriticalTransientData {
        description: String,
        location: usize,
    },
    /// Medium: Transient storage overwriting
    TransientStorageConflict {
        description: String,
        location: usize,
    },
}

pub struct TransientStorageAttackDetector {
    bytecode: Vec<u8>,
}

impl TransientStorageAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<TransientStorageAttackVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern 1: Check for TSTORE/TLOAD opcodes (EIP-1153)
        // TLOAD: 0x5c, TSTORE: 0x5d
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x5c { // TLOAD
                // Check if used for reentrancy protection
                let used_for_reentrancy = self.is_reentrancy_guard_pattern(i);
                
                if used_for_reentrancy {
                    vulnerabilities.push(TransientStorageAttackVulnerability::TransientReentrancyGuard {
                        description: "Transient storage used for reentrancy guard - vulnerable to gas optimization attacks".to_string(),
                        location: i,
                        confidence: 0.90,
                    });
                }
                
                // Check if transient data is used in critical operations
                let used_in_critical = self.used_in_critical_operation(i);
                
                if used_in_critical {
                    vulnerabilities.push(TransientStorageAttackVulnerability::CriticalTransientData {
                        description: "Transient storage value used in critical calculation - survives reentrancy".to_string(),
                        location: i,
                    });
                }
            }
            
            if self.bytecode[i] == 0x5d { // TSTORE
                // Check if TSTORE is in a function with external calls
                let has_external_calls_after = self.has_external_calls_after(i);
                
                if has_external_calls_after {
                    // Check if transient state is properly managed
                    let properly_managed = self.transient_properly_managed(i);
                    
                    if !properly_managed {
                        vulnerabilities.push(TransientStorageAttackVulnerability::NonIsolatedTransientState {
                            description: "Transient storage set before external call - can be exploited via reentrancy".to_string(),
                            location: i,
                        });
                    }
                }
            }
        }
        
        // Pattern 2: Check for transient storage in cross-contract interactions
        for i in 0..self.bytecode.len().saturating_sub(60) {
            // Look for CALL/DELEGATECALL near transient storage operations
            if self.bytecode[i] == 0xf1 || self.bytecode[i] == 0xf4 {
                // Check if transient storage is read before or after call
                let uses_transient_before = self.bytecode[i.saturating_sub(30)..i]
                    .iter()
                    .any(|&b| b == 0x5c || b == 0x5d); // TLOAD or TSTORE
                
                let uses_transient_after = self.bytecode[i..std::cmp::min(i+30, self.bytecode.len())]
                    .iter()
                    .any(|&b| b == 0x5c || b == 0x5d);
                
                if uses_transient_before || uses_transient_after {
                    vulnerabilities.push(TransientStorageAttackVulnerability::CrossContractTransientRisk {
                        description: "Transient storage used around external call - state confusion possible".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        // Pattern 3: Check for multiple TSTORE to same slot
        let transient_slots = self.find_transient_storage_slots();
        
        for (slot, locations) in &transient_slots {
            if locations.len() > 1 {
                // Multiple writes to same transient slot
                // Check if they're properly sequenced
                let properly_sequenced = self.are_tstores_sequenced(&locations);
                
                if !properly_sequenced {
                    vulnerabilities.push(TransientStorageAttackVulnerability::TransientStorageConflict {
                        description: format!(
                            "Multiple TSTORE operations to slot {} without proper sequencing",
                            slot
                        ),
                        location: locations[0],
                    });
                }
            }
        }
        
        // Pattern 4: Check for transient storage used in loops
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x5c || self.bytecode[i] == 0x5d {
                // Check if this is in a loop (JUMP back pattern)
                let in_loop = self.is_in_loop_context(i);
                
                if in_loop {
                    // Transient storage in loops can be problematic
                    let has_protection = self.has_loop_protection(i);
                    
                    if !has_protection {
                        vulnerabilities.push(TransientStorageAttackVulnerability::TransientStorageConflict {
                            description: "Transient storage operation in loop without bounds check".to_string(),
                            location: i,
                        });
                    }
                }
            }
        }
        
        // Pattern 5: Check for transient storage slot collisions
        let permanent_slots = self.find_permanent_storage_slots();
        let transient_slot_nums: Vec<u8> = transient_slots.keys().copied().collect();
        
        for t_slot in transient_slot_nums {
            if permanent_slots.contains(&t_slot) {
                // Same slot number used for both permanent and transient
                // This is actually OK (separate namespaces) but can be confusing
                vulnerabilities.push(TransientStorageAttackVulnerability::TransientStorageConflict {
                    description: format!(
                        "Slot {} used for both permanent and transient storage - potential confusion",
                        t_slot
                    ),
                    location: 0,
                });
            }
        }
        
        // Pattern 6: Check for transient storage in delegatecall context
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0xf4 { // DELEGATECALL
                // Check if delegate uses transient storage
                let delegate_uses_transient = self.bytecode[i..std::cmp::min(i+40, self.bytecode.len())]
                    .iter()
                    .any(|&b| b == 0x5c || b == 0x5d);
                
                if delegate_uses_transient {
                    vulnerabilities.push(TransientStorageAttackVulnerability::CrossContractTransientRisk {
                        description: "DELEGATECALL with transient storage - namespace confusion risk".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_reentrancy_guard_pattern(&self, location: usize) -> bool {
        let end = std::cmp::min(location + 20, self.bytecode.len());
        
        // Pattern: TLOAD, ISZERO, JUMPI (checking if locked)
        self.bytecode[location..end]
            .windows(3)
            .any(|w| {
                w[0] == 0x15 && // ISZERO
                w[1] == 0x57    // JUMPI
            })
    }
    
    fn used_in_critical_operation(&self, location: usize) -> bool {
        let end = std::cmp::min(location + 40, self.bytecode.len());
        
        // Check if TLOAD result is used in:
        // 1. Financial calculations (MUL/DIV)
        // 2. Authorization (EQ + JUMPI)
        // 3. External calls
        
        self.bytecode[location..end]
            .iter()
            .any(|&b| {
                b == 0x02 || // MUL
                b == 0x04 || // DIV
                b == 0xf1 || // CALL
                b == 0x55    // SSTORE
            })
    }
    
    fn has_external_calls_after(&self, location: usize) -> bool {
        let end = std::cmp::min(location + 50, self.bytecode.len());
        
        self.bytecode[location..end]
            .iter()
            .any(|&b| b == 0xf1 || b == 0xf4) // CALL or DELEGATECALL
    }
    
    fn transient_properly_managed(&self, location: usize) -> bool {
        let end = std::cmp::min(location + 50, self.bytecode.len());
        
        // Check if transient storage is cleared after use
        // Pattern: TSTORE with 0
        self.bytecode[location..end]
            .windows(3)
            .any(|w| {
                w[0] == 0x60 && // PUSH1
                w[1] == 0x00 && // 0
                w[2] == 0x5d    // TSTORE
            })
    }
    
    fn find_transient_storage_slots(&self) -> std::collections::HashMap<u8, Vec<usize>> {
        let mut slots = std::collections::HashMap::new();
        
        for i in 0..self.bytecode.len().saturating_sub(3) {
            // Look for: PUSH slot, TSTORE pattern
            if self.bytecode[i] == 0x60 && // PUSH1
               i + 2 < self.bytecode.len() &&
               self.bytecode[i+2] == 0x5d { // TSTORE
                
                let slot = self.bytecode[i+1];
                slots.entry(slot).or_insert_with(Vec::new).push(i);
            }
        }
        
        slots
    }
    
    fn are_tstores_sequenced(&self, locations: &[usize]) -> bool {
        if locations.len() < 2 {
            return true;
        }
        
        // Check if there are control flow guards between stores
        for i in 0..locations.len()-1 {
            let gap = locations[i+1] - locations[i];
            
            // If very close together without branching, might be conflict
            if gap < 10 {
                return false;
            }
        }
        
        true
    }
    
    fn is_in_loop_context(&self, location: usize) -> bool {
        // Look backwards for JUMPDEST and forwards for JUMP back
        let start = location.saturating_sub(50);
        let end = std::cmp::min(location + 50, self.bytecode.len());
        
        let has_jumpdest_before = self.bytecode[start..location]
            .iter()
            .any(|&b| b == 0x5b); // JUMPDEST
        
        let has_jump_after = self.bytecode[location..end]
            .iter()
            .any(|&b| b == 0x56 || b == 0x57); // JUMP or JUMPI
        
        has_jumpdest_before && has_jump_after
    }
    
    fn has_loop_protection(&self, location: usize) -> bool {
        let start = location.saturating_sub(30);
        let end = std::cmp::min(location + 30, self.bytecode.len());
        
        // Look for iteration counter or bounds check
        self.bytecode[start..end]
            .windows(3)
            .any(|w| {
                (w[0] == 0x10 || w[0] == 0x11) && // LT or GT
                w[1] == 0x15 && // ISZERO
                w[2] == 0x57    // JUMPI
            })
    }
    
    fn find_permanent_storage_slots(&self) -> Vec<u8> {
        let mut slots = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(3) {
            // Look for: PUSH slot, SSTORE pattern
            if self.bytecode[i] == 0x60 && // PUSH1
               i + 2 < self.bytecode.len() &&
               self.bytecode[i+2] == 0x55 { // SSTORE
                
                let slot = self.bytecode[i+1];
                if !slots.contains(&slot) {
                    slots.push(slot);
                }
            }
        }
        
        slots
    }
}
