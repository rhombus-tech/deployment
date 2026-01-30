use serde::{Serialize, Deserialize};

/// Vyper Lock Mechanism Bug Detection
/// 
/// Specific vulnerability in Vyper's @nonreentrant decorator implementation
/// where the lock mechanism can be bypassed through specific call patterns
/// 
/// Affected versions: 0.2.15, 0.2.16, 0.3.0
/// The lock is not properly maintained across internal function calls
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VyperLockMechanismVulnerability {
    /// Critical: Lock bypassed through internal calls
    LockBypassViaInternal {
        description: String,
        location: usize,
        confidence: f32,
    },
    /// Critical: Lock state not checked before operation
    MissingLockCheck {
        description: String,
        location: usize,
    },
    /// High: Lock cleared prematurely
    PrematureLockClear {
        description: String,
        location: usize,
    },
    /// High: Multiple entry points share same lock
    SharedLockVulnerability {
        description: String,
        location: usize,
    },
}

pub struct VyperLockMechanismDetector {
    bytecode: Vec<u8>,
}

impl VyperLockMechanismDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<VyperLockMechanismVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern 1: Detect lock variable operations
        // Vyper uses storage slot for lock (typically slot 0 or dedicated slot)
        let lock_operations = self.find_lock_operations();
        
        for lock_op in &lock_operations {
            // Check if lock is properly checked before critical operations
            let has_check_before = self.has_lock_check_before(lock_op.location);
            
            if !has_check_before && lock_op.is_critical {
                vulnerabilities.push(VyperLockMechanismVulnerability::MissingLockCheck {
                    description: format!(
                        "Critical operation at {} without prior lock check",
                        lock_op.location
                    ),
                    location: lock_op.location,
                });
            }
        }
        
        // Pattern 2: Check for internal function calls that bypass lock
        for i in 0..self.bytecode.len().saturating_sub(40) {
            // Look for JUMP/JUMPI (internal function calls)
            if self.bytecode[i] == 0x56 || self.bytecode[i] == 0x57 {
                // Check if this is within a locked section
                let in_locked_section = self.is_in_locked_section(i);
                
                if in_locked_section {
                    // Check if the jump target also checks the lock
                    let jump_target = self.find_jump_target(i);
                    
                    if let Some(target) = jump_target {
                        let target_checks_lock = self.has_lock_check_at(target);
                        
                        if !target_checks_lock {
                            vulnerabilities.push(VyperLockMechanismVulnerability::LockBypassViaInternal {
                                description: "Internal call bypasses reentrancy lock - Vyper bug pattern".to_string(),
                                location: i,
                                confidence: 0.85,
                            });
                        }
                    }
                }
            }
        }
        
        // Pattern 3: Check for premature lock clearing
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Look for SSTORE to lock variable (clearing it)
            if self.bytecode[i] == 0x55 { // SSTORE
                // Check if this is storing 0 to lock slot
                let stores_zero = self.bytecode[i.saturating_sub(5)..i]
                    .iter()
                    .any(|&b| b == 0x60 && self.bytecode.get(i.saturating_sub(4)) == Some(&0x00));
                
                if stores_zero {
                    // Check if there are external calls after this
                    let has_calls_after = self.bytecode[i..std::cmp::min(i+30, self.bytecode.len())]
                        .iter()
                        .any(|&b| b == 0xf1 || b == 0xf4); // CALL or DELEGATECALL
                    
                    if has_calls_after {
                        vulnerabilities.push(VyperLockMechanismVulnerability::PrematureLockClear {
                            description: "Lock cleared before external calls complete".to_string(),
                            location: i,
                        });
                    }
                }
            }
        }
        
        // Pattern 4: Check for shared lock across multiple functions
        let lock_slot = self.identify_lock_slot();
        
        if let Some(slot) = lock_slot {
            let functions_using_lock = self.find_functions_using_slot(slot);
            
            if functions_using_lock.len() > 1 {
                // Multiple functions using same lock - verify they all properly manage it
                for func_loc in functions_using_lock {
                    let properly_managed = self.properly_manages_lock(func_loc, slot);
                    
                    if !properly_managed {
                        vulnerabilities.push(VyperLockMechanismVulnerability::SharedLockVulnerability {
                            description: format!(
                                "Function at {} improperly manages shared lock at slot {}",
                                func_loc, slot
                            ),
                            location: func_loc,
                        });
                    }
                }
            }
        }
        
        vulnerabilities
    }
    
    fn find_lock_operations(&self) -> Vec<LockOperation> {
        let mut operations = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(10) {
            // Look for SLOAD from lock slot followed by check
            if self.bytecode[i] == 0x60 && // PUSH1
               i + 2 < self.bytecode.len() &&
               self.bytecode[i+2] == 0x54 { // SLOAD
                
                let slot = self.bytecode[i+1];
                
                // Check if this is followed by ISZERO (lock check)
                let is_lock_check = i + 3 < self.bytecode.len() && 
                                   self.bytecode[i+3] == 0x15; // ISZERO
                
                if is_lock_check {
                    // Determine if this guards a critical operation
                    let is_critical = self.guards_critical_operation(i);
                    
                    operations.push(LockOperation {
                        location: i,
                        slot,
                        is_critical,
                    });
                }
            }
        }
        
        operations
    }
    
    fn has_lock_check_before(&self, location: usize) -> bool {
        // Look backwards for lock check pattern
        let start = location.saturating_sub(30);
        self.bytecode[start..location]
            .windows(4)
            .any(|w| {
                // PUSH slot, SLOAD, ISZERO pattern
                w[0] == 0x60 && w[2] == 0x54 && w[3] == 0x15
            })
    }
    
    fn has_lock_check_at(&self, location: usize) -> bool {
        if location >= self.bytecode.len().saturating_sub(10) {
            return false;
        }
        
        self.bytecode[location..std::cmp::min(location+10, self.bytecode.len())]
            .windows(4)
            .any(|w| w[0] == 0x60 && w[2] == 0x54 && w[3] == 0x15)
    }
    
    fn is_in_locked_section(&self, location: usize) -> bool {
        // Check if location is between lock set and lock clear
        let start = location.saturating_sub(50);
        
        // Look for lock being set (SSTORE with 1)
        let lock_set = self.bytecode[start..location]
            .windows(3)
            .rposition(|w| {
                w[0] == 0x60 && w[1] == 0x01 && w[2] == 0x55 // PUSH1 1, SSTORE
            });
        
        lock_set.is_some()
    }
    
    fn find_jump_target(&self, location: usize) -> Option<usize> {
        // Look backwards for PUSH of jump destination
        let start = location.saturating_sub(10);
        
        for i in start..location {
            if self.bytecode[i] == 0x61 && i + 2 < self.bytecode.len() {
                // PUSH2 - common for jump destinations
                let target = u16::from_be_bytes([
                    self.bytecode[i+1],
                    self.bytecode[i+2],
                ]) as usize;
                
                if target < self.bytecode.len() {
                    return Some(target);
                }
            }
        }
        
        None
    }
    
    fn guards_critical_operation(&self, location: usize) -> bool {
        // Check if the lock check is followed by critical operations
        let end = std::cmp::min(location + 50, self.bytecode.len());
        
        self.bytecode[location..end].iter().any(|&b| {
            b == 0xf1 || // CALL
            b == 0xf4 || // DELEGATECALL
            b == 0x55    // SSTORE
        })
    }
    
    fn identify_lock_slot(&self) -> Option<u8> {
        // Find the most commonly used slot in lock patterns
        let mut slot_counts = std::collections::HashMap::new();
        
        for i in 0..self.bytecode.len().saturating_sub(5) {
            if self.bytecode[i] == 0x60 && 
               i + 2 < self.bytecode.len() &&
               self.bytecode[i+2] == 0x54 &&
               i + 3 < self.bytecode.len() &&
               self.bytecode[i+3] == 0x15 {
                
                let slot = self.bytecode[i+1];
                *slot_counts.entry(slot).or_insert(0) += 1;
            }
        }
        
        slot_counts.into_iter()
            .max_by_key(|(_, count)| *count)
            .map(|(slot, _)| slot)
    }
    
    fn find_functions_using_slot(&self, slot: u8) -> Vec<usize> {
        let mut locations = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(5) {
            if self.bytecode[i] == 0x60 &&
               self.bytecode[i+1] == slot &&
               i + 2 < self.bytecode.len() &&
               (self.bytecode[i+2] == 0x54 || self.bytecode[i+2] == 0x55) {
                locations.push(i);
            }
        }
        
        locations
    }
    
    fn properly_manages_lock(&self, location: usize, slot: u8) -> bool {
        // Check if function both sets and clears the lock
        let end = std::cmp::min(location + 100, self.bytecode.len());
        let section = &self.bytecode[location..end];
        
        let sets_lock = section.windows(3).any(|w| {
            w[0] == 0x60 && w[1] == 0x01 && w[2] == 0x55
        });
        
        let clears_lock = section.windows(3).any(|w| {
            w[0] == 0x60 && w[1] == 0x00 && w[2] == 0x55
        });
        
        sets_lock && clears_lock
    }
}

#[derive(Debug)]
struct LockOperation {
    location: usize,
    slot: u8,
    is_critical: bool,
}
