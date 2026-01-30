use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CurveVyperReentrancyVulnerability {
    VyperVersionVulnerable { description: String, location: usize, confidence: f32 },
    NonreentrantMalfunctionPattern { description: String, location: usize },
    RawCallWithoutLock { description: String, location: usize },
}

pub struct CurveVyperReentrancyDetector {
    bytecode: Vec<u8>,
}

impl CurveVyperReentrancyDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<CurveVyperReentrancyVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Vyper 0.2.15-0.3.0 reentrancy bug: @nonreentrant decorator malfunction
        if self.has_vyper_nonreentrant_pattern() {
            if !self.has_proper_lock_implementation() {
                vulnerabilities.push(CurveVyperReentrancyVulnerability::NonreentrantMalfunctionPattern {
                    description: "Vyper @nonreentrant pattern detected without proper lock - vulnerable to Curve-style reentrancy".to_string(),
                    location: 0,
                });
            }
        }
        
        for i in 0..self.bytecode.len().saturating_sub(80) {
            if self.has_raw_call_pattern(i, i + 80) {
                if !self.has_lock_before_call(i) {
                    vulnerabilities.push(CurveVyperReentrancyVulnerability::RawCallWithoutLock {
                        description: "External call without reentrancy lock - Vyper compiler bug pattern".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn has_vyper_nonreentrant_pattern(&self) -> bool {
        // Vyper uses specific storage slot for lock (typically slot 0 or 1)
        // Pattern: SLOAD lock, ISZERO check, SSTORE lock
        
        let mut has_lock_check = false;
        let mut lock_slot_reads = 0;
        
        for i in 0..self.bytecode.len().saturating_sub(10) {
            // SLOAD from slot 0 or 1
            if i + 3 < self.bytecode.len() {
                if self.bytecode[i] == 0x60 && // PUSH1
                   (self.bytecode[i+1] == 0x00 || self.bytecode[i+1] == 0x01) && // slot 0 or 1
                   self.bytecode[i+2] == 0x54 { // SLOAD
                    lock_slot_reads += 1;
                }
            }
            
            // ISZERO check for lock
            if self.bytecode[i] == 0x15 { // ISZERO
                has_lock_check = true;
            }
        }
        
        // Vyper pattern: multiple reads of lock slot + ISZERO
        lock_slot_reads >= 2 && has_lock_check
    }
    
    fn has_proper_lock_implementation(&self) -> bool {
        // Proper lock: SSTORE lock=1 BEFORE call, SSTORE lock=0 AFTER call
        let mut lock_sets = 0;
        
        for i in 0..self.bytecode.len().saturating_sub(5) {
            // PUSH1 1, PUSH1 0, SSTORE pattern (set lock)
            if i + 4 < self.bytecode.len() {
                if self.bytecode[i] == 0x60 && // PUSH1
                   self.bytecode[i+1] == 0x01 && // value 1
                   self.bytecode[i+2] == 0x60 && // PUSH1
                   self.bytecode[i+3] == 0x00 && // slot 0
                   self.bytecode[i+4] == 0x55 { // SSTORE
                    lock_sets += 1;
                }
            }
        }
        
        // Need both lock and unlock
        lock_sets >= 2
    }
    
    fn has_raw_call_pattern(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Vyper raw_call pattern: CALL with dynamic target
        self.bytecode[start..range_end].iter().any(|&b| b == 0xF1) // CALL
    }
    
    fn has_lock_before_call(&self, call_location: usize) -> bool {
        let start = call_location.saturating_sub(30);
        
        // Check for SSTORE (lock) before CALL
        self.bytecode[start..call_location].iter().any(|&b| b == 0x55) // SSTORE
    }
}
