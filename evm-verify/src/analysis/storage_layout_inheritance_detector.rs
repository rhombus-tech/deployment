/// Storage Layout Inheritance Detector
/// Detects storage layout issues in contract inheritance and upgrades

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageLayoutIssue {
    pub vulnerability_type: String,
    pub severity: String,
    pub location: usize,
    pub description: String,
    pub remediation: String,
}

pub struct StorageLayoutInheritanceDetector {
    bytecode: Vec<u8>,
}

impl StorageLayoutInheritanceDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect(&self) -> Vec<StorageLayoutIssue> {
        let mut vulns = Vec::new();
        
        vulns.extend(self.detect_storage_collision());
        vulns.extend(self.detect_gap_missing());
        vulns.extend(self.detect_unordered_storage());
        
        vulns
    }
    
    fn detect_storage_collision(&self) -> Vec<StorageLayoutIssue> {
        let mut vulns = Vec::new();
        let mut slot_writes: std::collections::HashMap<u8, usize> = std::collections::HashMap::new();
        
        // Track all storage slots written
        for i in 0..self.bytecode.len().saturating_sub(5) {
            if self.bytecode[i] == 0x55 { // SSTORE
                if let Some(slot) = self.get_slot_at(i) {
                    *slot_writes.entry(slot).or_insert(0) += 1;
                }
            }
        }
        
        // Check for same slot written multiple times (potential collision)
        for (slot, count) in slot_writes {
            if count > 3 && slot < 50 {
                vulns.push(StorageLayoutIssue {
                    vulnerability_type: "Storage Slot Collision Risk".to_string(),
                    severity: "High".to_string(),
                    location: 0,
                    description: format!("Slot {} written {} times - possible layout collision", slot, count),
                    remediation: "Use storage gaps in upgradeable contracts: uint256[50] private __gap;".to_string(),
                });
            }
        }
        vulns
    }
    
    fn detect_gap_missing(&self) -> Vec<StorageLayoutIssue> {
        let mut vulns = Vec::new();
        
        // Check if contract writes to sequential low slots (missing gaps)
        let mut sequential_slots = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(5) {
            if self.bytecode[i] == 0x55 {
                if let Some(slot) = self.get_slot_at(i) {
                    if slot < 20 {
                        sequential_slots.push(slot);
                    }
                }
            }
        }
        
        sequential_slots.sort();
        sequential_slots.dedup();
        
        // Check for consecutive slots (no gaps)
        for i in 0..sequential_slots.len().saturating_sub(2) {
            if sequential_slots[i+1] == sequential_slots[i] + 1 &&
               sequential_slots[i+2] == sequential_slots[i] + 2 {
                vulns.push(StorageLayoutIssue {
                    vulnerability_type: "Missing Storage Gaps".to_string(),
                    severity: "Medium".to_string(),
                    location: 0,
                    description: "No storage gaps detected - risky for upgradeable contracts".to_string(),
                    remediation: "Add storage gap at end: uint256[50] private __gap;".to_string(),
                });
                break;
            }
        }
        vulns
    }
    
    fn detect_unordered_storage(&self) -> Vec<StorageLayoutIssue> {
        let mut vulns = Vec::new();
        
        // Check if storage access is not in ascending order (bad practice)
        let mut prev_slot: Option<u8> = None;
        let mut out_of_order_count = 0;
        
        for i in 0..self.bytecode.len().saturating_sub(5) {
            if matches!(self.bytecode[i], 0x54 | 0x55) {
                if let Some(slot) = self.get_slot_at(i) {
                    if let Some(prev) = prev_slot {
                        if slot < prev {
                            out_of_order_count += 1;
                        }
                    }
                    prev_slot = Some(slot);
                }
            }
        }
        
        if out_of_order_count > 5 {
            vulns.push(StorageLayoutIssue {
                vulnerability_type: "Unordered Storage Access".to_string(),
                severity: "Low".to_string(),
                location: 0,
                description: "Storage accessed in non-sequential order - review layout".to_string(),
                remediation: "Organize state variables logically and consistently".to_string(),
            });
        }
        vulns
    }
    
    fn get_slot_at(&self, pc: usize) -> Option<u8> {
        for i in (pc.saturating_sub(10)..pc).rev() {
            if self.bytecode[i] == 0x60 && i+1 < self.bytecode.len() {
                return Some(self.bytecode[i+1]);
            }
        }
        None
    }
}
