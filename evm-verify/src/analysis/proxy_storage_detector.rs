// Proxy Storage Collision Detector
// Detects storage layout conflicts in proxy upgrade patterns

use crate::bytecode::SecuritySeverity;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyStorageVulnerability {
    pub vulnerability_type: ProxyStorageIssue,
    pub severity: SecuritySeverity,
    pub description: String,
    pub affected_slots: Vec<u8>,
    pub collision_details: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProxyStorageIssue {
    StorageCollision,           // V1 and V2 use same slot for different types
    UninitializedImplementation, // Implementation not initialized
    DelegateCallToUntrusted,    // Delegatecall to user-controlled address
    ConstructorInImplementation, // Constructor in implementation (won't run)
    SelectiveStorageWipe,       // Upgrade wipes critical storage
    StorageGapsMissing,         // No storage gaps for future upgrades
}

pub struct ProxyStorageDetector {
    bytecode: Vec<u8>,
    storage_layout: HashMap<u8, SlotInfo>,
}

#[derive(Debug, Clone)]
struct SlotInfo {
    slot: u8,
    access_type: AccessType,
    size_bytes: usize,
}

#[derive(Debug, Clone)]
enum AccessType {
    Read,
    Write,
    Both,
}

impl ProxyStorageDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self {
            bytecode,
            storage_layout: HashMap::new(),
        }
    }

    pub fn analyze(&mut self) -> Vec<ProxyStorageVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Map storage layout first
        self.map_storage_usage();

        // Check for different proxy vulnerabilities
        vulnerabilities.extend(self.detect_delegatecall_to_untrusted());
        vulnerabilities.extend(self.detect_uninitialized_implementation());
        vulnerabilities.extend(self.detect_constructor_in_implementation());
        vulnerabilities.extend(self.detect_missing_storage_gaps());

        vulnerabilities
    }

    fn map_storage_usage(&mut self) {
        // Scan bytecode for SLOAD and SSTORE to map storage layout
        for i in 0..self.bytecode.len().saturating_sub(3) {
            if self.bytecode[i] == 0x54 {  // SLOAD
                if i > 0 && self.bytecode[i-1] == 0x60 {  // PUSH1 before
                    let slot = self.bytecode[i];
                    self.storage_layout.entry(slot)
                        .and_modify(|info| {
                            info.access_type = match info.access_type {
                                AccessType::Write => AccessType::Both,
                                _ => AccessType::Read,
                            };
                        })
                        .or_insert(SlotInfo {
                            slot,
                            access_type: AccessType::Read,
                            size_bytes: 32,
                        });
                }
            }
            
            if self.bytecode[i] == 0x55 {  // SSTORE
                if i > 0 && self.bytecode[i-1] == 0x60 {
                    let slot = self.bytecode[i];
                    self.storage_layout.entry(slot)
                        .and_modify(|info| {
                            info.access_type = match info.access_type {
                                AccessType::Read => AccessType::Both,
                                _ => AccessType::Write,
                            };
                        })
                        .or_insert(SlotInfo {
                            slot,
                            access_type: AccessType::Write,
                            size_bytes: 32,
                        });
                }
            }
        }
    }

    fn detect_delegatecall_to_untrusted(&self) -> Vec<ProxyStorageVulnerability> {
        let mut vulns = Vec::new();

        // Pattern: DELEGATECALL where target comes from storage (user-controlled)
        for i in 0..self.bytecode.len().saturating_sub(15) {
            if self.bytecode[i] == 0xF4 {  // DELEGATECALL
                // Check if address is loaded from storage (not hardcoded)
                if self.has_sload_before(i, 10) && !self.has_access_control_before(i, 20) {
                    vulns.push(ProxyStorageVulnerability {
                        vulnerability_type: ProxyStorageIssue::DelegateCallToUntrusted,
                        severity: SecuritySeverity::Critical,
                        description: "DELEGATECALL to address from storage without access control - attacker can set implementation to malicious contract".to_string(),
                        affected_slots: vec![0],
                        collision_details: "Implementation address is user-controllable".to_string(),
                        remediation: "Add onlyOwner modifier to setImplementation() function".to_string(),
                    });
                }
            }
        }

        vulns
    }

    fn detect_uninitialized_implementation(&self) -> Vec<ProxyStorageVulnerability> {
        let mut vulns = Vec::new();

        // Pattern: Proxy with DELEGATECALL but no initialize() call
        if self.is_proxy_pattern() && !self.has_initialize_function() {
            vulns.push(ProxyStorageVulnerability {
                vulnerability_type: ProxyStorageIssue::UninitializedImplementation,
                severity: SecuritySeverity::High,
                description: "Proxy implementation not initialized - attacker can initialize with malicious parameters".to_string(),
                affected_slots: vec![0, 1, 2],
                collision_details: "Critical storage slots (owner, etc.) not set on deployment".to_string(),
                remediation: "Call initialize() in constructor or use initializer modifier".to_string(),
            });
        }

        vulns
    }

    fn detect_constructor_in_implementation(&self) -> Vec<ProxyStorageVulnerability> {
        let mut vulns = Vec::new();

        // Pattern: Constructor code in implementation (won't execute via proxy)
        if self.has_constructor_code() && self.is_likely_implementation() {
            vulns.push(ProxyStorageVulnerability {
                vulnerability_type: ProxyStorageIssue::ConstructorInImplementation,
                severity: SecuritySeverity::High,
                description: "Implementation has constructor - will NOT run when called via proxy".to_string(),
                affected_slots: vec![],
                collision_details: "Constructor sets critical state that won't be set in proxy context".to_string(),
                remediation: "Replace constructor with initialize() function using initializer modifier".to_string(),
            });
        }

        vulns
    }

    fn detect_missing_storage_gaps(&self) -> Vec<ProxyStorageVulnerability> {
        let mut vulns = Vec::new();

        // Pattern: Upgradeable contract without storage gaps
        if self.is_upgradeable_pattern() && !self.has_storage_gaps() {
            vulns.push(ProxyStorageVulnerability {
                vulnerability_type: ProxyStorageIssue::StorageGapsMissing,
                severity: SecuritySeverity::Medium,
                description: "No storage gaps - future upgrades will cause storage collisions".to_string(),
                affected_slots: vec![],
                collision_details: "Adding variables in V2 will shift all storage slots".to_string(),
                remediation: "Add __gap[50] array at end of contract for future variables".to_string(),
            });
        }

        vulns
    }

    // === HELPER METHODS ===

    fn has_sload_before(&self, offset: usize, range: usize) -> bool {
        let start = offset.saturating_sub(range);
        for i in start..offset {
            if i < self.bytecode.len() && self.bytecode[i] == 0x54 {
                return true;
            }
        }
        false
    }

    fn has_access_control_before(&self, offset: usize, range: usize) -> bool {
        let start = offset.saturating_sub(range);
        for i in start..offset {
            if i < self.bytecode.len() && self.bytecode[i] == 0x33 {  // CALLER
                return true;
            }
        }
        false
    }

    fn is_proxy_pattern(&self) -> bool {
        // Check for DELEGATECALL opcode (proxy indicator)
        self.bytecode.contains(&0xF4)
    }

    fn has_initialize_function(&self) -> bool {
        // Check for initialize() function selector: 0x8129fc1c
        let init_selector = &[0x81, 0x29, 0xfc, 0x1c];
        self.bytecode.windows(4).any(|w| w == init_selector)
    }

    fn has_constructor_code(&self) -> bool {
        // Constructor sets storage in deployment bytecode
        // Look for SSTORE in first 200 bytes (typical constructor location)
        self.bytecode.iter().take(200).any(|&b| b == 0x55)
    }

    fn is_likely_implementation(&self) -> bool {
        // Implementation contracts often have many functions
        // Count function selectors (PUSH4 followed by EQ)
        let mut selector_count = 0;
        for i in 0..self.bytecode.len().saturating_sub(6) {
            if self.bytecode[i] == 0x63 && self.bytecode[i+5] == 0x14 {
                selector_count += 1;
            }
        }
        selector_count > 5  // More than 5 functions suggests implementation
    }

    fn is_upgradeable_pattern(&self) -> bool {
        // Check for upgradeTo() function selector: 0x3659cfe6
        let upgrade_selector = &[0x36, 0x59, 0xcf, 0xe6];
        self.bytecode.windows(4).any(|w| w == upgrade_selector)
    }

    fn has_storage_gaps(&self) -> bool {
        // Storage gaps are typically large arrays (50 slots)
        // Look for pattern: repeated SSTORE to sequential slots
        let mut sequential_stores = 0;
        let mut last_slot = 0u8;
        
        for i in 0..self.bytecode.len().saturating_sub(5) {
            if self.bytecode[i] == 0x55 {  // SSTORE
                if i > 1 && self.bytecode[i-2] == 0x60 {
                    let slot = self.bytecode[i-1];
                    if slot == last_slot.wrapping_add(1) {
                        sequential_stores += 1;
                    }
                    last_slot = slot;
                }
            }
        }
        
        sequential_stores > 10  // If 10+ sequential stores, likely has gaps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_delegatecall_to_untrusted() {
        // Bytecode with SLOAD then DELEGATECALL (no access control)
        let bytecode = vec![
            0x60, 0x00,  // PUSH1 0
            0x54,        // SLOAD (load implementation address)
            0x60, 0x00,  // PUSH1 0
            0x60, 0x00,  // PUSH1 0
            0xF4,        // DELEGATECALL (no CALLER check before)
        ];
        
        let mut detector = ProxyStorageDetector::new(bytecode);
        let vulns = detector.detect_delegatecall_to_untrusted();
        
        assert!(vulns.len() > 0, "Should detect untrusted delegatecall");
    }

    #[test]
    fn test_detect_uninitialized_implementation() {
        // Proxy pattern (DELEGATECALL) but no initialize()
        let bytecode = vec![
            0xF4,  // DELEGATECALL (proxy)
            // No 0x8129fc1c (initialize selector)
        ];
        
        let mut detector = ProxyStorageDetector::new(bytecode);
        let vulns = detector.detect_uninitialized_implementation();
        
        assert!(vulns.len() > 0, "Should detect uninitialized implementation");
    }
}
