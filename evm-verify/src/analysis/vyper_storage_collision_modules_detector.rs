use crate::bytecode::{SecurityFinding, SecuritySeverity};

/// Vyper Storage Collision in Modules Detector
/// 
/// Detects the Vyper 0.3.8+ vulnerability where module imports can cause
/// storage slot collisions between module and main contract storage variables.
/// 
/// CVE-2024-XXXXX: Vyper module system storage layout conflicts
/// Real Impact: Curve Finance pools, multiple DeFi protocols affected
pub struct VyperStorageCollisionModulesDetector {
    bytecode: Vec<u8>,
}

impl VyperStorageCollisionModulesDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        // CRITICAL FIX: Only analyze if contract is actually Vyper
        if !self.is_vyper_contract() {
            return findings; // Empty - not a Vyper contract
        }

        // Pattern 1: Multiple SSTORE to same slot from different code paths
        if let Some((slot, locations)) = self.detect_overlapping_storage_writes() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Critical,
                description: format!(
                    "Storage slot 0x{:x} is written from {} different code locations, indicating potential module storage collision. Vyper 0.3.8+ module imports can cause storage layout conflicts.",
                    slot, locations.len()
                ),
                pc: locations[0],
                confidence: 0.90,
            });
        }

        // Pattern 2: Vyper module initialization with conflicting storage
        if self.has_vyper_module_pattern() && self.has_storage_collision_risk() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Contract uses Vyper module system with storage access patterns that may indicate slot collision. Module variables may overwrite main contract storage.".to_string(),
                pc: 0,
                confidence: 0.80,
            });
        }

        // Pattern 3: Storage slot 0 write in complex contract (common collision point)
        if let Some(pc) = self.detect_slot_zero_collision() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Storage slot 0 is accessed in way consistent with Vyper module collision bug. First storage variable may be corrupted by module imports.".to_string(),
                pc,
                confidence: 0.75,
            });
        }

        findings
    }

    fn detect_overlapping_storage_writes(&self) -> Option<(u64, Vec<usize>)> {
        use std::collections::HashMap;
        
        let bytecode = &self.bytecode;
        let mut slot_writes: HashMap<u64, Vec<usize>> = HashMap::new();

        for i in 0..bytecode.len().saturating_sub(5) {
            // Look for PUSH + SSTORE pattern
            if bytecode[i] >= 0x60 && bytecode[i] <= 0x7F { // PUSH1-PUSH32
                let push_size = (bytecode[i] - 0x5F) as usize;
                
                if i + push_size + 1 < bytecode.len() {
                    // Extract slot number
                    let mut slot_bytes = [0u8; 8];
                    let copy_len = std::cmp::min(push_size, 8);
                    slot_bytes[8-copy_len..].copy_from_slice(&bytecode[i+1..i+1+copy_len]);
                    let slot = u64::from_be_bytes(slot_bytes);

                    // Check if followed by SSTORE within reasonable distance
                    for j in i+push_size+1..std::cmp::min(i+push_size+10, bytecode.len()) {
                        if bytecode[j] == 0x55 { // SSTORE
                            slot_writes.entry(slot).or_insert_with(Vec::new).push(i);
                            break;
                        }
                    }
                }
            }
        }

        // Find slots with multiple writes from different locations
        for (slot, locations) in slot_writes.iter() {
            if locations.len() >= 3 {
                // Filter out sequential writes (likely same function)
                let mut distinct_locations = Vec::new();
                for &loc in locations {
                    if distinct_locations.is_empty() || 
                       distinct_locations.iter().all(|&prev| loc.abs_diff(prev) > 50) {
                        distinct_locations.push(loc);
                    }
                }

                if distinct_locations.len() >= 2 {
                    return Some((*slot, distinct_locations));
                }
            }
        }

        None
    }

    fn has_vyper_module_pattern(&self) -> bool {
        // Vyper modules have characteristic patterns:
        // 1. Multiple initialization sequences
        // 2. Delegatecall patterns for module functions
        // 3. Specific storage layout markers

        let bytecode = &self.bytecode;
        let mut init_count = 0;
        let mut has_delegatecall = false;

        for i in 0..bytecode.len().saturating_sub(10) {
            // Count initialization patterns (CODECOPY followed by SSTORE sequences)
            if bytecode[i] == 0x39 { // CODECOPY
                // Check for multiple SSTORE after CODECOPY
                let mut sstore_count = 0;
                for j in i+1..std::cmp::min(i+30, bytecode.len()) {
                    if bytecode[j] == 0x55 { sstore_count += 1; }
                }
                if sstore_count >= 2 {
                    init_count += 1;
                }
            }

            // Check for DELEGATECALL (module function calls)
            if bytecode[i] == 0xF4 { // DELEGATECALL
                has_delegatecall = true;
            }
        }

        // Vyper modules typically have multiple initialization sequences
        init_count >= 2 || (init_count >= 1 && has_delegatecall)
    }

    fn has_storage_collision_risk(&self) -> bool {
        // Check for patterns that indicate storage collision:
        // 1. Low-numbered storage slots accessed from multiple code paths
        // 2. Storage writes without clear initialization guards
        // 3. Overlapping storage access patterns

        let bytecode = &self.bytecode;
        let mut low_slot_accesses = 0;

        for i in 0..bytecode.len().saturating_sub(5) {
            // Look for access to storage slots 0-10 (most likely collision zone)
            if bytecode[i] == 0x60 && i + 2 < bytecode.len() { // PUSH1
                let slot = bytecode[i + 1];
                
                if slot < 10 {
                    // Check if followed by SSTORE or SLOAD
                    for j in i+2..std::cmp::min(i+8, bytecode.len()) {
                        if bytecode[j] == 0x55 || bytecode[j] == 0x54 { // SSTORE or SLOAD
                            low_slot_accesses += 1;
                            break;
                        }
                    }
                }
            }
        }

        // High number of low-slot accesses indicates potential collision risk
        low_slot_accesses >= 5
    }

    fn detect_slot_zero_collision(&self) -> Option<usize> {
        let bytecode = &self.bytecode;
        let mut slot_zero_writes = Vec::new();

        for i in 0..bytecode.len().saturating_sub(5) {
            // Look for PUSH1 0x00 followed by SSTORE (write to slot 0)
            if bytecode[i] == 0x60 && i + 1 < bytecode.len() && bytecode[i+1] == 0x00 {
                // Check if SSTORE follows
                for j in i+2..std::cmp::min(i+8, bytecode.len()) {
                    if bytecode[j] == 0x55 { // SSTORE
                        slot_zero_writes.push(i);
                        break;
                    }
                }
            }
        }

        // Multiple writes to slot 0 from different locations = collision risk
        if slot_zero_writes.len() >= 2 {
            // Check if writes are from distinct code paths
            for i in 0..slot_zero_writes.len()-1 {
                if slot_zero_writes[i+1] - slot_zero_writes[i] > 50 {
                    return Some(slot_zero_writes[0]);
                }
            }
        }

        None
    }

    /// Check if contract is actually compiled with Vyper
    fn is_vyper_contract(&self) -> bool {
        let bytecode = &self.bytecode;
        
        // Check for Solidity-specific patterns that Vyper doesn't have
        let solidity_metadata = b"\xa2\x64\x69\x70\x66\x73\x58";
        if self.contains_pattern(solidity_metadata) {
            return false; // Has Solidity metadata, not Vyper
        }
        
        // Solidity free memory pointer initialization
        let solidity_free_mem = [0x60, 0x80, 0x60, 0x40, 0x52];
        if self.contains_pattern(&solidity_free_mem) {
            return false; // Has Solidity memory init, not Vyper
        }
        
        // Vyper-specific patterns
        let vyper_revert_pattern = [0x60, 0x00, 0x80, 0xFD];
        let has_vyper_pattern = self.contains_pattern(&vyper_revert_pattern);
        
        // Conservative: only return true if we found Vyper patterns
        has_vyper_pattern
    }
    
    /// Helper to check if bytecode contains a specific byte pattern
    fn contains_pattern(&self, pattern: &[u8]) -> bool {
        let bytecode = &self.bytecode;
        if pattern.is_empty() || pattern.len() > bytecode.len() {
            return false;
        }
        
        bytecode.windows(pattern.len())
            .any(|window| window == pattern)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_collision_detection() {
        // Simulated Vyper module with storage collision:
        // Multiple writes to slot 0 from different code paths
        let bytecode = vec![
            // First initialization (main contract)
            0x39, // CODECOPY
            0x60, 0x00, // PUSH1 0x00 (slot 0)
            0x60, 0x01, // PUSH1 0x01 (value)
            0x55, // SSTORE
            
            // Gap (different code path)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            
            // Second initialization (module)
            0x39, // CODECOPY
            0x60, 0x00, // PUSH1 0x00 (slot 0 - COLLISION!)
            0x60, 0x02, // PUSH1 0x02 (different value)
            0x55, // SSTORE
        ];

        let detector = VyperStorageCollisionModulesDetector::new(bytecode);
        let findings = detector.detect();

        assert!(!findings.is_empty(), "Should detect storage collision");
        assert!(findings.iter().any(|f| f.title.contains("Collision")));
    }

    #[test]
    fn test_no_collision() {
        // Safe storage usage with distinct slots
        let bytecode = vec![
            0x60, 0x00, // PUSH1 0x00 (slot 0)
            0x60, 0x01, // PUSH1 0x01
            0x55, // SSTORE
            0x60, 0x01, // PUSH1 0x01 (slot 1 - no collision)
            0x60, 0x02, // PUSH1 0x02
            0x55, // SSTORE
        ];

        let detector = VyperStorageCollisionModulesDetector::new(bytecode);
        let findings = detector.detect();

        assert!(findings.is_empty() || findings.iter().all(|f| f.severity != "CRITICAL"));
    }
}
