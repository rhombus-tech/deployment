use serde::{Deserialize, Serialize};

/// ZK Circuit Under-Constrained Detector
/// 
/// Detects potential under-constrained circuits in ZK proof verification.
/// Critical for ZK-Rollups, privacy protocols.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ZkCircuitUnderconstrainedVulnerability {
    MissingRangeCheck { description: String, location: usize },
    UnconstrainedPublicInput { description: String, location: usize },
    MissingNullifierCheck { description: String, location: usize },
    WeakCommitmentScheme { description: String, location: usize },
}

pub struct ZkCircuitUnderconstrainedDetector {
    bytecode: Vec<u8>,
}

impl ZkCircuitUnderconstrainedDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ZkCircuitUnderconstrainedVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.is_zk_verification(i) {
                if !self.has_range_checks(i, i + 100) {
                    vulnerabilities.push(ZkCircuitUnderconstrainedVulnerability::MissingRangeCheck {
                        description: "ZK proof verification without range checks on public inputs".to_string(),
                        location: i,
                    });
                }
                
                if !self.validates_public_inputs(i, i + 100) {
                    vulnerabilities.push(ZkCircuitUnderconstrainedVulnerability::UnconstrainedPublicInput {
                        description: "Public inputs not properly constrained in verification".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        if self.has_nullifier_system() && !self.checks_nullifier_uniqueness() {
            vulnerabilities.push(ZkCircuitUnderconstrainedVulnerability::MissingNullifierCheck {
                description: "Nullifier system without uniqueness enforcement - double-spend risk".to_string(),
                location: 0,
            });
        }
        
        vulnerabilities
    }
    
    fn is_zk_verification(&self, location: usize) -> bool {
        if location + 30 > self.bytecode.len() {
            return false;
        }
        
        // Check for pairing precompile calls (0x08) - used in Groth16/PLONK
        self.bytecode[location..location + 30]
            .windows(2)
            .any(|w| w[0] == 0x60 && w[1] == 0x08)
    }
    
    fn has_range_checks(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Range checks use LT/GT comparisons
        self.bytecode[start..range_end]
            .iter()
            .any(|&b| b == 0x10 || b == 0x11)
    }
    
    fn validates_public_inputs(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Public input validation requires comparison and revert
        let has_comparison = self.bytecode[start..range_end]
            .iter()
            .any(|&b| b == 0x14); // EQ
        
        let has_revert = self.bytecode[start..range_end]
            .iter()
            .any(|&b| b == 0xFD);
        
        has_comparison && has_revert
    }
    
    fn has_nullifier_system(&self) -> bool {
        // Nullifiers are typically stored in mappings
        self.bytecode.windows(4).any(|w| {
            w.iter().filter(|&&b| b == 0x55).count() > 0 // SSTORE
        })
    }
    
    fn checks_nullifier_uniqueness(&self) -> bool {
        // Must SLOAD nullifier and check if already used
        let has_sload = self.bytecode.iter().any(|&b| b == 0x54);
        let has_check = self.bytecode.iter().any(|&b| b == 0x15); // ISZERO
        
        has_sload && has_check
    }
}
