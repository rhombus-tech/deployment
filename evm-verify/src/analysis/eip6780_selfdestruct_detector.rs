/// EIP-6780 SELFDESTRUCT Changes Detector
/// Detects contracts assuming old SELFDESTRUCT behavior
/// Critical for: EIP-6780 (already deployed, breaking change)

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EIP6780VulnerabilityType {
    pub vulnerability_type: EIP6780IssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EIP6780IssueType {
    OldSelfdestructAssumption,     // Assumes old SELFDESTRUCT behavior
    MetamorphicStrategyBroken,     // Metamorphic contracts broken
    UnsafeUpgradePattern,          // Upgrade pattern now unsafe
    CleanupLogicFailure,           // Cleanup logic won't work
    StorageRentAssumption,         // Storage rent assumptions invalid
}

pub struct EIP6780SelfdestructDetector {
    bytecode: Vec<u8>,
}

impl EIP6780SelfdestructDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<EIP6780VulnerabilityType> {
        let mut vulnerabilities = Vec::new();

        if !self.uses_selfdestruct() {
            return vulnerabilities;
        }

        vulnerabilities.extend(self.detect_cross_tx_assumptions());
        vulnerabilities.extend(self.detect_metamorphic_patterns());

        vulnerabilities
    }

    fn detect_cross_tx_assumptions(&self) -> Vec<EIP6780VulnerabilityType> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.has_selfdestruct(i) && !self.is_same_transaction(i) {
                vulnerabilities.push(EIP6780VulnerabilityType {
                    vulnerability_type: EIP6780IssueType::OldSelfdestructAssumption,
                    severity: SecuritySeverity::High,
                    confidence: 0.80,
                    description: "SELFDESTRUCT used assuming pre-EIP-6780 behavior".to_string(),
                    exploit_scenario: format!(
                        "Exploit at position {}:\n\
                        1. Contract uses SELFDESTRUCT for cleanup\n\
                        2. Assumes funds sent + code removed\n\
                        3. Post-EIP-6780: only works in same transaction\n\
                        4. Storage and code persist across transactions\n\n\
                        Fix: Don't rely on SELFDESTRUCT for cross-tx cleanup",
                        i
                    ),
                    location: i,
                });
            }
        }

        vulnerabilities
    }

    fn detect_metamorphic_patterns(&self) -> Vec<EIP6780VulnerabilityType> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.has_create2(i) && self.has_selfdestruct_later(i) {
                vulnerabilities.push(EIP6780VulnerabilityType {
                    vulnerability_type: EIP6780IssueType::MetamorphicStrategyBroken,
                    severity: SecuritySeverity::Critical,
                    confidence: 0.85,
                    description: "Metamorphic contract pattern broken by EIP-6780".to_string(),
                    exploit_scenario: format!(
                        "Exploit at position {}:\n\
                        1. Contract uses CREATE2 + SELFDESTRUCT for metamorphism\n\
                        2. Post-EIP-6780: SELFDESTRUCT doesn't remove code\n\
                        3. Cannot redeploy at same address\n\
                        4. Metamorphic strategy completely broken\n\n\
                        Fix: Use alternative upgrade mechanisms (proxies)",
                        i
                    ),
                    location: i,
                });
            }
        }

        vulnerabilities
    }

    fn uses_selfdestruct(&self) -> bool {
        self.bytecode.iter().any(|&b| b == 0xFF) // SELFDESTRUCT opcode
    }

    fn has_selfdestruct(&self, pos: usize) -> bool {
        pos < self.bytecode.len() && self.bytecode[pos] == 0xFF
    }

    fn is_same_transaction(&self, pos: usize) -> bool {
        // Heuristic: Check if in constructor (same tx as creation)
        pos < 100 // Rough heuristic for constructor code
    }

    fn has_create2(&self, pos: usize) -> bool {
        pos < self.bytecode.len() && self.bytecode[pos] == 0xF5 // CREATE2
    }

    fn has_selfdestruct_later(&self, pos: usize) -> bool {
        self.bytecode[pos..].iter().any(|&b| b == 0xFF)
    }
}
