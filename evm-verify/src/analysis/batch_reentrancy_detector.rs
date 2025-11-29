/// Batch Operation Reentrancy Detector
/// Detects reentrancy within batch/multicall-style operations

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchReentrancyVulnerability {
    pub vulnerability_type: BatchReentrancyIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BatchReentrancyIssueType {
    ReentrancyWithinBatch,         // Reenter during batch execution
    StateManipulationBetweenOps,   // State changed between operations
    BalancerVaultStyleReentrancy,  // Balancer-style read-only reentrancy in batch
    CrossOperationRaceCondition,   // Race between batch operations
}

pub struct BatchReentrancyDetector {
    bytecode: Vec<u8>,
}

impl BatchReentrancyDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<BatchReentrancyVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: External call in loop without reentrancy guard
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if (self.bytecode[i] == 0xF1 || self.bytecode[i] == 0xF4) && // CALL or DELEGATECALL
               self.is_in_loop(i) &&
               !self.has_reentrancy_protection(i) {
                
                vulnerabilities.push(BatchReentrancyVulnerability {
                    vulnerability_type: BatchReentrancyIssueType::ReentrancyWithinBatch,
                    severity: SecuritySeverity::High,
                    confidence: 0.80,
                    description: "Batch operation vulnerable to reentrancy between items".to_string(),
                    exploit_scenario: format!(
                        "Exploit at position {}:\n\
                        1. Batch: [opA(), opB(), opC()]\n\
                        2. opA() makes external call\n\
                        3. External contract reenters batch\n\
                        4. Executes opB() before original opB()\n\
                        5. State inconsistency and exploitation\n\n\
                        Fix: Use reentrancy guard or checks-effects-interactions",
                        i
                    ),
                    location: i,
                });
            }
        }

        vulnerabilities
    }

    fn is_in_loop(&self, pos: usize) -> bool {
        let has_jumpdest = self.bytecode[pos.saturating_sub(20)..pos].iter().any(|&b| b == 0x5B);
        let has_jumpi = self.bytecode[pos..pos.saturating_add(30).min(self.bytecode.len())].iter().any(|&b| b == 0x57);
        has_jumpdest && has_jumpi
    }

    fn has_reentrancy_protection(&self, pos: usize) -> bool {
        // Check for reentrancy guard pattern
        for i in pos.saturating_sub(50)..pos {
            if self.bytecode[i] == 0x54 && i + 2 < self.bytecode.len() && self.bytecode[i + 2] == 0x14 {
                return true;
            }
        }
        false
    }
}
