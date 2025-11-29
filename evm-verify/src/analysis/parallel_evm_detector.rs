/// Parallel EVM Execution Exploit Detector
/// Detects vulnerabilities in parallel EVM execution environments
/// Critical for: Monad, Sei v2, Neon, parallel execution chains

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParallelEVMVulnerability {
    pub vulnerability_type: ParallelEVMIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ParallelEVMIssueType {
    RaceConditionInParallel,       // Race condition in parallel execution
    StateAccessOrderViolation,     // State access ordering issue
    DependencyGraphManipulation,   // Transaction dependency exploitation
    NonDeterministicExecution,     // Non-deterministic execution result
    ParallelMEVExtraction,         // MEV in parallel environment
}

pub struct ParallelEVMDetector {
    bytecode: Vec<u8>,
}

impl ParallelEVMDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ParallelEVMVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_race_conditions());
        vulnerabilities.extend(self.detect_state_ordering_issues());

        vulnerabilities
    }

    fn detect_race_conditions(&self) -> Vec<ParallelEVMVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Read-modify-write without proper locking
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.has_read_modify_write(i) && !self.has_parallel_lock(i) {
                vulnerabilities.push(ParallelEVMVulnerability {
                    vulnerability_type: ParallelEVMIssueType::RaceConditionInParallel,
                    severity: SecuritySeverity::High,
                    confidence: 0.75,
                    description: "Read-modify-write pattern without parallel execution protection".to_string(),
                    exploit_scenario: format!(
                        "Exploit at position {}:\n\
                        1. Contract uses read-modify-write pattern\n\
                        2. No mutex/lock for parallel execution\n\
                        3. Parallel transactions create race condition\n\
                        4. State corruption or double-spend\n\n\
                        Fix: Use atomic operations or explicit locking",
                        i
                    ),
                    location: i,
                });
            }
        }

        vulnerabilities
    }

    fn detect_state_ordering_issues(&self) -> Vec<ParallelEVMVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: State dependency without ordering enforcement
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.has_state_dependency(i) && !self.has_ordering_constraint(i) {
                vulnerabilities.push(ParallelEVMVulnerability {
                    vulnerability_type: ParallelEVMIssueType::StateAccessOrderViolation,
                    severity: SecuritySeverity::High,
                    confidence: 0.70,
                    description: "State access without ordering constraint in parallel execution".to_string(),
                    exploit_scenario: format!(
                        "Exploit at position {}:\n\
                        1. Contract has state dependencies\n\
                        2. No ordering constraint specified\n\
                        3. Parallel executor reorders transactions\n\
                        4. Business logic violation\n\n\
                        Fix: Declare access dependencies explicitly",
                        i
                    ),
                    location: i,
                });
            }
        }

        vulnerabilities
    }

    fn has_read_modify_write(&self, pos: usize) -> bool {
        // SLOAD followed by arithmetic then SSTORE
        pos + 10 < self.bytecode.len() &&
        self.bytecode[pos] == 0x54 && // SLOAD
        (self.bytecode[pos+5] == 0x01 || self.bytecode[pos+5] == 0x03) && // ADD/SUB
        self.bytecode[pos+10] == 0x55 // SSTORE
    }

    fn has_parallel_lock(&self, pos: usize) -> bool {
        // Look for mutex pattern (check-set-reset)
        for i in pos.saturating_sub(30)..pos {
            if self.bytecode[i] == 0x54 && i + 3 < self.bytecode.len() && self.bytecode[i+3] == 0x15 {
                return true; // SLOAD ISZERO (lock check)
            }
        }
        false
    }

    fn has_state_dependency(&self, pos: usize) -> bool {
        // Multiple SLOAD operations
        let sload_count = self.bytecode[pos..pos.saturating_add(30).min(self.bytecode.len())]
            .iter()
            .filter(|&&b| b == 0x54)
            .count();
        sload_count >= 2
    }

    fn has_ordering_constraint(&self, pos: usize) -> bool {
        // Look for nonce or sequential ID check
        for i in pos.saturating_sub(20)..pos {
            if self.bytecode[i] == 0x14 { // EQ (sequence check)
                return true;
            }
        }
        false
    }
}
