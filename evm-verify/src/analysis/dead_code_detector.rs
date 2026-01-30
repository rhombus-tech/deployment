/// Dead Code Detector
/// 
/// Finds unreachable code that can never execute
/// Impact: $200M+ - unreachable validation/cleanup code

use crate::bytecode::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadCodeVulnerability {
    pub location: usize,
    pub severity: SecuritySeverity,
    pub dead_code_type: DeadCodeType,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeadCodeType {
    UnreachableAfterRevert,
    UnreachableAfterReturn,
    ImpossibleCondition,
    DeadBranch,
}

pub struct DeadCodeDetector {
    bytecode: Vec<u8>,
}

impl DeadCodeDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<DeadCodeVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            if self.has_dead_code(pc) {
                vulnerabilities.push(DeadCodeVulnerability {
                    location: pc,
                    severity: SecuritySeverity::High,
                    dead_code_type: DeadCodeType::UnreachableAfterRevert,
                    description: "Code after unconditional revert never executes".to_string(),
                    exploit_scenario: "function withdraw() {\n\
                        require(false); // Always reverts!\n\
                        balances[msg.sender] = 0; // Never executes\n\
                        // Funds locked forever\n\
                    }".to_string(),
                    remediation: "Remove unreachable code or fix condition".to_string(),
                    confidence: 0.90,
                });
            }
            pc += 1;
        }

        vulnerabilities
    }

    fn has_dead_code(&self, start: usize) -> bool {
        if start + 10 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 10];
        
        // Pattern: REVERT/RETURN followed by non-metadata code
        if window[0] == 0xFD || window[0] == 0xF3 { // REVERT or RETURN
            // Check if there's more code after (not just metadata)
            window[1..].iter().any(|&b| {
                b != 0x00 && // Not padding
                b != 0x5B && // Not JUMPDEST
                b != 0xFE    // Not INVALID
            })
        } else {
            false
        }
    }
}
