/// Unbounded Growth Detector
/// 
/// Detects data structures that grow without bounds
/// Impact: $280M+ - DOS via unbounded arrays

use crate::bytecode::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnboundedGrowthVulnerability {
    pub location: usize,
    pub severity: SecuritySeverity,
    pub growth_type: GrowthType,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GrowthType {
    UnboundedArray,
    UnboundedMapping,
    UnboundedLoop,
    UnlimitedAppends,
}

pub struct UnboundedGrowthDetector {
    bytecode: Vec<u8>,
}

impl UnboundedGrowthDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<UnboundedGrowthVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            if self.has_unbounded_array_push(pc) {
                vulnerabilities.push(UnboundedGrowthVulnerability {
                    location: pc,
                    severity: SecuritySeverity::High,
                    growth_type: GrowthType::UnboundedArray,
                    description: "Array grows without limit, eventually causing DOS".to_string(),
                    exploit_scenario: "address[] public users;\n\
                        \n\
                        function register() {\n\
                            users.push(msg.sender); // No limit!\n\
                        }\n\
                        \n\
                        function distributeAll() {\n\
                            for (uint i = 0; i < users.length; i++) {\n\
                                users[i].call{value: 1 ether}(\"\");\n\
                            }\n\
                        }\n\
                        \n\
                        Attack:\n\
                        1. Attacker registers 10,000 times\n\
                        2. users.length = 10,000\n\
                        3. distributeAll() costs 10,000x gas\n\
                        4. Exceeds block gas limit\n\
                        5. Distribution permanently DOS'd".to_string(),
                    remediation: "Add maximum size limit or use pagination".to_string(),
                    confidence: 0.85,
                });
            }
            pc += 1;
        }

        vulnerabilities
    }

    fn has_unbounded_array_push(&self, start: usize) -> bool {
        if start + 20 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 20];
        
        // Pattern: Array push (SSTORE to length slot) without size check
        let has_array_op = window.iter().any(|&b| b == 0x55); // SSTORE
        
        if has_array_op {
            // Check if there's NO length check before push
            let has_length_check = window.windows(3).any(|w| {
                w[0] == 0x54 && // SLOAD (length)
                w[1] == 0x10 && // LT (length < max)
                w[2] == 0x57    // JUMPI
            });
            !has_length_check
        } else {
            false
        }
    }
}
