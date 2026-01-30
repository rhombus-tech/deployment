use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OptimizerBugVulnerability {
    VulnerableOptimizerVersion { description: String, location: usize, confidence: f32, version: String },
    FullInlinerBug { description: String, location: usize },
    YulOptimizerBug { description: String, location: usize },
}

pub struct OptimizerBugDetector {
    bytecode: Vec<u8>,
}

impl OptimizerBugDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<OptimizerBugVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Solidity 0.8.13-0.8.17 had optimizer bugs
        // Check for suspicious optimization patterns
        if self.has_suspicious_jump_pattern() {
            vulnerabilities.push(OptimizerBugVulnerability::FullInlinerBug {
                description: "Suspicious jump pattern - may be affected by Solidity 0.8.13-0.8.17 optimizer bug".to_string(),
                location: 0,
            });
        }
        
        if self.has_yul_optimizer_pattern() {
            vulnerabilities.push(OptimizerBugVulnerability::YulOptimizerBug {
                description: "Complex inline assembly - Yul optimizer bugs in 0.8.13-0.8.15".to_string(),
                location: 0,
            });
        }
        
        vulnerabilities
    }
    
    fn has_suspicious_jump_pattern(&self) -> bool {
        // Optimizer bug manifests as incorrect JUMP destinations
        // Look for JUMP immediately after complex expression
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x56 { // JUMP
                // Check if preceded by complex stack manipulation
                let prev_10 = &self.bytecode[i.saturating_sub(10)..i];
                let dup_swap_count = prev_10.iter()
                    .filter(|&&b| (b >= 0x80 && b <= 0x8F) || (b >= 0x90 && b <= 0x9F))
                    .count();
                if dup_swap_count > 5 {
                    return true;
                }
            }
        }
        false
    }
    
    fn has_yul_optimizer_pattern(&self) -> bool {
        // Yul optimizer bugs with inline assembly
        // Look for unusual opcode sequences
        self.bytecode.windows(3).any(|w| {
            // Invalid opcode sequence that shouldn't appear
            w[0] == 0x39 && w[1] == 0x3D && w[2] == 0xF3 // CODECOPY RETURNDATASIZE RETURN
        })
    }
}
