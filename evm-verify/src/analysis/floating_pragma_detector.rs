use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FloatingPragmaVulnerability {
    NonDeterministicCompiler { description: String, location: usize, confidence: f32 },
    CaretPragma { description: String, location: usize },
}

pub struct FloatingPragmaDetector {
    bytecode: Vec<u8>,
}

impl FloatingPragmaDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<FloatingPragmaVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Floating pragma is a source-level issue, but we can detect metadata
        // Solidity embeds CBOR-encoded metadata at end of bytecode
        // For bytecode analysis, we check for version inconsistencies
        
        if self.has_metadata() {
            // Check metadata for version info
            // This is a heuristic - true floating pragma detection needs source
            vulnerabilities.push(FloatingPragmaVulnerability::NonDeterministicCompiler {
                description: "Contract may have been compiled with floating pragma - non-deterministic".to_string(),
                location: 0,
                confidence: 0.60,
            });
        }
        
        vulnerabilities
    }
    
    fn has_metadata(&self) -> bool {
        // Solidity metadata starts with 0xa2 0x64 'i' 'p' 'f' 's'
        self.bytecode.windows(6).any(|w| {
            w[0] == 0xa2 && w[1] == 0x64 && 
            w[2] == 0x69 && w[3] == 0x70 && 
            w[4] == 0x66 && w[5] == 0x73
        })
    }
}
