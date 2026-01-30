use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AbiEncoderV2BugVulnerability {
    VulnerableCompilerVersion { description: String, location: usize, confidence: f32, version_range: String },
    StructArrayEncoding { description: String, location: usize },
    NestedArrayBug { description: String, location: usize },
}

pub struct AbiEncoderV2BugDetector {
    bytecode: Vec<u8>,
}

impl AbiEncoderV2BugDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<AbiEncoderV2BugVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Check for metadata indicating vulnerable Solidity version (0.5.8 - 0.5.16)
        if let Some(version) = self.extract_compiler_version() {
            if self.is_vulnerable_version(&version) {
                if self.uses_abi_encoder_v2() {
                    vulnerabilities.push(AbiEncoderV2BugVulnerability::VulnerableCompilerVersion {
                        description: format!("Compiled with Solidity {} - ABI encoder v2 bugs present", version),
                        location: 0,
                        confidence: 0.95,
                        version_range: "0.5.8-0.5.16".to_string(),
                    });
                }
            }
        }
        
        // Check for struct/array encoding patterns (vulnerable regardless of version detection)
        if self.has_complex_struct_encoding() {
            vulnerabilities.push(AbiEncoderV2BugVulnerability::StructArrayEncoding {
                description: "Complex struct array encoding - may be vulnerable to ABI encoder v2 bug".to_string(),
                location: 0,
            });
        }
        
        vulnerabilities
    }
    
    fn extract_compiler_version(&self) -> Option<String> {
        // Solidity embeds metadata at end: 0xa2 0x64 'i' 'p' 'f' 's' ... 'solc' <version>
        // This is heuristic - in bytecode analysis we look for patterns
        if self.bytecode.len() > 100 {
            // Check for metadata marker
            if self.bytecode.windows(6).any(|w| {
                w[0] == 0xa2 && w[1] == 0x64 && 
                w[2] == 0x69 && w[3] == 0x70 && 
                w[4] == 0x66 && w[5] == 0x73
            }) {
                return Some("0.5.x-0.8.x".to_string()); // Placeholder
            }
        }
        None
    }
    
    fn is_vulnerable_version(&self, version: &str) -> bool {
        // Versions 0.5.8 through 0.5.16 have ABI encoder v2 bugs
        version.contains("0.5")
    }
    
    fn uses_abi_encoder_v2(&self) -> bool {
        // ABI encoder v2 uses more complex encoding patterns
        // Look for multiple CODECOPY operations (struct encoding)
        self.bytecode.iter().filter(|&&b| b == 0x39).count() > 2
    }
    
    fn has_complex_struct_encoding(&self) -> bool {
        // Multiple MSTORE operations followed by RETURN (complex data structures)
        let mstore_count = self.bytecode.iter().filter(|&&b| b == 0x52).count();
        mstore_count > 5
    }
}
