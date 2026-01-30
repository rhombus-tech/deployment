use serde::{Deserialize, Serialize};

/// EIP-2098 Compact Signature Detector
/// 
/// Detects vulnerabilities in compact signature (64-byte) implementations.
/// EIP-2098 allows signatures to be 64 bytes instead of 65 by encoding v in s.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CompactSignatureVulnerability {
    /// Critical: Compact signature decoded incorrectly
    IncorrectDecoding {
        description: String,
        location: usize,
        confidence: f32,
    },
    /// High: V value not extracted from high bit of s
    VNotExtractedFromS {
        description: String,
        location: usize,
    },
    /// High: S value not normalized after v extraction
    SNotNormalized {
        description: String,
        location: usize,
    },
    /// Medium: Mixed compact and standard signature handling
    MixedSignatureHandling {
        description: String,
        location: usize,
    },
}

pub struct CompactSignatureEip2098Detector {
    bytecode: Vec<u8>,
}

impl CompactSignatureEip2098Detector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<CompactSignatureVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern 1: Detect compact signature handling (64-byte signatures)
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.handles_compact_signatures(i) {
                // Check if v is correctly extracted from s high bit
                if !self.extracts_v_from_s_correctly(i, i + 100) {
                    vulnerabilities.push(CompactSignatureVulnerability::VNotExtractedFromS {
                        description: "Compact signature (EIP-2098) v value not extracted from s high bit".to_string(),
                        location: i,
                    });
                }
                
                // Check if s is normalized after v extraction
                if !self.normalizes_s_after_extraction(i, i + 100) {
                    vulnerabilities.push(CompactSignatureVulnerability::SNotNormalized {
                        description: "S value not normalized after extracting v from high bit".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        // Pattern 2: Mixed handling of compact and standard signatures
        if self.has_both_signature_types() {
            if !self.properly_distinguishes_signature_types() {
                vulnerabilities.push(CompactSignatureVulnerability::MixedSignatureHandling {
                    description: "Contract handles both compact (64-byte) and standard (65-byte) signatures without proper differentiation".to_string(),
                    location: 0,
                });
            }
        }
        
        // Pattern 3: Check for incorrect compact signature decoding
        for i in 0..self.bytecode.len().saturating_sub(80) {
            if self.decodes_compact_signature(i) {
                if self.has_incorrect_decoding_logic(i, i + 80) {
                    vulnerabilities.push(CompactSignatureVulnerability::IncorrectDecoding {
                        description: "Compact signature decoding logic appears incorrect - may not follow EIP-2098 spec".to_string(),
                        location: i,
                        confidence: 0.75,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn handles_compact_signatures(&self, location: usize) -> bool {
        if location + 20 > self.bytecode.len() {
            return false;
        }
        
        // Look for 64-byte signature handling (0x40 = 64 in hex)
        // Pattern: PUSH1 0x40 (signature length check)
        self.bytecode[location..location + 20]
            .windows(2)
            .any(|w| w[0] == 0x60 && w[1] == 0x40)
    }
    
    fn extracts_v_from_s_correctly(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // EIP-2098: v = s[31] >> 7 (extract high bit)
        // Bytecode pattern: SHR with 0xFF (255) or 0x80 (128) to get high bit
        
        for i in start..range_end.saturating_sub(5) {
            // Look for bit shifting operations
            if self.bytecode[i] == 0x1C { // SHR
                // Check if shifting by 255 to get high bit
                if i > 0 && self.bytecode[i - 2] == 0x60 {
                    let shift_amount = self.bytecode[i - 1];
                    if shift_amount == 0xFF || shift_amount == 0xF8 { // 255 or 248 bits
                        return true;
                    }
                }
            }
            
            // Or using AND with 0x80... to extract high bit
            if self.bytecode[i] == 0x16 { // AND
                return true;
            }
        }
        
        false
    }
    
    fn normalizes_s_after_extraction(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // After extracting v from s, must normalize s by:
        // s = s & 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        // (clear the high bit)
        
        for i in start..range_end.saturating_sub(10) {
            // Look for AND operation with mask 0x7F...
            if self.bytecode[i] == 0x16 { // AND
                // Check for 0x7F pattern (high bit cleared)
                for j in (i.saturating_sub(35))..i {
                    if self.bytecode[j] == 0x7F { // PUSH32 starting with 0x7F
                        return true;
                    }
                }
            }
        }
        
        false
    }
    
    fn has_both_signature_types(&self) -> bool {
        // Check if contract handles both 64-byte and 65-byte signatures
        let has_64_byte = self.bytecode.windows(2).any(|w| w[0] == 0x60 && w[1] == 0x40);
        let has_65_byte = self.bytecode.windows(2).any(|w| w[0] == 0x60 && w[1] == 0x41);
        
        has_64_byte && has_65_byte
    }
    
    fn properly_distinguishes_signature_types(&self) -> bool {
        // Check if there's logic to differentiate between signature types
        // Should have conditional branching based on signature length
        
        let mut has_length_check = false;
        let mut has_conditional = false;
        
        for i in 0..self.bytecode.len().saturating_sub(10) {
            // Length comparison
            if (self.bytecode[i] == 0x60 && 
                (self.bytecode[i + 1] == 0x40 || self.bytecode[i + 1] == 0x41)) &&
               i + 3 < self.bytecode.len() &&
               self.bytecode[i + 2] == 0x14 { // EQ
                has_length_check = true;
            }
            
            // Conditional jump after length check
            if has_length_check && self.bytecode[i] == 0x57 { // JUMPI
                has_conditional = true;
            }
        }
        
        has_length_check && has_conditional
    }
    
    fn decodes_compact_signature(&self, location: usize) -> bool {
        // Look for compact signature decoding operations
        // Pattern: Loading 64 bytes and extracting r, s, v
        
        if location + 30 > self.bytecode.len() {
            return false;
        }
        
        // Check for CALLDATALOAD or memory operations with 64-byte offset
        self.bytecode[location..location + 30]
            .windows(3)
            .any(|w| {
                (w[0] == 0x35 || w[0] == 0x51) && // CALLDATALOAD or MLOAD
                w[1] == 0x60 && w[2] == 0x40      // 64 bytes
            })
    }
    
    fn has_incorrect_decoding_logic(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Check for common mistakes in compact signature decoding:
        // 1. Not extracting v from s
        // 2. Not clearing high bit of s
        // 3. Wrong byte offsets
        
        let has_v_extraction = self.extracts_v_from_s_correctly(start, end);
        let has_s_normalization = self.normalizes_s_after_extraction(start, end);
        
        // If decoding but missing critical steps, it's incorrect
        if !has_v_extraction || !has_s_normalization {
            return true;
        }
        
        // Check for wrong offsets (common mistake)
        for i in start..range_end.saturating_sub(5) {
            // R should be at offset 0, S at offset 32
            // Common mistake: using wrong offsets
            if self.bytecode[i] == 0x60 { // PUSH1
                if i + 1 < range_end {
                    let offset = self.bytecode[i + 1];
                    // Suspicious offsets that don't align with EIP-2098
                    if offset > 0x40 && offset < 0x60 {
                        return true;
                    }
                }
            }
        }
        
        false
    }
}
