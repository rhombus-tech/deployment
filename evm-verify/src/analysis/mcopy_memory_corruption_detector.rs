use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum McopyCorruptionVulnerability {
    OverlappingMemoryRegions { description: String, location: usize, confidence: f32 },
    UncheckedMemoryBoundaries { description: String, location: usize, confidence: f32 },
    McopyOffByOneError { description: String, location: usize, confidence: f32 },
}

pub struct McopyMemoryCorruptionDetector {
    bytecode: Vec<u8>,
}

impl McopyMemoryCorruptionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<McopyCorruptionVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_mcopy_usage());
        vulnerabilities
    }
    
    fn detect_mcopy_usage(&self) -> Vec<McopyCorruptionVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // MCOPY opcode is 0x5E (Cancun EIP-5656)
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x5E {
                let section = &self.bytecode[i..std::cmp::min(i + 30, self.bytecode.len())];
                
                // Check for overlapping memory regions pattern
                // MCOPY takes destOffset, srcOffset, length from stack
                // Dangerous if srcOffset and destOffset ranges overlap
                let has_unchecked_overlap = !section.windows(5).any(|w| {
                    // Look for comparison opcodes before MCOPY
                    w.contains(&0x10) || // LT
                    w.contains(&0x11) || // GT
                    w.contains(&0x12) || // SLT
                    w.contains(&0x13)    // SGT
                });
                
                if has_unchecked_overlap {
                    vulnerabilities.push(McopyCorruptionVulnerability::OverlappingMemoryRegions {
                        description: format!("MCOPY at PC {} without overlap checks. Cancun EIP-5656: If src and dest regions overlap, behavior is like memmove() - copies occur as if intermediate buffer used. However, without validation, off-by-one errors can corrupt data. Example: mcopy(dest=100, src=99, len=50) → overlapping regions. Validate: require(dest >= src + len || src >= dest + len)", i),
                        location: i,
                        confidence: 0.88,
                    });
                }
                
                // Check for boundary validation
                let has_boundary_check = section.windows(8).any(|w| {
                    // MSIZE check before MCOPY
                    w.contains(&0x59) && // MSIZE
                    (w.contains(&0x10) || w.contains(&0x11)) // LT or GT
                });
                
                if !has_boundary_check {
                    vulnerabilities.push(McopyCorruptionVulnerability::UncheckedMemoryBoundaries {
                        description: format!("MCOPY at PC {} without memory boundary validation. Risk: Copy beyond allocated memory causing memory expansion gas bomb or data corruption. Best practice: check dest + length <= safe_bound before MCOPY.", i),
                        location: i,
                        confidence: 0.85,
                    });
                }
            }
        }
        
        vulnerabilities
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mcopy_no_overlap_check() {
        // MCOPY without preceding comparison
        let bytecode = vec![
            0x60, 0x20, // PUSH1 32 (length)
            0x60, 0x00, // PUSH1 0 (srcOffset)
            0x60, 0x20, // PUSH1 32 (destOffset)
            0x5E,       // MCOPY (no overlap check)
        ];
        
        let detector = McopyMemoryCorruptionDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(!vulns.is_empty());
    }

    #[test]
    fn test_mcopy_with_validation() {
        // MCOPY with LT comparison before
        let bytecode = vec![
            0x60, 0x20, // PUSH1 32
            0x60, 0x00, // PUSH1 0
            0x10,       // LT (comparison)
            0x60, 0x20, // PUSH1 32
            0x60, 0x00, // PUSH1 0
            0x60, 0x20, // PUSH1 32
            0x5E,       // MCOPY (with check)
        ];
        
        let detector = McopyMemoryCorruptionDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        // Should have fewer or no vulnerabilities
        assert!(vulns.len() < 2);
    }
}
