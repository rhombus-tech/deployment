use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PhantomOverflowVulnerability {
    UncheckedBlockOverflow { description: String, location: usize, confidence: f32 },
    AssemblyArithmeticUnchecked { description: String, location: usize },
    ExternalCallReturnUnchecked { description: String, location: usize },
}

pub struct PhantomOverflowDetector {
    bytecode: Vec<u8>,
}

impl PhantomOverflowDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<PhantomOverflowVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Phantom overflow: arithmetic in unchecked blocks (Solidity 0.8+)
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.is_arithmetic_operation(i) {
                if !self.has_overflow_check_nearby(i, i + 50) {
                    vulnerabilities.push(PhantomOverflowVulnerability::UncheckedBlockOverflow {
                        description: "Arithmetic in unchecked block without validation - phantom overflow risk".to_string(),
                        location: i,
                        confidence: 0.75,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_arithmetic_operation(&self, location: usize) -> bool {
        if location >= self.bytecode.len() {
            return false;
        }
        
        matches!(self.bytecode[location], 0x01 | 0x02 | 0x03 | 0x0A) // ADD, MUL, SUB, EXP
    }
    
    fn has_overflow_check_nearby(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Check for comparison + revert pattern
        self.bytecode[start..range_end].windows(3).any(|w| {
            (w[0] == 0x10 || w[0] == 0x11) && // LT or GT
            (w[1] == 0xFD || w[2] == 0xFD)    // REVERT
        })
    }
}
