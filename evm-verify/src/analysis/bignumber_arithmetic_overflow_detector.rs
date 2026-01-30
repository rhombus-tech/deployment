use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BigNumberOverflowVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct BigNumberArithmeticOverflowDetector {
    bytecode: Vec<u8>,
}

impl BigNumberArithmeticOverflowDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<BigNumberOverflowVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_multi_word_overflow() {
            vulnerabilities.push(BigNumberOverflowVulnerability {
                vulnerability_type: "Multi-Word Arithmetic Overflow".to_string(),
                location: loc,
                severity: "High".to_string(),
                description: "BigNumber ops can overflow across limbs".to_string(),
                confidence: 0.80,
            });
        }
        vulnerabilities
    }
    fn has_multi_word_overflow(&self) -> Option<usize> {
        // Pattern: Multiple ADD with SSTORE (multi-limb arithmetic)
        for i in 0..self.bytecode.len().saturating_sub(25) {
            let mut add_count = 0;
            let mut has_carry_check = false;
            for j in i..i+20.min(self.bytecode.len()) {
                if self.bytecode[j] == 0x01 { add_count += 1; }
                if self.bytecode[j] == 0x10 { has_carry_check = true; } // LT (carry)
            }
            if add_count >= 3 && !has_carry_check {
                return Some(i);
            }
        }
        None
    }
}
