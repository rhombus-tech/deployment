/// Exponential Overflow Detector  
/// Detects overflow in exponentiation (a**b) and power operations

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExponentialOverflow {
    pub vulnerability_type: String,
    pub severity: String,
    pub location: usize,
    pub description: String,
    pub remediation: String,
}

pub struct ExponentialOverflowDetector {
    bytecode: Vec<u8>,
}

impl ExponentialOverflowDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect(&self) -> Vec<ExponentialOverflow> {
        let mut vulns = Vec::new();
        
        vulns.extend(self.detect_exp_operation());
        vulns.extend(self.detect_repeated_multiplication());
        vulns.extend(self.detect_unchecked_power());
        
        vulns
    }
    
    fn detect_exp_operation(&self) -> Vec<ExponentialOverflow> {
        let mut vulns = Vec::new();
        
        // EXP opcode (0x0A) can overflow
        for i in 0..self.bytecode.len() {
            if self.bytecode[i] == 0x0A { // EXP
                vulns.push(ExponentialOverflow {
                    vulnerability_type: "Exponential Overflow".to_string(),
                    severity: "High".to_string(),
                    location: i,
                    description: "EXP operation without overflow check".to_string(),
                    remediation: "Check result: require(result / base == base**(exp-1))".to_string(),
                });
            }
        }
        vulns
    }
    
    fn detect_repeated_multiplication(&self) -> Vec<ExponentialOverflow> {
        let mut vulns = Vec::new();
        
        // Pattern: Multiple MUL in sequence (manual exponentiation)
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x02 { // MUL
                let mut mul_count = 1;
                
                let end = (i + 20).min(self.bytecode.len());
                for j in i+1..end {
                    if self.bytecode[j] == 0x02 {
                        mul_count += 1;
                    }
                }
                
                if mul_count >= 3 {
                    vulns.push(ExponentialOverflow {
                        vulnerability_type: "Repeated Multiplication".to_string(),
                        severity: "Medium".to_string(),
                        location: i,
                        description: format!("{} multiplications - risk of overflow", mul_count),
                        remediation: "Use SafeMath or check intermediate results".to_string(),
                    });
                }
            }
        }
        vulns
    }
    
    fn detect_unchecked_power(&self) -> Vec<ExponentialOverflow> {
        let mut vulns = Vec::new();
        
        // Power calculation in loop without checks
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x02 && self.is_in_loop(i) { // MUL in loop
                vulns.push(ExponentialOverflow {
                    vulnerability_type: "Power Calculation in Loop".to_string(),
                    severity: "High".to_string(),
                    location: i,
                    description: "Multiplication in loop (power calculation) without overflow check".to_string(),
                    remediation: "Add overflow checks or use library with safe exponentiation".to_string(),
                });
            }
        }
        vulns
    }
    
    fn is_in_loop(&self, pc: usize) -> bool {
        let has_jumpdest = self.bytecode[pc.saturating_sub(30)..pc].iter().any(|&op| op == 0x5B);
        let end = (pc + 30).min(self.bytecode.len());
        let has_jumpi = if end > pc {
            self.bytecode[pc..end].iter().any(|&op| op == 0x57)
        } else {
            false
        };
        has_jumpdest && has_jumpi
    }
}
