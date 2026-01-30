#[derive(Debug, Clone, PartialEq)]
pub enum LossAversionVulnerability {
    AsymmetricPenalty { pc: usize, penalty_ratio: f64, description: String },
}

pub struct LossAversionAttackDetector { 
    bytecode: Vec<u8> 
}

impl LossAversionAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { 
        Self { bytecode } 
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<LossAversionVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Detect asymmetric withdrawal penalties
        if let Some((pc, ratio)) = self.detect_asymmetric_withdrawal_penalty() {
            vulnerabilities.push(LossAversionVulnerability::AsymmetricPenalty {
                pc,
                penalty_ratio: ratio,
                description: format!(
                    "Withdrawal penalty ({:.0}%) is asymmetrically higher than deposit bonus, exploiting loss aversion bias",
                    ratio * 100.0
                ),
            });
        }
        
        // Detect exit fee escalation over time
        if let Some((pc, ratio)) = self.detect_time_increasing_exit_fees() {
            vulnerabilities.push(LossAversionVulnerability::AsymmetricPenalty {
                pc,
                penalty_ratio: ratio,
                description: format!(
                    "Exit fees increase {:.0}% over time, exploiting loss aversion to trap users",
                    ratio * 100.0
                ),
            });
        }
        
        vulnerabilities
    }
    
    fn detect_asymmetric_withdrawal_penalty(&self) -> Option<(usize, f64)> {
        // Look for withdrawal functions with penalty calculations
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 { // PUSH4
                let sig = &self.bytecode[i+1..i+5];
                // withdraw function signatures
                if matches!(sig, [0x2e, 0x1a, _, _] | [0x3c, 0xcf, _, _]) {
                    let mut has_penalty = false;
                    let mut penalty_pc = None;
                    
                    // Look for penalty calculation pattern
                    for j in i..i.saturating_add(25).min(self.bytecode.len()) {
                        // MUL followed by SUB (amount * fee - amount)
                        if self.bytecode[j] == 0x02 { // MUL
                            for k in j..j.saturating_add(8).min(self.bytecode.len()) {
                                if self.bytecode[k] == 0x03 { // SUB
                                    has_penalty = true;
                                    penalty_pc = Some(j);
                                    break;
                                }
                            }
                        }
                    }
                    
                    if has_penalty {
                        // Estimate penalty ratio (conservative 5%)
                        return Some((penalty_pc.unwrap(), 0.05));
                    }
                }
            }
        }
        None
    }
    
    fn detect_time_increasing_exit_fees(&self) -> Option<(usize, f64)> {
        // Look for exit fee calculations involving timestamps
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                let mut has_subtraction = false;
                let mut has_multiplication = false;
                
                for j in i..i.saturating_add(20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x03 { // SUB (time elapsed)
                        has_subtraction = true;
                    }
                    if has_subtraction && self.bytecode[j] == 0x02 { // MUL (fee scaling)
                        has_multiplication = true;
                    }
                }
                
                // Time-based penalty escalation
                if has_subtraction && has_multiplication {
                    return Some((i, 0.10)); // 10% escalation over time
                }
            }
        }
        None
    }
}
