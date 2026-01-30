/// Division Before Multiplication Detector
/// 
/// Detects precision loss from: (a / b) * c instead of (a * c) / b
/// 
/// Example: (1000 / 3) * 3 = 333 * 3 = 999 (lost 1)
/// Correct: (1000 * 3) / 3 = 3000 / 3 = 1000
///
/// Common in: Interest calculations, fee calculations, share pricing

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrecisionLoss {
    pub vulnerability_type: String,
    pub severity: String,
    pub location: usize,
    pub description: String,
    pub operation_sequence: String,
    pub precision_loss_estimate: String,
    pub exploit_scenario: String,
    pub remediation: String,
}

pub struct DivisionBeforeMultiplicationDetector {
    bytecode: Vec<u8>,
}

impl DivisionBeforeMultiplicationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect(&self) -> Vec<PrecisionLoss> {
        let mut vulnerabilities = Vec::new();
        
        vulnerabilities.extend(self.detect_div_mul_pattern());
        vulnerabilities.extend(self.detect_multiple_divisions());
        vulnerabilities.extend(self.detect_division_in_loop());
        
        vulnerabilities
    }
    
    fn detect_div_mul_pattern(&self) -> Vec<PrecisionLoss> {
        let mut vulns = Vec::new();
        
        // Pattern: DIV followed by MUL (potential precision loss)
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x04 { // DIV
                // Look for MUL shortly after
                let end = (i + 15).min(self.bytecode.len());
                for j in (i+1)..end {
                    if self.bytecode[j] == 0x02 { // MUL
                        // Found DIV -> MUL pattern
                        let intermediate_ops = &self.bytecode[i+1..j];
                        
                        // Check if there are only stack operations between (no storage/calls)
                        let only_stack_ops = intermediate_ops.iter().all(|&op| {
                            matches!(op, 
                                0x50..=0x5F | // PUSH
                                0x60..=0x7F | // PUSH
                                0x80..=0x8F | // DUP
                                0x90..=0x9F | // SWAP
                                0x01..=0x1D   // Arithmetic/comparison
                            )
                        });
                        
                        if only_stack_ops || intermediate_ops.len() < 5 {
                            vulns.push(PrecisionLoss {
                                vulnerability_type: "Division Before Multiplication".to_string(),
                                severity: self.calculate_severity(intermediate_ops.len()),
                                location: i,
                                description: "Division followed by multiplication causes precision loss".to_string(),
                                operation_sequence: format!("DIV at {} -> MUL at {}", i, j),
                                precision_loss_estimate: "Up to (divisor - 1) per operation".to_string(),
                                exploit_scenario: 
                                    "Example: (1000 / 3) * 3 = 333 * 3 = 999 (loss of 1)\n\
                                     In fee calculations: Users lose fractional amounts\n\
                                     In share pricing: Incorrect share valuations\n\
                                     Cumulative: Losses compound over many operations".to_string(),
                                remediation: "Reorder: Multiply first, then divide. Use (a * c) / b instead of (a / b) * c".to_string(),
                            });
                        }
                        
                        break; // Only report first MUL after each DIV
                    }
                }
            }
        }
        
        vulns
    }
    
    fn detect_multiple_divisions(&self) -> Vec<PrecisionLoss> {
        let mut vulns = Vec::new();
        
        // Pattern: Multiple divisions in sequence (compounds precision loss)
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x04 { // First DIV
                let mut div_count = 1;
                let mut last_div_pos = i;
                
                // Count consecutive divisions
                let end = (i + 30).min(self.bytecode.len());
                for j in i+1..end {
                    if self.bytecode[j] == 0x04 { // Another DIV
                        div_count += 1;
                        last_div_pos = j;
                    }
                }
                
                if div_count >= 2 {
                    vulns.push(PrecisionLoss {
                        vulnerability_type: "Multiple Sequential Divisions".to_string(),
                        severity: "High".to_string(),
                        location: i,
                        description: format!("{} divisions in sequence compound precision loss", div_count),
                        operation_sequence: format!("{} DIV operations from {} to {}", div_count, i, last_div_pos),
                        precision_loss_estimate: format!("Exponential: up to (divisor-1)^{}", div_count),
                        exploit_scenario: "Each division truncates, compounding error geometrically".to_string(),
                        remediation: "Combine divisions: (a / b) / c = a / (b * c)".to_string(),
                    });
                }
            }
        }
        
        vulns
    }
    
    fn detect_division_in_loop(&self) -> Vec<PrecisionLoss> {
        let mut vulns = Vec::new();
        
        // Pattern: Division inside loop (precision loss accumulates)
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x04 { // DIV
                if self.is_in_loop(i) {
                    vulns.push(PrecisionLoss {
                        vulnerability_type: "Division in Loop".to_string(),
                        severity: "Critical".to_string(),
                        location: i,
                        description: "Division inside loop causes cumulative precision loss".to_string(),
                        operation_sequence: "Repeated DIV in loop iteration".to_string(),
                        precision_loss_estimate: "Linear with iterations: loss * iteration_count".to_string(),
                        exploit_scenario: 
                            "Distributing rewards with division in loop:\n\
                             foreach user: reward = total / userCount\n\
                             Loss accumulates: final user gets less".to_string(),
                        remediation: "Calculate once outside loop or use fixed-point arithmetic library".to_string(),
                    });
                }
            }
        }
        
        vulns
    }
    
    fn calculate_severity(&self, ops_between: usize) -> String {
        if ops_between <= 2 {
            "High".to_string()        // Direct DIV->MUL
        } else if ops_between <= 5 {
            "Medium".to_string()      // Few ops between
        } else {
            "Low".to_string()         // Many ops, might be intentional
        }
    }
    
    fn is_in_loop(&self, pc: usize) -> bool {
        // Check if PC is inside a loop
        // Pattern: JUMPDEST before and backward JUMP/JUMPI after
        
        let has_jumpdest_before = self.bytecode[pc.saturating_sub(50)..pc]
            .iter()
            .any(|&op| op == 0x5B);
        
        let end = (pc + 50).min(self.bytecode.len());
        let has_backward_jump = if end > pc {
            self.bytecode[pc..end]
                .iter()
                .any(|&op| op == 0x56 || op == 0x57)
        } else {
            false
        };
        
        has_jumpdest_before && has_backward_jump
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_div_mul_pattern() {
        let bytecode = vec![
            0x60, 0x64,  // PUSH1 100
            0x60, 0x03,  // PUSH1 3
            0x04,        // DIV (100 / 3 = 33)
            0x60, 0x03,  // PUSH1 3  
            0x02,        // MUL (33 * 3 = 99, lost 1!)
        ];
        
        let detector = DivisionBeforeMultiplicationDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.len() > 0);
    }
    
    #[test]
    fn test_safe_mul_div_pattern() {
        let bytecode = vec![
            0x60, 0x64,  // PUSH1 100
            0x60, 0x03,  // PUSH1 3
            0x02,        // MUL (100 * 3 = 300)
            0x60, 0x03,  // PUSH1 3
            0x04,        // DIV (300 / 3 = 100, correct!)
        ];
        
        let detector = DivisionBeforeMultiplicationDetector::new(bytecode);
        let vulns = detector.detect_div_mul_pattern();
        
        assert_eq!(vulns.len(), 0); // Safe pattern
    }
    
    #[test]
    fn test_multiple_divisions() {
        let bytecode = vec![
            0x04,        // DIV
            0x04,        // DIV (second division compounds error)
            0x04,        // DIV (third division makes it worse)
        ];
        
        let detector = DivisionBeforeMultiplicationDetector::new(bytecode);
        let vulns = detector.detect_multiple_divisions();
        
        assert!(vulns.len() > 0);
    }
}
