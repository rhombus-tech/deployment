use serde::{Deserialize, Serialize};

/// Fixed-Point Arithmetic Drift Detector
/// 
/// Fixed-point math (e.g., WAD=1e18, RAY=1e27) accumulates rounding errors over operations.
/// Long calculation chains can drift significantly from true values.
///
/// Key Attacks:
/// 1. Rounding accumulation in loops (e.g., fee calculations)
/// 2. Division before multiplication causing precision loss
/// 3. Scaling factor inconsistencies (mixing WAD/RAY)
/// 4. Unbounded iteration accumulating drift
/// 5. Loss of precision in compound operations
///
/// Real-World Impact:
/// - MakerDAO uses RAY (1e27) to minimize drift
/// - Compound uses mantissa (1e18) for interest
/// - Small drift = millions in losses over time

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixedPointDriftVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct FixedPointArithmeticDriftDetector {
    bytecode: Vec<u8>,
}

impl FixedPointArithmeticDriftDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<FixedPointDriftVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.has_division_before_multiplication() {
            vulnerabilities.push(FixedPointDriftVulnerability {
                vulnerability_type: "Division Before Multiplication".to_string(),
                location: loc,
                severity: "High".to_string(),
                description: "Dividing before multiplying loses precision in fixed-point math".to_string(),
                confidence: 0.90,
            });
        }

        if let Some(loc) = self.has_loop_accumulation_drift() {
            vulnerabilities.push(FixedPointDriftVulnerability {
                vulnerability_type: "Loop Accumulation Drift".to_string(),
                location: loc,
                severity: "High".to_string(),
                description: "Fixed-point operations in loop accumulate rounding errors".to_string(),
                confidence: 0.85,
            });
        }

        if let Some(loc) = self.has_scaling_factor_mismatch() {
            vulnerabilities.push(FixedPointDriftVulnerability {
                vulnerability_type: "Scaling Factor Mismatch".to_string(),
                location: loc,
                severity: "Medium".to_string(),
                description: "Mixing WAD/RAY scaling factors causes precision loss".to_string(),
                confidence: 0.80,
            });
        }

        if let Some(loc) = self.has_unbounded_compound_operations() {
            vulnerabilities.push(FixedPointDriftVulnerability {
                vulnerability_type: "Unbounded Compound Operations".to_string(),
                location: loc,
                severity: "Medium".to_string(),
                description: "Multiple fixed-point operations without precision checks".to_string(),
                confidence: 0.75,
            });
        }

        vulnerabilities
    }

    fn has_division_before_multiplication(&self) -> Option<usize> {
        // Pattern: DIV followed by MUL = precision loss
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x04 { // DIV
                for j in i+1..i+8.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x02 { // MUL (should be MUL then DIV)
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn has_loop_accumulation_drift(&self) -> Option<usize> {
        // Pattern: Loop with DIV/MUL operations
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x5b { // JUMPDEST (loop start)
                let mut has_fixed_point_op = false;
                let mut has_jump_back = false;

                for j in i+1..i+25.min(self.bytecode.len()) {
                    // Fixed-point operation
                    if self.bytecode[j] == 0x04 || self.bytecode[j] == 0x02 { // DIV or MUL
                        has_fixed_point_op = true;
                    }
                    // Loop back
                    if self.bytecode[j] == 0x57 { // JUMPI
                        has_jump_back = true;
                    }
                }

                if has_fixed_point_op && has_jump_back {
                    return Some(i);
                }
            }
        }
        None
    }

    fn has_scaling_factor_mismatch(&self) -> Option<usize> {
        // Look for: Different scaling constants (1e18 vs 1e27)
        // Common patterns: PUSH17 for 1e18, PUSH17 for 1e27
        let mut found_scales = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x70 { // PUSH17 (often used for scaling)
                found_scales.push(i);
            }
        }

        // If we have multiple different scaling constants = potential mismatch
        if found_scales.len() >= 2 {
            return Some(found_scales[0]);
        }
        None
    }

    fn has_unbounded_compound_operations(&self) -> Option<usize> {
        // Pattern: Multiple MUL/DIV without intermediate checks
        for i in 0..self.bytecode.len().saturating_sub(25) {
            let mut op_count = 0;
            let mut has_check = false;

            for j in i..i+20.min(self.bytecode.len()) {
                if self.bytecode[j] == 0x02 || self.bytecode[j] == 0x04 { // MUL/DIV
                    op_count += 1;
                }
                // Check: comparison or revert
                if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 || 
                   self.bytecode[j] == 0xfd { // LT/GT/REVERT
                    has_check = true;
                }
            }

            // 4+ operations without checks = drift risk
            if op_count >= 4 && !has_check {
                return Some(i);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_division_before_multiplication() {
        let bytecode = vec![
            0x04, // DIV (loses precision)
            0x02, // MUL (should be MUL first)
        ];
        
        let detector = FixedPointArithmeticDriftDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        assert!(!vulns.is_empty(), "Should detect div before mul");
    }

    #[test]
    fn test_safe_multiplication_first() {
        let bytecode = vec![
            0x02, // MUL (correct order)
            0x04, // DIV
        ];
        
        let detector = FixedPointArithmeticDriftDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        // Should have fewer precision issues
        assert!(vulns.len() < 2);
    }
}
