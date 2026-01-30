use serde::{Deserialize, Serialize};

/// Logarithm Approximation Attack Detector
/// Detects vulnerabilities in logarithm approximations (log2, ln, log10).
/// Taylor series and other approximations can be gamed at boundaries.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogarithmApproximationVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct LogarithmApproximationAttackDetector {
    bytecode: Vec<u8>,
}

impl LogarithmApproximationAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    
    pub fn detect_vulnerabilities(&self) -> Vec<LogarithmApproximationVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if let Some(loc) = self.has_unbounded_taylor_series() {
            vulnerabilities.push(LogarithmApproximationVulnerability {
                vulnerability_type: "Unbounded Taylor Series Approximation".to_string(),
                location: loc,
                severity: "High".to_string(),
                description: "Log approximation lacks iteration bounds, vulnerable to gaming".to_string(),
                confidence: 0.85,
            });
        }
        
        if let Some(loc) = self.has_boundary_precision_loss() {
            vulnerabilities.push(LogarithmApproximationVulnerability {
                vulnerability_type: "Log Boundary Precision Loss".to_string(),
                location: loc,
                severity: "Medium".to_string(),
                description: "Logarithm near 0 or overflow loses precision".to_string(),
                confidence: 0.75,
            });
        }
        
        vulnerabilities
    }
    
    fn has_unbounded_taylor_series(&self) -> Option<usize> {
        // Pattern: Loop (for Taylor series) without iteration limit
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x5b { // JUMPDEST (loop)
                let mut has_power_op = false;
                let mut has_bound = false;
                
                for j in i+1..i+25.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x0a { // EXP (power operation)
                        has_power_op = true;
                    }
                    if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 { // LT/GT bound
                        has_bound = true;
                    }
                }
                
                if has_power_op && !has_bound {
                    return Some(i);
                }
            }
        }
        None
    }
    
    fn has_boundary_precision_loss(&self) -> Option<usize> {
        // Pattern: Log-like operation without input validation
        for i in 0..self.bytecode.len().saturating_sub(15) {
            // Approximation: DIV in loop (log uses divisions)
            if self.bytecode[i] == 0x04 { // DIV
                let mut in_loop = false;
                let mut has_input_check = false;
                
                for j in i.saturating_sub(10)..i {
                    if self.bytecode[j] == 0x5b { in_loop = true; }
                    if self.bytecode[j] == 0x15 { has_input_check = true; } // ISZERO check
                }
                
                if in_loop && !has_input_check {
                    return Some(i);
                }
            }
        }
        None
    }
}
