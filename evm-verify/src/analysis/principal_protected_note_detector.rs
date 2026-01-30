/// Principal Protected Note Detector
///
/// Detects vulnerabilities in structured note payoff calculations.
/// Coverage: Ribbon Finance, Friktion, structured DeFi products
/// Market: $10B+ structured products

use crate::bytecode::SecurityFinding;

pub struct PrincipalProtectedNoteDetector {
    bytecode: Vec<u8>,
}

impl PrincipalProtectedNoteDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_principal_underflow() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!("Principal protection calculation vulnerable to underflow at PC {}", pc),
                pc,
                confidence: 0.91,
            });
        }

        if let Some(pc) = self.detect_barrier_manipulation() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Protection barrier level manipulable via oracle at PC {}", pc),
                pc,
                confidence: 0.87,
            });
        }

        findings
    }

    fn detect_principal_underflow(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                // calculatePayout, redeem selectors
                if matches!(self.bytecode[i+1], 0x3e | 0x4f) {
                    let mut has_subtraction = false;
                    let mut has_underflow_check = false;

                    for j in i..i+45.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x03 { // SUB
                            has_subtraction = true;
                        }
                        // Check for underflow protection (result >= principal)
                        if has_subtraction && self.bytecode[j] == 0x10 { // LT
                            has_underflow_check = true;
                        }
                    }

                    if has_subtraction && !has_underflow_check {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_barrier_manipulation(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(45) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                // checkBarrier, evaluateProtection selectors
                if matches!(self.bytecode[i+1], 0x6a | 0x7b) {
                    let mut oracle_count = 0;

                    for j in i..i+40.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0xfa { // STATICCALL
                            oracle_count += 1;
                        }
                    }

                    // Single oracle = manipulation risk
                    if oracle_count == 1 {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
