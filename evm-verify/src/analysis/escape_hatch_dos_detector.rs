use serde::{Deserialize, Serialize};

/// Escape Hatch DOS: Block users from withdrawing via escape hatch
/// Attack: Grief withdrawal queue to prevent exits

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscapeHatchDosVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct EscapeHatchDosDetector {
    bytecode: Vec<u8>,
}

impl EscapeHatchDosDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<EscapeHatchDosVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_griefable_escape() {
            vulnerabilities.push(EscapeHatchDosVulnerability {
                vulnerability_type: "Griefable Escape Hatch".to_string(),
                location: loc,
                severity: "Critical".to_string(),
                description: "Escape mechanism vulnerable to DoS".to_string(),
                confidence: 0.90,
            });
        }
        vulnerabilities
    }
    fn has_griefable_escape(&self) -> Option<usize> {
        // Withdrawal processing in unbounded loop
        for i in 0..self.bytecode.len().saturating_sub(35) {
            if self.bytecode[i] == 0x5b { // JUMPDEST (loop start)
                let mut has_withdrawal = false;
                let mut has_gas_check = false;
                for j in i+1..i+30.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0xf1 { // CALL (withdrawal)
                        has_withdrawal = true;
                    }
                    if self.bytecode[j] == 0x5a { // GAS
                        has_gas_check = true;
                    }
                }
                if has_withdrawal && !has_gas_check { return Some(i); }
            }
        }
        None
    }
}
