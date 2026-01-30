use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoundryFuzzVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct FoundryFuzzSeedPredictabilityDetector {
    bytecode: Vec<u8>,
}

impl FoundryFuzzSeedPredictabilityDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<FoundryFuzzVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_deterministic_randomness());
        vulnerabilities.extend(self.detect_insufficient_fuzz_runs());
        vulnerabilities.extend(self.detect_input_constraint_bypass());
        vulnerabilities
    }

    fn detect_deterministic_randomness(&self) -> Vec<FoundryFuzzVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x20 { // KECCAK256 (randomness)
                let start = if pc > 80 { pc - 80 } else { 0 };
                let window = &self.bytecode[start..pc];
                if window.iter().filter(|&&b| b == 0x20).count() == 1 && !window.iter().any(|&b| b == 0x42) {
                    vulns.push(FoundryFuzzVulnerability {
                        pc, vulnerability_type: "DeterministicRandomness".to_string(),
                        description: format!("Randomness generation at PC {} deterministic with fixed seed, fuzzer finds same inputs every run.", pc),
                        confidence: 0.83,
                    });
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_insufficient_fuzz_runs(&self) -> Vec<FoundryFuzzVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x35 { // CALLDATALOAD
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                if window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 3 {
                    vulns.push(FoundryFuzzVulnerability {
                        pc, vulnerability_type: "InsufficientFuzzRuns".to_string(),
                        description: format!("Complex input validation at PC {} requires more fuzz runs than default 256 to find edge cases.", pc),
                        confidence: 0.75,
                    });
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_input_constraint_bypass(&self) -> Vec<FoundryFuzzVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x57 { // JUMPI (assume/bound)
                let start = if pc > 60 { pc - 60 } else { 0 };
                let window = &self.bytecode[start..pc];
                if window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 2 && !window.iter().any(|&b| b == 0xFD) {
                    vulns.push(FoundryFuzzVulnerability {
                        pc, vulnerability_type: "InputConstraintBypass".to_string(),
                        description: format!("Conditional at PC {} uses vm.assume() but constraint can be bypassed by fuzzer finding edge case inputs.", pc),
                        confidence: 0.79,
                    });
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }
}
