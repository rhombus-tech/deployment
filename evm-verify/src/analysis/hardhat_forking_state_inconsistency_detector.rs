use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardhatForkingVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct HardhatForkingStateInconsistencyDetector {
    bytecode: Vec<u8>,
}

impl HardhatForkingStateInconsistencyDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<HardhatForkingVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_fork_block_number_assumptions());
        vulnerabilities.extend(self.detect_cached_state_staleness());
        vulnerabilities.extend(self.detect_timestamp_manipulation());
        vulnerabilities
    }

    fn detect_fork_block_number_assumptions(&self) -> Vec<HardhatForkingVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x43 { // NUMBER
                let window_end = (pc + 80).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                if window.iter().any(|&b| b == 0x14) && !window.iter().filter(|&&b| b == 0x43).count() >= 2 {
                    vulns.push(HardhatForkingVulnerability {
                        pc, vulnerability_type: "ForkBlockNumberAssumption".to_string(),
                        description: format!("Block number check at PC {} assumes mainnet state but tests fork at specific block, causing inconsistencies.", pc),
                        confidence: 0.82,
                    });
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_cached_state_staleness(&self) -> Vec<HardhatForkingVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x54 { // SLOAD
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                if window.iter().filter(|&&b| b == 0x54).count() >= 3 && !window.iter().any(|&b| b == 0x55) {
                    vulns.push(HardhatForkingVulnerability {
                        pc, vulnerability_type: "CachedStateStaleness".to_string(),
                        description: format!("Storage read at PC {} uses cached fork state that may be stale if mainnet advanced.", pc),
                        confidence: 0.78,
                    });
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_timestamp_manipulation(&self) -> Vec<HardhatForkingVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x42 { // TIMESTAMP
                let window_end = (pc + 60).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                if window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 2 {
                    vulns.push(HardhatForkingVulnerability {
                        pc, vulnerability_type: "TimestampManipulation".to_string(),
                        description: format!("Timestamp check at PC {} may fail in forked tests where evm_setNextBlockTimestamp manipulates time.", pc),
                        confidence: 0.80,
                    });
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }
}
