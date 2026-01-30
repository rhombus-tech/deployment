use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatspecVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct NatspecMissingSecurityNoticeDetector {
    bytecode: Vec<u8>,
}

impl NatspecMissingSecurityNoticeDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<NatspecVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_undocumented_delegatecall());
        vulnerabilities.extend(self.detect_missing_reentrancy_warning());
        vulnerabilities.extend(self.detect_undocumented_access_control());
        vulnerabilities
    }

    fn detect_undocumented_delegatecall(&self) -> Vec<NatspecVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0xF4 { // DELEGATECALL
                vulns.push(NatspecVulnerability {
                    pc, vulnerability_type: "UndocumentedDelegatecall".to_string(),
                    description: format!("DELEGATECALL at PC {} lacks NatSpec @notice warning about execution context risks and storage collision.", pc),
                    confidence: 0.85,
                });
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_missing_reentrancy_warning(&self) -> Vec<NatspecVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0xF1 { // CALL
                let window_end = (pc + 80).min(self.bytecode.len());
                if self.bytecode[pc..window_end].iter().any(|&b| b == 0x55) {
                    vulns.push(NatspecVulnerability {
                        pc, vulnerability_type: "MissingReentrancyWarning".to_string(),
                        description: format!("External call at PC {} with state changes lacks @custom:security-note about reentrancy protection.", pc),
                        confidence: 0.81,
                    });
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_undocumented_access_control(&self) -> Vec<NatspecVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x55 { // SSTORE (privileged operation)
                let start = if pc > 80 { pc - 80 } else { 0 };
                if self.bytecode[start..pc].iter().any(|&b| b == 0x33) {
                    vulns.push(NatspecVulnerability {
                        pc, vulnerability_type: "UndocumentedAccessControl".to_string(),
                        description: format!("Privileged function at PC {} lacks @dev explanation of access control requirements and risks.", pc),
                        confidence: 0.78,
                    });
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }
}
