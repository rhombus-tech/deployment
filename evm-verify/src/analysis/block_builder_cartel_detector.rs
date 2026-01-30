use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct BlockBuilderCartelDetector;

impl BlockBuilderCartelDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if self.has_builder_coordination(bytecode, i) && self.lacks_decentralization(bytecode, i) {
                findings.push(SecurityFinding {
                    severity: SecuritySeverity::Critical,
                    description: "Block builder cartel: builder coordination without decentralization allows cartel formation".to_string(),
                    pc: i,
                    confidence: 0.87,
                });
            }
            i += 1;
        }

        findings
    }

    fn has_builder_coordination(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 35.min(bytecode.len().saturating_sub(pos));
        let mut has_sload = false;
        let mut has_call = false;
        let mut has_sstore = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x54 => has_sload = true,
                    0xf1 | 0xfa => has_call = true,
                    0x55 => has_sstore = true,
                    _ => {}
                }
            }
        }

        has_sload && has_call && has_sstore
    }

    fn lacks_decentralization(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 40.min(bytecode.len().saturating_sub(pos));
        let mut validation_count = 0;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x20 => validation_count += 1,
                    _ => {}
                }
            }
        }

        validation_count < 2
    }
}
