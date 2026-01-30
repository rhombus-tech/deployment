use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct LiquidDemocracyDelegationCycleDetector;

impl LiquidDemocracyDelegationCycleDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if self.has_delegation_logic(bytecode, i) && self.lacks_cycle_detection(bytecode, i) {
                findings.push(SecurityFinding {
                    severity: SecuritySeverity::High,
                    description: "Liquid democracy delegation cycle: delegation logic without cycle detection allows infinite loops and DOS".to_string(),
                    pc: i,
                    confidence: 0.87,
                });
            }
            i += 1;
        }

        findings
    }

    fn has_delegation_logic(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 30.min(bytecode.len().saturating_sub(pos));
        let mut has_sload = false;
        let mut has_sstore = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x54 => has_sload = true,
                    0x55 => has_sstore = true,
                    _ => {}
                }
            }
        }

        has_sload && has_sstore
    }

    fn lacks_cycle_detection(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 40.min(bytecode.len().saturating_sub(pos));
        let mut loop_protection = 0;

        for offset in 0..window {
            if pos + offset + 1 < bytecode.len() {
                if bytecode[pos + offset] == 0x57 {
                    loop_protection += 1;
                }
            }
        }

        loop_protection < 2
    }
}
