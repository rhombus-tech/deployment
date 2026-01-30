use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct GnosisSafeModuleSupplyChainAttackDetector;

impl GnosisSafeModuleSupplyChainAttackDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if self.has_module_logic(bytecode, i) && self.lacks_supply_chain_validation(bytecode, i) {
                findings.push(SecurityFinding {
                    severity: SecuritySeverity::Critical,
                    description: "Gnosis Safe module supply chain attack: module operations without supply chain validation allow malicious modules".to_string(),
                    pc: i,
                    confidence: 0.88,
                });
            }
            i += 1;
        }

        findings
    }

    fn has_module_logic(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 35.min(bytecode.len().saturating_sub(pos));
        let mut has_delegatecall = false;
        let mut has_sload = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0xf4 => has_delegatecall = true,
                    0x54 => has_sload = true,
                    _ => {}
                }
            }
        }

        has_delegatecall && has_sload
    }

    fn lacks_supply_chain_validation(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 30.min(pos);
        let mut validation_count = 0;

        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x14 | 0x20 => validation_count += 1,
                    _ => {}
                }
            }
        }

        validation_count < 2
    }
}
