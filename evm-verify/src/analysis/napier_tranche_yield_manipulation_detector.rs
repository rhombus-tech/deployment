use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct NapierTrancheYieldManipulationDetector {
    bytecode: Vec<u8>,
}

impl NapierTrancheYieldManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_tranche_yield_manipulation() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Yield distribution across tranches can be manipulated through flash loan attacks or timestamp exploitation, favoring senior/junior tranches unfairly.".to_string(),
                pc,
                confidence: 0.85,
            });
        }

        if let Some(pc) = self.detect_cross_tranche_arbitrage() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Medium,
                description: "Price differences between tranches can be exploited atomically for risk-free profit.".to_string(),
                pc,
                confidence: 0.80,
            });
        }

        findings
    }

    fn detect_tranche_yield_manipulation(&self) -> Option<usize> {
        let bytecode = &self.bytecode;
        let mut tranche_operations = 0;

        for i in 0..bytecode.len().saturating_sub(50) {
            if bytecode[i] == 0x54 { // SLOAD (tranche state)
                for j in i+1..std::cmp::min(i+45, bytecode.len()) {
                    if bytecode[j] == 0x04 { // DIV (yield calculation)
                        tranche_operations += 1;
                        if bytecode[j+1] == 0x55 { // SSTORE (update)
                            if tranche_operations >= 2 {
                                return Some(i);
                            }
                        }
                    }
                }
            }
        }

        None
    }

    fn detect_cross_tranche_arbitrage(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(60) {
            if bytecode[i] == 0xF1 { // CALL (swap in one tranche)
                for j in i+1..std::cmp::min(i+55, bytecode.len()) {
                    if bytecode[j] == 0xF1 { // CALL (swap in another tranche)
                        for k in j+1..std::cmp::min(j+20, bytecode.len()) {
                            if bytecode[k] == 0x10 || bytecode[k] == 0x11 { // LT/GT (profit check)
                                return Some(i);
                            }
                        }
                    }
                }
            }
        }

        None
    }
}
