use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct SizeCreditFixedRateOracleManipulationDetector {
    bytecode: Vec<u8>,
}

impl SizeCreditFixedRateOracleManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_fixed_rate_oracle_manipulation() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Critical,
                description: "Fixed-rate lending oracle can be manipulated through flash loans or price lag exploitation, leading to undercollateralized positions.".to_string(),
                pc,
                confidence: 0.88,
            });
        }

        if let Some(pc) = self.detect_rate_model_gaming() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Interest rate model can be gamed through atomic operations to extract value or manipulate borrowing costs.".to_string(),
                pc,
                confidence: 0.82,
            });
        }

        findings
    }

    fn detect_fixed_rate_oracle_manipulation(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(50) {
            if bytecode[i] == 0xFA { // STATICCALL (oracle read)
                let mut has_div = false;
                let mut has_rate_calc = false;
                let mut has_borrow = false;

                for j in i+1..std::cmp::min(i+45, bytecode.len()) {
                    if bytecode[j] == 0x04 { has_div = true; }
                    if bytecode[j] == 0x02 { has_rate_calc = true; }
                    if bytecode[j] == 0xF1 && has_div && has_rate_calc {
                        has_borrow = true;
                    }
                }

                if has_div && has_rate_calc && has_borrow {
                    return Some(i);
                }
            }
        }

        None
    }

    fn detect_rate_model_gaming(&self) -> Option<usize> {
        let bytecode = &self.bytecode;
        let mut rate_calculations = 0;

        for i in 0..bytecode.len().saturating_sub(30) {
            if bytecode[i] == 0x54 { // SLOAD (rate storage)
                for j in i+1..std::cmp::min(i+25, bytecode.len()) {
                    if bytecode[j] == 0x04 || bytecode[j] == 0x02 {
                        rate_calculations += 1;
                        break;
                    }
                }
            }
        }

        if rate_calculations >= 3 {
            return Some(0);
        }

        None
    }
}
