use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct SenseFinanceAdapterYieldSkewDetector {
    bytecode: Vec<u8>,
}

impl SenseFinanceAdapterYieldSkewDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_adapter_yield_skew() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Adapter-specific yield calculations can be skewed through oracle manipulation or adapter-specific exploits, causing unfair distribution.".to_string(),
                pc,
                confidence: 0.86,
            });
        }

        if let Some(pc) = self.detect_scale_manipulation() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Medium,
                description: "Scale factor used for yield normalization can be manipulated to favor certain positions.".to_string(),
                pc,
                confidence: 0.81,
            });
        }

        findings
    }

    fn detect_adapter_yield_skew(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(50) {
            if bytecode[i] == 0xFA { // STATICCALL (adapter call)
                let mut has_scale = false;
                let mut has_yield_calc = false;

                for j in i+1..std::cmp::min(i+45, bytecode.len()) {
                    if bytecode[j] == 0x02 { // MUL (scale application)
                        has_scale = true;
                    }
                    if bytecode[j] == 0x04 && has_scale { // DIV (yield)
                        has_yield_calc = true;
                    }
                }

                if has_scale && has_yield_calc {
                    return Some(i);
                }
            }
        }

        None
    }

    fn detect_scale_manipulation(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(40) {
            if bytecode[i] == 0x54 { // SLOAD (scale factor)
                for j in i+1..std::cmp::min(i+35, bytecode.len()) {
                    if bytecode[j] == 0x55 { // SSTORE (update scale)
                        for k in j+1..std::cmp::min(j+15, bytecode.len()) {
                            if bytecode[k] == 0x02 || bytecode[k] == 0x04 {
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
