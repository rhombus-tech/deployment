use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct ThrusterBlastNativeYieldIntegrationDetector {
    bytecode: Vec<u8>,
}

impl ThrusterBlastNativeYieldIntegrationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_native_yield_manipulation() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Blast native yield integration can be manipulated to extract yield that should belong to LPs.".to_string(),
                pc,
                confidence: 0.85,
            });
        }

        if let Some(pc) = self.detect_rebasing_token_accounting_error() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Medium,
                description: "Rebasing tokens with Blast yield can cause accounting errors in liquidity pools.".to_string(),
                pc,
                confidence: 0.80,
            });
        }

        findings
    }

    fn detect_native_yield_manipulation(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(50) {
            if bytecode[i] == 0xFA { // STATICCALL (yield oracle)
                let mut has_yield_calc = false;
                let mut has_distribution = false;

                for j in i+1..std::cmp::min(i+45, bytecode.len()) {
                    if bytecode[j] == 0x02 { // MUL (yield calculation)
                        has_yield_calc = true;
                    }
                    if bytecode[j] == 0xF1 && has_yield_calc { // CALL (distribute)
                        has_distribution = true;
                    }
                }

                if has_yield_calc && has_distribution {
                    return Some(i);
                }
            }
        }

        None
    }

    fn detect_rebasing_token_accounting_error(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(40) {
            if bytecode[i] == 0x54 { // SLOAD (balance)
                for j in i+1..std::cmp::min(i+35, bytecode.len()) {
                    if bytecode[j] == 0x01 { // ADD (rebase adjustment)
                        for k in j+1..std::cmp::min(j+15, bytecode.len()) {
                            if bytecode[k] == 0x55 { // SSTORE without proper tracking
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
