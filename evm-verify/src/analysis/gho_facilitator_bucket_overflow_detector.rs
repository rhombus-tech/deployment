use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct GhoFacilitatorBucketOverflowDetector {
    bytecode: Vec<u8>,
}

impl GhoFacilitatorBucketOverflowDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_bucket_capacity_overflow() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Critical,
                description: "Facilitator bucket capacity can overflow, allowing unlimited GHO minting beyond intended limits.".to_string(),
                pc,
                confidence: 0.90,
            });
        }

        if let Some(pc) = self.detect_cross_facilitator_manipulation() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Multiple facilitators can coordinate to bypass total supply caps.".to_string(),
                pc,
                confidence: 0.85,
            });
        }

        findings
    }

    fn detect_bucket_capacity_overflow(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(45) {
            if bytecode[i] == 0x54 { // SLOAD (bucket capacity)
                let mut has_capacity_check = false;
                let mut has_mint = false;

                for j in i+1..std::cmp::min(i+40, bytecode.len()) {
                    if bytecode[j] == 0x01 { // ADD (increase usage)
                        has_capacity_check = true;
                    }
                    if bytecode[j] == 0xF1 && has_capacity_check { // CALL (mint)
                        has_mint = true;
                    }
                }

                if has_capacity_check && has_mint {
                    return Some(i);
                }
            }
        }

        None
    }

    fn detect_cross_facilitator_manipulation(&self) -> Option<usize> {
        let bytecode = &self.bytecode;
        let mut facilitator_calls = 0;

        for i in 0..bytecode.len().saturating_sub(50) {
            if bytecode[i] == 0xF1 { // CALL (facilitator)
                facilitator_calls += 1;
                
                if facilitator_calls >= 2 {
                    for j in i+1..std::cmp::min(i+45, bytecode.len()) {
                        if bytecode[j] == 0x54 { // SLOAD (total supply)
                            return Some(i);
                        }
                    }
                }
            }
        }

        None
    }
}
