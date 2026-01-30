use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct DutchAuctionPriceStalenessDetector;

impl DutchAuctionPriceStalenessDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if bytecode[i] == 0x42 {
                if self.has_price_decay(bytecode, i) && self.lacks_freshness_check(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Medium,
                        description: "Dutch auction price staleness: timestamp-based price decay without freshness check allows stale pricing".to_string(),
                        pc: i,
                        confidence: 0.84,
                    });
                }
            }
            i += 1;
        }

        findings
    }

    fn has_price_decay(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 25.min(bytecode.len().saturating_sub(pos));
        let mut has_sub = false;
        let mut has_mul = false;

        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x03 => has_sub = true,
                    0x02 => has_mul = true,
                    _ => {}
                }
            }
        }

        has_sub && has_mul
    }

    fn lacks_freshness_check(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 30.min(bytecode.len().saturating_sub(pos));
        for offset in 1..window {
            if pos + offset + 1 < bytecode.len() {
                if bytecode[pos + offset] == 0x03 && bytecode[pos + offset + 1] == 0x10 {
                    return false;
                }
            }
        }
        true
    }
}
