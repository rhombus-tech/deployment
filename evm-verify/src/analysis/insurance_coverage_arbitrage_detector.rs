use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct InsuranceCoverageArbitrageDetector;

impl InsuranceCoverageArbitrageDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if self.has_coverage_pricing(bytecode, i) && self.has_market_price_check(bytecode, i) && self.lacks_arbitrage_protection(bytecode, i) {
                findings.push(SecurityFinding {
                    severity: SecuritySeverity::High,
                    description: "Insurance coverage arbitrage vulnerability: pricing discrepancy between coverage and market without arbitrage protection".to_string(),
                    pc: i,
                    confidence: 0.87,
                });
            }
            i += 1;
        }

        findings
    }

    fn has_coverage_pricing(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 30.min(bytecode.len().saturating_sub(pos));
        let mut has_mul = false;
        let mut has_div = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x02 => has_mul = true,
                    0x04 => has_div = true,
                    _ => {}
                }
            }
        }

        has_mul && has_div
    }

    fn has_market_price_check(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 25.min(bytecode.len().saturating_sub(pos));
        for offset in 0..window {
            if pos + offset < bytecode.len() {
                let op = bytecode[pos + offset];
                if op == 0xf1 || op == 0xfa {
                    return true;
                }
            }
        }
        false
    }

    fn lacks_arbitrage_protection(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 35.min(bytecode.len().saturating_sub(pos));
        for offset in 0..window {
            if pos + offset + 1 < bytecode.len() {
                if bytecode[pos + offset] == 0x10 && bytecode[pos + offset + 1] == 0x57 {
                    return false;
                }
            }
        }
        true
    }
}
