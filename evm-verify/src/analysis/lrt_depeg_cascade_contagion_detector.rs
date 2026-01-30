use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct LrtDepegCascadeContagionDetector {
    bytecode: Vec<u8>,
}

impl LrtDepegCascadeContagionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_lrt_price_feed_dependency() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Critical,
                description: "LRT pricing depends on other LRTs creating circular dependency. Depeg in one LRT can cascade across ecosystem causing systemic failure.".to_string(),
                pc,
                confidence: 0.90,
            });
        }

        if let Some(pc) = self.detect_redemption_rate_manipulation() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Redemption rate can be manipulated through oracle attacks, triggering depeg cascade.".to_string(),
                pc,
                confidence: 0.85,
            });
        }

        findings
    }

    fn detect_lrt_price_feed_dependency(&self) -> Option<usize> {
        let bytecode = &self.bytecode;
        let mut external_price_calls = 0;

        for i in 0..bytecode.len().saturating_sub(20) {
            if bytecode[i] == 0xFA { // STATICCALL (oracle read)
                external_price_calls += 1;
                
                for j in i+1..std::cmp::min(i+15, bytecode.len()) {
                    if bytecode[j] == 0x04 || bytecode[j] == 0x05 { // DIV or SDIV (price calc)
                        if external_price_calls >= 2 {
                            return Some(i);
                        }
                    }
                }
            }
        }

        None
    }

    fn detect_redemption_rate_manipulation(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(30) {
            if bytecode[i] == 0xFA { // STATICCALL
                let mut has_division = false;
                let mut has_balance_check = false;

                for j in i+1..std::cmp::min(i+25, bytecode.len()) {
                    if bytecode[j] == 0x04 { has_division = true; }
                    if bytecode[j] == 0x31 { has_balance_check = true; } // BALANCE
                }

                if has_division && has_balance_check {
                    return Some(i);
                }
            }
        }

        None
    }
}
