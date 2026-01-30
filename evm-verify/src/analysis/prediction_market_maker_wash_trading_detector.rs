use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct PredictionMarketMakerWashTradingDetector;

impl PredictionMarketMakerWashTradingDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if self.has_market_maker_logic(bytecode, i) && self.lacks_wash_trading_detection(bytecode, i) {
                findings.push(SecurityFinding {
                    severity: SecuritySeverity::High,
                    description: "Prediction market maker wash trading: market maker without wash trading detection allows artificial volume".to_string(),
                    pc: i,
                    confidence: 0.84,
                });
            }
            i += 1;
        }

        findings
    }

    fn has_market_maker_logic(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 35.min(bytecode.len().saturating_sub(pos));
        let mut has_balance_op = false;
        let mut has_transfer = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x31 => has_balance_op = true,
                    0xf1 | 0xfa => has_transfer = true,
                    _ => {}
                }
            }
        }

        has_balance_op && has_transfer
    }

    fn lacks_wash_trading_detection(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 40.min(pos);
        let mut caller_checks = 0;

        for offset in 1..=lookback {
            if pos >= offset && bytecode[pos - offset] == 0x33 {
                caller_checks += 1;
            }
        }

        caller_checks < 2
    }
}
