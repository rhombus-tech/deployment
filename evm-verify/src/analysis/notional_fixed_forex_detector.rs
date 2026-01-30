use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NotionalFixedForexVulnerability {
    CrossCurrencyRateManipulation,
    FiatPegDeviationExploit,
    ForexOracleDesync,
    FixedRateBypass,
    CurrencyConversionError,
    CollateralCurrencyMismatch,
    LiquidationForexRisk,
    InterestRateDiscrepancy,
    ForexVolatilityExploit,
    MultiCurrencyArbitrage,
}

pub struct NotionalFixedForexDetector {
    bytecode: Vec<u8>,
}

impl NotionalFixedForexDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<NotionalFixedForexVulnerability> {
        let mut vulnerabilities = Vec::new();
        if !self.has_forex_oracle_check() {
            vulnerabilities.push(NotionalFixedForexVulnerability::ForexOracleDesync);
        }
        vulnerabilities
    }

    fn has_forex_oracle_check(&self) -> bool {
        self.bytecode.windows(4).any(|w| w[0] == 0x50 && w[1] == 0xd2)
    }
}
