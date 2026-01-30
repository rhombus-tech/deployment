pub struct PerpetualFundingRateManipulationDetector {
    bytecode: Vec<u8>,
}

impl PerpetualFundingRateManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_funding_rate_oracle_manipulation() {
            findings.push("Perpetual: Funding rate oracle can be manipulated".to_string());
        }

        if self.has_settlement_timing_attack() {
            findings.push("Perpetual: Settlement timing can be exploited".to_string());
        }

        if self.has_position_skew_amplification() {
            findings.push("Perpetual: Position skew amplifies funding rate manipulation".to_string());
        }

        findings
    }

    fn has_funding_rate_oracle_manipulation(&self) -> bool {
        let funding_patterns = [b"funding", b"Funding", b"fundingRate"];
        let has_funding = funding_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_funding {
            // Check for oracle dependency
            let oracle_patterns = [b"oracle", b"price", b"mark"];
            let has_oracle = oracle_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            if has_oracle {
                // Check for TWAP protection
                let twap_patterns = [b"twap", b"average", b"weighted"];
                let has_twap = twap_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
                
                return !has_twap;
            }
        }
        
        false
    }

    fn has_settlement_timing_attack(&self) -> bool {
        let settle_patterns = [b"settle", b"Settlement", b"update"];
        let has_settle = settle_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_settle {
            // Check for timestamp dependency
            let has_timestamp = self.bytecode.iter().any(|&b| b == 0x42); // TIMESTAMP
            
            if has_timestamp {
                // Check for manipulation resistance
                let resistance_patterns = [b"interval", b"minTime", b"cooldown"];
                let has_resistance = resistance_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
                
                return !has_resistance;
            }
        }
        
        false
    }

    fn has_position_skew_amplification(&self) -> bool {
        let perpetual_patterns = [b"perpetual", b"perp", b"position"];
        let has_perpetual = perpetual_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_perpetual {
            // Check for skew calculation
            let skew_patterns = [b"skew", b"imbalance", b"long", b"short"];
            let has_skew = skew_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            if has_skew {
                // Check for skew limits
                let limit_patterns = [b"maxSkew", b"limit", b"cap"];
                let has_limit = limit_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
                
                return !has_limit;
            }
        }
        
        false
    }
}
