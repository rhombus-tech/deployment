pub struct BasisTradingFundingRateManipulationDetector {
    bytecode: Vec<u8>,
}

impl BasisTradingFundingRateManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_funding_rate_manipulation() {
            findings.push("Basis trading: Funding rate can be manipulated".to_string());
        }

        if self.has_mark_price_exploitation() {
            findings.push("Basis trading: Mark price vulnerable to manipulation".to_string());
        }

        if self.has_basis_arbitrage_frontrun() {
            findings.push("Basis trading: Basis arbitrage trades can be frontrun".to_string());
        }

        findings
    }

    fn has_funding_rate_manipulation(&self) -> bool {
        let funding_patterns: &[&[u8]] = &[b"fundingRate", b"funding", b"paymentRate"];
        let has_funding = funding_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_funding {
            // Check for oracle dependency
            let oracle_patterns: &[&[u8]] = &[b"oracle", b"price", b"mark"];
            let has_oracle = oracle_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            if has_oracle {
                // Check for manipulation protection
                let protection_patterns: &[&[u8]] = &[b"twap", b"median", b"vwap"];
                let has_protection = protection_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
                
                return !has_protection;
            }
        }
        
        false
    }

    fn has_mark_price_exploitation(&self) -> bool {
        let mark_patterns: &[&[u8]] = &[b"markPrice", b"indexPrice", b"fairPrice"];
        let has_mark = mark_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_mark {
            // Check for spot price influence
            let spot_patterns: &[&[u8]] = &[b"spotPrice", b"spot", b"currentPrice"];
            let has_spot = spot_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            return has_spot;
        }
        
        false
    }

    fn has_basis_arbitrage_frontrun(&self) -> bool {
        let basis_patterns: &[&[u8]] = &[b"basis", b"spread", b"arbitrage"];
        let has_basis = basis_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_basis {
            // Check for timestamp dependency
            let has_timestamp = self.bytecode.iter().any(|&b| b == 0x42); // TIMESTAMP
            
            // Check for slippage protection
            let slippage_patterns: &[&[u8]] = &[b"slippage", b"minOut", b"maxSlippage"];
            let has_slippage = slippage_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            return has_timestamp && !has_slippage;
        }
        
        false
    }
}
