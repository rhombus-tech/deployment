pub struct StablecoinDepegBankRunDetector {
    bytecode: Vec<u8>,
}

impl StablecoinDepegBankRunDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_depeg_amplification() {
            findings.push("Stablecoin depeg: Depeg can trigger cascading withdrawals".to_string());
        }

        if self.has_redemption_pause_risk() {
            findings.push("Stablecoin depeg: Redemption pause during depeg creates bank run".to_string());
        }

        if self.has_collateral_ratio_manipulation() {
            findings.push("Stablecoin depeg: Collateral ratio can be manipulated during stress".to_string());
        }

        findings
    }

    fn has_depeg_amplification(&self) -> bool {
        let stable_patterns: &[&[u8]] = &[b"stable", b"peg", b"anchor"];
        let has_stable = stable_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_stable {
            // Check for price dependency
            let price_patterns: &[&[u8]] = &[b"price", b"getPrice", b"oracle"];
            let has_price = price_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            if has_price {
                // Check for withdrawal/redemption
                let withdraw_patterns: &[&[u8]] = &[b"withdraw", b"redeem", b"unstake"];
                let has_withdraw = withdraw_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
                
                if has_withdraw {
                    // Check for circuit breaker
                    let breaker_patterns: &[&[u8]] = &[b"circuit", b"pause", b"emergency"];
                    let has_breaker = breaker_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
                    
                    return !has_breaker;
                }
            }
        }
        
        false
    }

    fn has_redemption_pause_risk(&self) -> bool {
        let redeem_patterns: &[&[u8]] = &[b"redeem", b"withdraw", b"exit"];
        let has_redeem = redeem_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_redeem {
            // Check for pause functionality
            let pause_patterns: &[&[u8]] = &[b"pause", b"paused", b"whenNotPaused"];
            let has_pause = pause_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            if has_pause {
                // Check for partial redemption support
                let partial_patterns: &[&[u8]] = &[b"partial", b"queue", b"delayed"];
                let has_partial = partial_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
                
                return !has_partial;
            }
        }
        
        false
    }

    fn has_collateral_ratio_manipulation(&self) -> bool {
        let collateral_patterns: &[&[u8]] = &[b"collateral", b"backing", b"reserve"];
        let has_collateral = collateral_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_collateral {
            // Check for ratio calculation
            let ratio_patterns: &[&[u8]] = &[b"ratio", b"Ratio", b"percentage"];
            let has_ratio = ratio_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            if has_ratio {
                // Check for oracle manipulation resistance
                let resistance_patterns: &[&[u8]] = &[b"twap", b"median", b"snapshot"];
                let has_resistance = resistance_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
                
                return !has_resistance;
            }
        }
        
        false
    }
}
