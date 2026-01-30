pub struct AutoCompoundingRewardDilutionDetector {
    bytecode: Vec<u8>,
}

impl AutoCompoundingRewardDilutionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_reward_dilution() {
            findings.push("Auto-compounding: Rewards can be diluted by front-runners".to_string());
        }

        if self.has_compound_timing_exploit() {
            findings.push("Auto-compounding: Compound timing vulnerable to manipulation".to_string());
        }

        if self.has_share_price_manipulation() {
            findings.push("Auto-compounding: Share price can be manipulated during compounding".to_string());
        }

        findings
    }

    fn has_reward_dilution(&self) -> bool {
        let compound_patterns: &[&[u8]] = &[b"compound", b"autoCompound", b"harvest"];
        let has_compound = compound_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_compound {
            // Check for reward distribution
            let reward_patterns: &[&[u8]] = &[b"reward", b"yield", b"earn"];
            let has_reward = reward_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            if has_reward {
                // Check for anti-dilution protection
                let protection_patterns: &[&[u8]] = &[b"lock", b"cooldown", b"delay"];
                let has_protection = protection_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
                
                return !has_protection;
            }
        }
        
        false
    }

    fn has_compound_timing_exploit(&self) -> bool {
        let compound_patterns: &[&[u8]] = &[b"compound", b"reinvest", b"harvest"];
        let has_compound = compound_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_compound {
            // Check for timestamp dependency
            let has_timestamp = self.bytecode.iter().any(|&b| b == 0x42); // TIMESTAMP
            
            // Check for block number dependency
            let has_blocknumber = self.bytecode.iter().any(|&b| b == 0x43); // NUMBER
            
            if has_timestamp || has_blocknumber {
                // Check for timing protection
                let timing_patterns: &[&[u8]] = &[b"lastCompound", b"nextCompound", b"minInterval"];
                let has_timing = timing_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
                
                return !has_timing;
            }
        }
        
        false
    }

    fn has_share_price_manipulation(&self) -> bool {
        let share_patterns: &[&[u8]] = &[b"share", b"totalSupply", b"pricePerShare"];
        let has_share = share_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_share {
            // Check for compound operation
            let compound_patterns: &[&[u8]] = &[b"compound", b"harvest"];
            let has_compound = compound_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            if has_compound {
                // Check for manipulation resistance
                let resistance_patterns: &[&[u8]] = &[b"snapshot", b"twap", b"checkpoint"];
                let has_resistance = resistance_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
                
                return !has_resistance;
            }
        }
        
        false
    }
}
