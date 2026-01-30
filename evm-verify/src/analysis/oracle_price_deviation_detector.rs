use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OraclePriceDeviationVulnerability {
    NoCircuitBreaker { description: String, location: usize, confidence: f32 },
    NoDeviationCheck { description: String, location: usize },
    ExcessiveDeviationAllowed { description: String, location: usize, max_deviation_bps: u64 },
    SingleOracleNoValidation { description: String, location: usize },
}

pub struct OraclePriceDeviationDetector {
    bytecode: Vec<u8>,
}

impl OraclePriceDeviationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<OraclePriceDeviationVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(120) {
            if self.is_price_fetch(i) {
                if !self.has_circuit_breaker(i, i + 120) {
                    vulnerabilities.push(OraclePriceDeviationVulnerability::NoCircuitBreaker {
                        description: "Oracle price used without circuit breaker - flash crash risk".to_string(),
                        location: i,
                        confidence: 0.85,
                    });
                }
                
                if !self.validates_price_deviation(i, i + 120) {
                    vulnerabilities.push(OraclePriceDeviationVulnerability::NoDeviationCheck {
                        description: "No price deviation check against previous price".to_string(),
                        location: i,
                    });
                }
                
                if let Some(max_dev) = self.get_max_deviation(i, i + 120) {
                    // >20% deviation is dangerous
                    if max_dev > 2000 {
                        vulnerabilities.push(OraclePriceDeviationVulnerability::ExcessiveDeviationAllowed {
                            description: format!("Max price deviation of {}bps too high - flash crash exploitable", max_dev),
                            location: i,
                            max_deviation_bps: max_dev,
                        });
                    }
                }
            }
        }
        
        if self.uses_single_oracle() && !self.has_fallback_oracle() {
            vulnerabilities.push(OraclePriceDeviationVulnerability::SingleOracleNoValidation {
                description: "Single oracle without fallback or validation".to_string(),
                location: 0,
            });
        }
        
        vulnerabilities
    }
    
    fn is_price_fetch(&self, location: usize) -> bool {
        if location + 20 > self.bytecode.len() {
            return false;
        }
        
        // latestAnswer(), latestRoundData(), getPrice() selectors
        let selectors = [
            [0x50, 0xd2, 0x5b, 0xcd], // latestAnswer
            [0xfe, 0xaf, 0x96, 0x8c], // latestRoundData
            [0x41, 0x97, 0x6e, 0x09], // getPrice (common)
        ];
        
        selectors.iter().any(|sel| {
            self.bytecode[location..location + 20].windows(4).any(|w| w == sel)
        })
    }
    
    fn has_circuit_breaker(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Circuit breaker: price comparison with min/max bounds + revert
        let has_bounds_check = self.bytecode[start..range_end]
            .windows(3)
            .any(|w| {
                (w[0] == 0x10 || w[0] == 0x11) && // LT or GT
                (w[1] == 0x57 || w[2] == 0xFD)     // JUMPI or REVERT
            });
        
        has_bounds_check
    }
    
    fn validates_price_deviation(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Deviation check: |newPrice - oldPrice| / oldPrice
        // Pattern: SUB + DIV + comparison
        let mut has_sub = false;
        let mut has_div = false;
        
        for i in start..range_end {
            if self.bytecode[i] == 0x03 { has_sub = true; }
            if has_sub && self.bytecode[i] == 0x04 { has_div = true; }
            if has_div && (self.bytecode[i] == 0x10 || self.bytecode[i] == 0x11) {
                return true;
            }
        }
        
        false
    }
    
    fn get_max_deviation(&self, start: usize, end: usize) -> Option<u64> {
        let range_end = end.min(self.bytecode.len());
        
        // Look for deviation threshold constant (in basis points, typically 100-2000)
        for i in start..range_end.saturating_sub(3) {
            if self.bytecode[i] == 0x61 { // PUSH2
                if i + 2 < range_end {
                    let value = ((self.bytecode[i + 1] as u64) << 8) | (self.bytecode[i + 2] as u64);
                    if value >= 100 && value <= 10000 {
                        return Some(value);
                    }
                }
            }
        }
        
        None
    }
    
    fn uses_single_oracle(&self) -> bool {
        // Count oracle calls
        let oracle_calls = self.bytecode.windows(4).filter(|w| {
            matches!(w, [0x50, 0xd2, 0x5b, 0xcd] | [0xfe, 0xaf, 0x96, 0x8c])
        }).count();
        
        oracle_calls == 1
    }
    
    fn has_fallback_oracle(&self) -> bool {
        // Multiple oracle implementations
        self.bytecode.windows(4).filter(|w| {
            matches!(w, [0x50, 0xd2, 0x5b, 0xcd] | [0xfe, 0xaf, 0x96, 0x8c])
        }).count() > 1
    }
}
