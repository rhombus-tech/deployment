use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EMHVulnerability {
    pub location: usize,
    pub confidence: f32,
    pub description: String,
    pub vulnerability_type: String,
}

pub struct EfficientMarketViolationDetector { 
    bytecode: Vec<u8> 
}

impl EfficientMarketViolationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { 
        Self { bytecode } 
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<EMHVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Detect price discrepancies enabling arbitrage
        if let Some((pc, profit)) = self.detect_price_discrepancy_arbitrage() {
            vulnerabilities.push(EMHVulnerability {
                location: pc,
                confidence: 0.80,
                description: format!(
                    "Contract has exploitable price discrepancy allowing {:.2}% arbitrage profit",
                    profit * 100.0
                ),
                vulnerability_type: "ArbitrageOpportunity".to_string(),
            });
        }
        
        // Detect delayed price updates
        if let Some((pc, profit)) = self.detect_stale_price_exploitation() {
            vulnerabilities.push(EMHVulnerability {
                location: pc,
                confidence: 0.75,
                description: format!(
                    "Delayed price updates create {:.2}% arbitrage window before market efficiency restored",
                    profit * 100.0
                ),
                vulnerability_type: "StalePriceExploitation".to_string(),
            });
        }
        
        vulnerabilities
    }
    
    fn detect_price_discrepancy_arbitrage(&self) -> Option<(usize, f64)> {
        // Look for contracts that read prices from multiple sources without arbitrage protection
        let mut price_sources = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if matches!(self.bytecode[i], 0xf1 | 0xfa) { // CALL or STATICCALL
                // Check if this is a price oracle call
                for j in (i.saturating_sub(20)..i).rev() {
                    if self.bytecode[j] == 0x63 && j + 4 < self.bytecode.len() { // PUSH4
                        let sig = &self.bytecode[j+1..j+5];
                        // Price-related function signatures
                        if matches!(sig, [0x50, 0xd2, _, _] | [0xb5, 0xab, _, _] | [0xfe, 0xaf, _, _]) {
                            price_sources.push(i);
                        }
                    }
                }
            }
        }
        
        // If multiple price sources without comparison/averaging
        if price_sources.len() >= 2 {
            let first_price = price_sources[0];
            let second_price = price_sources[1];
            
            // Check if prices are compared or averaged
            let mut has_comparison = false;
            for i in first_price..second_price.min(first_price + 50) {
                if matches!(self.bytecode[i], 0x10 | 0x11 | 0x01 | 0x04) { // LT, GT, ADD, DIV
                    has_comparison = true;
                }
            }
            
            // No comparison = potential arbitrage
            if !has_comparison {
                return Some((first_price, 0.05)); // 5% potential arbitrage
            }
        }
        
        None
    }
    
    fn detect_stale_price_exploitation(&self) -> Option<(usize, f64)> {
        // Look for price storage without timestamp checks
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x54 { // SLOAD (loading stored price)
                let mut has_timestamp_check = false;
                let mut used_in_value_calc = false;
                
                // Check if timestamp is verified
                for j in i..i.saturating_add(20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x42 { // TIMESTAMP
                        // Look for comparison
                        for k in j..j.saturating_add(8).min(self.bytecode.len()) {
                            if matches!(self.bytecode[k], 0x10 | 0x11) { // LT or GT
                                has_timestamp_check = true;
                            }
                        }
                    }
                    
                    // Check if price is used in financial calculation
                    if matches!(self.bytecode[j], 0x02 | 0x04) && j > i { // MUL or DIV
                        used_in_value_calc = true;
                    }
                }
                
                // Stale price used without staleness check
                if used_in_value_calc && !has_timestamp_check {
                    return Some((i, 0.03)); // 3% potential profit from stale prices
                }
            }
        }
        None
    }
}
