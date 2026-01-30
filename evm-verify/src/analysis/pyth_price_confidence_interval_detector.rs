use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PythConfidenceVulnerability {
    ConfidenceIntervalNotChecked { description: String, location: usize, confidence: f32 },
    StalePublisherCount { description: String, location: usize, confidence: f32 },
}

pub struct PythPriceConfidenceIntervalDetector {
    bytecode: Vec<u8>,
}

impl PythPriceConfidenceIntervalDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<PythConfidenceVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pyth Network: price comes with confidence interval - MUST validate
        for i in 0..self.bytecode.len().saturating_sub(80) {
            let section = &self.bytecode[i..std::cmp::min(i + 80, self.bytecode.len())];
            
            // Pyth price read pattern
            let has_pyth_read = section.windows(4).any(|w| {
                w[0] == 0x63 && w[1] == 0x45 // getPrice() or similar
            });
            
            // Check if confidence field is validated
            let validates_confidence = section.windows(15).any(|w| {
                w.contains(&0x35) && // CALLDATALOAD (read conf field)
                w.contains(&0x10) && // LT (check threshold)
                w.contains(&0x57)    // JUMPI (revert if too wide)
            });
            
            if has_pyth_read && !validates_confidence {
                vulnerabilities.push(PythConfidenceVulnerability::ConfidenceIntervalNotChecked {
                    description: format!("Pyth price confidence interval not validated at PC {}. Pyth returns (price, conf, publishTime). 'conf' = confidence interval (±). Example: price=$2000, conf=$100 → actual price in [$1900, $2100]. Risk: During volatility, conf spikes to $500+ → using midpoint causes 25% error. Require: conf/price < MAX_CONF_RATIO (e.g., 2%). Code: require(price.conf * 100 / price.price < 200, 'HIGH_CONF');", i),
                    location: i,
                    confidence: 0.89,
                });
            }
        }
        
        vulnerabilities
    }
}
