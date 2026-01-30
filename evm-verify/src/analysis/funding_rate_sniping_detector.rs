use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FundingRateVulnerability {
    FundingRateSniping { description: String, location: usize, confidence: f32 },
    FundingTimestampManipulation { description: String, location: usize, confidence: f32 },
}

pub struct FundingRateSnipingDetector {
    bytecode: Vec<u8>,
}

impl FundingRateSnipingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<FundingRateVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Funding sniping: Open position right before funding payment, close immediately after
        
        for i in 0..self.bytecode.len().saturating_sub(90) {
            let section = &self.bytecode[i..std::cmp::min(i + 90, self.bytecode.len())];
            
            // Pattern: Funding payment without minimum holding period
            let has_funding_payment = section.windows(12).any(|w| {
                w.contains(&0x42) && // TIMESTAMP (check funding time)
                w.contains(&0x02) && // MUL (calculate payment)
                w.contains(&0xF1)    // CALL (transfer funds)
            });
            
            let no_min_holding = !section.windows(15).any(|w| {
                w.contains(&0x54) && // SLOAD (position open time)
                w.contains(&0x42) && // TIMESTAMP
                w.contains(&0x03) && // SUB (holding duration)
                w.contains(&0x10)    // LT (vs minimum)
            });
            
            if has_funding_payment && no_min_holding {
                vulnerabilities.push(FundingRateVulnerability::FundingRateSniping {
                    description: format!("Funding rate sniping at PC {}. Attack: 1) Funding in 1 minute, rate = +0.05% (shorts pay longs), 2) Open massive long position, 3) Collect funding, 4) Close position immediately. Profit = position_size * 0.05% in <1min. Example: $10M long → $5k profit in 60 seconds. Real: Bybit, FTX had this issue. Mitigation: Minimum holding period (1 hour) OR pro-rata funding based on time held.", i),
                    location: i,
                    confidence: 0.91,
                });
            }
            
            // Pattern: Funding timestamp without delay
            let has_timestamp_check = section.contains(&0x42); // TIMESTAMP
            let has_immediate_execute = section.windows(6).any(|w| {
                w.contains(&0x14) && // EQ (exact match)
                w.contains(&0xF1)    // CALL (execute)
            });
            
            if has_timestamp_check && has_immediate_execute {
                vulnerabilities.push(FundingRateVulnerability::FundingTimestampManipulation {
                    description: format!("Funding timestamp manipulation at PC {}. If funding executes at exact timestamp (e.g., 00:00:00 UTC), MEV bots can: 1) Frontrun funding tx, 2) Open favorable position, 3) Funding executes, 4) Close position same block. Mitigation: Randomized funding time (±5 min window), or delayed execution (funding calculated at T, executed at T+delay).", i),
                    location: i,
                    confidence: 0.83,
                });
            }
        }
        
        vulnerabilities
    }
}
