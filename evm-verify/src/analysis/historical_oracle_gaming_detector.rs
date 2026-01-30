use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoricalOracleGamingVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: String,
}

pub struct HistoricalOracleGamingDetector {
    bytecode: Vec<u8>,
}

impl HistoricalOracleGamingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<HistoricalOracleGamingVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Detect use of outdated oracle data
        if let Some(location) = self.has_outdated_oracle_usage() {
            vulnerabilities.push(HistoricalOracleGamingVulnerability {
                vulnerability_type: "Historical Oracle Data Gaming".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "Contract uses historical oracle data without freshness validation. Attackers can exploit stale prices for arbitrage or liquidations. Enforce maximum staleness threshold (e.g., 1 hour).".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect TWAP manipulation via historical data
        if let Some(location) = self.has_twap_historical_manipulation() {
            vulnerabilities.push(HistoricalOracleGamingVulnerability {
                vulnerability_type: "TWAP Historical Data Manipulation".to_string(),
                location,
                severity: "High".to_string(),
                description: "Time-Weighted Average Price (TWAP) uses historical data that can be gamed. Attackers observe old prices and execute trades before TWAP updates. Use minimum observation window and multiple checkpoints.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect cached oracle reads without expiration
        if let Some(location) = self.has_cached_oracle_without_expiry() {
            vulnerabilities.push(HistoricalOracleGamingVulnerability {
                vulnerability_type: "Cached Oracle Without Expiration".to_string(),
                location,
                severity: "High".to_string(),
                description: "Oracle data cached without expiration time. Cached prices become stale and exploitable. Implement cache expiration based on oracle update frequency.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_outdated_oracle_usage(&self) -> Option<usize> {
        // Pattern: SLOAD of stored oracle data without timestamp validation
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x54 { // SLOAD (reading stored oracle data)
                // Check if followed by usage without freshness check
                let mut has_timestamp_check = false;
                
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    // Look for TIMESTAMP comparison
                    if self.bytecode[j] == 0x42 { // TIMESTAMP
                        for k in j+1..(j+5).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x03 { // SUB (timestamp difference)
                                for m in k+1..(k+5).min(self.bytecode.len()) {
                                    if self.bytecode[m] == 0x10 || self.bytecode[m] == 0x11 { // LT or GT
                                        has_timestamp_check = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                
                // If data used without freshness check
                if !has_timestamp_check {
                    for j in i+1..i+15.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x02 || self.bytecode[j] == 0x04 { // MUL or DIV (calculations)
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn has_twap_historical_manipulation(&self) -> Option<usize> {
        // Pattern: Time-weighted average without sufficient observation count
        for i in 0..self.bytecode.len().saturating_sub(40) {
            // Look for TWAP pattern: multiple SLOADs + timestamp weighting + averaging
            if self.bytecode[i] == 0x54 { // SLOAD
                let mut has_time_weighting = false;
                let mut has_averaging = false;
                let mut observation_count = 0;
                
                // Count observations (SLOADs)
                for j in i..(i+50).min(self.bytecode.len()) {
                    if j >= self.bytecode.len() { break; }
                    if self.bytecode[j] == 0x54 { // SLOAD
                        observation_count += 1;
                    }
                    // Look for timestamp multiplication (time-weighting)
                    if self.bytecode[j] == 0x42 { // TIMESTAMP
                        for k in (j+1)..(j+5).min(self.bytecode.len()) {
                            if k >= self.bytecode.len() { break; }
                            if self.bytecode[k] == 0x02 { // MUL
                                has_time_weighting = true;
                            }
                        }
                    }
                    // Look for averaging (ADD followed by DIV)
                    if self.bytecode[j] == 0x01 { // ADD
                        for k in (j+1)..(j+10).min(self.bytecode.len()) {
                            if k >= self.bytecode.len() { break; }
                            if self.bytecode[k] == 0x04 { // DIV
                                has_averaging = true;
                            }
                        }
                    }
                }
                
                // TWAP with insufficient observations (< 3)
                if has_time_weighting && has_averaging && observation_count < 3 {
                    return Some(i);
                }
            }
        }
        None
    }

    fn has_cached_oracle_without_expiry(&self) -> Option<usize> {
        // Pattern: SSTORE after oracle call without timestamp storage
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0xfa { // STATICCALL (oracle read)
                // Look for SSTORE (caching)
                for j in i+1..i+20.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x55 { // SSTORE
                        // Check if timestamp is also stored (indicates expiration tracking)
                        let mut has_timestamp_storage = false;
                        
                        for k in j+1..(j+15).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x42 { // TIMESTAMP
                                for m in k+1..(k+5).min(self.bytecode.len()).min(self.bytecode.len()) {
                                    if self.bytecode[m] == 0x55 { // SSTORE timestamp
                                        has_timestamp_storage = true;
                                        break;
                                    }
                                }
                            }
                        }
                        
                        if !has_timestamp_storage {
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }
}
