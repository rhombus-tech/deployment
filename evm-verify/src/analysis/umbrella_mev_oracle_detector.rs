use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UmbrellaMevOracleVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: String,
}

pub struct UmbrellaMevOracleDetector {
    bytecode: Vec<u8>,
}

impl UmbrellaMevOracleDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<UmbrellaMevOracleVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Detect Umbrella oracle update without MEV protection
        if let Some(location) = self.has_oracle_update_without_mev_protection() {
            vulnerabilities.push(UmbrellaMevOracleVulnerability {
                vulnerability_type: "Umbrella Network MEV Oracle Attack".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "Umbrella Network oracle update vulnerable to MEV. Oracle data can be front-run before on-chain update completes. Implement commit-reveal or private transactions for oracle updates.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect oracle read in same block as update (sandwich opportunity)
        if let Some(location) = self.has_same_block_update_and_read() {
            vulnerabilities.push(UmbrellaMevOracleVulnerability {
                vulnerability_type: "Same-Block Oracle Update Sandwich".to_string(),
                location,
                severity: "High".to_string(),
                description: "Oracle data read in same block as update without delay. MEV bots can sandwich trades between oracle update and price-dependent operations.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        // Detect lack of MEV-resistant oracle aggregation
        if let Some(location) = self.has_vulnerable_aggregation() {
            vulnerabilities.push(UmbrellaMevOracleVulnerability {
                vulnerability_type: "Non-MEV-Resistant Oracle Aggregation".to_string(),
                location,
                severity: "High".to_string(),
                description: "Oracle data aggregation without MEV resistance. Aggregation logic can be exploited by observing pending oracle updates. Use time-weighted or block-delayed aggregation.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_oracle_update_without_mev_protection(&self) -> Option<usize> {
        // Pattern: Oracle update (CALL/DELEGATECALL) followed immediately by state change without delay
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0xf1 || self.bytecode[i] == 0xf4 { // CALL or DELEGATECALL
                // Check if followed by immediate SSTORE without block delay check
                let mut has_block_delay = false;
                
                for j in i+1..(i+15).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x43 { // NUMBER (block number check)
                        has_block_delay = true;
                    }
                    if self.bytecode[j] == 0x55 && !has_block_delay { // SSTORE without delay
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn has_same_block_update_and_read(&self) -> Option<usize> {
        // Pattern: Oracle read (STATICCALL) without block number comparison
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0xfa { // STATICCALL (oracle read)
                let mut has_block_check = false;
                
                // Look for block number check before use
                for j in i+1..(i+30).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x43 { // NUMBER
                        // Check for comparison operation
                        for k in j+1..(j+5).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x11 || self.bytecode[k] == 0x10 { // GT or LT
                                has_block_check = true;
                                break;
                            }
                        }
                    }
                }
                
                if !has_block_check {
                    // Check if used in critical operation
                    for j in i+1..(i+20).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0xf1 || self.bytecode[j] == 0x55 { // CALL or SSTORE
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn has_vulnerable_aggregation(&self) -> Option<usize> {
        // Pattern: Multiple oracle reads with immediate aggregation (no time-weighting)
        let mut oracle_calls = Vec::new();
        
        for i in 0..self.bytecode.len() {
            if self.bytecode[i] == 0xfa { // STATICCALL
                oracle_calls.push(i);
            }
        }
        
        // If multiple oracle calls found, check aggregation logic
        if oracle_calls.len() >= 2 {
            let first_call = oracle_calls[0];
            
            // Look for aggregation (ADD, DIV) without timestamp weighting
            for i in first_call..(first_call+50).min(self.bytecode.len()) {
                if self.bytecode[i] == 0x01 { // ADD
                    // Check if timestamp-weighted
                    let mut has_timestamp_weight = false;
                    
                    for j in i.saturating_sub(10)..(i+10).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x42 { // TIMESTAMP
                            for k in j+1..(j+5).min(self.bytecode.len()) {
                                if self.bytecode[k] == 0x02 || self.bytecode[k] == 0x04 { // MUL or DIV
                                    has_timestamp_weight = true;
                                    break;
                                }
                            }
                        }
                    }
                    
                    if !has_timestamp_weight {
                        return Some(first_call);
                    }
                }
            }
        }
        
        None
    }
}
