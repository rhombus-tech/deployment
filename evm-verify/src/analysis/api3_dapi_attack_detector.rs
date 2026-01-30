use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Api3DapiVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: String,
}

pub struct Api3DapiAttackDetector {
    bytecode: Vec<u8>,
}

impl Api3DapiAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<Api3DapiVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Detect API3 dAPI read without beacon update timestamp validation
        if let Some(location) = self.has_dapi_read_without_timestamp_check() {
            vulnerabilities.push(Api3DapiVulnerability {
                vulnerability_type: "API3 dAPI Stale Data Attack".to_string(),
                location,
                severity: "High".to_string(),
                description: "API3 dAPI read detected without beacon update timestamp validation. First-party oracle data could be stale if Airnode fails to update. Implement heartbeat and deviation threshold checks.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        // Detect dAPI read without deviation threshold validation
        if let Some(location) = self.has_dapi_without_deviation_check() {
            vulnerabilities.push(Api3DapiVulnerability {
                vulnerability_type: "API3 dAPI Deviation Threshold Bypass".to_string(),
                location,
                severity: "High".to_string(),
                description: "API3 dAPI used without deviation threshold validation. Price could be outdated if deviation threshold not met. Verify both time-based and deviation-based updates.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        // Detect single beacon usage without beacon set aggregation
        if let Some(location) = self.has_single_beacon_without_set() {
            vulnerabilities.push(Api3DapiVulnerability {
                vulnerability_type: "API3 Single Beacon Risk".to_string(),
                location,
                severity: "Medium".to_string(),
                description: "Single API3 beacon read without beacon set aggregation. Single Airnode failure could cause oracle outage. Use beacon sets for redundancy.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_dapi_read_without_timestamp_check(&self) -> Option<usize> {
        // Pattern: STATICCALL (dAPI read) without subsequent TIMESTAMP comparison
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0xfa { // STATICCALL
                let mut has_timestamp_check = false;
                
                for j in (i+1)..(i+25).min(self.bytecode.len()) {
                    if j >= self.bytecode.len() { break; }
                    if self.bytecode[j] == 0x42 { // TIMESTAMP
                        // Look for comparison (LT, GT, SUB)
                        for k in (j+1)..(j+5).min(self.bytecode.len()) {
                            if k >= self.bytecode.len() { break; }
                            if self.bytecode[k] == 0x10 || self.bytecode[k] == 0x11 || self.bytecode[k] == 0x03 {
                                has_timestamp_check = true;
                                break;
                            }
                        }
                    }
                }
                
                if !has_timestamp_check {
                    // Check if data is used directly in state change
                    for j in i+1..i+15.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x55 { // SSTORE
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn has_dapi_without_deviation_check(&self) -> Option<usize> {
        // Pattern: Oracle read without price comparison (deviation check)
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0xfa { // STATICCALL
                let mut has_deviation_check = false;
                
                // Look for SUB (price difference) followed by DIV (percentage calculation)
                for j in i+1..i+30.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x03 { // SUB
                        for k in j+1..(j+10).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x04 { // DIV (calculating percentage)
                                has_deviation_check = true;
                                break;
                            }
                        }
                    }
                }
                
                if !has_deviation_check {
                    return Some(i);
                }
            }
        }
        None
    }

    fn has_single_beacon_without_set(&self) -> Option<usize> {
        // Pattern: Single oracle call without aggregation from multiple sources
        let mut oracle_call_count = 0;
        let first_call_location = self.bytecode.iter().position(|&b| b == 0xfa)?;
        
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0xfa { // STATICCALL
                oracle_call_count += 1;
            }
        }
        
        // If only one oracle call and it's used in state change
        if oracle_call_count == 1 {
            for i in first_call_location..first_call_location+20.min(self.bytecode.len()) {
                if self.bytecode[i] == 0x55 { // SSTORE
                    return Some(first_call_location);
                }
            }
        }
        
        None
    }
}
