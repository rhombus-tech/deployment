use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiaOracleSourceGamingVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: String,
}

pub struct DiaOracleSourceGamingDetector {
    bytecode: Vec<u8>,
}

impl DiaOracleSourceGamingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<DiaOracleSourceGamingVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Detect DIA oracle usage without data source validation
        if let Some(location) = self.has_oracle_without_source_validation() {
            vulnerabilities.push(DiaOracleSourceGamingVulnerability {
                vulnerability_type: "DIA Oracle Data Source Gaming".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "DIA oracle data consumed without validating data sources. Attackers can game specific exchange sources or manipulate low-liquidity pairs. Validate source exchanges and require minimum liquidity thresholds.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect single-source DIA feed usage
        if let Some(location) = self.has_single_source_feed() {
            vulnerabilities.push(DiaOracleSourceGamingVulnerability {
                vulnerability_type: "DIA Single Source Risk".to_string(),
                location,
                severity: "High".to_string(),
                description: "DIA oracle reading from single data source. Single exchange can be manipulated via wash trading or low-liquidity attacks. Use multi-source aggregated feeds.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        // Detect lack of volume-weighted aggregation
        if let Some(location) = self.has_non_volume_weighted_aggregation() {
            vulnerabilities.push(DiaOracleSourceGamingVulnerability {
                vulnerability_type: "DIA Non-Volume-Weighted Data".to_string(),
                location,
                severity: "High".to_string(),
                description: "DIA oracle data used without volume-weighted aggregation. Low-volume exchanges have equal weight as high-volume ones. Use VWAP or volume-weighted median.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_oracle_without_source_validation(&self) -> Option<usize> {
        // Pattern: STATICCALL (oracle read) without source metadata validation
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0xfa { // STATICCALL
                // Check if data is used directly without source validation
                let mut has_source_check = false;
                
                // Look for multiple data fields being read (source metadata)
                let mut data_field_count = 0;
                for j in i+1..(i+30).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x51 { // MLOAD (reading return data)
                        data_field_count += 1;
                    }
                }
                
                // If only one field read (just price, no source info)
                if data_field_count <= 1 {
                    // Check if used in state change
                    for j in i+1..(i+15).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x55 { // SSTORE
                            return Some(i);
                        }
                    }
                }
                
                // Check for explicit source validation (comparison operations on source data)
                for j in i+1..(i+35).min(self.bytecode.len()) {
                    if data_field_count > 1 {
                        // Multiple fields but check for validation logic
                        if self.bytecode[j] == 0x14 || self.bytecode[j] == 0x10 { // EQ or LT
                            has_source_check = true;
                        }
                    }
                }
                
                if data_field_count > 1 && !has_source_check {
                    return Some(i);
                }
            }
        }
        None
    }

    fn has_single_source_feed(&self) -> Option<usize> {
        // Pattern: Single oracle call without multi-source aggregation
        let mut oracle_calls = 0;
        let first_call_pos = self.bytecode.iter().position(|&b| b == 0xfa)?;
        
        for i in 0..self.bytecode.len() {
            if self.bytecode[i] == 0xfa { // STATICCALL
                oracle_calls += 1;
            }
        }
        
        // Single oracle call followed by direct usage
        if oracle_calls == 1 {
            for i in first_call_pos..(first_call_pos+20).min(self.bytecode.len()) {
                if self.bytecode[i] == 0x55 || self.bytecode[i] == 0xf1 { // SSTORE or CALL
                    return Some(first_call_pos);
                }
            }
        }
        
        None
    }

    fn has_non_volume_weighted_aggregation(&self) -> Option<usize> {
        // Pattern: Price aggregation without volume weighting
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0xfa { // STATICCALL
                // Look for aggregation logic
                let mut has_aggregation = false;
                let mut has_volume_weighting = false;
                
                for j in i+1..(i+50).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x01 { // ADD (summing prices)
                        has_aggregation = true;
                        
                        // Check for volume weighting: MUL before ADD
                        for k in j.saturating_sub(10)..j {
                            if self.bytecode[k] == 0x02 { // MUL (price * volume)
                                has_volume_weighting = true;
                                break;
                            }
                        }
                    }
                }
                
                if has_aggregation && !has_volume_weighting {
                    return Some(i);
                }
            }
        }
        None
    }
}
