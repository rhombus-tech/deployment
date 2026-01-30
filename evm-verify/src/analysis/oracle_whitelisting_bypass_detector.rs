use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleWhitelistingBypassVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: String,
}

pub struct OracleWhitelistingBypassDetector {
    bytecode: Vec<u8>,
}

impl OracleWhitelistingBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<OracleWhitelistingBypassVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Detect oracle call without whitelist check
        if let Some(location) = self.has_oracle_without_whitelist() {
            vulnerabilities.push(OracleWhitelistingBypassVulnerability {
                vulnerability_type: "Oracle Whitelisting Bypass".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "Oracle address not validated against whitelist before use. Attackers can inject malicious oracle addresses to feed manipulated data. Implement strict oracle address whitelist validation.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect user-controlled oracle address
        if let Some(location) = self.has_user_controlled_oracle() {
            vulnerabilities.push(OracleWhitelistingBypassVulnerability {
                vulnerability_type: "User-Controlled Oracle Address".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "Oracle address sourced from user input without validation. Users can specify malicious oracles to manipulate prices. Always use hardcoded or governance-controlled oracle addresses.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect weak whitelist check (only checking non-zero)
        if let Some(location) = self.has_weak_whitelist_check() {
            vulnerabilities.push(OracleWhitelistingBypassVulnerability {
                vulnerability_type: "Weak Oracle Whitelist Validation".to_string(),
                location,
                severity: "High".to_string(),
                description: "Oracle address only checked for non-zero value, not against proper whitelist. Attacker can use any non-zero address. Implement mapping-based whitelist with explicit approval.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_oracle_without_whitelist(&self) -> Option<usize> {
        // Pattern: STATICCALL without prior whitelist validation
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0xfa { // STATICCALL
                // Check if address is validated before call
                let mut has_whitelist_check = false;
                
                // Look backwards for SLOAD (whitelist mapping) + EQ check
                for j in i.saturating_sub(25)..i {
                    if self.bytecode[j] == 0x54 { // SLOAD (whitelist lookup)
                        for k in j+1..(j+10).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x14 { // EQ (checking if whitelisted)
                                has_whitelist_check = true;
                                break;
                            }
                        }
                    }
                }
                
                if !has_whitelist_check {
                    return Some(i);
                }
            }
        }
        None
    }

    fn has_user_controlled_oracle(&self) -> Option<usize> {
        // Pattern: CALLDATALOAD (user input) used as oracle address in STATICCALL
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x35 { // CALLDATALOAD (user input)
                // Check if this value is used as address in STATICCALL
                let upper_bound = (i + 35).min(self.bytecode.len());
                for j in (i+1)..upper_bound {
                    if j >= self.bytecode.len() { break; }
                    if self.bytecode[j] == 0xfa { // STATICCALL
                        // Check if CALLDATALOAD value is used without validation
                        let mut has_validation = false;
                        
                        for k in i+1..j {
                            // Look for EQ check (whitelist validation)
                            if self.bytecode[k] == 0x14 { // EQ
                                has_validation = true;
                            }
                            // Look for SLOAD (whitelist mapping lookup)
                            if self.bytecode[k] == 0x54 { // SLOAD
                                has_validation = true;
                            }
                        }
                        
                        if !has_validation {
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn has_weak_whitelist_check(&self) -> Option<usize> {
        // Pattern: ISZERO check (non-zero) instead of proper whitelist validation
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0xfa { // STATICCALL
                // Look for weak validation: ISZERO check only
                let mut has_iszero_only = false;
                let mut has_proper_whitelist = false;
                
                for j in i.saturating_sub(20)..i {
                    if self.bytecode[j] == 0x15 { // ISZERO
                        has_iszero_only = true;
                    }
                    // Proper whitelist: SLOAD (mapping lookup)
                    if self.bytecode[j] == 0x54 { // SLOAD
                        // Check if followed by EQ check
                        for k in j+1..(j+10).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x14 { // EQ
                                has_proper_whitelist = true;
                            }
                        }
                    }
                }
                
                // If only ISZERO check without proper whitelist
                if has_iszero_only && !has_proper_whitelist {
                    return Some(i);
                }
            }
        }
        None
    }
}
