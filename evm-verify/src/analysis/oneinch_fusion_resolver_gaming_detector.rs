use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OneinchFusionResolverGamingVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: String,
}

pub struct OneinchFusionResolverGamingDetector {
    bytecode: Vec<u8>,
}

impl OneinchFusionResolverGamingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<OneinchFusionResolverGamingVulnerability> {
        let mut vulnerabilities = Vec::new();

        // 1inch Fusion uses resolvers to fill orders
        // Detect resolver exclusive fill rights manipulation
        if let Some(location) = self.has_resolver_exclusivity_gaming() {
            vulnerabilities.push(OneinchFusionResolverGamingVulnerability {
                vulnerability_type: "1inch Fusion Resolver Exclusivity Gaming".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "Resolver exclusivity period allows front-running after exclusivity ends. First resolver can delay until exclusivity expires then compete in public auction. Implement continuous exclusivity decay or immediate public access.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect resolver reputation manipulation
        if let Some(location) = self.has_resolver_reputation_gaming() {
            vulnerabilities.push(OneinchFusionResolverGamingVulnerability {
                vulnerability_type: "1inch Fusion Resolver Reputation Gaming".to_string(),
                location,
                severity: "High".to_string(),
                description: "Resolver selection based on manipulable reputation metrics. Resolvers can game reputation through wash trading or Sybil attacks. Implement stake-weighted reputation and fraud proofs.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        // Detect partial fill timing manipulation
        if let Some(location) = self.has_partial_fill_gaming() {
            vulnerabilities.push(OneinchFusionResolverGamingVulnerability {
                vulnerability_type: "1inch Fusion Partial Fill Gaming".to_string(),
                location,
                severity: "High".to_string(),
                description: "Partial fills allow resolvers to front-run remaining order amount. First resolver can fill minimum and front-run rest when profitable. Require all-or-nothing fills or auction-based partials.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_resolver_exclusivity_gaming(&self) -> Option<usize> {
        // Pattern: Time-based exclusivity period transitioning to open
        for i in 0..self.bytecode.len().saturating_sub(45) {
            // Look for time comparison (exclusivity check)
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                // Check if used to determine resolver eligibility
                for j in i+1..i+25.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 { // LT or GT
                        // Check if this controls fill authorization
                        for k in j+1..(j+25).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x57 { // JUMPI (exclusive vs public path)
                                // Check if transition is gradual (decay) or abrupt
                                let mut has_gradual_transition = false;
                                
                                for m in i.saturating_sub(30)..k {
                                    // Look for continuous decay (MUL or DIV with time)
                                    if self.bytecode[m] == 0x02 || self.bytecode[m] == 0x04 { // MUL/DIV
                                        has_gradual_transition = true;
                                    }
                                }
                                
                                if !has_gradual_transition {
                                    return Some(i);
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }

    fn has_resolver_reputation_gaming(&self) -> Option<usize> {
        // Pattern: Resolver selection based on reputation score
        for i in 0..self.bytecode.len().saturating_sub(40) {
            // Look for reputation check
            if self.bytecode[i] == 0x54 { // SLOAD (resolver reputation)
                // Check if reputation affects selection
                for j in i+1..i+20.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 { // LT/GT (reputation threshold)
                        // Check if reputation is stake-weighted
                        let mut is_stake_weighted = false;
                        
                        for k in j.saturating_sub(25)..j {
                            // Look for stake in calculation
                            if self.bytecode[k] == 0x54 { // SLOAD (resolver stake)
                                for m in k+1..(k+10).min(self.bytecode.len()).min(self.bytecode.len()) {
                                    if self.bytecode[m] == 0x02 || self.bytecode[m] == 0x04 { // MUL/DIV
                                        is_stake_weighted = true;
                                        break;
                                    }
                                }
                            }
                        }
                        
                        if !is_stake_weighted {
                            // Verify this is resolver selection
                            for k in j+1..(j+30).min(self.bytecode.len()).min(self.bytecode.len()) {
                                if self.bytecode[k] == 0xf1 { // CALL (authorizing resolver)
                                    return Some(i);
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }

    fn has_partial_fill_gaming(&self) -> Option<usize> {
        // Pattern: Partial fill without minimum fill requirements
        for i in 0..self.bytecode.len().saturating_sub(40) {
            // Look for fill amount storage
            if self.bytecode[i] == 0x55 { // SSTORE (recording fill)
                // Check if partial fills allowed
                let mut allows_partial = false;
                
                for j in i.saturating_sub(30)..i {
                    // Look for partial fill check (filled < total)
                    if self.bytecode[j] == 0x10 { // LT
                        allows_partial = true;
                        break;
                    }
                }
                
                if allows_partial {
                    // Check for minimum fill percentage
                    let mut enforces_minimum_fill = false;
                    
                    for j in i.saturating_sub(35)..i {
                        // Look for percentage calculation and threshold
                        if self.bytecode[j] == 0x04 { // DIV (fill / total = percentage)
                            for k in j+1..(j+10).min(self.bytecode.len()) {
                                if self.bytecode[k] == 0x10 { // LT (percentage >= minimum)
                                    enforces_minimum_fill = true;
                                    break;
                                }
                            }
                        }
                    }
                    
                    if !enforces_minimum_fill {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
