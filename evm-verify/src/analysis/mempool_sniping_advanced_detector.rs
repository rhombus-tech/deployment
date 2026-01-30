use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolSnipingAdvancedVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: String,
}

pub struct MempoolSnipingAdvancedDetector {
    bytecode: Vec<u8>,
}

impl MempoolSnipingAdvancedDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<MempoolSnipingAdvancedVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Advanced mempool sniping (Frontrunning 2.0) with MEV-Boost
        // Detect public transaction ordering vulnerability
        if let Some(location) = self.has_public_mempool_ordering_risk() {
            vulnerabilities.push(MempoolSnipingAdvancedVulnerability {
                vulnerability_type: "Advanced Mempool Sniping Vulnerability".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "Transaction execution order deterministic from public mempool. Sophisticated searchers can simulate and front-run profitable transactions with perfect timing. Implement encrypted mempools or batch auctions.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect gas price priority allowing sniping
        if let Some(location) = self.has_gas_price_priority_sniping() {
            vulnerabilities.push(MempoolSnipingAdvancedVulnerability {
                vulnerability_type: "Gas Price Priority Sniping".to_string(),
                location,
                severity: "High".to_string(),
                description: "Operation prioritizes transactions by gas price enabling systematic front-running. Attackers can always outbid by 1 gwei to guarantee front-running. Use fair ordering (FIFO) or encrypted execution.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect multi-step operations vulnerable to sniping
        if let Some(location) = self.has_multi_step_sniping_vulnerability() {
            vulnerabilities.push(MempoolSnipingAdvancedVulnerability {
                vulnerability_type: "Multi-Step Operation Sniping".to_string(),
                location,
                severity: "High".to_string(),
                description: "Multi-transaction operations reveal intent in first transaction. Attackers can snipe subsequent transactions or sandwich entire sequence. Implement atomic multi-step execution or private transactions.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_public_mempool_ordering_risk(&self) -> Option<usize> {
        // Pattern: Price-sensitive operation without ordering protection
        for i in 0..self.bytecode.len().saturating_sub(45) {
            // Look for swap/trade operations (CALL to DEX or internal calculation)
            if self.bytecode[i] == 0xf1 || self.bytecode[i] == 0xfa { // CALL or STATICCALL
                // Check if this involves price calculation
                let mut is_price_sensitive = false;
                
                for j in i.saturating_sub(40)..i {
                    // Look for price calculation (MUL, DIV with reserves)
                    if self.bytecode[j] == 0x02 || self.bytecode[j] == 0x04 { // MUL or DIV
                        // Check if involves reserves/balances
                        for k in j.saturating_sub(10)..j {
                            if self.bytecode[k] == 0x54 || self.bytecode[k] == 0x31 { // SLOAD or BALANCE
                                is_price_sensitive = true;
                                break;
                            }
                        }
                    }
                }
                
                if is_price_sensitive {
                    // Check for ordering protection (commit-reveal, encryption, etc.)
                    let mut has_ordering_protection = false;
                    
                    for j in i.saturating_sub(50)..i {
                        // Look for commitment scheme
                        if self.bytecode[j] == 0x20 { // SHA3 (commitment hash)
                            // Check if compared (reveal phase)
                            for k in j+1..(j+20).min(self.bytecode.len()).min(self.bytecode.len()) {
                                if self.bytecode[k] == 0x14 { // EQ
                                    has_ordering_protection = true;
                                    break;
                                }
                            }
                        }
                    }
                    
                    if !has_ordering_protection {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn has_gas_price_priority_sniping(&self) -> Option<usize> {
        // Pattern: First-come-first-served logic that can be bypassed by gas price
        for i in 0..self.bytecode.len().saturating_sub(40) {
            // Look for FIFO queue or ordering logic
            if self.bytecode[i] == 0x55 { // SSTORE (adding to queue)
                // Check if order depends on transaction position
                let mut has_position_dependency = false;
                
                for j in i.saturating_sub(30)..i {
                    // Look for queue index or counter
                    if self.bytecode[j] == 0x54 { // SLOAD (queue position)
                        for k in j+1..(j+10).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x01 { // ADD (incrementing)
                                has_position_dependency = true;
                                break;
                            }
                        }
                    }
                }
                
                if has_position_dependency {
                    // Check if there's gas price enforcement (preventing priority)
                    let mut enforces_equal_gas = false;
                    
                    for j in i.saturating_sub(40)..i {
                        // Look for GASPRICE check
                        if self.bytecode[j] == 0x3a { // GASPRICE
                            // Check if compared to fixed value
                            for k in j+1..(j+10).min(self.bytecode.len()).min(self.bytecode.len()) {
                                if self.bytecode[k] == 0x14 { // EQ (must match)
                                    enforces_equal_gas = true;
                                    break;
                                }
                            }
                        }
                    }
                    
                    if !enforces_equal_gas {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn has_multi_step_sniping_vulnerability(&self) -> Option<usize> {
        // Pattern: Multi-step operation without atomicity protection
        for i in 0..self.bytecode.len().saturating_sub(45) {
            // Look for approval + transfer pattern (common multi-step)
            if self.bytecode[i] == 0x55 { // SSTORE (approval)
                // Check if followed by conditional execution (transfer in next tx)
                for j in i+1..i+40.min(self.bytecode.len()) {
                    // Look for another operation that depends on this state
                    if self.bytecode[j] == 0x54 { // SLOAD (reading approval)
                        // Check if this leads to value transfer
                        for k in j+1..(j+25).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0xf1 { // CALL (transfer)
                                // Check if atomic (no transaction boundary)
                                // Heuristic: if there's a REVERT path, it might be atomic
                                let mut has_atomicity = false;
                                
                                for m in i..k {
                                    if self.bytecode[m] == 0xfd { // REVERT (atomic rollback)
                                        has_atomicity = true;
                                        break;
                                    }
                                }
                                
                                if !has_atomicity {
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
}
