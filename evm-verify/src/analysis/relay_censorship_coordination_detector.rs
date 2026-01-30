use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayCensorshipCoordinationVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: String,
}

pub struct RelayCensorshipCoordinationDetector {
    bytecode: Vec<u8>,
}

impl RelayCensorshipCoordinationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<RelayCensorshipCoordinationVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Multiple relays coordinating to censor transactions
        // Detect lack of relay diversity requirements
        if let Some(location) = self.has_single_relay_dependency() {
            vulnerabilities.push(RelayCensorshipCoordinationVulnerability {
                vulnerability_type: "Single Relay Censorship Vulnerability".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "Protocol relies on single relay without fallback mechanisms. Single relay can censor all transactions targeting protocol. Implement multi-relay submission with timeout fallbacks.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect missing censorship resistance for time-sensitive operations
        if let Some(location) = self.has_time_sensitive_censorship_risk() {
            vulnerabilities.push(RelayCensorshipCoordinationVulnerability {
                vulnerability_type: "Time-Sensitive Censorship Risk".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "Time-sensitive operations (liquidations, oracles) lack censorship resistance. Coordinated relay censorship can delay critical transactions causing protocol harm. Implement direct mempool submission or inclusion lists.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        // Detect missing relay reputation system
        if let Some(location) = self.has_no_relay_reputation_tracking() {
            vulnerabilities.push(RelayCensorshipCoordinationVulnerability {
                vulnerability_type: "Missing Relay Reputation Tracking".to_string(),
                location,
                severity: "High".to_string(),
                description: "No mechanism to track relay censorship or malicious behavior. Users cannot identify and avoid censoring relays. Implement on-chain relay performance metrics and reputation scoring.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_single_relay_dependency(&self) -> Option<usize> {
        // Pattern: Transaction submission to single hardcoded address
        for i in 0..self.bytecode.len().saturating_sub(40) {
            // Look for external call to specific address (relay)
            if self.bytecode[i] == 0xf1 || self.bytecode[i] == 0xf4 { // CALL or DELEGATECALL
                // Check if target address is hardcoded
                let mut has_hardcoded_relay = false;
                
                for j in i.saturating_sub(25)..i {
                    // Look for PUSH with address
                    if self.bytecode[j] >= 0x73 && self.bytecode[j] <= 0x74 { // PUSH20/PUSH21 (address)
                        has_hardcoded_relay = true;
                        break;
                    }
                }
                
                if has_hardcoded_relay {
                    // Check if there's no fallback mechanism
                    let mut has_fallback = false;
                    
                    for j in i+1..i+40.min(self.bytecode.len()) {
                        // Look for success check followed by alternative call
                        if self.bytecode[j] == 0x15 { // ISZERO (checking failure)
                            for k in j+1..(j+20).min(self.bytecode.len()).min(self.bytecode.len()) {
                                if self.bytecode[k] == 0xf1 { // Alternative CALL
                                    has_fallback = true;
                                    break;
                                }
                            }
                        }
                    }
                    
                    if !has_fallback {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn has_time_sensitive_censorship_risk(&self) -> Option<usize> {
        // Pattern: Time-dependent critical operation without censorship protection
        for i in 0..self.bytecode.len().saturating_sub(45) {
            // Look for timestamp-based deadline
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                // Check if used in deadline check
                for j in i+1..i+20.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 { // LT or GT
                        // Check if followed by critical operation (CALL, transfer, etc.)
                        for k in j+1..(j+25).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0xf1 || self.bytecode[k] == 0x55 { // CALL or SSTORE
                                // Check if there's censorship protection (inclusion list, etc.)
                                let mut has_censorship_protection = false;
                                
                                for m in i.saturating_sub(40)..i+40.min(self.bytecode.len()) {
                                    // Look for multi-path execution or forced inclusion
                                    // This is heuristic - checking for multiple execution paths
                                    if self.bytecode[m] == 0x57 { // JUMPI (alternative path)
                                        has_censorship_protection = true;
                                    }
                                }
                                
                                if !has_censorship_protection {
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

    fn has_no_relay_reputation_tracking(&self) -> Option<usize> {
        // Pattern: Relay interaction without performance tracking
        for i in 0..self.bytecode.len().saturating_sub(35) {
            // Look for external call (relay submission)
            if self.bytecode[i] == 0xf1 { // CALL
                // Check if success/failure is recorded for reputation
                let mut tracks_reputation = false;
                
                for j in i+1..i+30.min(self.bytecode.len()) {
                    // Look for success check followed by storage update
                    if self.bytecode[j] == 0x15 { // ISZERO (check success)
                        for k in j+1..(j+15).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x55 { // SSTORE (recording result)
                                tracks_reputation = true;
                                break;
                            }
                        }
                    }
                }
                
                if !tracks_reputation {
                    // Verify this is relay interaction (external address)
                    for j in i.saturating_sub(20)..i {
                        if self.bytecode[j] >= 0x60 && self.bytecode[j] <= 0x7f { // PUSH (address)
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }
}
