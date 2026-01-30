use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentSettlementTimingVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: String,
}

pub struct IntentSettlementTimingDetector {
    bytecode: Vec<u8>,
}

impl IntentSettlementTimingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<IntentSettlementTimingVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Intent-based systems settle user intents with timing flexibility
        // Detect intentional settlement delays for MEV extraction
        if let Some(location) = self.has_settlement_delay_mev() {
            vulnerabilities.push(IntentSettlementTimingVulnerability {
                vulnerability_type: "Intent Settlement Delay MEV".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "Intent settlement can be delayed within deadline to extract MEV. Solvers can wait for favorable market conditions or front-run other intents. Implement strict earliest-settlement incentives.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect deadline manipulation in intent settlement
        if let Some(location) = self.has_deadline_manipulation() {
            vulnerabilities.push(IntentSettlementTimingVulnerability {
                vulnerability_type: "Intent Deadline Manipulation".to_string(),
                location,
                severity: "High".to_string(),
                description: "Intent deadlines flexible or solver-controlled. Malicious solvers can extend deadlines to wait for MEV opportunities. Make deadlines user-specified and strictly enforced.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        // Detect partial intent fills allowing timing games
        if let Some(location) = self.has_partial_fill_timing_attack() {
            vulnerabilities.push(IntentSettlementTimingVulnerability {
                vulnerability_type: "Partial Intent Fill Timing Attack".to_string(),
                location,
                severity: "High".to_string(),
                description: "Partial intent fills allow solvers to split execution across multiple blocks for timing advantage. Solvers can extract MEV by strategically timing fill portions. Require atomic or time-locked partial fills.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_settlement_delay_mev(&self) -> Option<usize> {
        // Pattern: Intent settlement with flexible timing window
        for i in 0..self.bytecode.len().saturating_sub(45) {
            // Look for deadline check
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                // Check if used in deadline comparison
                for j in i+1..i+20.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 { // LT or GT
                        // Check if settlement can happen anytime before deadline
                        // (no earliest-time enforcement)
                        let mut enforces_earliest_settlement = false;
                        
                        for k in i.saturating_sub(35)..i+35.min(self.bytecode.len()) {
                            // Look for minimum time check (earliest settlement)
                            if self.bytecode[k] == 0x54 { // SLOAD (intent submission time)
                                for m in k+1..(k+15).min(self.bytecode.len()) {
                                    if self.bytecode[m] == 0x01 { // ADD (submission + min delay)
                                        // Check if compared
                                        for n in m+1..(m+10).min(self.bytecode.len()) {
                                            if self.bytecode[n] == 0x11 { // GT (must wait minimum)
                                                enforces_earliest_settlement = true;
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        
                        if !enforces_earliest_settlement {
                            // Verify this is intent settlement (transfer follows)
                            for k in j+1..(j+30).min(self.bytecode.len()).min(self.bytecode.len()) {
                                if self.bytecode[k] == 0xf1 { // CALL (settlement transfer)
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

    fn has_deadline_manipulation(&self) -> Option<usize> {
        // Pattern: Deadline that can be extended by solver
        for i in 0..self.bytecode.len().saturating_sub(40) {
            // Look for deadline update
            if self.bytecode[i] == 0x55 { // SSTORE (updating deadline)
                // Check if deadline can be modified after intent creation
                let mut deadline_is_immutable = false;
                
                for j in i.saturating_sub(35)..i {
                    // Look for intent state check (must be pending/unfilled)
                    if self.bytecode[j] == 0x54 { // SLOAD (intent state)
                        for k in j+1..(j+10).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x14 { // EQ (checking if pending)
                                // Check if state must be initial (no extensions allowed)
                                deadline_is_immutable = true;
                                break;
                            }
                        }
                    }
                }
                
                if !deadline_is_immutable {
                    // Verify this is intent deadline (preceded by timestamp ops)
                    for j in i.saturating_sub(20)..i {
                        if self.bytecode[j] == 0x42 { // TIMESTAMP
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn has_partial_fill_timing_attack(&self) -> Option<usize> {
        // Pattern: Partial fill without time lock between fills
        for i in 0..self.bytecode.len().saturating_sub(45) {
            // Look for fill amount storage (partial fill)
            if self.bytecode[i] == 0x55 { // SSTORE (recording fill amount)
                // Check if this is partial (fill < intent amount)
                let mut allows_partial = false;
                
                for j in i.saturating_sub(30)..i {
                    // Look for comparison showing partial fill
                    if self.bytecode[j] == 0x10 { // LT (filled < total)
                        allows_partial = true;
                        break;
                    }
                }
                
                if allows_partial {
                    // Check if there's minimum time between fills
                    let mut enforces_fill_delay = false;
                    
                    for j in i.saturating_sub(40)..i {
                        // Look for timestamp of last fill
                        if self.bytecode[j] == 0x54 { // SLOAD (last fill time)
                            for k in j+1..(j+15).min(self.bytecode.len()) {
                                // Check if time delta enforced
                                if self.bytecode[k] == 0x03 { // SUB (time since last fill)
                                    for m in k+1..(k+10).min(self.bytecode.len()) {
                                        if self.bytecode[m] == 0x10 { // LT (must wait)
                                            enforces_fill_delay = true;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    
                    if !enforces_fill_delay {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
