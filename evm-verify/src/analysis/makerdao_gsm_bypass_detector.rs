use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MakerdaoGsmBypassVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: String,
}

pub struct MakerdaoGsmBypassDetector {
    bytecode: Vec<u8>,
}

impl MakerdaoGsmBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<MakerdaoGsmBypassVulnerability> {
        let mut vulnerabilities = Vec::new();

        // MakerDAO GSM (Governance Security Module) provides delay for emergency response
        // Detect GSM bypass for critical operations
        if let Some(location) = self.has_gsm_bypass() {
            vulnerabilities.push(MakerdaoGsmBypassVulnerability {
                vulnerability_type: "MakerDAO GSM Bypass".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "Critical governance action without GSM delay. Emergency shutdown or parameter changes execute immediately without community response window. Route all critical operations through GSM with minimum 24-48 hour delay.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect insufficient GSM delay
        if let Some(location) = self.has_insufficient_gsm_delay() {
            vulnerabilities.push(MakerdaoGsmBypassVulnerability {
                vulnerability_type: "MakerDAO Insufficient GSM Delay".to_string(),
                location,
                severity: "High".to_string(),
                description: "GSM delay under 24 hours insufficient for emergency response. Community needs adequate time to assess and potentially trigger emergency shutdown. Require minimum 24-48 hour GSM delay.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        // Detect GSM pause bypass
        if let Some(location) = self.has_gsm_pause_bypass() {
            vulnerabilities.push(MakerdaoGsmBypassVulnerability {
                vulnerability_type: "MakerDAO GSM Pause Bypass".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "Emergency pause authority missing or insufficient. Malicious proposals in GSM delay period cannot be stopped. Implement multi-sig emergency pause with Guardian role.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_gsm_bypass(&self) -> Option<usize> {
        // Pattern: Critical operation without GSM delay check
        for i in 0..self.bytecode.len().saturating_sub(40) {
            // Look for critical operations (DELEGATECALL or state changes)
            if self.bytecode[i] == 0xf4 || self.bytecode[i] == 0x55 { // DELEGATECALL or SSTORE
                // Check for GSM delay validation
                let mut has_gsm_delay = false;
                
                for j in i.saturating_sub(40)..i {
                    // Look for timestamp comparison (GSM delay)
                    if self.bytecode[j] == 0x42 { // TIMESTAMP
                        for k in j+1..(j+15).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x10 || self.bytecode[k] == 0x11 { // LT/GT
                                has_gsm_delay = true;
                                break;
                            }
                        }
                    }
                }
                
                if !has_gsm_delay {
                    // Verify this is critical governance operation
                    // Look for governance authorization check
                    for j in i.saturating_sub(30)..i {
                        if self.bytecode[j] == 0x33 { // CALLER
                            for k in j+1..(j+10).min(self.bytecode.len()).min(self.bytecode.len()) {
                                if self.bytecode[k] == 0x14 { // EQ (auth check)
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

    fn has_insufficient_gsm_delay(&self) -> Option<usize> {
        // Pattern: GSM delay constant too small
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Look for delay addition to timestamp
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                for j in i+1..i+20.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x01 { // ADD (timestamp + delay)
                        // Check delay constant
                        for k in j.saturating_sub(10)..j {
                            if self.bytecode[k] >= 0x60 && self.bytecode[k] <= 0x7f { // PUSH
                                // Heuristic: check if delay appears small
                                if k + 1 < self.bytecode.len() {
                                    let delay_bytes = &self.bytecode[k+1..std::cmp::min(k+4, self.bytecode.len())];
                                    // If first byte < 2, likely less than ~2 days
                                    if !delay_bytes.is_empty() && delay_bytes[0] < 2 {
                                        // Verify this is GSM by checking subsequent comparison
                                        for m in j+1..j+10.min(self.bytecode.len()) {
                                            if self.bytecode[m] == 0x11 { // GT
                                                return Some(i);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }

    fn has_gsm_pause_bypass(&self) -> Option<usize> {
        // Pattern: GSM execution without pause check
        for i in 0..self.bytecode.len().saturating_sub(40) {
            // Look for GSM execution (after delay check)
            if self.bytecode[i] == 0xf4 { // DELEGATECALL (executing scheduled action)
                // Check if pause state is validated
                let mut has_pause_check = false;
                
                for j in i.saturating_sub(40)..i {
                    // Look for pause state load
                    if self.bytecode[j] == 0x54 { // SLOAD (pause state)
                        for k in j+1..(j+10).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x15 { // ISZERO (not paused)
                                has_pause_check = true;
                                break;
                            }
                        }
                    }
                }
                
                if !has_pause_check {
                    // Verify this is GSM execution (timelock check exists)
                    for j in i.saturating_sub(35)..i {
                        if self.bytecode[j] == 0x42 { // TIMESTAMP
                            for k in j+1..(j+10).min(self.bytecode.len()) {
                                if self.bytecode[k] == 0x11 { // GT (delay passed)
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
