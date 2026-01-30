use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuaveConfidentialLeakVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: String,
}

pub struct SuaveConfidentialLeakDetector {
    bytecode: Vec<u8>,
}

impl SuaveConfidentialLeakDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<SuaveConfidentialLeakVulnerability> {
        let mut vulnerabilities = Vec::new();

        // SUAVE provides confidential compute but can leak information
        // Detect confidential data exposure through public state
        if let Some(location) = self.has_confidential_state_leakage() {
            vulnerabilities.push(SuaveConfidentialLeakVulnerability {
                vulnerability_type: "SUAVE Confidential State Leakage".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "Confidential computation results stored in public state. SUAVE confidential data must never touch public storage or logs. Use SUAVE-specific storage or keep data off-chain.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect timing side-channel in confidential compute
        if let Some(location) = self.has_timing_side_channel() {
            vulnerabilities.push(SuaveConfidentialLeakVulnerability {
                vulnerability_type: "SUAVE Timing Side-Channel".to_string(),
                location,
                severity: "High".to_string(),
                description: "Confidential computation execution time varies based on secret data. Attackers can infer confidential information through gas usage patterns. Implement constant-time operations for sensitive paths.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        // Detect confidential data in transaction calldata
        if let Some(location) = self.has_calldata_confidential_leak() {
            vulnerabilities.push(SuaveConfidentialLeakVulnerability {
                vulnerability_type: "SUAVE Calldata Confidential Leak".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "Confidential data passed via transaction calldata visible to all network participants. Use SUAVE confidential requests or encrypted channels. Never pass secrets in plain calldata.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_confidential_state_leakage(&self) -> Option<usize> {
        // Pattern: SSTORE after confidential computation
        for i in 0..self.bytecode.len().saturating_sub(40) {
            // Look for confidential compute (typically via CALL to SUAVE precompile)
            if self.bytecode[i] == 0xfa { // STATICCALL (to SUAVE)
                // Check if result is stored publicly
                for j in i+1..i+35.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x55 { // SSTORE (public storage)
                        // Check if this is SUAVE-specific storage (different slot range)
                        let mut uses_suave_storage = false;
                        
                        for k in j.saturating_sub(15)..j {
                            // SUAVE storage typically uses specific slot prefixes
                            // This is heuristic - checking for slot manipulation
                            if self.bytecode[k] == 0x1b || self.bytecode[k] == 0x1c { // SHL or SHR (slot manipulation)
                                uses_suave_storage = true;
                            }
                        }
                        
                        if !uses_suave_storage {
                            return Some(i);
                        }
                    }
                    // Also check for LOG (events leak data)
                    if self.bytecode[j] >= 0xa0 && self.bytecode[j] <= 0xa4 { // LOG0-LOG4
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn has_timing_side_channel(&self) -> Option<usize> {
        // Pattern: Conditional branches based on confidential data
        for i in 0..self.bytecode.len().saturating_sub(45) {
            // Look for confidential data access
            if self.bytecode[i] == 0xfa { // STATICCALL (SUAVE operation)
                // Check if result used in conditional
                for j in i+1..i+40.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x57 { // JUMPI (conditional branch)
                        // Check if branch leads to significantly different execution
                        // This is heuristic - checking for gas-heavy operations in one branch
                        let mut has_asymmetric_branches = false;
                        
                        for k in j+1..(j+30).min(self.bytecode.len()).min(self.bytecode.len()) {
                            // Look for expensive operations (SLOAD, CALL, loops)
                            if self.bytecode[k] == 0x54 || self.bytecode[k] == 0xf1 || self.bytecode[k] == 0x5b {
                                has_asymmetric_branches = true;
                                break;
                            }
                        }
                        
                        if has_asymmetric_branches {
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn has_calldata_confidential_leak(&self) -> Option<usize> {
        // Pattern: Sensitive data in CALLDATALOAD without encryption
        for i in 0..self.bytecode.len().saturating_sub(40) {
            // Look for calldata access
            if self.bytecode[i] == 0x35 { // CALLDATALOAD
                // Check if data is used in confidential operation
                for j in i+1..i+35.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0xfa { // STATICCALL (SUAVE)
                        // Check if calldata was encrypted first
                        let mut data_is_encrypted = false;
                        
                        for k in i+1..j {
                            // Look for decryption (hash operations, XOR, etc.)
                            if self.bytecode[k] == 0x20 { // SHA3 (part of decryption)
                                // Check if followed by XOR or similar
                                for m in k+1..(k+10).min(self.bytecode.len()).min(self.bytecode.len()) {
                                    if self.bytecode[m] == 0x18 { // XOR (decryption)
                                        data_is_encrypted = true;
                                        break;
                                    }
                                }
                            }
                        }
                        
                        if !data_is_encrypted {
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }
}
