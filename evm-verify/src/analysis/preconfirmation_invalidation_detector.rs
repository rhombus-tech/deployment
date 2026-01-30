use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreconfirmationInvalidationVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: String,
}

pub struct PreconfirmationInvalidationDetector {
    bytecode: Vec<u8>,
}

impl PreconfirmationInvalidationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<PreconfirmationInvalidationVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Based rollups use preconfirmations that can be invalidated
        // Detect preconfirmation dependency without invalidation protection
        if let Some(location) = self.has_preconfirmation_dependency() {
            vulnerabilities.push(PreconfirmationInvalidationVulnerability {
                vulnerability_type: "Preconfirmation Invalidation Risk".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "Protocol relies on based preconfirmations without handling invalidation. Proposers can invalidate preconfirms to extract MEV, causing transaction failures. Implement preconfirmation bonds or fallback execution.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect insufficient slashing for preconfirmation violations
        if let Some(location) = self.has_insufficient_preconf_slashing() {
            vulnerabilities.push(PreconfirmationInvalidationVulnerability {
                vulnerability_type: "Insufficient Preconfirmation Slashing".to_string(),
                location,
                severity: "High".to_string(),
                description: "Preconfirmation violations lack adequate slashing penalties. Proposers can profitably break preconfirms if MEV exceeds slash amount. Increase slash to exceed maximum extractable MEV.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        // Detect preconfirmation timing manipulation
        if let Some(location) = self.has_preconf_timing_manipulation() {
            vulnerabilities.push(PreconfirmationInvalidationVulnerability {
                vulnerability_type: "Preconfirmation Timing Manipulation".to_string(),
                location,
                severity: "High".to_string(),
                description: "Preconfirmation validity window allows timing manipulation. Proposers can delay execution within preconf window to front-run or manipulate state. Implement strict execution timing requirements.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_preconfirmation_dependency(&self) -> Option<usize> {
        // Pattern: State transition assuming preconfirmed transaction execution
        for i in 0..self.bytecode.len().saturating_sub(40) {
            // Look for state read expecting specific value (preconfirmed)
            if self.bytecode[i] == 0x54 { // SLOAD
                // Check if value is required (used in assertion or comparison)
                for j in i+1..i+25.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x14 { // EQ (expecting specific value)
                        // Check if followed by REVERT on mismatch
                        for k in j+1..(j+10).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x15 { // ISZERO
                                for m in k+1..(k+5).min(self.bytecode.len()).min(self.bytecode.len()) {
                                    if self.bytecode[m] == 0xfd { // REVERT
                                        // Check for preconf invalidation handling
                                        let mut handles_invalidation = false;
                                        
                                        // Look for fallback execution path
                                        for n in i.saturating_sub(40)..i+40.min(self.bytecode.len()) {
                                            // Alternative execution (JUMPI to different path)
                                            if self.bytecode[n] == 0x57 { // JUMPI
                                                handles_invalidation = true;
                                            }
                                        }
                                        
                                        if !handles_invalidation {
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
        None
    }

    fn has_insufficient_preconf_slashing(&self) -> Option<usize> {
        // Pattern: Preconfirmation bond without MEV-aware slashing
        for i in 0..self.bytecode.len().saturating_sub(40) {
            // Look for bond/collateral storage
            if self.bytecode[i] == 0x55 { // SSTORE (storing bond)
                // Check if bond amount is dynamic based on transaction value
                let mut bond_is_mev_aware = false;
                
                for j in i.saturating_sub(35)..i {
                    // Look for transaction value in bond calculation
                    if self.bytecode[j] == 0x34 { // CALLVALUE
                        // Check if used to calculate bond (MUL with multiplier)
                        for k in j+1..(j+15).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x02 { // MUL (bond = value * factor)
                                bond_is_mev_aware = true;
                                break;
                            }
                        }
                    }
                }
                
                if !bond_is_mev_aware {
                    // Verify this is preconf bond (preceded by commitment)
                    for j in i.saturating_sub(30)..i {
                        if self.bytecode[j] == 0x20 { // SHA3 (preconf hash)
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn has_preconf_timing_manipulation(&self) -> Option<usize> {
        // Pattern: Preconfirmation execution with flexible timing
        for i in 0..self.bytecode.len().saturating_sub(45) {
            // Look for preconf validation (hash comparison)
            if self.bytecode[i] == 0x20 { // SHA3 (preconf commitment)
                for j in i+1..i+20.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x14 { // EQ (verifying preconf)
                        // Check if timing is strictly enforced
                        let mut enforces_strict_timing = false;
                        
                        for k in j+1..(j+30).min(self.bytecode.len()).min(self.bytecode.len()) {
                            // Look for exact block/timestamp requirement
                            if self.bytecode[k] == 0x42 || self.bytecode[k] == 0x43 { // TIMESTAMP or NUMBER
                                for m in k+1..(k+10).min(self.bytecode.len()).min(self.bytecode.len()) {
                                    if self.bytecode[m] == 0x14 { // EQ (exact time)
                                        enforces_strict_timing = true;
                                        break;
                                    }
                                }
                            }
                        }
                        
                        if !enforces_strict_timing {
                            // Check if this allows execution (CALL follows)
                            for k in j+1..(j+35).min(self.bytecode.len()).min(self.bytecode.len()) {
                                if self.bytecode[k] == 0xf1 { // CALL (executing preconf)
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
