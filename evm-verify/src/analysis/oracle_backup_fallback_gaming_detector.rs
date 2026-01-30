use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleBackupFallbackVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: String,
}

pub struct OracleBackupFallbackGamingDetector {
    bytecode: Vec<u8>,
}

impl OracleBackupFallbackGamingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<OracleBackupFallbackVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Detect oracle fallback without validation
        if let Some(location) = self.has_unvalidated_fallback() {
            vulnerabilities.push(OracleBackupFallbackVulnerability {
                vulnerability_type: "Oracle Backup Fallback Gaming".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "Oracle fallback mechanism without validation. Attackers can force primary oracle failure to use less secure backup oracle with manipulated prices. Implement equivalent security checks on fallback.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect fallback triggered by revert without price sanity check
        if let Some(location) = self.has_revert_fallback_without_sanity() {
            vulnerabilities.push(OracleBackupFallbackVulnerability {
                vulnerability_type: "Revert-Based Fallback Without Sanity Check".to_string(),
                location,
                severity: "High".to_string(),
                description: "Fallback oracle triggered by revert without cross-checking with primary. Attacker can DoS primary oracle to force fallback usage and exploit price differences.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect cascading fallback without circuit breaker
        if let Some(location) = self.has_cascading_fallback_without_breaker() {
            vulnerabilities.push(OracleBackupFallbackVulnerability {
                vulnerability_type: "Cascading Fallback Without Circuit Breaker".to_string(),
                location,
                severity: "High".to_string(),
                description: "Multiple fallback levels without circuit breaker. System degrades to least secure oracle under attack. Implement circuit breaker to pause operations if fallbacks exhausted.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_unvalidated_fallback(&self) -> Option<usize> {
        // Pattern: Try-catch or ISZERO(STATICCALL) fallback without validation
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0xfa { // STATICCALL
                // Look for ISZERO check (call failure detection)
                for j in i+1..i+5.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x15 { // ISZERO
                        // Look for second oracle call (fallback)
                        for k in j+1..(j+30).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0xfa { // Second STATICCALL (fallback)
                                // Check if fallback result is validated
                                let mut has_validation = false;
                                
                                for m in k+1..(k+20).min(self.bytecode.len()).min(self.bytecode.len()) {
                                    // Look for validation: comparison with primary or bounds check
                                    if self.bytecode[m] == 0x10 || self.bytecode[m] == 0x11 { // LT or GT
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
            }
        }
        None
    }

    fn has_revert_fallback_without_sanity(&self) -> Option<usize> {
        // Pattern: Fallback without comparing prices between primary and backup
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0xfa { // STATICCALL (primary)
                // Look for ISZERO (failure check)
                for j in i+1..i+10.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x15 { // ISZERO
                        // Look for second call (fallback)
                        for k in j+1..(j+35).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0xfa { // STATICCALL (fallback)
                                // Check for sanity comparison between primary and fallback prices
                                let mut has_price_comparison = false;
                                
                                // Look for SUB operation comparing two prices
                                for m in k+1..(k+25).min(self.bytecode.len()).min(self.bytecode.len()) {
                                    if self.bytecode[m] == 0x03 { // SUB
                                        // Check if followed by bounds check
                                        for n in m+1..(m+10).min(self.bytecode.len()).min(self.bytecode.len()) {
                                            if self.bytecode[n] == 0x10 || self.bytecode[n] == 0x11 { // LT or GT
                                                has_price_comparison = true;
                                                break;
                                            }
                                        }
                                    }
                                }
                                
                                if !has_price_comparison {
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

    fn has_cascading_fallback_without_breaker(&self) -> Option<usize> {
        // Pattern: Multiple fallback levels without pause mechanism
        let mut fallback_count = 0;
        let mut has_circuit_breaker = false;
        let first_fallback_pos: Option<usize> = None;
        
        for i in 0..self.bytecode.len().saturating_sub(10) {
            // Count ISZERO checks (fallback triggers)
            if self.bytecode[i] == 0x15 { // ISZERO
                // Check if preceded by STATICCALL
                if i > 0 && self.bytecode[i-1] == 0xfa {
                    fallback_count += 1;
                    if first_fallback_pos.is_none() {
                        // Store first fallback position
                    }
                }
            }
            
            // Check for circuit breaker: REVERT or emergency pause
            if self.bytecode[i] == 0xfd { // REVERT
                // Check if this is conditional (circuit breaker)
                if i > 0 && (self.bytecode[i-1] == 0x57 || self.bytecode[i-1] == 0x56) { // JUMPI or JUMP
                    has_circuit_breaker = true;
                }
            }
        }
        
        // If 3+ fallback levels without circuit breaker
        if fallback_count >= 3 && !has_circuit_breaker {
            return self.bytecode.iter().position(|&b| b == 0xfa);
        }
        
        None
    }
}
