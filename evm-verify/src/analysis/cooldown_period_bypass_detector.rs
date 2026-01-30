use serde::{Deserialize, Serialize};

/// Cooldown Period Bypass: Required waiting periods can be circumvented
/// Attack: Multiple accounts, contract recreation, etc.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CooldownBypassVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct CooldownPeriodBypassDetector {
    bytecode: Vec<u8>,
}

impl CooldownPeriodBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<CooldownBypassVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_weak_cooldown() {
            vulnerabilities.push(CooldownBypassVulnerability {
                vulnerability_type: "Weak Cooldown Implementation".to_string(),
                location: loc,
                severity: "Medium".to_string(),
                description: "Cooldown period bypassable via multiple addresses".to_string(),
                confidence: 0.75,
            });
        }
        vulnerabilities
    }
    fn has_weak_cooldown(&self) -> Option<usize> {
        // Cooldown: timestamp comparison without global tracking
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                for j in i+1..i+20.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x10 { // LT (cooldown check)
                        let mut has_global_tracking = false;
                        // Check if using CALLER-specific storage only
                        for k in i..j {
                            if self.bytecode[k] == 0x33 { // CALLER
                                has_global_tracking = false; // Per-user only
                            }
                        }
                        if !has_global_tracking { return Some(i); }
                    }
                }
            }
        }
        None
    }
}
