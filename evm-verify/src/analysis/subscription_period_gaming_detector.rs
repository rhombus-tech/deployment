use serde::{Deserialize, Serialize};

/// Subscription Period Gaming: Exploit subscription timing
/// Attack: Subscribe right before benefits, unsubscribe after

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionGamingVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct SubscriptionPeriodGamingDetector {
    bytecode: Vec<u8>,
}

impl SubscriptionPeriodGamingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<SubscriptionGamingVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_subscription_timing_issue() {
            vulnerabilities.push(SubscriptionGamingVulnerability {
                vulnerability_type: "Subscription Timing Exploitation".to_string(),
                location: loc,
                severity: "Medium".to_string(),
                description: "Subscription can be gamed for short-term benefits".to_string(),
                confidence: 0.75,
            });
        }
        vulnerabilities
    }
    fn has_subscription_timing_issue(&self) -> Option<usize> {
        // Subscription: timestamp-based without minimum duration
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x55 { // SSTORE (subscription start)
                let mut has_min_duration = false;
                for j in i+1..i+25.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x42 { // TIMESTAMP
                        for k in j+1..(j+10).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x01 { // ADD (duration)
                                has_min_duration = true;
                            }
                        }
                    }
                }
                if !has_min_duration { return Some(i); }
            }
        }
        None
    }
}
