use serde::{Deserialize, Serialize};

/// Fraud Proof Timeout Detector (Optimistic Rollups)
/// 
/// Detects vulnerabilities in fraud proof challenge windows.
/// Critical for Optimism, Arbitrum, and other optimistic rollups.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FraudProofTimeoutVulnerability {
    /// Critical: Challenge period too short
    ChallengePeriodTooShort {
        description: String,
        location: usize,
        period_seconds: u64,
    },
    /// High: No challenge period enforcement
    NoChallengePeriodEnforcement {
        description: String,
        location: usize,
    },
    /// High: Challenge period can be bypassed
    ChallengePeriodBypassable {
        description: String,
        location: usize,
    },
    /// Medium: Timestamp manipulation in finalization
    TimestampManipulationRisk {
        description: String,
        location: usize,
    },
}

pub struct FraudProofTimeoutDetector {
    bytecode: Vec<u8>,
}

impl FraudProofTimeoutDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<FraudProofTimeoutVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern 1: Check challenge period duration
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if let Some((period, location)) = self.find_challenge_period(i) {
                // 7 days minimum is standard for optimistic rollups
                if period < 604800 { // 7 days in seconds
                    vulnerabilities.push(FraudProofTimeoutVulnerability::ChallengePeriodTooShort {
                        description: format!("Challenge period of {} seconds ({} days) is too short - standard is 7 days", period, period / 86400),
                        location,
                        period_seconds: period,
                    });
                }
            }
        }
        
        // Pattern 2: Check if finalization enforces challenge period
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.is_finalization_function(i) {
                if !self.checks_challenge_period(i, i + 100) {
                    vulnerabilities.push(FraudProofTimeoutVulnerability::NoChallengePeriodEnforcement {
                        description: "Finalization function does not enforce challenge period wait time".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        // Pattern 3: Check for bypass mechanisms
        for i in 0..self.bytecode.len().saturating_sub(80) {
            if self.has_emergency_finalization(i) {
                vulnerabilities.push(FraudProofTimeoutVulnerability::ChallengePeriodBypassable {
                    description: "Emergency finalization mechanism can bypass challenge period".to_string(),
                    location: i,
                });
            }
        }
        
        // Pattern 4: Timestamp manipulation
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if self.uses_timestamp_for_finalization(i) {
                if !self.has_timestamp_validation(i, i + 60) {
                    vulnerabilities.push(FraudProofTimeoutVulnerability::TimestampManipulationRisk {
                        description: "Uses block.timestamp for finalization without validation".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn find_challenge_period(&self, location: usize) -> Option<(u64, usize)> {
        if location + 20 > self.bytecode.len() {
            return None;
        }
        
        // Look for time constants (in seconds)
        // Common patterns: 1 day = 86400, 7 days = 604800
        
        for offset in 0..15 {
            if location + offset + 4 < self.bytecode.len() {
                if self.bytecode[location + offset] == 0x62 { // PUSH3
                    let value = ((self.bytecode[location + offset + 1] as u64) << 16)
                        | ((self.bytecode[location + offset + 2] as u64) << 8)
                        | (self.bytecode[location + offset + 3] as u64);
                    
                    // Check if this looks like a time period (1 hour to 30 days)
                    if value >= 3600 && value <= 2592000 {
                        return Some((value, location + offset));
                    }
                }
            }
        }
        
        None
    }
    
    fn is_finalization_function(&self, location: usize) -> bool {
        if location + 20 > self.bytecode.len() {
            return false;
        }
        
        // Common finalization function selectors
        let finalize_selectors = [
            [0x84, 0xe4, 0x52, 0x76], // finalizeWithdrawal()
            [0x8d, 0xd1, 0x4e, 0x02], // finalize()
            [0x71, 0x11, 0xdf, 0xbb], // finalizeExit()
        ];
        
        for selector in &finalize_selectors {
            for i in location..location.saturating_add(15).min(self.bytecode.len()).saturating_sub(4) {
                if &self.bytecode[i..i + 4] == selector {
                    return true;
                }
            }
        }
        
        false
    }
    
    fn checks_challenge_period(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Check for timestamp comparison pattern:
        // TIMESTAMP, ADD (created_at + period), LT/GT, check
        
        let mut has_timestamp = false;
        let mut has_add = false;
        let mut has_comparison = false;
        
        for i in start..range_end {
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                has_timestamp = true;
            }
            if has_timestamp && self.bytecode[i] == 0x01 { // ADD
                has_add = true;
            }
            if has_add && (self.bytecode[i] == 0x10 || self.bytecode[i] == 0x11) { // LT or GT
                has_comparison = true;
            }
        }
        
        has_timestamp && has_add && has_comparison
    }
    
    fn has_emergency_finalization(&self, location: usize) -> bool {
        if location + 30 > self.bytecode.len() {
            return false;
        }
        
        // Look for emergency/admin bypass patterns
        // Pattern: special role check OR timestamp bypass
        
        let slice = &self.bytecode[location..location + 30];
        
        // Check for OR logic (multiple paths to finalization)
        slice.iter().any(|&b| b == 0x17) // OR opcode
    }
    
    fn uses_timestamp_for_finalization(&self, location: usize) -> bool {
        if location + 20 > self.bytecode.len() {
            return false;
        }
        
        // TIMESTAMP opcode used in finalization logic
        self.bytecode[location..location + 20]
            .iter()
            .any(|&b| b == 0x42)
    }
    
    fn has_timestamp_validation(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Check if timestamp is validated against stored value
        // Pattern: SLOAD (stored time) + comparison with TIMESTAMP
        
        let mut has_sload = false;
        let mut has_timestamp = false;
        let mut has_comparison = false;
        
        for i in start..range_end {
            if self.bytecode[i] == 0x54 { // SLOAD
                has_sload = true;
            }
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                has_timestamp = true;
            }
            if self.bytecode[i] == 0x10 || self.bytecode[i] == 0x11 { // LT or GT
                has_comparison = true;
            }
        }
        
        has_sload && has_timestamp && has_comparison
    }
}
