// Cross-Rollup Message Censorship Detector
// Detects relayer manipulation and cross-L2 message censorship vulnerabilities

use crate::bytecode::security::{SecuritySeverity, SecurityWarning};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossRollupCensorshipVulnerability {
    pub location: usize,
    pub vulnerability_type: CrossRollupCensorshipType,
    pub severity: SecuritySeverity,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CrossRollupCensorshipType {
    RelayerCentralization,           // Single relayer can censor messages
    MessageQueueManipulation,        // Priority queue gaming
    FeeThresholdCensorship,          // Prohibitively high relay fees
    TimeoutExploitation,             // Force message expiry through delays
    RelayerCollusion,                // Multiple relayers collude to censor
    FallbackMechanismAbsence,        // No permissionless fallback relay
}

pub struct CrossRollupCensorshipDetector {
    bytecode: Vec<u8>,
}

impl CrossRollupCensorshipDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<CrossRollupCensorshipVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_relayer_centralization() {
            vulnerabilities.push(CrossRollupCensorshipVulnerability {
                location: loc,
                vulnerability_type: CrossRollupCensorshipType::RelayerCentralization,
                severity: SecuritySeverity::Critical,
                description: "Single relayer or centralized relayer set controls message relay. \
                             Messages can be censored without recourse.".to_string(),
                confidence: 0.90,
            });
        }

        if let Some(loc) = self.detect_message_queue_manipulation() {
            vulnerabilities.push(CrossRollupCensorshipVulnerability {
                location: loc,
                vulnerability_type: CrossRollupCensorshipType::MessageQueueManipulation,
                severity: SecuritySeverity::High,
                description: "Message queue priority manipulable by relayers. High-value messages \
                             can be indefinitely delayed.".to_string(),
                confidence: 0.86,
            });
        }

        if let Some(loc) = self.detect_fee_threshold_censorship() {
            vulnerabilities.push(CrossRollupCensorshipVulnerability {
                location: loc,
                vulnerability_type: CrossRollupCensorshipType::FeeThresholdCensorship,
                severity: SecuritySeverity::High,
                description: "Relay fee threshold unbounded. Relayers can demand prohibitively \
                             high fees to effectively censor messages.".to_string(),
                confidence: 0.84,
            });
        }

        if let Some(loc) = self.detect_timeout_exploitation() {
            vulnerabilities.push(CrossRollupCensorshipVulnerability {
                location: loc,
                vulnerability_type: CrossRollupCensorshipType::TimeoutExploitation,
                severity: SecuritySeverity::High,
                description: "Message timeout exploitable. Relayers can delay messages until \
                             expiry causing irreversible failures.".to_string(),
                confidence: 0.88,
            });
        }

        if let Some(loc) = self.detect_relayer_collusion() {
            vulnerabilities.push(CrossRollupCensorshipVulnerability {
                location: loc,
                vulnerability_type: CrossRollupCensorshipType::RelayerCollusion,
                severity: SecuritySeverity::Critical,
                description: "Insufficient relayer diversity. Small subset of relayers can \
                             collude to censor specific messages or users.".to_string(),
                confidence: 0.82,
            });
        }

        if let Some(loc) = self.detect_fallback_mechanism_absence() {
            vulnerabilities.push(CrossRollupCensorshipVulnerability {
                location: loc,
                vulnerability_type: CrossRollupCensorshipType::FallbackMechanismAbsence,
                severity: SecuritySeverity::Critical,
                description: "No permissionless fallback relay mechanism. Users cannot force \
                             message inclusion if relayers censor.".to_string(),
                confidence: 0.91,
            });
        }

        vulnerabilities
    }

    fn detect_relayer_centralization(&self) -> Option<usize> {
        // Pattern: Single relayer authorization without alternatives
        // Whitelist check with no fallback path
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x33 {  // CALLER (relayer)
                let mut has_whitelist = false;
                let mut has_fallback = false;
                let mut is_relay_function = false;
                
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    // Relayer whitelist check
                    if self.bytecode[j] == 0x54 {  // SLOAD (relayer whitelist)
                        has_whitelist = true;
                    }
                    
                    // Message relay (CALL to target chain)
                    if self.bytecode[j] == 0xF1 {
                        is_relay_function = true;
                    }
                    
                    // Fallback: OR condition allowing permissionless relay
                    if self.bytecode[j] == 0x17 {  // OR
                        has_fallback = true;
                    }
                }
                
                if is_relay_function && has_whitelist && !has_fallback {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_message_queue_manipulation(&self) -> Option<usize> {
        // Pattern: Priority queue without fairness guarantees
        // Queue ordering controlled by relayer without FIFO enforcement
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x54 {  // SLOAD (queue position)
                let mut has_priority_calc = false;
                let mut has_fifo_check = false;
                
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    // Priority calculation (fee-based ordering)
                    if self.bytecode[j] == 0x02 {  // MUL (priority score)
                        has_priority_calc = true;
                    }
                    
                    // FIFO timestamp check
                    if self.bytecode[j] == 0x42 {  // TIMESTAMP
                        for k in j+1..(j+5).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x10 {  // LT (earlier timestamp)
                                has_fifo_check = true;
                            }
                        }
                    }
                }
                
                if has_priority_calc && !has_fifo_check {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_fee_threshold_censorship(&self) -> Option<usize> {
        // Pattern: Relay fee with no maximum cap
        // Fee requirement without upper bound check
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x54 {  // SLOAD (relay fee)
                let mut has_fee_check = false;
                let mut has_max_fee = false;
                
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    // Fee requirement check
                    if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 {  // LT/GT
                        has_fee_check = true;
                    }
                    
                    // Maximum fee enforcement
                    if has_fee_check && self.bytecode[j] == 0x10 {  // Fee < maximum
                        has_max_fee = true;
                    }
                }
                
                if has_fee_check && !has_max_fee {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_timeout_exploitation(&self) -> Option<usize> {
        // Pattern: Message expiry without retry mechanism
        // Timeout check without fallback relay option
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x42 {  // TIMESTAMP
                let mut has_timeout = false;
                let mut has_retry = false;
                
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    // Timeout comparison
                    if self.bytecode[j] == 0x10 {  // LT (expired)
                        has_timeout = true;
                    }
                    
                    // Retry mechanism: extend deadline or alternative relay
                    if self.bytecode[j] == 0x55 {  // SSTORE (update deadline)
                        has_retry = true;
                    }
                }
                
                if has_timeout && !has_retry {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_relayer_collusion(&self) -> Option<usize> {
        // Pattern: Small relayer set without slashing
        // Few relayers (< 5) without misbehavior penalties
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Check relayer set size
            if self.bytecode[i] == 0x60 && i + 1 < self.bytecode.len() {  // PUSH1 (relayer count)
                let relayer_count = self.bytecode[i + 1];
                
                if relayer_count < 5 {
                    let mut has_slashing = false;
                    
                    // Check for slashing mechanism
                    for j in i..(i+25).min(self.bytecode.len()) {
                        // Slashing: reduce stake or ban relayer
                        if self.bytecode[j] == 0x03 {  // SUB (reduce stake)
                            has_slashing = true;
                        }
                    }
                    
                    if !has_slashing {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_fallback_mechanism_absence(&self) -> Option<usize> {
        // Pattern: Message relay without permissionless fallback
        // No escape hatch for censored messages
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0xF1 {  // CALL (relay message)
                let mut has_auth_check = false;
                let mut has_time_fallback = false;
                
                // Check for authorization requirement
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x14 {  // EQ (auth check)
                        has_auth_check = true;
                    }
                }
                
                // Check for time-based permissionless fallback
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x42 {  // TIMESTAMP
                        for k in j+1..(j+8).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x10 {  // LT (delay passed)
                                has_time_fallback = true;
                            }
                        }
                    }
                }
                
                if has_auth_check && !has_time_fallback {
                    return Some(i);
                }
            }
        }
        None
    }

    pub fn to_security_warnings(&self) -> Vec<SecurityWarning> {
        self.detect()
            .into_iter()
            .map(|v| SecurityWarning {
                kind: crate::bytecode::security::SecurityWarningKind::Other(
                    format!("CrossRollupCensorship{:?}", v.vulnerability_type)
                ),
                severity: v.severity,
                pc: v.location as u64,
                description: format!(
                    "Cross-Rollup Censorship {:?}: {}",
                    v.vulnerability_type, v.description
                ),
                operations: Vec::new(),
                remediation: "Implement decentralized relayer sets, maximum fee caps, \
                             permissionless fallback relay, and anti-collusion measures".to_string(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relayer_centralization() {
        let bytecode = vec![
            0x33, // CALLER
            0x60, 0x00, // PUSH1 0
            0x54, // SLOAD (whitelist check)
            0xF1, // CALL (relay - no fallback)
        ];
        
        let detector = CrossRollupCensorshipDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, CrossRollupCensorshipType::RelayerCentralization)));
    }

    #[test]
    fn test_fallback_mechanism_absence() {
        let bytecode = vec![
            0x60, 0x00, // PUSH1 0
            0x14, // EQ (auth check)
            0xF1, // CALL (relay without time fallback)
        ];
        
        let detector = CrossRollupCensorshipDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, CrossRollupCensorshipType::FallbackMechanismAbsence)));
    }
}
