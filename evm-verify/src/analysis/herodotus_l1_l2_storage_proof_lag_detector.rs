// Herodotus L1→L2 Storage Proof Lag Detector
// Detects exploitation of L1 to L2 storage proof propagation delays

use crate::bytecode::security::{SecuritySeverity, SecurityWarning, SecurityWarningKind};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HerodotusVulnerability {
    pub location: usize,
    pub vulnerability_type: HerodotusVulnerabilityType,
    pub severity: SecuritySeverity,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HerodotusVulnerabilityType {
    ProofLagExploitation,           // Exploit delay in proof relay
    StaleDataUsage,                 // Use outdated L1 storage proof
    ProofFreshnessNotValidated,     // No freshness check on proof
    L1StateRaceCondition,           // Race between L1 state and proof
    ProofRelayManipulation,         // Manipulate proof relay timing
    CrossChainTimestampMismatch,    // Timestamp inconsistency L1/L2
}

pub struct HerodotusDetector {
    bytecode: Vec<u8>,
}

impl HerodotusDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<HerodotusVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_proof_lag_exploit() {
            vulnerabilities.push(HerodotusVulnerability {
                location: loc,
                vulnerability_type: HerodotusVulnerabilityType::ProofLagExploitation,
                severity: SecuritySeverity::Critical,
                description: "L1 storage proof used without age validation. Attacker can exploit \
                             propagation delay to act on L2 with outdated L1 state information.".to_string(),
                confidence: 0.88,
            });
        }

        if let Some(loc) = self.detect_stale_data() {
            vulnerabilities.push(HerodotusVulnerability {
                location: loc,
                vulnerability_type: HerodotusVulnerabilityType::StaleDataUsage,
                severity: SecuritySeverity::High,
                description: "Storage proof older than acceptable threshold. Critical decisions made \
                             using stale L1 data that no longer reflects current state.".to_string(),
                confidence: 0.85,
            });
        }

        if let Some(loc) = self.detect_freshness_not_validated() {
            vulnerabilities.push(HerodotusVulnerability {
                location: loc,
                vulnerability_type: HerodotusVulnerabilityType::ProofFreshnessNotValidated,
                severity: SecuritySeverity::High,
                description: "Proof block number not compared against current L1 block. No validation \
                             that proof represents recent L1 state.".to_string(),
                confidence: 0.86,
            });
        }

        if let Some(loc) = self.detect_l1_race_condition() {
            vulnerabilities.push(HerodotusVulnerability {
                location: loc,
                vulnerability_type: HerodotusVulnerabilityType::L1StateRaceCondition,
                severity: SecuritySeverity::High,
                description: "L1 state change can occur after proof generated but before L2 execution. \
                             No atomicity guarantee creating race condition window.".to_string(),
                confidence: 0.83,
            });
        }

        if let Some(loc) = self.detect_relay_manipulation() {
            vulnerabilities.push(HerodotusVulnerability {
                location: loc,
                vulnerability_type: HerodotusVulnerabilityType::ProofRelayManipulation,
                severity: SecuritySeverity::Medium,
                description: "Proof relay timing not enforced. Relayer can delay proof submission to \
                             manipulate when L2 receives L1 state update.".to_string(),
                confidence: 0.78,
            });
        }

        if let Some(loc) = self.detect_timestamp_mismatch() {
            vulnerabilities.push(HerodotusVulnerability {
                location: loc,
                vulnerability_type: HerodotusVulnerabilityType::CrossChainTimestampMismatch,
                severity: SecuritySeverity::Medium,
                description: "L1 and L2 timestamps not synchronized. Time-sensitive operations can \
                             behave incorrectly due to clock drift.".to_string(),
                confidence: 0.75,
            });
        }

        vulnerabilities
    }

    fn detect_proof_lag_exploit(&self) -> Option<usize> {
        // Pattern: Storage proof used without age check
        // Proof data loaded without block number validation
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x35 {  // CALLDATALOAD (proof)
                let mut validates_age = false;
                
                // Check for age validation (block number comparison)
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    // Age check: block.number - proofBlock < maxAge
                    if self.bytecode[j] == 0x43 {  // NUMBER (current L1 block)
                        for k in j+1..(j+8).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x03 {  // SUB (age calculation)
                                for m in k+1..(k+5).min(self.bytecode.len()) {
                                    if self.bytecode[m] == 0x10 {  // LT (age < max)
                                        validates_age = true;
                                    }
                                }
                            }
                        }
                    }
                }
                
                // Proof used without age validation
                if !validates_age {
                    for j in i+1..(i+15).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x55 {  // SSTORE (use proof data)
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn detect_stale_data(&self) -> Option<usize> {
        // Pattern: Proof age threshold too high
        // Age limit set to large value (> 100 blocks)
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x10 {  // LT (age check)
                let mut has_large_threshold = false;
                
                // Check threshold value
                for j in (i.saturating_sub(10))..i {
                    // Large threshold (PUSH2+ indicates > 255 blocks)
                    if matches!(self.bytecode[j], 0x61..=0x7F) {  // PUSH2 or larger
                        has_large_threshold = true;
                    }
                }
                
                // Check if this is proof age validation
                let mut is_age_check = false;
                for j in (i.saturating_sub(8))..i {
                    if self.bytecode[j] == 0x43 || self.bytecode[j] == 0x03 {  // NUMBER/SUB
                        is_age_check = true;
                    }
                }
                
                if is_age_check && has_large_threshold {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_freshness_not_validated(&self) -> Option<usize> {
        // Pattern: Proof block number not checked
        // Proof used without comparing proof.blockNumber against current
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x35 {  // CALLDATALOAD (proof with block number)
                let mut checks_block_number = false;
                
                // Look for block number comparison
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x43 {  // NUMBER
                        checks_block_number = true;
                    }
                }
                
                // Check if proof is verified
                let mut is_proof = false;
                for j in i+1..(i+15).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0xFA {  // STATICCALL (verify proof)
                        is_proof = true;
                    }
                }
                
                if is_proof && !checks_block_number {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_l1_race_condition(&self) -> Option<usize> {
        // Pattern: No atomicity guarantee between proof and execution
        // Proof verification followed immediately by state change without lock
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0xFA {  // STATICCALL (verify proof)
                let mut has_atomicity_lock = false;
                
                // Check for lock mechanism
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    // Lock: SSTORE setting flag, then checking it
                    if self.bytecode[j] == 0x55 {  // SSTORE (set lock)
                        for k in j+1..(j+8).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x54 {  // SLOAD (check lock)
                                has_atomicity_lock = true;
                            }
                        }
                    }
                }
                
                // State change without atomicity
                if !has_atomicity_lock {
                    for j in i+1..(i+20).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x55 {  // SSTORE (state change)
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn detect_relay_manipulation(&self) -> Option<usize> {
        // Pattern: No minimum relay time enforced
        // Proof submission without minimum delay check
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x55 {  // SSTORE (submit proof)
                let mut enforces_delay = false;
                
                // Check for minimum delay enforcement
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x42 {  // TIMESTAMP
                        for k in j+1..(j+10).min(self.bytecode.len()) {
                            // Delay: lastSubmit + minDelay < now
                            if self.bytecode[k] == 0x01 {  // ADD (calculate earliest)
                                for m in k+1..(k+5).min(self.bytecode.len()) {
                                    if self.bytecode[m] == 0x10 {  // LT (enforce delay)
                                        enforces_delay = true;
                                    }
                                }
                            }
                        }
                    }
                }
                
                // Check if this is proof submission
                let mut is_proof_submit = false;
                for j in (i.saturating_sub(15))..i {
                    if self.bytecode[j] == 0xFA {  // STATICCALL (verify)
                        is_proof_submit = true;
                    }
                }
                
                if is_proof_submit && !enforces_delay {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_timestamp_mismatch(&self) -> Option<usize> {
        // Pattern: L1 timestamp used directly on L2 without adjustment
        // Proof timestamp used without L1/L2 clock drift compensation
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x35 {  // CALLDATALOAD (L1 timestamp from proof)
                let mut adjusts_for_drift = false;
                
                // Check for drift adjustment
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    // Adjustment: ADD/SUB for clock drift
                    if self.bytecode[j] == 0x01 || self.bytecode[j] == 0x03 {
                        adjusts_for_drift = true;
                    }
                }
                
                // Check if timestamp is compared
                let mut uses_timestamp = false;
                for j in i+1..(i+15).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 {  // LT/GT
                        uses_timestamp = true;
                    }
                }
                
                if uses_timestamp && !adjusts_for_drift {
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
                kind: SecurityWarningKind::Herodotus,
                severity: v.severity,
                pc: v.location as u64,
                description: format!(
                    "Herodotus {:?}: {}",
                    v.vulnerability_type, v.description
                ),
                operations: Vec::new(),
                remediation: "Validate proof freshness and implement proper L1/L2 synchronization checks".to_string(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_lag_exploit() {
        let bytecode = vec![
            0x35, // CALLDATALOAD (proof)
            0x60, 0x00, // PUSH1 0
            0x55, // SSTORE (use without age check)
        ];
        
        let detector = HerodotusDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, HerodotusVulnerabilityType::ProofLagExploitation)));
    }

    #[test]
    fn test_freshness_not_validated() {
        let bytecode = vec![
            0x35, // CALLDATALOAD (proof)
            0xFA, // STATICCALL (verify - but no block number check)
            0x60, 0x00, // PUSH1 0
            0x55, // SSTORE
        ];
        
        let detector = HerodotusDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, HerodotusVulnerabilityType::ProofFreshnessNotValidated)));
    }
}
