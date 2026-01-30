// Shared Sequencer Censorship Detector
// Detects decentralized sequencer collusion and censorship vulnerabilities

use crate::bytecode::security::{SecuritySeverity, SecurityWarning};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedSequencerVulnerability {
    pub location: usize,
    pub vulnerability_type: SharedSequencerCensorshipType,
    pub severity: SecuritySeverity,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SharedSequencerCensorshipType {
    SequencerCartelFormation,        // Small set of sequencers collude
    TransactionInclusionBias,        // Preferential ordering for certain txs
    CrossRollupCensorship,           // Coordinated censorship across L2s
    MEVExtractionCollusion,          // Joint MEV extraction schemes
    SlashingResistance,              // Insufficient penalties for misbehavior
    PermissionlessEntryBarrier,      // High barriers prevent sequencer diversity
}

pub struct SharedSequencerDetector {
    bytecode: Vec<u8>,
}

impl SharedSequencerDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SharedSequencerVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_sequencer_cartel_formation() {
            vulnerabilities.push(SharedSequencerVulnerability {
                location: loc,
                vulnerability_type: SharedSequencerCensorshipType::SequencerCartelFormation,
                severity: SecuritySeverity::Critical,
                description: "Small sequencer set without rotation or diversity requirements. \
                             Sequencers can collude to censor transactions or users.".to_string(),
                confidence: 0.89,
            });
        }

        if let Some(loc) = self.detect_transaction_inclusion_bias() {
            vulnerabilities.push(SharedSequencerVulnerability {
                location: loc,
                vulnerability_type: SharedSequencerCensorshipType::TransactionInclusionBias,
                severity: SecuritySeverity::High,
                description: "Transaction ordering controlled by sequencer without neutrality \
                             guarantees. Preferential treatment possible.".to_string(),
                confidence: 0.86,
            });
        }

        if let Some(loc) = self.detect_cross_rollup_censorship() {
            vulnerabilities.push(SharedSequencerVulnerability {
                location: loc,
                vulnerability_type: SharedSequencerCensorshipType::CrossRollupCensorship,
                severity: SecuritySeverity::Critical,
                description: "Shared sequencer can censor transactions across multiple rollups \
                             simultaneously. No per-rollup fallback mechanism.".to_string(),
                confidence: 0.91,
            });
        }

        if let Some(loc) = self.detect_mev_extraction_collusion() {
            vulnerabilities.push(SharedSequencerVulnerability {
                location: loc,
                vulnerability_type: SharedSequencerCensorshipType::MEVExtractionCollusion,
                severity: SecuritySeverity::High,
                description: "MEV extraction not regulated or distributed fairly. Sequencers can \
                             collude to maximize extraction at user expense.".to_string(),
                confidence: 0.84,
            });
        }

        if let Some(loc) = self.detect_slashing_resistance() {
            vulnerabilities.push(SharedSequencerVulnerability {
                location: loc,
                vulnerability_type: SharedSequencerCensorshipType::SlashingResistance,
                severity: SecuritySeverity::High,
                description: "Slashing penalties insufficient or bypassable. Sequencers not \
                             adequately punished for censorship or misbehavior.".to_string(),
                confidence: 0.82,
            });
        }

        if let Some(loc) = self.detect_permissionless_entry_barrier() {
            vulnerabilities.push(SharedSequencerVulnerability {
                location: loc,
                vulnerability_type: SharedSequencerCensorshipType::PermissionlessEntryBarrier,
                severity: SecuritySeverity::Medium,
                description: "High capital or technical requirements prevent permissionless \
                             sequencer entry, limiting decentralization.".to_string(),
                confidence: 0.79,
            });
        }

        vulnerabilities
    }

    fn detect_sequencer_cartel_formation(&self) -> Option<usize> {
        // Pattern: Small fixed sequencer set without rotation
        // Sequencer list size check without dynamic updates
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Check for sequencer set size
            if self.bytecode[i] == 0x60 && i + 1 < self.bytecode.len() {  // PUSH1
                let set_size = self.bytecode[i + 1];
                
                if set_size < 10 {  // Small set vulnerable to collusion
                    let mut has_rotation = false;
                    let mut has_diversity_check = false;
                    
                    // Check for rotation mechanism
                    for j in i..(i+25).min(self.bytecode.len()) {
                        // Rotation: periodic sequencer replacement
                        if self.bytecode[j] == 0x42 {  // TIMESTAMP
                            for k in j+1..(j+8).min(self.bytecode.len()) {
                                if self.bytecode[k] == 0x06 {  // MOD (rotation period)
                                    has_rotation = true;
                                }
                            }
                        }
                        
                        // Diversity check: geographical or entity distribution
                        if self.bytecode[j] == 0x54 {  // SLOAD (diversity metric)
                            has_diversity_check = true;
                        }
                    }
                    
                    if !has_rotation && !has_diversity_check {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_transaction_inclusion_bias(&self) -> Option<usize> {
        // Pattern: Transaction ordering by sequencer without neutrality
        // Priority based on criteria other than timestamp/gas
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x33 {  // CALLER (sequencer)
                let mut has_ordering = false;
                let mut has_neutrality = false;
                
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    // Transaction ordering (priority queue manipulation)
                    if self.bytecode[j] == 0x55 {  // SSTORE (set order)
                        has_ordering = true;
                    }
                    
                    // Neutrality: FIFO based on timestamp only
                    if self.bytecode[j] == 0x42 {  // TIMESTAMP
                        for k in j+1..(j+5).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x10 {  // LT (FIFO check)
                                has_neutrality = true;
                            }
                        }
                    }
                }
                
                if has_ordering && !has_neutrality {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_cross_rollup_censorship(&self) -> Option<usize> {
        // Pattern: Single sequencer controls multiple rollups without escape hatch
        // No per-rollup permissionless fallback
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x54 {  // SLOAD (rollup ID)
                let mut controls_multiple = false;
                let mut has_fallback = false;
                
                // Check if sequencer handles multiple rollups
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    // Multiple rollup IDs in comparison
                    if self.bytecode[j] == 0x14 {  // EQ (rollup ID check)
                        controls_multiple = true;
                    }
                }
                
                // Check for escape hatch: time-based permissionless inclusion
                for j in i..(i+25).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x42 {  // TIMESTAMP
                        for k in j+1..(j+10).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x10 {  // LT (forced inclusion after delay)
                                has_fallback = true;
                            }
                        }
                    }
                }
                
                if controls_multiple && !has_fallback {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_mev_extraction_collusion(&self) -> Option<usize> {
        // Pattern: MEV extraction without fair distribution or limits
        // Sequencer can extract value without user compensation
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // MEV extraction (transaction reordering for profit)
            if self.bytecode[i] == 0x02 {  // MUL (calculate MEV profit)
                let mut has_extraction = false;
                let mut has_distribution = false;
                
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    // Profit extraction (transfer to sequencer)
                    if self.bytecode[j] == 0xF1 {  // CALL (extract value)
                        has_extraction = true;
                    }
                    
                    // Fair distribution: portion returned to users/protocol
                    if self.bytecode[j] == 0x04 {  // DIV (split rewards)
                        for k in j+1..(j+5).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0xF1 {  // CALL (distribute)
                                has_distribution = true;
                            }
                        }
                    }
                }
                
                if has_extraction && !has_distribution {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_slashing_resistance(&self) -> Option<usize> {
        // Pattern: Slashing mechanism weak or absent
        // Sequencer misbehavior not adequately punished
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x33 {  // CALLER (sequencer)
                let mut has_stake = false;
                let mut has_slashing = false;
                
                // Check for staking requirement
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x54 {  // SLOAD (stake amount)
                        has_stake = true;
                    }
                }
                
                // Check for slashing logic
                for j in i..(i+25).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x03 {  // SUB (reduce stake)
                        for k in j+1..(j+5).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x55 {  // SSTORE (update stake)
                                has_slashing = true;
                            }
                        }
                    }
                }
                
                if has_stake && !has_slashing {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_permissionless_entry_barrier(&self) -> Option<usize> {
        // Pattern: High minimum stake or complex requirements
        // Entry barrier prevents diverse sequencer set
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            // Sequencer registration with stake requirement
            if self.bytecode[i] == 0x60 || self.bytecode[i] == 0x61 {  // PUSH (stake amount)
                let stake_size = if self.bytecode[i] == 0x60 { 1 } else { 2 };
                
                // Large stake requirement (PUSH2 or higher indicates > 255 ETH equivalent)
                if stake_size >= 2 {
                    let mut is_stake_check = false;
                    
                    for j in i+stake_size+1..(i+15).min(self.bytecode.len()) {
                        // Stake comparison
                        if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 {  // LT/GT
                            is_stake_check = true;
                        }
                    }
                    
                    if is_stake_check {
                        return Some(i);
                    }
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
                    format!("SharedSequencerCensorship{:?}", v.vulnerability_type)
                ),
                severity: v.severity,
                pc: v.location as u64,
                description: format!(
                    "Shared Sequencer Censorship {:?}: {}",
                    v.vulnerability_type, v.description
                ),
                operations: Vec::new(),
                remediation: "Implement sequencer rotation, diversity requirements, neutrality proofs, \
                             MEV fair distribution, strong slashing, and low entry barriers".to_string(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sequencer_cartel_formation() {
        let bytecode = vec![
            0x60, 0x05, // PUSH1 5 (small sequencer set)
            0x60, 0x00, // PUSH1 0
            // No rotation mechanism
        ];
        
        let detector = SharedSequencerDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, SharedSequencerCensorshipType::SequencerCartelFormation)));
    }

    #[test]
    fn test_slashing_resistance() {
        let bytecode = vec![
            0x33, // CALLER
            0x60, 0x00, // PUSH1 0
            0x54, // SLOAD (stake - but no slashing logic)
        ];
        
        let detector = SharedSequencerDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, SharedSequencerCensorshipType::SlashingResistance)));
    }
}
