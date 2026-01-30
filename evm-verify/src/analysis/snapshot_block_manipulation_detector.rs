// Snapshot Block Manipulation Detector
// Detects front-running snapshot heights and delegation timing exploits

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotBlockManipulationVulnerability {
    pub location: usize,
    pub vulnerability_type: SnapshotManipulationType,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SnapshotManipulationType {
    FrontRunningSnapshot,            // Front-run snapshot block for advantage
    BlockHeightGaming,               // Manipulate timing around snapshot
    SnapshotTimingExploit,           // Exploit predictable snapshot timing
    VotingPowerInflation,            // Inflate power before snapshot
    DelegationBeforeSnapshot,        // Strategic delegation timing
    SnapshotReorgVulnerability,      // Snapshot vulnerable to chain reorgs
}

pub struct SnapshotBlockManipulationDetector {
    bytecode: Vec<u8>,
}

impl SnapshotBlockManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<SnapshotBlockManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_front_running_snapshot() {
            vulnerabilities.push(SnapshotBlockManipulationVulnerability {
                location: loc,
                vulnerability_type: SnapshotManipulationType::FrontRunningSnapshot,
                severity: "High".to_string(),
                description: "Snapshot block predictable and public. Users can front-run snapshot \
                             by acquiring tokens just before snapshot height.".to_string(),
                confidence: 0.89,
            });
        }

        if let Some(loc) = self.detect_block_height_gaming() {
            vulnerabilities.push(SnapshotBlockManipulationVulnerability {
                location: loc,
                vulnerability_type: SnapshotManipulationType::BlockHeightGaming,
                severity: "High".to_string(),
                description: "Snapshot uses current block number without delay. Snapshot timing \
                             can be gamed through strategic transaction inclusion.".to_string(),
                confidence: 0.87,
            });
        }

        if let Some(loc) = self.detect_snapshot_timing_exploit() {
            vulnerabilities.push(SnapshotBlockManipulationVulnerability {
                location: loc,
                vulnerability_type: SnapshotManipulationType::SnapshotTimingExploit,
                severity: "Medium".to_string(),
                description: "Snapshot timing follows predictable pattern. Attackers can prepare \
                             positions in advance knowing exact snapshot moment.".to_string(),
                confidence: 0.83,
            });
        }

        if let Some(loc) = self.detect_voting_power_inflation() {
            vulnerabilities.push(SnapshotBlockManipulationVulnerability {
                location: loc,
                vulnerability_type: SnapshotManipulationType::VotingPowerInflation,
                severity: "High".to_string(),
                description: "No restrictions on token acquisition before snapshot. Users can \
                             borrow or flash loan tokens to inflate voting power at snapshot.".to_string(),
                confidence: 0.90,
            });
        }

        if let Some(loc) = self.detect_delegation_before_snapshot() {
            vulnerabilities.push(SnapshotBlockManipulationVulnerability {
                location: loc,
                vulnerability_type: SnapshotManipulationType::DelegationBeforeSnapshot,
                severity: "Medium".to_string(),
                description: "Delegation allowed immediately before snapshot without delay. \
                             Voting power can be strategically delegated at last moment.".to_string(),
                confidence: 0.85,
            });
        }

        if let Some(loc) = self.detect_snapshot_reorg_vulnerability() {
            vulnerabilities.push(SnapshotBlockManipulationVulnerability {
                location: loc,
                vulnerability_type: SnapshotManipulationType::SnapshotReorgVulnerability,
                severity: "High".to_string(),
                description: "Snapshot taken at recent block without finality buffer. Chain reorg \
                             can invalidate snapshot causing governance inconsistency.".to_string(),
                confidence: 0.88,
            });
        }

        vulnerabilities
    }

    fn detect_front_running_snapshot(&self) -> Option<usize> {
        // Pattern: Snapshot block determined in same transaction
        // NUMBER opcode used to set snapshot without advance notice
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x43 {  // NUMBER (current block)
                let mut sets_snapshot = false;
                let mut has_delay = false;
                
                // Check if used to set snapshot height
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x55 {  // SSTORE (save snapshot block)
                        sets_snapshot = true;
                    }
                }
                
                // Check for advance notice (delay before snapshot)
                for j in i+1..(i+15).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x01 {  // ADD (future block)
                        has_delay = true;
                    }
                }
                
                if sets_snapshot && !has_delay {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_block_height_gaming(&self) -> Option<usize> {
        // Pattern: Snapshot at current block without buffer
        // Immediate snapshot capture allowing same-block manipulation
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x55 {  // SSTORE (record snapshot)
                let mut uses_current_block = false;
                let mut has_buffer = false;
                
                // Check if current block number used
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x43 {  // NUMBER
                        uses_current_block = true;
                        
                        // Check for buffer (subtraction for past block)
                        for k in j+1..(j+8).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x03 {  // SUB (use past block)
                                has_buffer = true;
                            }
                        }
                    }
                }
                
                if uses_current_block && !has_buffer {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_snapshot_timing_exploit(&self) -> Option<usize> {
        // Pattern: Predictable snapshot interval
        // Fixed interval or pattern for snapshots
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x06 {  // MOD (periodic interval)
                let mut determines_snapshot = false;
                let mut has_randomness = false;
                
                // Check if used for snapshot timing
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x14 {  // EQ (check if snapshot block)
                        determines_snapshot = true;
                    }
                }
                
                // Check for randomness (unpredictable component)
                for j in (i.saturating_sub(15))..i {
                    if self.bytecode[j] == 0x40 {  // BLOCKHASH (unpredictable)
                        has_randomness = true;
                    }
                }
                
                if determines_snapshot && !has_randomness {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_voting_power_inflation(&self) -> Option<usize> {
        // Pattern: Snapshot without minimum holding period
        // Balance snapshot without checking token age
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x54 {  // SLOAD (balance for snapshot)
                let mut is_snapshot = false;
                let mut checks_holding_period = false;
                
                // Check if snapshot operation (snapshot block comparison)
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x43 {  // NUMBER
                        for k in j+1..(j+10).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x14 {  // EQ (snapshot block check)
                                is_snapshot = true;
                            }
                        }
                    }
                }
                
                // Check for holding period verification
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x54 {  // SLOAD (acquisition timestamp)
                        for k in j+1..(j+10).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x03 {  // SUB (time held)
                                for m in k+1..(k+5).min(self.bytecode.len()) {
                                    if self.bytecode[m] == 0x10 {  // LT (held long enough)
                                        checks_holding_period = true;
                                    }
                                }
                            }
                        }
                    }
                }
                
                if is_snapshot && !checks_holding_period {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_delegation_before_snapshot(&self) -> Option<usize> {
        // Pattern: Delegation allowed up to snapshot block
        // No minimum time between delegation and snapshot
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x55 {  // SSTORE (set delegation)
                let mut is_delegation = false;
                let mut has_snapshot_buffer = false;
                
                // Check if delegation operation
                for j in (i.saturating_sub(15))..i {
                    if self.bytecode[j] == 0x33 {  // CALLER (delegator)
                        is_delegation = true;
                    }
                }
                
                // Check for snapshot proximity restriction
                for j in (i.saturating_sub(25))..i {
                    if self.bytecode[j] == 0x43 {  // NUMBER
                        for k in j+1..(j+15).min(self.bytecode.len()) {
                            // Check if snapshot block is far enough
                            if self.bytecode[k] == 0x03 {  // SUB
                                for m in k+1..(k+5).min(self.bytecode.len()) {
                                    if self.bytecode[m] == 0x10 {  // LT (buffer blocks)
                                        has_snapshot_buffer = true;
                                    }
                                }
                            }
                        }
                    }
                }
                
                if is_delegation && !has_snapshot_buffer {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_snapshot_reorg_vulnerability(&self) -> Option<usize> {
        // Pattern: Snapshot at recent block without finality delay
        // Using block within reorg window (< 64 blocks on Ethereum)
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x55 {  // SSTORE (save snapshot)
                let mut uses_recent_block = false;
                let mut has_finality_delay = false;
                
                // Check if recent block number
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x43 {  // NUMBER (current)
                        uses_recent_block = true;
                        
                        // Check for finality delay (64+ blocks back)
                        for k in j+1..(j+15).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x03 {  // SUB
                                // Check if subtracting enough blocks (PUSH1 >= 64)
                                for m in (k.saturating_sub(5))..k {
                                    if self.bytecode[m] == 0x60 && m+1 < self.bytecode.len() {
                                        if self.bytecode[m+1] >= 64 {  // At least 64 blocks
                                            has_finality_delay = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                
                if uses_recent_block && !has_finality_delay {
                    return Some(i);
                }
            }
        }
        None
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_front_running_snapshot() {
        let bytecode = vec![
            0x43, // NUMBER (current block)
            0x60, 0x00, // PUSH1 0
            0x55, // SSTORE (immediate snapshot - no delay)
        ];
        
        let detector = SnapshotBlockManipulationDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, SnapshotManipulationType::FrontRunningSnapshot)));
    }

    #[test]
    fn test_snapshot_reorg_vulnerability() {
        let bytecode = vec![
            0x43, // NUMBER (recent block)
            0x60, 0x00, // PUSH1 0
            0x55, // SSTORE (no finality delay)
        ];
        
        let detector = SnapshotBlockManipulationDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, SnapshotManipulationType::SnapshotReorgVulnerability)));
    }
}
