use serde::{Deserialize, Serialize};

/// Late Quorum Extension Griefing Detection
/// 
/// Detects vulnerabilities in late quorum extension mechanisms:
/// 1. Griefing attacks via last-minute votes
/// 2. Infinite extension loops
/// 3. Extension period manipulation
/// 4. Quorum threshold gaming
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LateQuorumExtensionGriefingVulnerability {
    /// Critical: Infinite extension possible
    InfiniteExtensionRisk {
        description: String,
        location: usize,
        max_extensions: u32,
    },
    /// High: Last-minute vote causes extension without cost
    FreeGriefingExtension {
        description: String,
        location: usize,
        confidence: f32,
    },
    /// Medium: Extension period too long
    ExcessiveExtensionPeriod {
        description: String,
        location: usize,
        extension_blocks: u64,
    },
    /// High: Quorum manipulation during extension
    QuorumManipulationDuringExtension {
        description: String,
        location: usize,
    },
}

pub struct LateQuorumExtensionGriefingDetector {
    bytecode: Vec<u8>,
}

impl LateQuorumExtensionGriefingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<LateQuorumExtensionGriefingVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern 1: Check for extension logic without max cap
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.is_extension_logic(i) {
                let has_max_cap = self.has_extension_cap(i, i + 100);
                let max_extensions = self.calculate_max_extensions(i);
                
                if !has_max_cap || max_extensions > 10 {
                    vulnerabilities.push(LateQuorumExtensionGriefingVulnerability::InfiniteExtensionRisk {
                        description: "Proposal extension lacks proper cap".to_string(),
                        location: i,
                        max_extensions,
                    });
                }
            }
        }
        
        // Pattern 2: Free griefing - no cost to trigger extension
        for i in 0..self.bytecode.len().saturating_sub(80) {
            if self.triggers_late_extension(i) {
                let has_cost = self.has_griefing_cost(i, i + 80);
                
                if !has_cost {
                    vulnerabilities.push(LateQuorumExtensionGriefingVulnerability::FreeGriefingExtension {
                        description: "Late vote triggers extension without cost".to_string(),
                        location: i,
                        confidence: 0.85,
                    });
                }
            }
        }
        
        // Pattern 3: Extension period validation
        let extension_periods = self.find_extension_periods();
        for (location, blocks) in extension_periods {
            if blocks > 50400 { // > 7 days at 12s blocks
                vulnerabilities.push(LateQuorumExtensionGriefingVulnerability::ExcessiveExtensionPeriod {
                    description: format!("Extension period of {} blocks is excessive", blocks),
                    location,
                    extension_blocks: blocks,
                });
            }
        }
        
        // Pattern 4: Quorum manipulation during extension
        for i in 0..self.bytecode.len().saturating_sub(120) {
            if self.is_quorum_calculation(i) {
                let can_manipulate_during_extension = self.quorum_changeable_during_voting(i, i + 120);
                
                if can_manipulate_during_extension {
                    vulnerabilities.push(LateQuorumExtensionGriefingVulnerability::QuorumManipulationDuringExtension {
                        description: "Quorum threshold can be changed during active voting period".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_extension_logic(&self, location: usize) -> bool {
        if location + 50 > self.bytecode.len() {
            return false;
        }
        
        // Look for timestamp/block number additions (extending deadline)
        self.bytecode[location..location + 50].windows(3).any(|w| {
            (w[0] == 0x42 || w[0] == 0x43) && // TIMESTAMP or NUMBER
            w[1] == 0x01 // ADD
        })
    }
    
    fn has_extension_cap(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return false;
        }
        
        // Check for max extension counter or limit
        self.bytecode[start..range_end].windows(3).any(|w| {
            w[0] == 0x10 || w[0] == 0x11 // LT or GT (comparison for limit)
        })
    }
    
    fn calculate_max_extensions(&self, location: usize) -> u32 {
        let search_end = (location + 100).min(self.bytecode.len());
        
        // Try to find constant defining max extensions
        for i in location..search_end {
            if self.bytecode[i] == 0x60 && i + 1 < search_end { // PUSH1
                let value = self.bytecode[i + 1] as u32;
                if value > 0 && value < 100 {
                    return value;
                }
            }
        }
        
        1000 // Assume unlimited if no cap found
    }
    
    fn triggers_late_extension(&self, location: usize) -> bool {
        if location + 30 > self.bytecode.len() {
            return false;
        }
        
        // Check for vote cast near deadline check
        let has_deadline_check = self.bytecode[location..location + 30]
            .windows(2)
            .any(|w| (w[0] == 0x42 || w[0] == 0x43) && w[1] == 0x11); // TIMESTAMP/NUMBER + GT
        
        let has_vote_cast = self.bytecode[location..location + 30]
            .iter()
            .any(|&b| b == 0x55); // SSTORE (recording vote)
        
        has_deadline_check && has_vote_cast
    }
    
    fn has_griefing_cost(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return false;
        }
        
        // Check for token burn, transfer, or fee on extension trigger
        self.bytecode[start..range_end].windows(4).any(|w| {
            // transfer or burn selector
            (w[0] == 0x63 && w[1] == 0xa9) || // transfer
            (w[0] == 0x63 && w[1] == 0x42) // burn
        })
    }
    
    fn find_extension_periods(&self) -> Vec<(usize, u64)> {
        let mut periods = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x60 { // PUSH1
                if i + 1 < self.bytecode.len() {
                    let value = self.bytecode[i + 1] as u64;
                    // Look for values that might be block counts (100 to 100000)
                    if value > 100 && value < 255 {
                        // Check if used in time calculation
                        if i + 5 < self.bytecode.len() && self.bytecode[i + 4] == 0x01 {
                            periods.push((i, value * 256)); // Estimate
                        }
                    }
                }
            }
            if self.bytecode[i] == 0x61 { // PUSH2
                if i + 2 < self.bytecode.len() {
                    let value = ((self.bytecode[i + 1] as u64) << 8) | (self.bytecode[i + 2] as u64);
                    if value > 1000 && value < 100000 {
                        periods.push((i, value));
                    }
                }
            }
        }
        
        periods
    }
    
    fn is_quorum_calculation(&self, location: usize) -> bool {
        if location + 40 > self.bytecode.len() {
            return false;
        }
        
        // Quorum calculations involve:
        // 1. totalSupply or totalVotes
        // 2. Percentage/fraction calculation
        // 3. Comparison
        
        let has_div = self.bytecode[location..location + 40].iter().any(|&b| b == 0x04);
        let has_comparison = self.bytecode[location..location + 40].iter().any(|&b| b == 0x10 || b == 0x11);
        
        has_div && has_comparison
    }
    
    fn quorum_changeable_during_voting(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return false;
        }
        
        // Check if quorum storage slot can be written during active proposal
        let has_quorum_write = self.bytecode[start..range_end]
            .windows(2)
            .any(|w| w[0] == 0x60 && w[1] < 10); // Low storage slots (likely config)
        
        let has_sstore = self.bytecode[start..range_end]
            .iter()
            .any(|&b| b == 0x55); // SSTORE
        
        has_quorum_write && has_sstore
    }
}
