use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MigrationFrontrunningVulnerability {
    PreMigrationExploit { description: String, location: usize, confidence: f32 },
    MigrationRaceCondition { description: String, location: usize, confidence: f32 },
}

pub struct MigrationFrontrunningDetector {
    bytecode: Vec<u8>,
}

impl MigrationFrontrunningDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<MigrationFrontrunningVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(70) {
            let section = &self.bytecode[i..std::cmp::min(i + 70, self.bytecode.len())];
            
            // Pattern: Migration function without atomicity
            let has_migration = section.windows(15).any(|w| {
                w.contains(&0x54) && w.contains(&0x55) && w.contains(&0xF1) // SLOAD + SSTORE + CALL
            });
            
            if has_migration {
                vulnerabilities.push(MigrationFrontrunningVulnerability::PreMigrationExploit {
                    description: format!("Migration frontrunning at PC {}. Users migrating V1→V2, attacker frontruns. Attack: See migration tx in mempool → frontrun with V1 exploit → user migrates exploited state. Example: V1 has inflation bug, user migrating 100 tokens → attacker frontruns, inflates to 1000 → user migrates 1000. Or: Drain V1 liquidity before migration completes. Mitigation: Atomic migration (pause V1, migrate, unpause V2), or snapshot-based migration.", i),
                    location: i,
                    confidence: 0.83,
                });
            }
        }
        
        vulnerabilities
    }
}
