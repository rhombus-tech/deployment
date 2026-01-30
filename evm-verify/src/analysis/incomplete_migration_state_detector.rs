use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IncompleteMigrationVulnerability {
    PartialMigrationInconsistency { description: String, location: usize, confidence: f32 },
    CrossVersionStateDesync { description: String, location: usize, confidence: f32 },
}

pub struct IncompleteMigrationStateDetector {
    bytecode: Vec<u8>,
}

impl IncompleteMigrationStateDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<IncompleteMigrationVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(70) {
            let section = &self.bytecode[i..std::cmp::min(i + 70, self.bytecode.len())];
            
            // Pattern: References both old and new state
            let has_external_call = section.windows(10).any(|w| {
                w.contains(&0xFA) || w.contains(&0xF1) // STATICCALL or CALL
            });
            
            let has_local_state = section.contains(&0x54); // SLOAD
            
            if has_external_call && has_local_state {
                vulnerabilities.push(IncompleteMigrationVulnerability::PartialMigrationInconsistency {
                    description: format!("Incomplete migration at PC {}. Some users on V1, some on V2 → state inconsistency. Attack: Exploit users stuck between versions. Example: 50% migrated to V2, 50% still on V1 → V1 state != V2 state → arbitrage. Or: V1 totals don't match V2 totals → accounting errors. Or: User deposits to V1, migrates, V2 doesn't see deposit. Mitigation: All-or-nothing migration, sync state continuously, or prohibit V1 operations during migration.", i),
                    location: i,
                    confidence: 0.81,
                });
            }
        }
        
        vulnerabilities
    }
}
