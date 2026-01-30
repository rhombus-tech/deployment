use serde::{Serialize, Deserialize};

/// Compound V3 Absorption Mechanism Detection
/// 
/// Compound V3's "absorption" is the process of handling underwater accounts.
/// Vulnerabilities:
/// 1. Absorption can be triggered prematurely
/// 2. Reserves manipulation during absorption
/// 3. Price manipulation to force absorption
/// 4. Absorb function griefing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CompoundV3AbsorptionVulnerability {
    /// Critical: Absorption can be triggered without proper checks
    PrematureAbsorption {
        description: String,
        location: usize,
        confidence: f32,
    },
    /// High: Reserve accounting during absorption
    AbsorptionReserveRisk {
        description: String,
        location: usize,
    },
    /// High: Oracle price used without staleness check
    AbsorptionOracleRisk {
        description: String,
        location: usize,
    },
    /// Medium: Absorption gas griefing possible
    AbsorptionGriefing {
        description: String,
        location: usize,
    },
}

pub struct CompoundV3AbsorptionDetector {
    bytecode: Vec<u8>,
}

impl CompoundV3AbsorptionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<CompoundV3AbsorptionVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern 1: Check absorb function
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.is_absorb_function(i) {
                // Check if health factor is properly validated
                let validates_underwater = self.validates_underwater_condition(i);
                
                if !validates_underwater {
                    vulnerabilities.push(CompoundV3AbsorptionVulnerability::PrematureAbsorption {
                        description: "Absorb function without proper underwater validation".to_string(),
                        location: i,
                        confidence: 0.85,
                    });
                }
                
                // Check oracle usage
                let checks_oracle_staleness = self.checks_oracle_staleness(i);
                
                if !checks_oracle_staleness {
                    vulnerabilities.push(CompoundV3AbsorptionVulnerability::AbsorptionOracleRisk {
                        description: "Absorption uses oracle price without staleness check".to_string(),
                        location: i,
                    });
                }
                
                // Check reserve accounting
                let properly_accounts_reserves = self.properly_accounts_reserves(i);
                
                if !properly_accounts_reserves {
                    vulnerabilities.push(CompoundV3AbsorptionVulnerability::AbsorptionReserveRisk {
                        description: "Absorption doesn't properly account for reserves".to_string(),
                        location: i,
                    });
                }
                
                // Check for gas griefing protection
                let has_gas_limits = self.has_absorption_gas_limits(i);
                
                if !has_gas_limits {
                    vulnerabilities.push(CompoundV3AbsorptionVulnerability::AbsorptionGriefing {
                        description: "Absorb function without gas limit protection".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_absorb_function(&self, location: usize) -> bool {
        let end = std::cmp::min(location + 100, self.bytecode.len());
        let section = &self.bytecode[location..end];
        
        // Absorb function: reads user position, liquidates, updates reserves
        let has_position_read = section.iter().filter(|&&b| b == 0x54).count() >= 3;
        let has_state_updates = section.iter().filter(|&&b| b == 0x55).count() >= 2;
        let has_external_calls = section.iter().any(|&b| b == 0xf1);
        
        has_position_read && has_state_updates && has_external_calls
    }
    
    fn validates_underwater_condition(&self, location: usize) -> bool {
        let end = std::cmp::min(location + 100, self.bytecode.len());
        
        // Should check: borrow > collateral * LTV
        self.bytecode[location..end]
            .windows(4)
            .any(|w| {
                w[0] == 0x02 && // MUL (collateral * price)
                w[2] == 0x10    // LT (compare borrow < collateral)
            })
    }
    
    fn checks_oracle_staleness(&self, location: usize) -> bool {
        let end = std::cmp::min(location + 100, self.bytecode.len());
        
        // Should have TIMESTAMP comparison
        self.bytecode[location..end]
            .windows(3)
            .any(|w| {
                w[0] == 0x42 && // TIMESTAMP
                (w[1] == 0x03 || w[1] == 0x10) // SUB or LT (check age)
            })
    }
    
    fn properly_accounts_reserves(&self, location: usize) -> bool {
        let end = std::cmp::min(location + 100, self.bytecode.len());
        
        // Multiple reserve updates expected
        self.bytecode[location..end]
            .iter()
            .filter(|&&b| b == 0x55)
            .count() >= 3
    }
    
    fn has_absorption_gas_limits(&self, location: usize) -> bool {
        let end = std::cmp::min(location + 100, self.bytecode.len());
        
        // Check for GAS opcode and limit
        self.bytecode[location..end]
            .iter()
            .any(|&b| b == 0x5a) // GAS
    }
}
