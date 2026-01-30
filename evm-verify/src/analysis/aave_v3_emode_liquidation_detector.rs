use serde::{Serialize, Deserialize};

/// Aave V3 E-Mode (Efficiency Mode) Liquidation Detection
/// 
/// E-Mode allows higher LTV for correlated assets but introduces risks:
/// 1. E-Mode category manipulation
/// 2. Incorrect asset categorization
/// 3. Liquidation threshold edge cases
/// 4. Cross-category position risks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AaveV3EmodeLiquidationVulnerability {
    /// Critical: E-Mode category can be manipulated
    CategoryManipulation {
        description: String,
        location: usize,
        confidence: f32,
    },
    /// High: Asset miscategorization risk
    AssetMiscategorization {
        description: String,
        location: usize,
    },
    /// High: Liquidation threshold not enforced
    MissingThresholdCheck {
        description: String,
        location: usize,
    },
    /// Medium: E-Mode switch without position check
    UnsafeEmodeSwitch {
        description: String,
        location: usize,
    },
}

pub struct AaveV3EmodeLiquidationDetector {
    bytecode: Vec<u8>,
}

impl AaveV3EmodeLiquidationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<AaveV3EmodeLiquidationVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern 1: Check setUserEMode function
        // Should validate that user's position is safe in new E-Mode
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i+1], self.bytecode[i+2],
                    self.bytecode[i+3], self.bytecode[i+4],
                ]);
                
                // setUserEMode selector: 0x28530a47
                if selector == 0x28530a47 || self.is_emode_setting_function(i) {
                    // Check if health factor is validated after switch
                    let validates_health = self.validates_health_factor(i);
                    
                    if !validates_health {
                        vulnerabilities.push(AaveV3EmodeLiquidationVulnerability::UnsafeEmodeSwitch {
                            description: "E-Mode switch without health factor validation".to_string(),
                            location: i,
                        });
                    }
                    
                    // Check if category exists and is valid
                    let validates_category = self.validates_emode_category(i);
                    
                    if !validates_category {
                        vulnerabilities.push(AaveV3EmodeLiquidationVulnerability::CategoryManipulation {
                            description: "E-Mode category not validated - invalid category possible".to_string(),
                            location: i,
                            confidence: 0.85,
                        });
                    }
                }
            }
        }
        
        // Pattern 2: Check liquidationCall with E-Mode
        for i in 0..self.bytecode.len().saturating_sub(120) {
            if self.is_liquidation_function(i) {
                // Check if E-Mode category is considered
                let considers_emode = self.considers_emode_in_liquidation(i);
                
                if !considers_emode {
                    vulnerabilities.push(AaveV3EmodeLiquidationVulnerability::MissingThresholdCheck {
                        description: "Liquidation doesn't properly consider E-Mode thresholds".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        // Pattern 3: Check E-Mode category configuration
        for i in 0..self.bytecode.len().saturating_sub(90) {
            if self.is_emode_config_function(i) {
                // Verify LTV/LT bounds are enforced
                let enforces_bounds = self.enforces_emode_bounds(i);
                
                if !enforces_bounds {
                    vulnerabilities.push(AaveV3EmodeLiquidationVulnerability::AssetMiscategorization {
                        description: "E-Mode category configuration without bound validation".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_emode_setting_function(&self, location: usize) -> bool {
        let end = std::cmp::min(location + 100, self.bytecode.len());
        let section = &self.bytecode[location..end];
        
        // E-Mode setting updates user's category
        let has_sstore = section.iter().any(|&b| b == 0x55);
        let has_calldataload = section.iter().any(|&b| b == 0x35);
        
        has_sstore && has_calldataload
    }
    
    fn validates_health_factor(&self, location: usize) -> bool {
        let end = std::cmp::min(location + 100, self.bytecode.len());
        
        // Health factor validation: calculate HF and check >= 1e18
        self.bytecode[location..end]
            .windows(4)
            .any(|w| {
                w[0] == 0x04 && // DIV (HF calculation)
                (w[2] == 0x10 || w[2] == 0x11) // LT or GT check
            })
    }
    
    fn validates_emode_category(&self, location: usize) -> bool {
        let end = std::cmp::min(location + 100, self.bytecode.len());
        
        // Should check: category exists, has valid config
        self.bytecode[location..end]
            .windows(4)
            .any(|w| {
                w[0] == 0x54 && // SLOAD (category config)
                w[1] == 0x15 && // ISZERO
                w[2] == 0x15 && // ISZERO (double negative)
                w[3] == 0x57    // JUMPI
            })
    }
    
    fn is_liquidation_function(&self, location: usize) -> bool {
        let end = std::cmp::min(location + 120, self.bytecode.len());
        let section = &self.bytecode[location..end];
        
        // Liquidation: transfers collateral, burns debt
        let has_transfers = section.iter().filter(|&&b| b == 0xf1).count() >= 2;
        let has_calculations = section.iter().any(|&b| b == 0x02 || b == 0x04);
        
        has_transfers && has_calculations
    }
    
    fn considers_emode_in_liquidation(&self, location: usize) -> bool {
        let end = std::cmp::min(location + 120, self.bytecode.len());
        
        // Should load E-Mode category and use in calculations
        let loads_emode = self.bytecode[location..end]
            .iter()
            .filter(|&&b| b == 0x54)
            .count() >= 3; // Multiple SLOADs for category, LT, LTV
        
        loads_emode
    }
    
    fn is_emode_config_function(&self, location: usize) -> bool {
        let end = std::cmp::min(location + 90, self.bytecode.len());
        let section = &self.bytecode[location..end];
        
        // Config function sets category parameters
        let has_multiple_sstores = section.iter().filter(|&&b| b == 0x55).count() >= 3;
        
        has_multiple_sstores
    }
    
    fn enforces_emode_bounds(&self, location: usize) -> bool {
        let end = std::cmp::min(location + 90, self.bytecode.len());
        
        // Should check: LTV <= LT <= 100%
        self.bytecode[location..end]
            .windows(2)
            .filter(|w| w[0] == 0x10 || w[0] == 0x11) // LT or GT
            .count() >= 2 // At least 2 bound checks
    }
}
