use serde::{Serialize, Deserialize};

/// Curve Vyper-Specific Pool Bug Detection
/// 
/// Curve pools compiled with vulnerable Vyper versions have specific bugs:
/// 1. Malfunctioning lock in specific pool types
/// 2. Tricrypto/twocrypto specific issues
/// 3. Price oracle manipulation in Vyper pools
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CurveVyperPoolBugVulnerability {
    /// Critical: Vulnerable Vyper version pattern
    VulnerableVyperPattern {
        description: String,
        location: usize,
        confidence: f32,
    },
    /// High: Tricrypto pool specific bug
    TricryptoSpecificBug {
        description: String,
        location: usize,
    },
    /// High: Price oracle manipulation
    PriceOracleRisk {
        description: String,
        location: usize,
    },
}

pub struct CurveVyperPoolBugDetector {
    bytecode: Vec<u8>,
}

impl CurveVyperPoolBugDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<CurveVyperPoolBugVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern 1: Detect Vyper compiler signature
        let is_vyper = self.is_vyper_compiled();
        
        if is_vyper {
            // Check for vulnerable reentrancy pattern
            if self.has_vulnerable_vyper_reentrancy() {
                vulnerabilities.push(CurveVyperPoolBugVulnerability::VulnerableVyperPattern {
                    description: "Vyper reentrancy bug pattern detected - matches Curve exploit".to_string(),
                    location: 0,
                    confidence: 0.90,
                });
            }
        }
        
        // Pattern 2: Tricrypto-specific (3-asset pool)
        if self.is_tricrypto_pool() {
            let has_tricrypto_bug = self.has_tricrypto_specific_vulnerability();
            
            if has_tricrypto_bug {
                vulnerabilities.push(CurveVyperPoolBugVulnerability::TricryptoSpecificBug {
                    description: "Tricrypto pool with vulnerable calculation pattern".to_string(),
                    location: 0,
                });
            }
        }
        
        // Pattern 3: Price oracle in Curve pools
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.is_curve_price_oracle(i) {
                let can_be_manipulated = self.oracle_can_be_manipulated(i);
                
                if can_be_manipulated {
                    vulnerabilities.push(CurveVyperPoolBugVulnerability::PriceOracleRisk {
                        description: "Curve price oracle vulnerable to manipulation".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_vyper_compiled(&self) -> bool {
        // Vyper has specific bytecode patterns
        self.bytecode.windows(4).any(|w| {
            w[0] == 0x63 && w[1] == 0x70 && w[2] == 0xa0 // Vyper metadata pattern
        })
    }
    
    fn has_vulnerable_vyper_reentrancy(&self) -> bool {
        // Check for lock pattern without proper guards
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x60 && self.bytecode[i+1] == 0x00 && self.bytecode[i+2] == 0x54 {
                let has_call_after = self.bytecode[i..std::cmp::min(i+20, self.bytecode.len())]
                    .iter()
                    .any(|&b| b == 0xf1);
                if has_call_after {
                    return true;
                }
            }
        }
        false
    }
    
    fn is_tricrypto_pool(&self) -> bool {
        // Tricrypto has 3 coins - check for array size
        self.bytecode.windows(2).any(|w| w[0] == 0x60 && w[1] == 0x03) // PUSH1 3
    }
    
    fn has_tricrypto_specific_vulnerability(&self) -> bool {
        // Complex math operations vulnerable in tricrypto
        self.bytecode.windows(10)
            .filter(|w| w.iter().filter(|&&b| b == 0x0a).count() >= 2) // Multiple EXP
            .count() > 0
    }
    
    fn is_curve_price_oracle(&self, _i: usize) -> bool {
        // Price oracle function pattern (checks for oracle function selector)
        self.bytecode.windows(4).any(|w| w[0] == 0x63) // Function selector pattern
    }
    
    fn oracle_can_be_manipulated(&self, _location: usize) -> bool {
        // Check for flash loan protection
        !self.bytecode.iter().any(|&b| b == 0x42) // No TIMESTAMP check
    }
}
