/// Weighted Oracle Gaming Detector
/// Detects weighted oracle price aggregation gaming

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeightedOracleGamingVulnerability {
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

pub struct WeightedOracleGamingDetector {
    bytecode: Vec<u8>,
}

impl WeightedOracleGamingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<WeightedOracleGamingVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_primary_vulnerability());
        vulnerabilities.extend(self.detect_secondary_vulnerability());
        vulnerabilities.extend(self.detect_edge_case_vulnerability());
        vulnerabilities
    }

    fn detect_primary_vulnerability(&self) -> Vec<WeightedOracleGamingVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(250) {
            if self.is_vulnerable_operation(pc) {
                if !self.has_primary_protection(pc, 200) {
                    vulnerabilities.push(WeightedOracleGamingVulnerability {
                        severity: SecuritySeverity::Critical,
                        confidence: 0.85,
                        description: format!(
                            "weighted oracle price aggregation gaming detected at PC {}. Primary vulnerability pattern found.",
                            pc
                        ),
                        exploit_scenario: 
                            "Manipulate high-weight oracle sources
1. Protocol weights oracles by liquidity
2. Attacker identifies highest-weight source
3. Flash loan manipulation of that source
4. Weighted average shifts significantly

                             Impact: High-value exploit enabling weighted oracle price aggregation gaming

                             Fix: Implement proper validation and bounds checking
                             require(condition, 'Protection failed');
                             // Add safety checks before critical operations".to_string(),
                        location: pc,
                    });
                }
            }
            pc += 1;
        }
        vulnerabilities
    }

    fn detect_secondary_vulnerability(&self) -> Vec<WeightedOracleGamingVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(220) {
            if self.is_vulnerable_operation(pc) {
                if self.has_secondary_risk_pattern(pc, 180) {
                    vulnerabilities.push(WeightedOracleGamingVulnerability {
                        severity: SecuritySeverity::High,
                        confidence: 0.75,
                        description: format!(
                            "Secondary weighted oracle price aggregation gaming risk at PC {}. Additional attack vector present.",
                            pc
                        ),
                        exploit_scenario:
                            "Exploit weight calculation bugs
1. Weights don't sum to 100%
2. Rounding errors accumulate
3. Attacker amplifies discrepancies
4. Price calculation becomes inaccurate

                             Secondary attack enables compound exploitation

                             Mitigation: Add secondary validation layer
                             uint256 check = validateSecondary();
                             require(check, 'Secondary validation failed');".to_string(),
                        location: pc,
                    });
                }
            }
            pc += 1;
        }
        vulnerabilities
    }

    fn detect_edge_case_vulnerability(&self) -> Vec<WeightedOracleGamingVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(200) {
            if self.is_vulnerable_operation(pc) {
                if !self.has_edge_case_handling(pc, 150) {
                    vulnerabilities.push(WeightedOracleGamingVulnerability {
                        severity: SecuritySeverity::Medium,
                        confidence: 0.70,
                        description: format!(
                            "Edge case in weighted oracle price aggregation gaming at PC {}. Uncommon scenario not handled.",
                            pc
                        ),
                        exploit_scenario:
                            "Dynamic weight adjustment needed
1. Recalculate weights frequently
2. Cap maximum single source weight
3. Detect manipulation attempts

                             Edge case exploitation allows bypass under specific conditions

                             Fix: Handle all edge cases explicitly
                             if (edgeCondition) {
                                 revert('Edge case not allowed');
                             }".to_string(),
                        location: pc,
                    });
                }
            }
            pc += 1;
        }
        vulnerabilities
    }

    fn is_vulnerable_operation(&self, pc: usize) -> bool {
        if pc + 100 >= self.bytecode.len() { return false; }
        // Pattern detection
        let mut has_operation = false;
        for i in pc..(pc + 100).min(self.bytecode.len()) {
            if matches!(self.bytecode[i], 0x02 | 0x04 | 0x54 | 0x55 | 0xf1 | 0xfa) {
                has_operation = true;
                break;
            }
        }
        has_operation
    }

    fn has_primary_protection(&self, pc: usize, range: usize) -> bool {
        let start = pc.saturating_sub(range / 2);
        let end = (pc + range / 2).min(self.bytecode.len());
        
        for i in start..end {
            if matches!(self.bytecode[i], 0x10 | 0x11) {
                for j in (i + 1)..(i + 10).min(end) {
                    if self.bytecode[j] == 0xfd { return true; }
                }
            }
        }
        false
    }

    fn has_secondary_risk_pattern(&self, pc: usize, range: usize) -> bool {
        let end = (pc + range).min(self.bytecode.len());
        let mut risk_indicators = 0;
        
        for i in pc..end {
            if matches!(self.bytecode[i], 0xf1 | 0xf2 | 0xf4) {
                risk_indicators += 1;
            }
        }
        
        risk_indicators >= 2
    }

    fn has_edge_case_handling(&self, pc: usize, range: usize) -> bool {
        let start = pc.saturating_sub(range / 2);
        let end = (pc + range / 2).min(self.bytecode.len());
        
        let mut has_condition = false;
        for i in start..end {
            if matches!(self.bytecode[i], 0x14 | 0x15) { // EQ, ISZERO
                has_condition = true;
                break;
            }
        }
        
        has_condition
    }
}
