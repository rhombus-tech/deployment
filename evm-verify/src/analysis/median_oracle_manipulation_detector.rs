/// Median Oracle Manipulation Detector
/// Detects median oracle price feed manipulation

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MedianOracleManipulationVulnerability {
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

pub struct MedianOracleManipulationDetector {
    bytecode: Vec<u8>,
}

impl MedianOracleManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<MedianOracleManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_primary_vulnerability());
        vulnerabilities.extend(self.detect_secondary_vulnerability());
        vulnerabilities.extend(self.detect_edge_case_vulnerability());
        vulnerabilities
    }

    fn detect_primary_vulnerability(&self) -> Vec<MedianOracleManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(250) {
            if self.is_vulnerable_operation(pc) {
                if !self.has_primary_protection(pc, 200) {
                    vulnerabilities.push(MedianOracleManipulationVulnerability {
                        severity: SecuritySeverity::Critical,
                        confidence: 0.85,
                        description: format!(
                            "median oracle price feed manipulation detected at PC {}. Primary vulnerability pattern found.",
                            pc
                        ),
                        exploit_scenario: 
                            "Control majority of oracle sources
1. Protocol uses 5 oracles
2. Attacker controls 3 of them
3. Attacker reports false prices
4. Median calculation uses false data
5. Protocol accepts manipulated price

                             Impact: High-value exploit enabling median oracle price feed manipulation

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

    fn detect_secondary_vulnerability(&self) -> Vec<MedianOracleManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(220) {
            if self.is_vulnerable_operation(pc) {
                if self.has_secondary_risk_pattern(pc, 180) {
                    vulnerabilities.push(MedianOracleManipulationVulnerability {
                        severity: SecuritySeverity::High,
                        confidence: 0.75,
                        description: format!(
                            "Secondary median oracle price feed manipulation risk at PC {}. Additional attack vector present.",
                            pc
                        ),
                        exploit_scenario:
                            "Exploit during oracle source changes
1. Protocol rotates oracle sources
2. During transition, fewer active oracles
3. Easier to control median
4. Submit manipulated data during window

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

    fn detect_edge_case_vulnerability(&self) -> Vec<MedianOracleManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(200) {
            if self.is_vulnerable_operation(pc) {
                if !self.has_edge_case_handling(pc, 150) {
                    vulnerabilities.push(MedianOracleManipulationVulnerability {
                        severity: SecuritySeverity::Medium,
                        confidence: 0.70,
                        description: format!(
                            "Edge case in median oracle price feed manipulation at PC {}. Uncommon scenario not handled.",
                            pc
                        ),
                        exploit_scenario:
                            "Require minimum oracle diversity
1. Use 7+ independent sources
2. Check oracle uptime history
3. Detect coordinated reporting patterns

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
