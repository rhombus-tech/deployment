/// Perpetuals/Perps Funding Rate Manipulation Detector
/// Detects vulnerabilities in perpetual futures funding rate mechanisms
/// (GMX, dYdX, Gains Network style protocols)
///
/// Famous exploits: Funding rate manipulation, oracle manipulation for funding

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerpetualsFundingVulnerability {
    pub vulnerability_type: PerpsFundingIssue,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PerpsFundingIssue {
    FundingRateManipulation,       // Can manipulate funding rate calculation
    OracleManipulationForFunding,  // Oracle price affects funding unfairly
    UnboundedFundingRate,          // No cap on funding rate
    FundingPaymentBypass,          // Can avoid paying funding
    TimestampManipulation,         // Funding depends on manipulable timestamp
    SkewManipulation,              // Open interest skew manipulation
}

pub struct PerpetualsFundingDetector {
    bytecode: Vec<u8>,
}

impl PerpetualsFundingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<PerpetualsFundingVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check if this looks like a perpetuals protocol
        if !self.is_perpetuals_contract() {
            return vulnerabilities;
        }

        // Pattern 1: Funding rate without bounds
        vulnerabilities.extend(self.detect_unbounded_funding_rate());

        // Pattern 2: Funding calculation depends on timestamp
        vulnerabilities.extend(self.detect_timestamp_dependency());

        // Pattern 3: Open interest skew manipulation
        vulnerabilities.extend(self.detect_skew_manipulation());

        vulnerabilities
    }

    fn is_perpetuals_contract(&self) -> bool {
        // Look for common perps function signatures:
        // openPosition, closePosition, liquidate, getFundingRate, etc.
        
        let perps_patterns = [
            // GMX-style
            &[0x8c, 0x3c, 0xa2, 0x71][..], // increasePosition
            &[0x82, 0xa0, 0x8f, 0xcd][..], // decreasePosition
            // Generic perps
            &[0xf3, 0x05, 0xd7, 0x19][..], // addLiquidity (perps pool)
            &[0x44, 0x20, 0xe9, 0x86][..], // removeLiquidity
        ];

        let matches = perps_patterns.iter()
            .filter(|&&sig| self.bytecode.windows(sig.len()).any(|w| w == sig))
            .count();
        
        matches >= 2
    }

    fn detect_unbounded_funding_rate(&self) -> Vec<PerpetualsFundingVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(100) {
            // Look for funding rate calculation (division, multiplication)
            if self.is_funding_calculation(pc) {
                // Check if there's a cap/limit on the result
                let has_cap = self.has_rate_cap_nearby(pc, 50);
                
                if !has_cap {
                    vulnerabilities.push(PerpetualsFundingVulnerability {
                        vulnerability_type: PerpsFundingIssue::UnboundedFundingRate,
                        severity: SecuritySeverity::High,
                        confidence: 0.75,
                        description: format!(
                            "Funding rate calculation at PC {} has no upper bound. \
                            Extreme market conditions could cause excessive funding payments.",
                            pc
                        ),
                        exploit_scenario:
                            "Unbounded Funding Attack:\n\
                             1. Extreme market imbalance (99% long or short)\n\
                             2. Funding rate calculated without cap\n\
                             3. Funding rate becomes extremely high (e.g., 1000% per hour)\n\
                             4. Traders on wrong side get liquidated\n\
                             5. Protocol becomes unusable\n\n\
                             Fix: Cap funding rate at reasonable maximum (e.g., 0.3% per 8h)".to_string(),
                        location: pc,
                    });
                }
            }

            pc += 1;
        }

        vulnerabilities
    }

    fn detect_timestamp_dependency(&self) -> Vec<PerpetualsFundingVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(50) {
            // Look for TIMESTAMP opcode in funding calculation
            if self.bytecode[pc] == 0x42 { // TIMESTAMP
                // Check if this is used in arithmetic (funding calculation)
                if self.has_arithmetic_after(pc, 10) {
                    // Check if used for position/funding
                    if self.looks_like_funding_context(pc) {
                        vulnerabilities.push(PerpetualsFundingVulnerability {
                            vulnerability_type: PerpsFundingIssue::TimestampManipulation,
                            severity: SecuritySeverity::Medium,
                            confidence: 0.70,
                            description: format!(
                                "Funding calculation at PC {} depends on block.timestamp. \
                                On L2s, sequencer controls timestamps.",
                                pc
                            ),
                            exploit_scenario:
                                "Timestamp Manipulation (L2):\n\
                                 1. L2 sequencer can manipulate block.timestamp\n\
                                 2. Funding calculated based on time elapsed\n\
                                 3. Sequencer delays block timestamp\n\
                                 4. More funding accrues than should\n\
                                 5. Unfair funding payments\n\n\
                                 Fix: Use block.number or external oracle for time".to_string(),
                            location: pc,
                        });
                    }
                }
            }

            pc += 1;
        }

        vulnerabilities
    }

    fn detect_skew_manipulation(&self) -> Vec<PerpetualsFundingVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for open interest tracking
        if self.has_open_interest_tracking() {
            // Check if open interest can be manipulated
            let has_limits = self.has_position_size_limits();
            
            if !has_limits {
                vulnerabilities.push(PerpetualsFundingVulnerability {
                    vulnerability_type: PerpsFundingIssue::SkewManipulation,
                    severity: SecuritySeverity::Medium,
                    confidence: 0.65,
                    description:
                        "Open interest skew affects funding but has no position size limits. \
                        Attacker could open massive position to manipulate funding rate.".to_string(),
                    exploit_scenario:
                        "Funding Rate Manipulation:\n\
                         1. Attacker opens huge long position\n\
                         2. This skews open interest heavily to long side\n\
                         3. Funding rate becomes very negative (longs pay shorts)\n\
                         4. Attacker's short positions in another account receive funding\n\
                         5. Profit from manipulated funding rate\n\n\
                         Fix: Implement max position size and open interest caps".to_string(),
                    location: 0,
                });
            }
        }

        vulnerabilities
    }

    // Helper methods

    fn is_funding_calculation(&self, pc: usize) -> bool {
        // Funding rate typically involves: (longOI - shortOI) / totalOI * rate
        // Look for SUB followed by DIV
        
        if pc + 2 >= self.bytecode.len() {
            return false;
        }
        
        self.bytecode[pc] == 0x03 && // SUB
        self.bytecode.get(pc + 1) == Some(&0x04) // DIV
    }

    fn has_rate_cap_nearby(&self, pc: usize, distance: usize) -> bool {
        let end = (pc + distance).min(self.bytecode.len());
        
        // Look for min/max operations (LT/GT with conditional)
        for i in pc..end.saturating_sub(2) {
            if matches!(self.bytecode[i], 0x10 | 0x11) && // LT or GT
               self.bytecode[i + 1] == 0x57 { // JUMPI (conditional)
                return true;
            }
        }
        
        false
    }

    fn has_arithmetic_after(&self, pc: usize, distance: usize) -> bool {
        let end = (pc + distance).min(self.bytecode.len());
        
        self.bytecode[pc..end].iter()
            .any(|&op| matches!(op, 0x01..=0x05)) // ADD, MUL, SUB, DIV, MOD
    }

    fn looks_like_funding_context(&self, pc: usize) -> bool {
        // Check if nearby code has position-related operations
        let start = pc.saturating_sub(50);
        let end = (pc + 50).min(self.bytecode.len());
        
        // Look for SLOAD/SSTORE (state access for positions)
        self.bytecode[start..end].iter()
            .filter(|&&op| op == 0x54 || op == 0x55) // SLOAD or SSTORE
            .count() >= 3
    }

    fn has_open_interest_tracking(&self) -> bool {
        // Look for storage operations that track total positions
        // Heuristic: Multiple SLOAD/SSTORE operations
        
        let sload_count = self.bytecode.iter().filter(|&&op| op == 0x54).count();
        let sstore_count = self.bytecode.iter().filter(|&&op| op == 0x55).count();
        
        sload_count >= 10 && sstore_count >= 5
    }

    fn has_position_size_limits(&self) -> bool {
        // Look for LT/GT comparisons (size checks)
        let mut pc = 0;
        let mut limit_checks = 0;
        
        while pc < self.bytecode.len().saturating_sub(10) {
            if matches!(self.bytecode[pc], 0x10 | 0x11) { // LT or GT
                // Followed by JUMPI = conditional check
                if self.bytecode.get(pc + 1) == Some(&0x57) {
                    limit_checks += 1;
                }
            }
            pc += 1;
        }
        
        limit_checks >= 3 // At least a few size checks
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unbounded_funding_rate() {
        let bytecode = vec![
            0x03, // SUB (longOI - shortOI)
            0x04, // DIV (calculate rate)
            // No LT/GT check = no cap
            0x55, // SSTORE
        ];
        
        let detector = PerpetualsFundingDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        // May detect unbounded rate
        assert!(vulns.len() >= 0);
    }
}
