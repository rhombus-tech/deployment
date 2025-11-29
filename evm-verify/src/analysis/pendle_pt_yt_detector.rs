/// Pendle PT/YT Exploit Detector
/// Detects vulnerabilities in Pendle's Principal/Yield Token splitting
/// Critical for: Pendle integrations, yield tokenization

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendleVulnerability {
    pub vulnerability_type: PendleIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PendleIssueType {
    PTMispricing,                  // Principal Token mispriced
    YTRedemptionTiming,            // Yield Token redemption exploit
    AMMCurveManipulation,          // PT/YT AMM curve exploit
    MaturityExploitation,          // Maturity date manipulation
    ImpliedAPYManipulation,        // Implied APY calculation exploit
}

pub struct PendlePTYTDetector {
    bytecode: Vec<u8>,
}

impl PendlePTYTDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<PendleVulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.is_pendle_integration() {
            return vulnerabilities;
        }

        vulnerabilities.extend(self.detect_pt_pricing_issues());
        vulnerabilities.extend(self.detect_redemption_timing());

        vulnerabilities
    }

    fn detect_pt_pricing_issues(&self) -> Vec<PendleVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: PT pricing without maturity consideration
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.has_pricing_calculation(i) {
                if !self.has_maturity_factor(i) {
                    vulnerabilities.push(PendleVulnerability {
                        vulnerability_type: PendleIssueType::PTMispricing,
                        severity: SecuritySeverity::High,
                        confidence: 0.75,
                        description: "PT pricing without maturity time consideration".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. PT price calculated without time-to-maturity\n\
                            2. Near maturity PT mispriced\n\
                            3. Attacker arbitrages PT vs underlying\n\
                            4. Risk-free profit extraction\n\n\
                            Fix: Include (maturity - now) in price calculation",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_redemption_timing(&self) -> Vec<PendleVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: YT redemption without maturity check
        for i in 0..self.bytecode.len().saturating_sub(30) {
            let redeem = [0x1e, 0x83, 0x40, 0x9b]; // redeem()
            if i + 4 <= self.bytecode.len() && &self.bytecode[i..i+4] == &redeem {
                if !self.has_maturity_check(i) {
                    vulnerabilities.push(PendleVulnerability {
                        vulnerability_type: PendleIssueType::YTRedemptionTiming,
                        severity: SecuritySeverity::Medium,
                        confidence: 0.70,
                        description: "YT redemption without maturity date validation".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. Redeem YT before maturity\n\
                            2. No maturity date check\n\
                            3. Claim yield prematurely\n\
                            4. Protocol accounting broken\n\n\
                            Fix: require(block.timestamp >= maturity)",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn is_pendle_integration(&self) -> bool {
        // Look for PT/YT related functions
        let redeem = [0x1e, 0x83, 0x40, 0x9b];
        self.bytecode.windows(4).any(|w| w == redeem)
    }

    fn has_pricing_calculation(&self, pos: usize) -> bool {
        // Look for MUL/DIV (pricing math)
        pos + 5 < self.bytecode.len() &&
        (self.bytecode[pos] == 0x02 || self.bytecode[pos] == 0x04)
    }

    fn has_maturity_factor(&self, pos: usize) -> bool {
        // Look for TIMESTAMP and SUB (time-to-maturity)
        for i in pos.saturating_sub(20)..pos.saturating_add(20).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x42 && i + 2 < self.bytecode.len() && self.bytecode[i+2] == 0x03 {
                return true;
            }
        }
        false
    }

    fn has_maturity_check(&self, pos: usize) -> bool {
        // Look for TIMESTAMP >= maturity
        for i in pos..pos.saturating_add(40).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x42 && i + 3 < self.bytecode.len() && self.bytecode[i+3] == 0x11 {
                return true;
            }
        }
        false
    }
}
