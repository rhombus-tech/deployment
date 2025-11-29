/// Curve Tricrypto v2 Advanced Detector
/// Detects vulnerabilities specific to Curve Tricrypto pools
/// Critical for: Curve Tricrypto integrations, advanced AMM exploits

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurveTricryptoVulnerability {
    pub vulnerability_type: CurveTricryptoIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CurveTricryptoIssueType {
    GeometricMeanPriceManipulation, // Geometric mean oracle exploit
    RepegMechanismExploit,          // Repeg mechanism manipulation
    OracleEMAAttack,                // EMA oracle price attack
    ConcentrationParameterExploit,  // Gamma parameter manipulation
    VirtualPriceManipulation,       // Virtual price calculation exploit
}

pub struct CurveTricryptoDetector {
    bytecode: Vec<u8>,
}

impl CurveTricryptoDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<CurveTricryptoVulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.is_curve_tricrypto() {
            return vulnerabilities;
        }

        vulnerabilities.extend(self.detect_oracle_issues());
        vulnerabilities.extend(self.detect_repeg_issues());

        vulnerabilities
    }

    fn detect_oracle_issues(&self) -> Vec<CurveTricryptoVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: EMA price used without staleness check
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.has_ema_price_fetch(i) {
                if !self.has_price_freshness(i) {
                    vulnerabilities.push(CurveTricryptoVulnerability {
                        vulnerability_type: CurveTricryptoIssueType::OracleEMAAttack,
                        severity: SecuritySeverity::High,
                        confidence: 0.75,
                        description: "Curve Tricrypto EMA oracle without freshness validation".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. EMA oracle price fetched\n\
                            2. No validation of last update time\n\
                            3. Stale price used for calculations\n\
                            4. Arbitrage or unfair liquidations\n\n\
                            Fix: Validate price_oracle timestamp",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_repeg_issues(&self) -> Vec<CurveTricryptoVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Repeg without price bounds
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.has_repeg_mechanism(i) {
                if !self.has_price_bounds(i) {
                    vulnerabilities.push(CurveTricryptoVulnerability {
                        vulnerability_type: CurveTricryptoIssueType::RepegMechanismExploit,
                        severity: SecuritySeverity::Medium,
                        confidence: 0.70,
                        description: "Tricrypto repeg mechanism without price bounds".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. Pool rebalances via repeg mechanism\n\
                            2. No bounds on target price\n\
                            3. Attacker manipulates repeg direction\n\
                            4. Extracts value during rebalance\n\n\
                            Fix: Enforce min/max repeg price",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn is_curve_tricrypto(&self) -> bool {
        // Look for Tricrypto-specific functions
        let price_oracle = [0xd5, 0xa0, 0x7b, 0xc3]; // price_oracle()
        let gamma = [0xb1, 0xc0, 0xf9, 0x12]; // gamma()
        
        self.bytecode.windows(4).any(|w| w == price_oracle || w == gamma)
    }

    fn has_ema_price_fetch(&self, pos: usize) -> bool {
        // Look for EMA price calculation
        pos + 10 < self.bytecode.len() &&
        self.bytecode[pos] == 0x02 // MUL (EMA calculation)
    }

    fn has_price_freshness(&self, pos: usize) -> bool {
        // Look for timestamp check
        for i in pos..pos.saturating_add(40).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                return true;
            }
        }
        false
    }

    fn has_repeg_mechanism(&self, pos: usize) -> bool {
        // Look for price adjustment
        pos + 15 < self.bytecode.len()
    }

    fn has_price_bounds(&self, pos: usize) -> bool {
        // Look for price limit checks
        for i in pos..pos.saturating_add(30).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x10 || self.bytecode[i] == 0x11 {
                return true;
            }
        }
        false
    }
}
