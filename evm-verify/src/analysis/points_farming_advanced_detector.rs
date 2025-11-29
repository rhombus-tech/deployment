/// Points/Airdrop Farming Advanced Detector (Enhanced)
/// Advanced detection beyond basic points_gaming_detector.rs
/// Critical for: Sybil resistance, airdrop integrity

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PointsFarmingVulnerability {
    pub vulnerability_type: PointsFarmingIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PointsFarmingIssueType {
    SybilAttackVulnerable,         // No sybil resistance
    WashTradingForPoints,          // Wash trading detection missing
    BotDrivenFarming,              // Bot farming not prevented
    ReferralManipulation,          // Referral system exploitable
    ActivityMultiplierExploit,     // Activity multiplier manipulation
}

pub struct PointsFarmingAdvancedDetector {
    bytecode: Vec<u8>,
}

impl PointsFarmingAdvancedDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<PointsFarmingVulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.is_points_system() {
            return vulnerabilities;
        }

        vulnerabilities.extend(self.detect_sybil_vulnerability());
        vulnerabilities.extend(self.detect_wash_trading());
        vulnerabilities.extend(self.detect_bot_farming());

        vulnerabilities
    }

    fn detect_sybil_vulnerability(&self) -> Vec<PointsFarmingVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Points allocation without sybil checks
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.has_points_allocation(i) {
                if !self.has_sybil_resistance(i) {
                    vulnerabilities.push(PointsFarmingVulnerability {
                        vulnerability_type: PointsFarmingIssueType::SybilAttackVulnerable,
                        severity: SecuritySeverity::High,
                        confidence: 0.75,
                        description: "Points system vulnerable to sybil attacks".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. Attacker creates multiple addresses\n\
                            2. No sybil resistance mechanism\n\
                            3. Each address farms points independently\n\
                            4. Attacker captures disproportionate airdrop\n\n\
                            Fix: Implement proof-of-humanity or similar",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_wash_trading(&self) -> Vec<PointsFarmingVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Volume-based points without wash trading detection
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.has_volume_based_points(i) {
                if !self.has_wash_trading_detection(i) {
                    vulnerabilities.push(PointsFarmingVulnerability {
                        vulnerability_type: PointsFarmingIssueType::WashTradingForPoints,
                        severity: SecuritySeverity::Medium,
                        confidence: 0.70,
                        description: "Volume-based points without wash trading detection".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. Attacker trades back-and-forth\n\
                            2. No detection of wash trading patterns\n\
                            3. Inflates volume artificially\n\
                            4. Earns points without real economic activity\n\n\
                            Fix: Detect circular trading patterns",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_bot_farming(&self) -> Vec<PointsFarmingVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: High-frequency points allocation without rate limiting
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.has_points_allocation(i) {
                if !self.has_rate_limiting(i) {
                    vulnerabilities.push(PointsFarmingVulnerability {
                        vulnerability_type: PointsFarmingIssueType::BotDrivenFarming,
                        severity: SecuritySeverity::Medium,
                        confidence: 0.65,
                        description: "Points allocation without rate limiting (bot vulnerable)".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. Bot performs high-frequency actions\n\
                            2. No rate limiting on points accrual\n\
                            3. Bot farms points faster than humans\n\
                            4. Unfair advantage in airdrop\n\n\
                            Fix: Implement per-address rate limits",
                            i
                        ),
                        location: i,
                    });
                    break; // One warning sufficient
                }
            }
        }

        vulnerabilities
    }

    fn is_points_system(&self) -> bool {
        // Look for points-related patterns (heuristic)
        // Multiple SSTORE operations (tracking points)
        self.bytecode.iter().filter(|&&b| b == 0x55).count() >= 5
    }

    fn has_points_allocation(&self, pos: usize) -> bool {
        // Look for SSTORE (points storage)
        pos + 10 < self.bytecode.len() &&
        self.bytecode[pos] == 0x55
    }

    fn has_sybil_resistance(&self, pos: usize) -> bool {
        // Look for proof verification (zkProof, attestation)
        for i in pos.saturating_sub(50)..pos {
            if self.bytecode[i] == 0xFA { // STATICCALL (verification)
                return true;
            }
        }
        false
    }

    fn has_volume_based_points(&self, pos: usize) -> bool {
        // Look for multiplication (volume * rate)
        for i in pos.saturating_sub(10)..pos {
            if self.bytecode[i] == 0x02 { // MUL
                return true;
            }
        }
        false
    }

    fn has_wash_trading_detection(&self, pos: usize) -> bool {
        // Complex heuristic - look for multiple SLOADs (checking patterns)
        let sload_count = self.bytecode[pos.saturating_sub(30)..pos.saturating_add(30).min(self.bytecode.len())]
            .iter().filter(|&&b| b == 0x54).count();
        sload_count >= 3
    }

    fn has_rate_limiting(&self, pos: usize) -> bool {
        // Look for TIMESTAMP comparison (rate limiting)
        for i in pos.saturating_sub(30)..pos {
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                return true;
            }
        }
        false
    }
}
