/// Cross-Chain Bridge Risk Analyzer
/// Unified risk analysis for all bridge vulnerabilities ($2B+ in bridge hacks)
use crate::bytecode::SecuritySeverity;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct CrossChainBridgeRiskAnalyzer {
    bytecode: Vec<u8>,
    bridge_type: BridgeType,
}

#[derive(Debug, Clone, PartialEq)]
pub enum BridgeType {
    LockAndMint,        // Lock on source, mint on dest
    BurnAndMint,        // Burn on source, mint on dest  
    Liquidity,          // Liquidity pools on both sides
    Optimistic,         // Optimistic verification
    ZKProof,            // ZK proof verification
    Unknown,
}

#[derive(Debug, Clone)]
pub struct BridgeRiskAssessment {
    pub overall_risk_score: f64,
    pub vulnerabilities: Vec<BridgeVulnerability>,
    pub historical_comparison: Vec<HistoricalBridgeHack>,
    pub risk_factors: HashMap<String, f64>,
}

#[derive(Debug, Clone)]
pub struct BridgeVulnerability {
    pub vuln_type: BridgeVulnType,
    pub severity: SecuritySeverity,
    pub description: String,
    pub historical_loss: u128,
}

#[derive(Debug, Clone, PartialEq)]
pub enum BridgeVulnType {
    SignatureVerificationBypass,   // Wormhole $325M, Ronin $625M
    MessageReplay,                  // Nomad $190M
    ValidatorCompromise,            // Ronin, Harmony
    OracleManipulation,             // Cross-chain oracle attacks
    StateRootForgery,               // Optimistic bridge attacks
    UntrustedRelayer,               // Relayer manipulation
    StorageProofFalsification,      // Merkle proof attacks
    TimelockBypass,                 // Emergency timelock issues
    UpgradeVulnerability,           // Upgrade path attacks
    LiquidityDrain,                 // Liquidity pool attacks
}

#[derive(Debug, Clone)]
pub struct HistoricalBridgeHack {
    pub name: String,
    pub date: String,
    pub amount_usd: u128,
    pub vulnerability_type: BridgeVulnType,
    pub similarity_score: f64,
}

impl CrossChainBridgeRiskAnalyzer {
    pub fn new(bytecode: Vec<u8>) -> Self {
        let bridge_type = Self::detect_bridge_type(&bytecode);
        Self {
            bytecode,
            bridge_type,
        }
    }

    pub fn analyze_bridge_risks(&self) -> BridgeRiskAssessment {
        let vulnerabilities = self.identify_vulnerabilities();
        let historical = self.find_similar_hacks(&vulnerabilities);
        let risk_factors = self.calculate_risk_factors();
        let overall_risk = self.calculate_overall_risk(&vulnerabilities, &risk_factors);

        BridgeRiskAssessment {
            overall_risk_score: overall_risk,
            vulnerabilities,
            historical_comparison: historical,
            risk_factors,
        }
    }

    fn detect_bridge_type(bytecode: &[u8]) -> BridgeType {
        // Detect bridge pattern by opcodes
        if bytecode.windows(3).any(|w| matches!(w, [0x01, 0x55, 0xf0])) {
            // ECRECOVER + SSTORE + CREATE = signature verification + minting
            BridgeType::LockAndMint
        } else if bytecode.contains(&0xff) {
            // SELFDESTRUCT = burning
            BridgeType::BurnAndMint
        } else {
            BridgeType::Unknown
        }
    }

    fn identify_vulnerabilities(&self) -> Vec<BridgeVulnerability> {
        let mut vulns = Vec::new();

        // Check signature verification
        if self.has_weak_signature_verification() {
            vulns.push(BridgeVulnerability {
                vuln_type: BridgeVulnType::SignatureVerificationBypass,
                severity: SecuritySeverity::Critical,
                description: "Weak signature verification - similar to Wormhole hack".to_string(),
                historical_loss: 325_000_000_000_000_000_000_000_000, // $325M
            });
        }

        // Check message replay protection
        if !self.has_nonce_tracking() {
            vulns.push(BridgeVulnerability {
                vuln_type: BridgeVulnType::MessageReplay,
                severity: SecuritySeverity::Critical,
                description: "Missing nonce/replay protection - similar to Nomad hack".to_string(),
                historical_loss: 190_000_000_000_000_000_000_000_000, // $190M
            });
        }

        // Check validator security
        if self.count_validators() < 5 {
            vulns.push(BridgeVulnerability {
                vuln_type: BridgeVulnType::ValidatorCompromise,
                severity: SecuritySeverity::Critical,
                description: "Insufficient validator decentralization - similar to Ronin hack".to_string(),
                historical_loss: 625_000_000_000_000_000_000_000_000, // $625M
            });
        }

        // Check relayer trust
        if self.has_untrusted_relayer() {
            vulns.push(BridgeVulnerability {
                vuln_type: BridgeVulnType::UntrustedRelayer,
                severity: SecuritySeverity::High,
                description: "Untrusted relayer with excessive privileges".to_string(),
                historical_loss: 50_000_000_000_000_000_000_000_000,
            });
        }

        // Check upgrade safety
        if self.has_unsafe_upgrade_mechanism() {
            vulns.push(BridgeVulnerability {
                vuln_type: BridgeVulnType::UpgradeVulnerability,
                severity: SecuritySeverity::High,
                description: "Unsafe upgrade mechanism without proper timelock".to_string(),
                historical_loss: 100_000_000_000_000_000_000_000_000,
            });
        }

        vulns
    }

    fn find_similar_hacks(&self, vulns: &[BridgeVulnerability]) -> Vec<HistoricalBridgeHack> {
        let mut similar = Vec::new();

        let all_hacks = vec![
            HistoricalBridgeHack {
                name: "Ronin Bridge".to_string(),
                date: "2022-03-23".to_string(),
                amount_usd: 625_000_000,
                vulnerability_type: BridgeVulnType::ValidatorCompromise,
                similarity_score: 0.0,
            },
            HistoricalBridgeHack {
                name: "Wormhole Bridge".to_string(),
                date: "2022-02-02".to_string(),
                amount_usd: 325_000_000,
                vulnerability_type: BridgeVulnType::SignatureVerificationBypass,
                similarity_score: 0.0,
            },
            HistoricalBridgeHack {
                name: "Nomad Bridge".to_string(),
                date: "2022-08-01".to_string(),
                amount_usd: 190_000_000,
                vulnerability_type: BridgeVulnType::MessageReplay,
                similarity_score: 0.0,
            },
            HistoricalBridgeHack {
                name: "Poly Network".to_string(),
                date: "2021-08-10".to_string(),
                amount_usd: 611_000_000,
                vulnerability_type: BridgeVulnType::SignatureVerificationBypass,
                similarity_score: 0.0,
            },
            HistoricalBridgeHack {
                name: "Harmony Bridge".to_string(),
                date: "2022-06-23".to_string(),
                amount_usd: 100_000_000,
                vulnerability_type: BridgeVulnType::ValidatorCompromise,
                similarity_score: 0.0,
            },
        ];

        for mut hack in all_hacks {
            for vuln in vulns {
                if vuln.vuln_type == hack.vulnerability_type {
                    hack.similarity_score = 0.95; // High similarity
                    similar.push(hack.clone());
                    break;
                }
            }
        }

        similar.sort_by(|a, b| b.similarity_score.partial_cmp(&a.similarity_score).unwrap());
        similar
    }

    fn calculate_risk_factors(&self) -> HashMap<String, f64> {
        let mut factors = HashMap::new();

        factors.insert("Validator Count".to_string(), self.validator_risk_score());
        factors.insert("Signature Scheme".to_string(), self.signature_risk_score());
        factors.insert("Replay Protection".to_string(), self.replay_protection_score());
        factors.insert("Upgrade Safety".to_string(), self.upgrade_safety_score());
        factors.insert("Relayer Trust".to_string(), self.relayer_trust_score());

        factors
    }

    fn calculate_overall_risk(&self, vulns: &[BridgeVulnerability], factors: &HashMap<String, f64>) -> f64 {
        let vuln_score: f64 = vulns.iter()
            .map(|v| match v.severity {
                SecuritySeverity::Critical => 10.0,
                SecuritySeverity::High => 7.0,
                SecuritySeverity::Medium => 4.0,
                SecuritySeverity::Low => 2.0,
                SecuritySeverity::Info => 1.0,
            })
            .sum();

        let factor_score: f64 = factors.values().sum::<f64>() / factors.len() as f64;

        (vuln_score * 0.7) + (factor_score * 0.3)
    }

    // Helper methods
    fn has_weak_signature_verification(&self) -> bool {
        // Check for ECRECOVER (0x01) without proper validation
        self.bytecode.contains(&0x01) && !self.has_signature_validation()
    }

    fn has_signature_validation(&self) -> bool {
        // Look for checks after ECRECOVER (LT, GT, EQ)
        self.bytecode.windows(3).any(|w| w[0] == 0x01 && matches!(w[2], 0x10 | 0x11 | 0x14))
    }

    fn has_nonce_tracking(&self) -> bool {
        // Look for SLOAD + ADD + SSTORE pattern (nonce increment)
        self.bytecode.windows(3).any(|w| matches!(w, [0x54, 0x01, 0x55]))
    }

    fn count_validators(&self) -> u32 {
        // Count unique addresses in bytecode (simplified)
        // Real implementation would parse validator list
        3 // Placeholder
    }

    fn has_untrusted_relayer(&self) -> bool {
        // Check if relayer address is hardcoded without multisig
        self.bytecode.contains(&0x33) && !self.has_multisig_pattern()
    }

    fn has_multisig_pattern(&self) -> bool {
        // Look for signature aggregation patterns
        self.bytecode.windows(2).filter(|w| w == &[0x01, 0x01]).count() > 2
    }

    fn has_unsafe_upgrade_mechanism(&self) -> bool {
        // Check for DELEGATECALL without timelock
        self.bytecode.contains(&0xf4) && !self.has_timelock()
    }

    fn has_timelock(&self) -> bool {
        // Look for TIMESTAMP (0x42) checks
        self.bytecode.windows(2).any(|w| w[0] == 0x42 && matches!(w[1], 0x10 | 0x11))
    }

    fn validator_risk_score(&self) -> f64 {
        let count = self.count_validators();
        if count >= 7 { 2.0 } else if count >= 5 { 5.0 } else { 10.0 }
    }

    fn signature_risk_score(&self) -> f64 {
        if self.has_weak_signature_verification() { 10.0 } else { 2.0 }
    }

    fn replay_protection_score(&self) -> f64 {
        if self.has_nonce_tracking() { 2.0 } else { 10.0 }
    }

    fn upgrade_safety_score(&self) -> f64 {
        if self.has_unsafe_upgrade_mechanism() { 9.0 } else { 3.0 }
    }

    fn relayer_trust_score(&self) -> f64 {
        if self.has_untrusted_relayer() { 8.0 } else { 3.0 }
    }

    pub fn get_total_historical_risk(&self) -> u128 {
        let assessment = self.analyze_bridge_risks();
        assessment.historical_comparison
            .iter()
            .map(|h| (h.amount_usd as u128) * (h.similarity_score * 100.0) as u128)
            .sum()
    }
}
