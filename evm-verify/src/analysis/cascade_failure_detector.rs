// Cross-Protocol Cascade Failure Detector
// Detects systemic risks where failure in one protocol cascades to others

use crate::bytecode::SecuritySeverity;
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CascadeVulnerability {
    pub vulnerability_type: CascadeType,
    pub severity: SecuritySeverity,
    pub description: String,
    pub trigger_protocol: String,
    pub affected_protocols: Vec<String>,
    pub cascade_path: Vec<CascadeStep>,
    pub estimated_total_impact: u128,
    pub systemic_risk_score: f64,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CascadeType {
    LiquidationCascade,      // Liquidations trigger more liquidations
    OracleFailureCascade,    // Oracle fail → protocols using it fail
    StablecoinDepeg,         // Stablecoin depeg cascades to collateral
    LiquidityCrisis,         // Liquidity drain cascades across DEXs
    CircularDependency,      // A→B→C→A failure loop
    ContagionRisk,           // One protocol failure spreads
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CascadeStep {
    pub step_number: usize,
    pub protocol: String,
    pub event: String,
    pub impact: u128,
    pub probability: f64,
}

pub struct CascadeFailureDetector {
    bytecode: Vec<u8>,
    dependencies: HashMap<String, Vec<String>>,
}

impl CascadeFailureDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self {
            bytecode,
            dependencies: HashMap::new(),
        }
    }

    pub fn analyze(&mut self) -> Vec<CascadeVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Build dependency graph
        self.map_protocol_dependencies();

        // Check for different cascade scenarios
        vulnerabilities.extend(self.detect_liquidation_cascade());
        vulnerabilities.extend(self.detect_oracle_failure_cascade());
        vulnerabilities.extend(self.detect_stablecoin_depeg_risk());
        vulnerabilities.extend(self.detect_circular_dependencies());

        vulnerabilities
    }

    fn map_protocol_dependencies(&mut self) {
        // Detect external calls to identify dependencies
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0xF1 || self.bytecode[i] == 0xFA {  // CALL or STATICCALL
                // Look for address before call
                if i >= 20 && self.is_address_push(&self.bytecode[i-20..i]) {
                    let protocol = self.identify_protocol(&self.bytecode[i-20..i]);
                    self.dependencies.entry("current".to_string())
                        .or_insert_with(Vec::new)
                        .push(protocol);
                }
            }
        }
    }

    fn detect_liquidation_cascade(&self) -> Vec<CascadeVulnerability> {
        let mut vulns = Vec::new();

        // Pattern: Liquidation function without price impact limits
        if self.has_liquidation_function() && !self.has_cascade_protection() {
            vulns.push(CascadeVulnerability {
                vulnerability_type: CascadeType::LiquidationCascade,
                severity: SecuritySeverity::Critical,
                description: "Liquidations can trigger cascade: Liquidation → Price Drop → More Liquidations → Death Spiral".to_string(),
                trigger_protocol: "This Protocol".to_string(),
                affected_protocols: vec!["All protocols using same collateral".to_string()],
                cascade_path: vec![
                    CascadeStep {
                        step_number: 1,
                        protocol: "Initial Liquidation".to_string(),
                        event: "Large position liquidated, collateral sold".to_string(),
                        impact: 1_000_000_000_000_000_000_000u128,
                        probability: 0.3,
                    },
                    CascadeStep {
                        step_number: 2,
                        protocol: "Market Impact".to_string(),
                        event: "Collateral price drops 10%".to_string(),
                        impact: 5_000_000_000_000_000_000_000u128,
                        probability: 0.7,
                    },
                    CascadeStep {
                        step_number: 3,
                        protocol: "Secondary Liquidations".to_string(),
                        event: "More positions become underwater".to_string(),
                        impact: 10_000_000_000_000_000_000_000u128,
                        probability: 0.9,
                    },
                    CascadeStep {
                        step_number: 4,
                        protocol: "Protocol Insolvency".to_string(),
                        event: "Protocol reserves depleted".to_string(),
                        impact: 50_000_000_000_000_000_000_000u128,
                        probability: 0.5,
                    },
                ],
                estimated_total_impact: 66_000_000_000_000_000_000_000u128,
                systemic_risk_score: 0.85,
                remediation: "Add: 1) Liquidation limits per block, 2) Price impact circuit breakers, 3) Time-weighted liquidations".to_string(),
            });
        }

        vulns
    }

    fn detect_oracle_failure_cascade(&self) -> Vec<CascadeVulnerability> {
        let mut vulns = Vec::new();

        if self.uses_single_oracle() && self.has_dependent_protocols() {
            vulns.push(CascadeVulnerability {
                vulnerability_type: CascadeType::OracleFailureCascade,
                severity: SecuritySeverity::Critical,
                description: "Single oracle failure cascades to all dependent protocols".to_string(),
                trigger_protocol: "Oracle Provider".to_string(),
                affected_protocols: vec!["Lending Protocol".to_string(), "DEX".to_string(), "Derivatives".to_string()],
                cascade_path: vec![
                    CascadeStep {
                        step_number: 1,
                        protocol: "Oracle".to_string(),
                        event: "Oracle goes offline or manipulated".to_string(),
                        impact: 0,
                        probability: 0.1,
                    },
                    CascadeStep {
                        step_number: 2,
                        protocol: "Lending Protocol".to_string(),
                        event: "Cannot price collateral, halts".to_string(),
                        impact: 20_000_000_000_000_000_000_000u128,
                        probability: 0.95,
                    },
                    CascadeStep {
                        step_number: 3,
                        protocol: "DEX".to_string(),
                        event: "Cannot execute trades, liquidity locked".to_string(),
                        impact: 30_000_000_000_000_000_000_000u128,
                        probability: 0.9,
                    },
                    CascadeStep {
                        step_number: 4,
                        protocol: "Ecosystem".to_string(),
                        event: "Panic selling, protocol run".to_string(),
                        impact: 100_000_000_000_000_000_000_000u128,
                        probability: 0.6,
                    },
                ],
                estimated_total_impact: 150_000_000_000_000_000_000_000u128,
                systemic_risk_score: 0.92,
                remediation: "Use multiple independent oracles with fallback mechanisms".to_string(),
            });
        }

        vulns
    }

    fn detect_stablecoin_depeg_risk(&self) -> Vec<CascadeVulnerability> {
        let mut vulns = Vec::new();

        if self.is_stablecoin() && !self.has_peg_stability_mechanism() {
            vulns.push(CascadeVulnerability {
                vulnerability_type: CascadeType::StablecoinDepeg,
                severity: SecuritySeverity::Critical,
                description: "Stablecoin depeg triggers death spiral across ecosystem".to_string(),
                trigger_protocol: "Stablecoin".to_string(),
                affected_protocols: vec!["All protocols using this as collateral".to_string()],
                cascade_path: vec![
                    CascadeStep {
                        step_number: 1,
                        protocol: "Stablecoin".to_string(),
                        event: "Price drops to $0.95".to_string(),
                        impact: 5_000_000_000_000_000_000_000u128,
                        probability: 0.2,
                    },
                    CascadeStep {
                        step_number: 2,
                        protocol: "Lending Markets".to_string(),
                        event: "Collateral value drops, liquidations start".to_string(),
                        impact: 15_000_000_000_000_000_000_000u128,
                        probability: 0.8,
                    },
                    CascadeStep {
                        step_number: 3,
                        protocol: "Redemption Rush".to_string(),
                        event: "Users rush to exit, price drops to $0.80".to_string(),
                        impact: 25_000_000_000_000_000_000_000u128,
                        probability: 0.9,
                    },
                    CascadeStep {
                        step_number: 4,
                        protocol: "Total Collapse".to_string(),
                        event: "Bank run, protocol insolvent".to_string(),
                        impact: 60_000_000_000_000_000_000_000u128,
                        probability: 0.7,
                    },
                ],
                estimated_total_impact: 105_000_000_000_000_000_000_000u128,
                systemic_risk_score: 0.88,
                remediation: "Implement: 1) Reserve backing, 2) Circuit breakers, 3) Emergency collateral".to_string(),
            });
        }

        vulns
    }

    fn detect_circular_dependencies(&self) -> Vec<CascadeVulnerability> {
        let mut vulns = Vec::new();

        // Check for circular dependency: A depends on B depends on C depends on A
        if self.has_circular_dependency() {
            vulns.push(CascadeVulnerability {
                vulnerability_type: CascadeType::CircularDependency,
                severity: SecuritySeverity::High,
                description: "Circular dependency creates infinite failure loop".to_string(),
                trigger_protocol: "Protocol A".to_string(),
                affected_protocols: vec!["Protocol B".to_string(), "Protocol C".to_string(), "Protocol A".to_string()],
                cascade_path: vec![
                    CascadeStep {
                        step_number: 1,
                        protocol: "Protocol A".to_string(),
                        event: "Failure in Protocol A".to_string(),
                        impact: 10_000_000_000_000_000_000_000u128,
                        probability: 0.1,
                    },
                    CascadeStep {
                        step_number: 2,
                        protocol: "Protocol B".to_string(),
                        event: "Depends on A, now fails".to_string(),
                        impact: 10_000_000_000_000_000_000_000u128,
                        probability: 0.95,
                    },
                    CascadeStep {
                        step_number: 3,
                        protocol: "Protocol C".to_string(),
                        event: "Depends on B, now fails".to_string(),
                        impact: 10_000_000_000_000_000_000_000u128,
                        probability: 0.95,
                    },
                    CascadeStep {
                        step_number: 4,
                        protocol: "Protocol A".to_string(),
                        event: "Depends on C, failure amplified".to_string(),
                        impact: 20_000_000_000_000_000_000_000u128,
                        probability: 0.99,
                    },
                ],
                estimated_total_impact: 50_000_000_000_000_000_000_000u128,
                systemic_risk_score: 0.79,
                remediation: "Break circular dependencies, add independent fallbacks".to_string(),
            });
        }

        vulns
    }

    // === HELPER METHODS ===

    fn has_liquidation_function(&self) -> bool {
        // Check for liquidate() function selector
        let liquidate_selector = &[0x96, 0xcd, 0x46, 0x95];
        self.bytecode.windows(4).any(|w| w == liquidate_selector)
    }

    fn has_cascade_protection(&self) -> bool {
        // Look for circuit breaker patterns (price change limits)
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x03 {  // SUB (price change calculation)
                // Check if followed by comparison (limit check)
                if i + 5 < self.bytecode.len() && 
                   (self.bytecode[i+3] == 0x10 || self.bytecode[i+3] == 0x11) {
                    return true;
                }
            }
        }
        false
    }

    fn uses_single_oracle(&self) -> bool {
        // Check if only one oracle call exists
        let mut oracle_calls = 0;
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0xFA {  // STATICCALL (oracle query)
                oracle_calls += 1;
            }
        }
        oracle_calls == 1
    }

    fn has_dependent_protocols(&self) -> bool {
        !self.dependencies.is_empty()
    }

    fn is_stablecoin(&self) -> bool {
        // Check for mint/burn patterns (stablecoin indicators)
        let has_mint = self.bytecode.windows(4).any(|w| w == &[0x40, 0xc1, 0x0f, 0x19]);
        let has_burn = self.bytecode.windows(4).any(|w| w == &[0x42, 0x96, 0x6c, 0x68]);
        has_mint && has_burn
    }

    fn has_peg_stability_mechanism(&self) -> bool {
        // Look for collateral ratio checks
        for i in 0..self.bytecode.len().saturating_sub(15) {
            if self.bytecode[i] == 0x04 {  // DIV (ratio calculation)
                // Check if compared against threshold
                if i + 8 < self.bytecode.len() && 
                   (self.bytecode[i+5] == 0x10 || self.bytecode[i+5] == 0x11) {
                    return true;
                }
            }
        }
        false
    }

    fn has_circular_dependency(&self) -> bool {
        // Simplified: Check if contract calls itself indirectly
        // In production, would need full dependency graph analysis
        self.dependencies.len() >= 2
    }

    fn is_address_push(&self, bytecode: &[u8]) -> bool {
        bytecode.len() >= 21 && bytecode[0] == 0x73  // PUSH20
    }

    fn identify_protocol(&self, _bytecode: &[u8]) -> String {
        "Unknown Protocol".to_string()
    }
}

/// Calculate systemic risk across all vulnerabilities
pub fn calculate_systemic_risk(vulnerabilities: &[CascadeVulnerability]) -> SystemicRiskReport {
    let total_impact: u128 = vulnerabilities.iter()
        .map(|v| v.estimated_total_impact)
        .sum();

    let max_risk_score = vulnerabilities.iter()
        .map(|v| v.systemic_risk_score)
        .fold(0.0f64, |a, b| a.max(b));

    let cascade_count = vulnerabilities.len();

    SystemicRiskReport {
        total_potential_impact: total_impact,
        max_systemic_risk_score: max_risk_score,
        cascade_vulnerability_count: cascade_count,
        risk_level: if max_risk_score > 0.85 {
            "EXTREME - Ecosystem collapse possible".to_string()
        } else if max_risk_score > 0.70 {
            "HIGH - Multi-protocol failure likely".to_string()
        } else if max_risk_score > 0.50 {
            "MEDIUM - Localized cascade risk".to_string()
        } else {
            "LOW - Limited contagion risk".to_string()
        },
        recommendation: if total_impact > 50_000_000_000_000_000_000_000u128 {
            "URGENT: Implement circuit breakers and dependency isolation immediately".to_string()
        } else {
            "Monitor systemic risk and implement gradual hardening".to_string()
        },
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemicRiskReport {
    pub total_potential_impact: u128,
    pub max_systemic_risk_score: f64,
    pub cascade_vulnerability_count: usize,
    pub risk_level: String,
    pub recommendation: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_liquidation_cascade_detection() {
        // Bytecode with liquidate function
        let bytecode = vec![
            0x63, 0x96, 0xcd, 0x46, 0x95, // PUSH4 liquidate()
        ];
        
        let mut detector = CascadeFailureDetector::new(bytecode);
        let vulns = detector.detect_liquidation_cascade();
        
        assert!(vulns.len() > 0, "Should detect liquidation cascade risk");
    }

    #[test]
    fn test_systemic_risk_calculation() {
        let vulns = vec![
            CascadeVulnerability {
                vulnerability_type: CascadeType::LiquidationCascade,
                severity: SecuritySeverity::Critical,
                description: "test".to_string(),
                trigger_protocol: "A".to_string(),
                affected_protocols: vec![],
                cascade_path: vec![],
                estimated_total_impact: 100_000_000_000_000_000_000_000u128,
                systemic_risk_score: 0.9,
                remediation: "test".to_string(),
            }
        ];

        let report = calculate_systemic_risk(&vulns);
        assert!(report.max_systemic_risk_score > 0.8);
        assert!(report.total_potential_impact > 0);
    }
}
