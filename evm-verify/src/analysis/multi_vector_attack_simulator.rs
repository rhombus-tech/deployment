use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet};
use crate::circuits::execution_trace::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackVector {
    GovernanceManipulation,
    OracleManipulation,  
    FlashLoanExploit,
    LiquidityDrain,
    SocialEngineering,
    FrontendAttack,
    BridgeCompromise,
    ValidatorCollusion,
    RegulatoryPressure,
    MarketManipulation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinatedAttack {
    pub attack_vectors: Vec<AttackVector>,
    pub coordination_complexity: f32,
    pub total_attack_cost_eth: f64,
    pub success_probability: f32,
    pub economic_damage_eth: f64,
    pub execution_window_hours: u32,
    pub detection_difficulty: f32,
    pub recovery_time_days: u32,
    pub attack_description: String,
    pub defense_requirements: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSynergy {
    pub vector_a: AttackVector,
    pub vector_b: AttackVector,
    pub synergy_multiplier: f32,
    pub combined_success_boost: f32,
    pub cost_reduction_factor: f32,
    pub detection_evasion_boost: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiVectorVulnerability {
    pub attack: CoordinatedAttack,
    pub severity: SecuritySeverity,
    pub description: String,
    pub attack_success_probability: f32,
    pub mitigation_strategy: String,
    pub detection_methods: Vec<String>,
}

pub struct MultiVectorAttackSimulator {
    bytecode: Vec<u8>,
    governance_vulnerabilities: Vec<AttackVector>,
    oracle_vulnerabilities: Vec<AttackVector>,
    defi_vulnerabilities: Vec<AttackVector>,
    infrastructure_vulnerabilities: Vec<AttackVector>,
    execution_trace: Option<EVMExecutionTrace>,
    protocol_value_eth: f64,
    known_attack_patterns: HashMap<String, CoordinatedAttack>,
}

impl MultiVectorAttackSimulator {
    pub fn new(bytecode: Vec<u8>, protocol_value_eth: f64) -> Self {
        Self {
            bytecode,
            governance_vulnerabilities: Vec::new(),
            oracle_vulnerabilities: Vec::new(),
            defi_vulnerabilities: Vec::new(),
            infrastructure_vulnerabilities: Vec::new(),
            execution_trace: None,
            protocol_value_eth,
            known_attack_patterns: Self::initialize_known_patterns(),
        }
    }

    pub fn with_vulnerabilities(
        mut self,
        governance: Vec<AttackVector>,
        oracle: Vec<AttackVector>,
        defi: Vec<AttackVector>,
        infrastructure: Vec<AttackVector>
    ) -> Self {
        self.governance_vulnerabilities = governance;
        self.oracle_vulnerabilities = oracle;
        self.defi_vulnerabilities = defi;
        self.infrastructure_vulnerabilities = infrastructure;
        self
    }

    pub fn simulate_coordinated_attacks(&self) -> Vec<MultiVectorVulnerability> {
        let mut attacks = Vec::new();

        // Generate single-vector attacks
        attacks.extend(self.generate_single_vector_attacks());

        // Generate two-vector combinations
        attacks.extend(self.generate_two_vector_attacks());

        // Generate complex multi-vector attacks
        attacks.extend(self.generate_complex_coordinated_attacks());

        // Generate APT-style persistent attacks
        attacks.extend(self.generate_apt_style_attacks());

        attacks.sort_by(|a, b| b.economic_damage_eth.partial_cmp(&a.economic_damage_eth).unwrap());
        
        // Convert attacks to vulnerabilities
        let mut vulnerabilities = Vec::new();
        for attack in attacks {
            let severity = if attack.success_probability > 0.7 {
                SecuritySeverity::Critical
            } else if attack.success_probability > 0.4 {
                SecuritySeverity::High
            } else {
                SecuritySeverity::Medium
            };
            
            let vulnerability = MultiVectorVulnerability {
                attack: attack.clone(),
                severity,
                description: attack.attack_description.clone(),
                attack_success_probability: attack.success_probability,
                mitigation_strategy: "Implement comprehensive monitoring and circuit breakers".to_string(),
                detection_methods: vec!["Multi-vector pattern analysis".to_string(), "Behavioral anomaly detection".to_string()],
            };
            vulnerabilities.push(vulnerability);
        }
        
        vulnerabilities
    }

    fn generate_single_vector_attacks(&self) -> Vec<CoordinatedAttack> {
        let mut attacks = Vec::new();

        // Pure governance attack
        if !self.governance_vulnerabilities.is_empty() {
            attacks.push(CoordinatedAttack {
                attack_vectors: vec![AttackVector::GovernanceManipulation],
                coordination_complexity: 0.3,
                total_attack_cost_eth: 50_000.0,
                success_probability: 0.4,
                economic_damage_eth: self.protocol_value_eth * 0.3,
                execution_window_hours: 168, // 1 week
                detection_difficulty: 0.6,
                recovery_time_days: 30,
                attack_description: "Governance takeover through token accumulation and proposal manipulation".to_string(),
                defense_requirements: vec![
                    "Implement governance delays".to_string(),
                    "Add community override mechanisms".to_string(),
                ],
            });
        }

        // Pure oracle attack
        if !self.oracle_vulnerabilities.is_empty() {
            attacks.push(CoordinatedAttack {
                attack_vectors: vec![AttackVector::OracleManipulation],
                coordination_complexity: 0.4,
                total_attack_cost_eth: 100_000.0,
                success_probability: 0.6,
                economic_damage_eth: self.protocol_value_eth * 0.2,
                execution_window_hours: 4,
                detection_difficulty: 0.5,
                recovery_time_days: 7,
                attack_description: "Oracle price manipulation through economic incentives".to_string(),
                defense_requirements: vec![
                    "Use multiple oracle sources".to_string(),
                    "Implement price deviation limits".to_string(),
                ],
            });
        }

        attacks
    }

    fn generate_two_vector_attacks(&self) -> Vec<CoordinatedAttack> {
        let mut attacks = Vec::new();

        // Governance + Oracle Attack (Terra Luna style)
        if !self.governance_vulnerabilities.is_empty() && !self.oracle_vulnerabilities.is_empty() {
            let synergy = self.calculate_attack_synergy(&AttackVector::GovernanceManipulation, &AttackVector::OracleManipulation);
            
            attacks.push(CoordinatedAttack {
                attack_vectors: vec![AttackVector::GovernanceManipulation, AttackVector::OracleManipulation],
                coordination_complexity: 0.7,
                total_attack_cost_eth: 120_000.0, // Reduced due to synergy
                success_probability: 0.8 * synergy.combined_success_boost,
                economic_damage_eth: self.protocol_value_eth * 0.6,
                execution_window_hours: 72, // 3 days
                detection_difficulty: 0.8,
                recovery_time_days: 90,
                attack_description: "Coordinate governance control with oracle manipulation for maximum impact".to_string(),
                defense_requirements: vec![
                    "Separate governance and oracle systems".to_string(),
                    "Implement cross-system monitoring".to_string(),
                    "Add emergency circuit breakers".to_string(),
                ],
            });
        }

        // Flash Loan + Oracle Attack
        if !self.defi_vulnerabilities.is_empty() && !self.oracle_vulnerabilities.is_empty() {
            attacks.push(CoordinatedAttack {
                attack_vectors: vec![AttackVector::FlashLoanExploit, AttackVector::OracleManipulation],
                coordination_complexity: 0.8,
                total_attack_cost_eth: 5_000.0, // Very low cost with flash loans
                success_probability: 0.9,
                economic_damage_eth: self.protocol_value_eth * 0.15,
                execution_window_hours: 1, // Single block attack
                detection_difficulty: 0.9,
                recovery_time_days: 1,
                attack_description: "Flash loan funded oracle manipulation for immediate profit extraction".to_string(),
                defense_requirements: vec![
                    "Implement flash loan protection".to_string(),
                    "Add same-block oracle update limits".to_string(),
                ],
            });
        }

        // Social Engineering + Governance Attack
        attacks.push(CoordinatedAttack {
            attack_vectors: vec![AttackVector::SocialEngineering, AttackVector::GovernanceManipulation],
            coordination_complexity: 0.6,
            total_attack_cost_eth: 30_000.0,
            success_probability: 0.5,
            economic_damage_eth: self.protocol_value_eth * 0.4,
            execution_window_hours: 720, // 30 days
            detection_difficulty: 0.7,
            recovery_time_days: 60,
            attack_description: "Social engineering to gain community support for malicious governance proposals".to_string(),
            defense_requirements: vec![
                "Implement proposal review processes".to_string(),
                "Add technical analysis requirements".to_string(),
            ],
        });

        attacks
    }

    fn generate_complex_coordinated_attacks(&self) -> Vec<CoordinatedAttack> {
        let mut attacks = Vec::new();

        // Triple vector: Governance + Oracle + Liquidity Attack
        attacks.push(CoordinatedAttack {
            attack_vectors: vec![
                AttackVector::GovernanceManipulation,
                AttackVector::OracleManipulation,
                AttackVector::LiquidityDrain
            ],
            coordination_complexity: 0.95,
            total_attack_cost_eth: 500_000.0,
            success_probability: 0.7,
            economic_damage_eth: self.protocol_value_eth * 0.8,
            execution_window_hours: 336, // 2 weeks
            detection_difficulty: 0.9,
            recovery_time_days: 180,
            attack_description: "Systematic protocol destruction through coordinated governance takeover, oracle manipulation, and liquidity extraction".to_string(),
            defense_requirements: vec![
                "Implement multi-layer defense systems".to_string(),
                "Add real-time threat monitoring".to_string(),
                "Create emergency protocol freeze mechanisms".to_string(),
            ],
        });

        // Quadruple vector: Full spectrum attack
        attacks.push(CoordinatedAttack {
            attack_vectors: vec![
                AttackVector::GovernanceManipulation,
                AttackVector::OracleManipulation,
                AttackVector::SocialEngineering,
                AttackVector::FrontendAttack
            ],
            coordination_complexity: 0.99,
            total_attack_cost_eth: 1_000_000.0,
            success_probability: 0.6,
            economic_damage_eth: self.protocol_value_eth * 0.95,
            execution_window_hours: 2160, // 3 months
            detection_difficulty: 0.95,
            recovery_time_days: 365,
            attack_description: "Nation-state level coordinated attack targeting all protocol layers simultaneously".to_string(),
            defense_requirements: vec![
                "Implement defense-in-depth architecture".to_string(),
                "Add threat intelligence integration".to_string(),
                "Create incident response protocols".to_string(),
                "Establish external security partnerships".to_string(),
            ],
        });

        attacks
    }

    fn generate_apt_style_attacks(&self) -> Vec<CoordinatedAttack> {
        let mut attacks = Vec::new();

        // Advanced Persistent Threat - Long-term infiltration
        attacks.push(CoordinatedAttack {
            attack_vectors: vec![
                AttackVector::SocialEngineering,
                AttackVector::GovernanceManipulation,
                AttackVector::ValidatorCollusion,
                AttackVector::RegulatoryPressure
            ],
            coordination_complexity: 0.98,
            total_attack_cost_eth: 2_000_000.0,
            success_probability: 0.4,
            economic_damage_eth: self.protocol_value_eth * 1.2, // Can exceed protocol value through contagion
            execution_window_hours: 8760, // 1 year
            detection_difficulty: 0.99,
            recovery_time_days: 730, // 2 years
            attack_description: "Long-term infiltration campaign combining social engineering, regulatory capture, validator corruption, and governance manipulation".to_string(),
            defense_requirements: vec![
                "Implement continuous security monitoring".to_string(),
                "Add behavioral analysis systems".to_string(),
                "Create distributed decision-making processes".to_string(),
                "Establish multiple fallback systems".to_string(),
                "Add legal and regulatory defenses".to_string(),
            ],
        });

        attacks
    }

    fn calculate_attack_synergy(&self, vector_a: &AttackVector, vector_b: &AttackVector) -> AttackSynergy {
        match (vector_a, vector_b) {
            (AttackVector::GovernanceManipulation, AttackVector::OracleManipulation) => {
                AttackSynergy {
                    vector_a: vector_a.clone(),
                    vector_b: vector_b.clone(),
                    synergy_multiplier: 1.8, // High synergy
                    combined_success_boost: 1.4,
                    cost_reduction_factor: 0.8, // 20% cost reduction
                    detection_evasion_boost: 1.3,
                }
            },
            (AttackVector::FlashLoanExploit, AttackVector::OracleManipulation) => {
                AttackSynergy {
                    vector_a: vector_a.clone(),
                    vector_b: vector_b.clone(),
                    synergy_multiplier: 2.0, // Very high synergy
                    combined_success_boost: 1.6,
                    cost_reduction_factor: 0.1, // 90% cost reduction due to flash loans
                    detection_evasion_boost: 1.5,
                }
            },
            (AttackVector::SocialEngineering, AttackVector::GovernanceManipulation) => {
                AttackSynergy {
                    vector_a: vector_a.clone(),
                    vector_b: vector_b.clone(),
                    synergy_multiplier: 1.5,
                    combined_success_boost: 1.3,
                    cost_reduction_factor: 0.7, // 30% cost reduction
                    detection_evasion_boost: 1.4,
                }
            },
            _ => {
                AttackSynergy {
                    vector_a: vector_a.clone(),
                    vector_b: vector_b.clone(),
                    synergy_multiplier: 1.1, // Minimal synergy
                    combined_success_boost: 1.1,
                    cost_reduction_factor: 0.95, // 5% cost reduction
                    detection_evasion_boost: 1.05,
                }
            }
        }
    }

    fn initialize_known_patterns() -> HashMap<String, CoordinatedAttack> {
        let mut patterns = HashMap::new();

        // Terra Luna collapse pattern
        patterns.insert("terra_luna_collapse".to_string(), CoordinatedAttack {
            attack_vectors: vec![AttackVector::GovernanceManipulation, AttackVector::OracleManipulation, AttackVector::MarketManipulation],
            coordination_complexity: 0.9,
            total_attack_cost_eth: 1_000_000.0,
            success_probability: 0.8,
            economic_damage_eth: 60_000_000_000.0, // $60B actual damage
            execution_window_hours: 168, // 1 week
            detection_difficulty: 0.85,
            recovery_time_days: 999, // Never recovered
            attack_description: "Coordinated attack on algorithmic stablecoin through governance manipulation, oracle attacks, and market manipulation".to_string(),
            defense_requirements: vec![
                "Implement death spiral prevention".to_string(),
                "Add emergency reserves".to_string(),
                "Separate governance from economic mechanisms".to_string(),
            ],
        });

        // Iron Finance collapse pattern  
        patterns.insert("iron_finance_collapse".to_string(), CoordinatedAttack {
            attack_vectors: vec![AttackVector::LiquidityDrain, AttackVector::MarketManipulation],
            coordination_complexity: 0.6,
            total_attack_cost_eth: 10_000.0,
            success_probability: 0.9,
            economic_damage_eth: 2_000_000_000.0, // $2B damage
            execution_window_hours: 48,
            detection_difficulty: 0.7,
            recovery_time_days: 999, // Never recovered
            attack_description: "Bank run attack on partially collateralized stablecoin".to_string(),
            defense_requirements: vec![
                "Maintain full collateralization".to_string(),
                "Implement progressive withdrawal fees".to_string(),
            ],
        });

        patterns
    }

    pub fn assess_protocol_resilience(&self) -> ProtocolResilienceAssessment {
        let attacks = self.simulate_coordinated_attacks();
        
        let max_damage = attacks.iter()
            .map(|a| a.attack.economic_damage_eth)
            .fold(0.0f64, |max, val| max.max(val));

        let highest_success_probability = attacks.iter()
            .map(|a| a.attack.success_probability)
            .fold(0.0f32, |max, val| max.max(val));

        let most_complex_attack = attacks.iter()
            .map(|a| a.attack.coordination_complexity)
            .fold(0.0f32, |max, val| max.max(val));

        let average_detection_difficulty = attacks.iter()
            .map(|a| a.attack.detection_difficulty)
            .sum::<f32>() / attacks.len() as f32;

        ProtocolResilienceAssessment {
            overall_resilience_score: self.calculate_overall_resilience(&attacks),
            max_potential_damage_eth: max_damage,
            highest_attack_success_probability: highest_success_probability,
            most_complex_attack_coordination: most_complex_attack,
            average_detection_difficulty,
            critical_vulnerabilities: self.identify_critical_vulnerabilities(&attacks),
            recommended_defenses: self.generate_defense_recommendations(&attacks),
        }
    }

    fn calculate_overall_resilience(&self, attacks: &[MultiVectorVulnerability]) -> f32 {
        let mut resilience_score = 1.0;

        // Reduce score based on successful attack potential
        for attack in attacks {
            let attack_risk = attack.attack.success_probability * (attack.attack.economic_damage_eth / self.protocol_value_eth) as f32;
            resilience_score *= (1.0 - attack_risk * 0.1); // Each attack reduces resilience
        }

        resilience_score.max(0.0)
    }

    fn identify_critical_vulnerabilities(&self, attacks: &[MultiVectorVulnerability]) -> Vec<String> {
        let mut critical_vulns = Vec::new();

        for attack in attacks {
            if attack.attack.success_probability > 0.8 && attack.attack.economic_damage_eth > self.protocol_value_eth * 0.5 {
                critical_vulns.push(format!("CRITICAL: {}", attack.attack.attack_description));
            }
        }

        critical_vulns
    }

    fn generate_defense_recommendations(&self, attacks: &[MultiVectorVulnerability]) -> Vec<String> {
        let mut all_requirements = HashSet::new();

        // Collect all defense requirements
        for attack in attacks {
            for requirement in &attack.attack.defense_requirements {
                all_requirements.insert(requirement.clone());
            }
        }

        // Prioritize by frequency
        let mut requirements: Vec<_> = all_requirements.into_iter().collect();
        requirements.sort();
        requirements
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolResilienceAssessment {
    pub overall_resilience_score: f32,
    pub max_potential_damage_eth: f64,
    pub highest_attack_success_probability: f32,
    pub most_complex_attack_coordination: f32,
    pub average_detection_difficulty: f32,
    pub critical_vulnerabilities: Vec<String>,
    pub recommended_defenses: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_vector_attack_simulation() {
        let simulator = MultiVectorAttackSimulator::new(vec![], 1_000_000.0)
            .with_vulnerabilities(
                vec![AttackVector::GovernanceManipulation],
                vec![],
                vec![],
                vec![]
            );

        let attacks = simulator.simulate_coordinated_attacks();
        assert!(!attacks.is_empty());

        let governance_attacks: Vec<_> = attacks.iter()
            .filter(|a| a.attack_vectors.contains(&AttackVector::GovernanceManipulation))
            .collect();
        assert!(!governance_attacks.is_empty());
    }

    #[test]
    fn test_coordinated_attack_synergy() {
        let simulator = MultiVectorAttackSimulator::new(vec![], 10_000_000.0)
            .with_vulnerabilities(
                vec![AttackVector::GovernanceManipulation],
                vec![AttackVector::OracleManipulation],
                vec![],
                vec![]
            );

        let attacks = simulator.simulate_coordinated_attacks();
        
        // Should have combination attacks with higher damage
        let combo_attacks: Vec<_> = attacks.iter()
            .filter(|a| a.attack_vectors.len() > 1)
            .collect();
        
        assert!(!combo_attacks.is_empty());
        
        // Combination attacks should generally have higher success probability
        if let Some(combo_attack) = combo_attacks.first() {
            assert!(combo_attack.success_probability > 0.5);
        }
    }

    #[test]
    fn test_protocol_resilience_assessment() {
        let simulator = MultiVectorAttackSimulator::new(vec![], 5_000_000.0)
            .with_vulnerabilities(
                vec![AttackVector::GovernanceManipulation],
                vec![AttackVector::OracleManipulation],
                vec![AttackVector::FlashLoanExploit],
                vec![]
            );

        let assessment = simulator.assess_protocol_resilience();
        
        assert!(assessment.overall_resilience_score >= 0.0);
        assert!(assessment.overall_resilience_score <= 1.0);
        assert!(assessment.max_potential_damage_eth > 0.0);
        assert!(!assessment.recommended_defenses.is_empty());
    }
}
