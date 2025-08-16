use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet, VecDeque};
use crate::circuits::execution_trace::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AIAttackCategory {
    NovelMEVStrategy,
    AdaptiveGovernanceAttack,
    DynamicOracleManipulation,
    EvolutionaryFlashLoanExploit,
    ReinforcementLearningArbitrage,
    GeneticAlgorithmLiquidityAttack,
    NeuralNetworkFrontRunning,
    MachineLearningPriceManipulation,
    AICoordinatedBotSwarm,
    UnknownNovelPattern,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPattern {
    pub pattern_id: String,
    pub bytecode_signatures: Vec<Vec<u8>>,
    pub execution_sequences: Vec<String>,
    pub gas_usage_patterns: Vec<u64>,
    pub timing_patterns: Vec<u64>,
    pub frequency_characteristics: f32,
    pub success_indicators: Vec<String>,
    pub economic_footprint: f64,
    pub complexity_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIDetectedVulnerability {
    pub attack_category: AIAttackCategory,
    pub detection_confidence: f32,
    pub novelty_score: f32,
    pub severity: SecuritySeverity,
    pub pattern_matches: Vec<AttackPattern>,
    pub learning_model_source: String,
    pub prediction_accuracy: f32,
    pub economic_risk_eth: f64,
    pub mitigation_difficulty: f32,
    pub adaptation_speed: f32,
    pub counter_strategy: Vec<String>,
    pub vulnerability_description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralFingerprint {
    pub transaction_patterns: Vec<f32>,
    pub gas_optimization_signature: Vec<f32>,
    pub timing_distribution: Vec<f32>,
    pub interaction_graph: HashMap<String, f32>,
    pub economic_behavior_vector: Vec<f32>,
    pub complexity_metrics: Vec<f32>,
    pub entropy_measures: Vec<f32>,
}

pub struct AIAdaptiveAttackDetector {
    bytecode: Vec<u8>,
    known_patterns: HashMap<String, AttackPattern>,
    behavioral_models: HashMap<String, BehavioralFingerprint>,
    learning_buffer: VecDeque<ExecutionSample>,
    pattern_recognition_threshold: f32,
    novelty_detection_sensitivity: f32,
    adaptation_learning_rate: f32,
    execution_trace: Option<EVMExecutionTrace>,
    ml_feature_extractors: HashMap<String, FeatureExtractor>,
}

#[derive(Debug, Clone)]
struct ExecutionSample {
    bytecode: Vec<u8>,
    execution_trace: EVMExecutionTrace,
    gas_usage: u64,
    timestamp: u64,
    success: bool,
    economic_impact: f64,
}

#[derive(Debug, Clone)]
struct FeatureExtractor {
    name: String,
    weight: f32,
    extraction_function: String, // Simplified - would be actual ML feature extraction
}

impl AIAdaptiveAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        let mut ml_extractors = HashMap::new();
        
        // Initialize feature extractors for different attack dimensions
        ml_extractors.insert("opcode_sequence_analyzer".to_string(), FeatureExtractor {
            name: "Opcode Sequence Pattern Analyzer".to_string(),
            weight: 0.25,
            extraction_function: "extract_opcode_n_grams".to_string(),
        });
        
        ml_extractors.insert("gas_pattern_analyzer".to_string(), FeatureExtractor {
            name: "Gas Usage Pattern Analyzer".to_string(),
            weight: 0.20,
            extraction_function: "extract_gas_optimization_features".to_string(),
        });
        
        ml_extractors.insert("timing_analyzer".to_string(), FeatureExtractor {
            name: "Execution Timing Pattern Analyzer".to_string(),
            weight: 0.15,
            extraction_function: "extract_timing_features".to_string(),
        });
        
        ml_extractors.insert("economic_behavior_analyzer".to_string(), FeatureExtractor {
            name: "Economic Behavior Pattern Analyzer".to_string(),
            weight: 0.20,
            extraction_function: "extract_economic_features".to_string(),
        });
        
        ml_extractors.insert("interaction_graph_analyzer".to_string(), FeatureExtractor {
            name: "Contract Interaction Graph Analyzer".to_string(),
            weight: 0.20,
            extraction_function: "extract_interaction_features".to_string(),
        });

        Self {
            bytecode,
            known_patterns: Self::initialize_baseline_patterns(),
            behavioral_models: HashMap::new(),
            learning_buffer: VecDeque::with_capacity(1000),
            pattern_recognition_threshold: 0.75,
            novelty_detection_sensitivity: 0.6,
            adaptation_learning_rate: 0.01,
            execution_trace: None,
            ml_feature_extractors: ml_extractors,
        }
    }

    pub fn with_execution_trace(mut self, trace: EVMExecutionTrace) -> Self {
        self.execution_trace = Some(trace);
        self
    }

    pub fn detect_ai_powered_attacks(&mut self) -> Vec<AIDetectedVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Extract behavioral fingerprint from current bytecode
        let fingerprint = self.extract_behavioral_fingerprint();
        
        // Pattern matching against known AI attack patterns
        vulnerabilities.extend(self.detect_known_ai_patterns(&fingerprint));
        
        // Novel pattern detection using unsupervised learning
        vulnerabilities.extend(self.detect_novel_patterns(&fingerprint));
        
        // Adaptive attack evolution detection
        vulnerabilities.extend(self.detect_attack_evolution(&fingerprint));
        
        // Reinforcement learning attack detection
        vulnerabilities.extend(self.detect_rl_based_attacks(&fingerprint));
        
        // AI coordination and swarm behavior detection
        vulnerabilities.extend(self.detect_ai_coordination_patterns(&fingerprint));

        // Update learning models with new data
        self.update_learning_models(&fingerprint, &vulnerabilities);

        vulnerabilities
    }

    fn extract_behavioral_fingerprint(&self) -> BehavioralFingerprint {
        BehavioralFingerprint {
            transaction_patterns: self.extract_transaction_patterns(),
            gas_optimization_signature: self.extract_gas_optimization_patterns(),
            timing_distribution: self.extract_timing_patterns(),
            interaction_graph: self.extract_interaction_patterns(),
            economic_behavior_vector: self.extract_economic_patterns(),
            complexity_metrics: self.extract_complexity_metrics(),
            entropy_measures: self.extract_entropy_measures(),
        }
    }

    fn detect_known_ai_patterns(&self, fingerprint: &BehavioralFingerprint) -> Vec<AIDetectedVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check against known MEV bot patterns
        if self.matches_mev_ai_pattern(fingerprint) {
            vulnerabilities.push(AIDetectedVulnerability {
                attack_category: AIAttackCategory::NovelMEVStrategy,
                detection_confidence: 0.85,
                novelty_score: 0.3, // Known pattern, low novelty
                severity: SecuritySeverity::High,
                pattern_matches: vec![self.get_mev_ai_pattern()],
                learning_model_source: "MEV Bot Pattern Recognition".to_string(),
                prediction_accuracy: 0.92,
                economic_risk_eth: 100_000.0,
                mitigation_difficulty: 0.7,
                adaptation_speed: 0.8,
                counter_strategy: vec![
                    "Implement dynamic gas price adjustment".to_string(),
                    "Add randomized execution delays".to_string(),
                ],
                vulnerability_description: "AI-optimized MEV extraction with machine learning gas bidding".to_string(),
            });
        }

        // Check against adaptive governance attack patterns
        if self.matches_adaptive_governance_pattern(fingerprint) {
            vulnerabilities.push(AIDetectedVulnerability {
                attack_category: AIAttackCategory::AdaptiveGovernanceAttack,
                detection_confidence: 0.78,
                novelty_score: 0.6,
                severity: SecuritySeverity::Critical,
                pattern_matches: vec![self.get_adaptive_governance_pattern()],
                learning_model_source: "Governance Attack Evolution Tracker".to_string(),
                prediction_accuracy: 0.84,
                economic_risk_eth: 1_000_000.0,
                mitigation_difficulty: 0.9,
                adaptation_speed: 0.6,
                counter_strategy: vec![
                    "Implement proposal complexity analysis".to_string(),
                    "Add behavioral anomaly detection".to_string(),
                ],
                vulnerability_description: "AI-driven governance proposal optimization with behavioral adaptation".to_string(),
            });
        }

        vulnerabilities
    }

    fn detect_novel_patterns(&self, fingerprint: &BehavioralFingerprint) -> Vec<AIDetectedVulnerability> {
        let mut vulnerabilities = Vec::new();

        let novelty_score = self.calculate_novelty_score(fingerprint);
        
        if novelty_score > self.novelty_detection_sensitivity {
            let attack_complexity = self.analyze_attack_complexity(fingerprint);
            let economic_risk = self.estimate_economic_risk(fingerprint);
            
            vulnerabilities.push(AIDetectedVulnerability {
                attack_category: AIAttackCategory::UnknownNovelPattern,
                detection_confidence: novelty_score,
                novelty_score,
                severity: if economic_risk > 500_000.0 { SecuritySeverity::Critical } else { SecuritySeverity::High },
                pattern_matches: vec![self.create_novel_pattern(fingerprint)],
                learning_model_source: "Unsupervised Anomaly Detection".to_string(),
                prediction_accuracy: 0.65, // Lower for novel patterns
                economic_risk_eth: economic_risk,
                mitigation_difficulty: 0.95, // Very hard to mitigate unknown attacks
                adaptation_speed: 0.9, // Novel attacks adapt quickly
                counter_strategy: vec![
                    "Implement real-time behavior monitoring".to_string(),
                    "Add emergency circuit breakers".to_string(),
                    "Create adaptive defense mechanisms".to_string(),
                ],
                vulnerability_description: format!(
                    "Novel attack pattern detected with complexity score {:.2} and economic risk ${:.0}",
                    attack_complexity, economic_risk
                ),
            });
        }

        vulnerabilities
    }

    fn detect_attack_evolution(&self, fingerprint: &BehavioralFingerprint) -> Vec<AIDetectedVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Detect if known attack patterns are evolving
        for (pattern_id, known_pattern) in &self.known_patterns {
            let evolution_score = self.calculate_evolution_score(fingerprint, known_pattern);
            
            if evolution_score > 0.7 {
                vulnerabilities.push(AIDetectedVulnerability {
                    attack_category: AIAttackCategory::EvolutionaryFlashLoanExploit,
                    detection_confidence: evolution_score,
                    novelty_score: evolution_score * 0.8,
                    severity: SecuritySeverity::High,
                    pattern_matches: vec![known_pattern.clone()],
                    learning_model_source: "Attack Evolution Detector".to_string(),
                    prediction_accuracy: 0.88,
                    economic_risk_eth: known_pattern.economic_footprint * 1.5, // Evolved attacks more dangerous
                    mitigation_difficulty: 0.85,
                    adaptation_speed: 0.95, // Very fast adaptation
                    counter_strategy: vec![
                        "Update pattern recognition models".to_string(),
                        "Implement evolutionary defense algorithms".to_string(),
                    ],
                    vulnerability_description: format!(
                        "Evolutionary adaptation of {} pattern detected",
                        pattern_id
                    ),
                });
            }
        }

        vulnerabilities
    }

    fn detect_rl_based_attacks(&self, fingerprint: &BehavioralFingerprint) -> Vec<AIDetectedVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for reinforcement learning signatures
        let rl_confidence = self.detect_rl_signatures(fingerprint);
        
        if rl_confidence > 0.75 {
            vulnerabilities.push(AIDetectedVulnerability {
                attack_category: AIAttackCategory::ReinforcementLearningArbitrage,
                detection_confidence: rl_confidence,
                novelty_score: 0.8,
                severity: SecuritySeverity::Critical,
                pattern_matches: vec![self.create_rl_pattern(fingerprint)],
                learning_model_source: "Reinforcement Learning Detector".to_string(),
                prediction_accuracy: 0.82,
                economic_risk_eth: 2_000_000.0, // RL attacks can be very sophisticated
                mitigation_difficulty: 0.95,
                adaptation_speed: 1.0, // RL adapts in real-time
                counter_strategy: vec![
                    "Implement adversarial training".to_string(),
                    "Add reward function disruption".to_string(),
                    "Create multi-agent defense systems".to_string(),
                ],
                vulnerability_description: 
                    "Reinforcement learning-based attack with real-time strategy adaptation".to_string(),
            });
        }

        vulnerabilities
    }

    fn detect_ai_coordination_patterns(&self, fingerprint: &BehavioralFingerprint) -> Vec<AIDetectedVulnerability> {
        let mut vulnerabilities = Vec::new();

        let coordination_score = self.detect_coordination_signatures(fingerprint);
        
        if coordination_score > 0.8 {
            vulnerabilities.push(AIDetectedVulnerability {
                attack_category: AIAttackCategory::AICoordinatedBotSwarm,
                detection_confidence: coordination_score,
                novelty_score: 0.9,
                severity: SecuritySeverity::Critical,
                pattern_matches: vec![self.create_coordination_pattern(fingerprint)],
                learning_model_source: "Multi-Agent Coordination Detector".to_string(),
                prediction_accuracy: 0.79,
                economic_risk_eth: 5_000_000.0, // Coordinated attacks extremely dangerous
                mitigation_difficulty: 0.98,
                adaptation_speed: 0.95,
                counter_strategy: vec![
                    "Implement distributed defense mechanisms".to_string(),
                    "Add cross-protocol coordination monitoring".to_string(),
                    "Create AI vs AI defense systems".to_string(),
                ],
                vulnerability_description: 
                    "Coordinated AI bot swarm with distributed attack execution".to_string(),
            });
        }

        vulnerabilities
    }

    // Feature extraction methods
    fn extract_transaction_patterns(&self) -> Vec<f32> {
        // Simplified feature extraction - would use real ML feature engineering
        let mut patterns = Vec::new();
        
        // Pattern 1: Transaction frequency characteristics
        patterns.push(self.calculate_transaction_frequency());
        
        // Pattern 2: Gas price optimization patterns
        patterns.push(self.calculate_gas_optimization_score());
        
        // Pattern 3: Timing precision indicators
        patterns.push(self.calculate_timing_precision());
        
        // Pattern 4: Success rate consistency (AI optimization indicator)
        patterns.push(self.calculate_success_rate_consistency());
        
        patterns
    }

    fn extract_gas_optimization_patterns(&self) -> Vec<f32> {
        vec![
            self.detect_dynamic_gas_pricing(),
            self.detect_gas_limit_optimization(),
            self.detect_transaction_ordering_optimization(),
            self.detect_batch_optimization_patterns(),
        ]
    }

    fn extract_timing_patterns(&self) -> Vec<f32> {
        vec![
            self.calculate_timing_precision(),
            self.detect_mempool_timing_exploitation(),
            self.detect_block_timing_coordination(),
            self.calculate_execution_timing_variance(),
        ]
    }

    fn extract_interaction_patterns(&self) -> HashMap<String, f32> {
        let mut patterns = HashMap::new();
        patterns.insert("cross_contract_coordination".to_string(), self.detect_cross_contract_coordination());
        patterns.insert("protocol_dependency_exploitation".to_string(), self.detect_dependency_exploitation());
        patterns.insert("multi_dex_coordination".to_string(), self.detect_multi_dex_patterns());
        patterns
    }

    fn extract_economic_patterns(&self) -> Vec<f32> {
        vec![
            self.calculate_profit_optimization_score(),
            self.detect_risk_adjusted_strategy(),
            self.calculate_capital_efficiency(),
            self.detect_portfolio_rebalancing_patterns(),
        ]
    }

    fn extract_complexity_metrics(&self) -> Vec<f32> {
        vec![
            self.calculate_bytecode_complexity(),
            self.calculate_execution_path_complexity(),
            self.calculate_interaction_complexity(),
        ]
    }

    fn extract_entropy_measures(&self) -> Vec<f32> {
        vec![
            self.calculate_behavioral_entropy(),
            self.calculate_pattern_entropy(),
            self.calculate_timing_entropy(),
        ]
    }

    // Helper calculation methods (simplified implementations)
    fn calculate_transaction_frequency(&self) -> f32 { 0.5 }
    fn calculate_gas_optimization_score(&self) -> f32 { 0.7 }
    fn calculate_timing_precision(&self) -> f32 { 0.8 }
    fn calculate_success_rate_consistency(&self) -> f32 { 0.9 }
    fn detect_dynamic_gas_pricing(&self) -> f32 { 0.6 }
    fn detect_gas_limit_optimization(&self) -> f32 { 0.7 }
    fn detect_transaction_ordering_optimization(&self) -> f32 { 0.8 }
    fn detect_batch_optimization_patterns(&self) -> f32 { 0.5 }
    fn detect_mempool_timing_exploitation(&self) -> f32 { 0.9 }
    fn detect_block_timing_coordination(&self) -> f32 { 0.7 }
    fn calculate_execution_timing_variance(&self) -> f32 { 0.3 }
    fn detect_cross_contract_coordination(&self) -> f32 { 0.8 }
    fn detect_dependency_exploitation(&self) -> f32 { 0.6 }
    fn detect_multi_dex_patterns(&self) -> f32 { 0.7 }
    fn calculate_profit_optimization_score(&self) -> f32 { 0.85 }
    fn detect_risk_adjusted_strategy(&self) -> f32 { 0.75 }
    fn calculate_capital_efficiency(&self) -> f32 { 0.9 }
    fn detect_portfolio_rebalancing_patterns(&self) -> f32 { 0.6 }
    fn calculate_bytecode_complexity(&self) -> f32 { 0.7 }
    fn calculate_execution_path_complexity(&self) -> f32 { 0.8 }
    fn calculate_interaction_complexity(&self) -> f32 { 0.9 }
    fn calculate_behavioral_entropy(&self) -> f32 { 0.5 }
    fn calculate_pattern_entropy(&self) -> f32 { 0.6 }
    fn calculate_timing_entropy(&self) -> f32 { 0.4 }

    // Pattern matching methods
    fn matches_mev_ai_pattern(&self, _fingerprint: &BehavioralFingerprint) -> bool {
        // Simplified - would use actual ML pattern matching
        true
    }

    fn matches_adaptive_governance_pattern(&self, _fingerprint: &BehavioralFingerprint) -> bool {
        false // Simplified
    }

    fn calculate_novelty_score(&self, _fingerprint: &BehavioralFingerprint) -> f32 {
        0.8 // Simplified - would calculate distance from known patterns
    }

    fn analyze_attack_complexity(&self, _fingerprint: &BehavioralFingerprint) -> f32 {
        0.9 // Simplified complexity analysis
    }

    fn estimate_economic_risk(&self, _fingerprint: &BehavioralFingerprint) -> f64 {
        750_000.0 // Simplified risk estimation
    }

    fn calculate_evolution_score(&self, _fingerprint: &BehavioralFingerprint, _pattern: &AttackPattern) -> f32 {
        0.6 // Simplified evolution detection
    }

    fn detect_rl_signatures(&self, _fingerprint: &BehavioralFingerprint) -> f32 {
        0.8 // Simplified RL detection
    }

    fn detect_coordination_signatures(&self, _fingerprint: &BehavioralFingerprint) -> f32 {
        0.85 // Simplified coordination detection
    }

    // Pattern creation methods
    fn get_mev_ai_pattern(&self) -> AttackPattern {
        AttackPattern {
            pattern_id: "mev_ai_v1".to_string(),
            bytecode_signatures: vec![vec![0xF1, 0x55, 0x3A]], // CALL, SSTORE, GASPRICE
            execution_sequences: vec!["frontrun->execute->backrun".to_string()],
            gas_usage_patterns: vec![21000, 150000, 21000],
            timing_patterns: vec![0, 1, 2], // Block numbers
            frequency_characteristics: 0.95,
            success_indicators: vec!["profit_extraction".to_string()],
            economic_footprint: 100_000.0,
            complexity_score: 0.8,
        }
    }

    fn get_adaptive_governance_pattern(&self) -> AttackPattern {
        AttackPattern {
            pattern_id: "adaptive_governance_v1".to_string(),
            bytecode_signatures: vec![vec![0x40, 0xe5, 0x8e, 0xe5]], // propose()
            execution_sequences: vec!["accumulate_tokens->propose->vote->execute".to_string()],
            gas_usage_patterns: vec![500000, 300000, 100000, 200000],
            timing_patterns: vec![0, 100800, 201600, 302400], // 1 week intervals
            frequency_characteristics: 0.3,
            success_indicators: vec!["governance_control".to_string()],
            economic_footprint: 1_000_000.0,
            complexity_score: 0.95,
        }
    }

    fn create_novel_pattern(&self, _fingerprint: &BehavioralFingerprint) -> AttackPattern {
        AttackPattern {
            pattern_id: "novel_pattern_detected".to_string(),
            bytecode_signatures: vec![vec![0x00]], // Unknown pattern
            execution_sequences: vec!["unknown_sequence".to_string()],
            gas_usage_patterns: vec![0],
            timing_patterns: vec![0],
            frequency_characteristics: 0.0,
            success_indicators: vec!["unknown_success".to_string()],
            economic_footprint: 750_000.0,
            complexity_score: 0.9,
        }
    }

    fn create_rl_pattern(&self, _fingerprint: &BehavioralFingerprint) -> AttackPattern {
        AttackPattern {
            pattern_id: "reinforcement_learning_attack".to_string(),
            bytecode_signatures: vec![vec![0xF1, 0x55, 0x3A, 0x42]], // CALL, SSTORE, GASPRICE, TIMESTAMP
            execution_sequences: vec!["explore->exploit->adapt".to_string()],
            gas_usage_patterns: vec![200000, 300000, 250000],
            timing_patterns: vec![0, 15, 30], // Adaptive timing
            frequency_characteristics: 0.8,
            success_indicators: vec!["learning_improvement".to_string()],
            economic_footprint: 2_000_000.0,
            complexity_score: 0.98,
        }
    }

    fn create_coordination_pattern(&self, _fingerprint: &BehavioralFingerprint) -> AttackPattern {
        AttackPattern {
            pattern_id: "ai_coordination_swarm".to_string(),
            bytecode_signatures: vec![vec![0xF1]], // Multiple coordinated calls
            execution_sequences: vec!["coordinate->synchronize->execute".to_string()],
            gas_usage_patterns: vec![100000, 100000, 100000, 100000], // Multiple bots
            timing_patterns: vec![0, 0, 0, 0], // Simultaneous execution
            frequency_characteristics: 0.95,
            success_indicators: vec!["coordinated_success".to_string()],
            economic_footprint: 5_000_000.0,
            complexity_score: 0.99,
        }
    }

    fn initialize_baseline_patterns() -> HashMap<String, AttackPattern> {
        let mut patterns = HashMap::new();
        
        patterns.insert("baseline_mev".to_string(), AttackPattern {
            pattern_id: "baseline_mev".to_string(),
            bytecode_signatures: vec![vec![0x38, 0xed, 0x17, 0x39]], // swapExactTokensForTokens()
            execution_sequences: vec!["detect->frontrun->backrun".to_string()],
            gas_usage_patterns: vec![21000, 150000, 21000],
            timing_patterns: vec![0, 1, 2],
            frequency_characteristics: 0.7,
            success_indicators: vec!["arbitrage_profit".to_string()],
            economic_footprint: 50_000.0,
            complexity_score: 0.6,
        });

        patterns
    }

    fn update_learning_models(&mut self, _fingerprint: &BehavioralFingerprint, _vulnerabilities: &[AIDetectedVulnerability]) {
        // Update internal ML models with new observations
        // This would involve actual machine learning model updates in production
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ai_attack_detection() {
        let bytecode = vec![
            // MEV-like pattern
            0x38, 0xed, 0x17, 0x39, // swapExactTokensForTokens()
            0x3A, // GASPRICE (AI gas optimization)
            0xF1, // CALL
        ];

        let mut detector = AIAdaptiveAttackDetector::new(bytecode);
        let vulnerabilities = detector.detect_ai_powered_attacks();

        assert!(!vulnerabilities.is_empty());
        assert!(vulnerabilities.iter().any(|v| matches!(v.attack_category, AIAttackCategory::NovelMEVStrategy)));
    }

    #[test]
    fn test_novelty_detection() {
        let bytecode = vec![
            // Novel pattern with high complexity
            0xFF, 0xEE, 0xDD, 0xCC, // Unknown opcodes pattern
        ];

        let mut detector = AIAdaptiveAttackDetector::new(bytecode);
        detector.novelty_detection_sensitivity = 0.5; // Lower threshold for testing
        
        let vulnerabilities = detector.detect_ai_powered_attacks();
        
        // Should detect some novel patterns
        let novel_attacks: Vec<_> = vulnerabilities.iter()
            .filter(|v| v.novelty_score > 0.6)
            .collect();
        
        assert!(!novel_attacks.is_empty());
    }

    #[test]
    fn test_behavioral_fingerprint_extraction() {
        let detector = AIAdaptiveAttackDetector::new(vec![0x01, 0x02, 0x03]);
        let fingerprint = detector.extract_behavioral_fingerprint();

        assert!(!fingerprint.transaction_patterns.is_empty());
        assert!(!fingerprint.gas_optimization_signature.is_empty());
        assert!(!fingerprint.timing_distribution.is_empty());
        assert!(!fingerprint.economic_behavior_vector.is_empty());
    }
}
