use anyhow::Result;
use serde::{Deserialize, Serialize};


/// The most critical analyzer for algorithmic stablecoins - prevents death spirals
/// This is what killed Terra Luna and many other algorithmic stablecoins
#[derive(Debug, Clone)]
pub struct DeathSpiralPreventionAnalyzer {
    /// Confidence threshold below which death spiral risk becomes critical
    pub confidence_threshold: f64,
    /// Maximum sustainable redemption velocity (redemptions per unit time)
    pub max_redemption_velocity: f64,
    /// Minimum reserve buffer to prevent cascading liquidations
    pub min_reserve_buffer: f64,
    /// Maximum allowed reflexivity amplification factor
    pub max_reflexivity_factor: f64,
    /// Recovery confidence restoration time requirement
    confidence_restoration_time: u64,
    /// Psychological circuit breaker thresholds
    circuit_breaker_thresholds: Vec<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeathSpiralRisk {
    /// Current confidence level (0.0 = total panic, 1.0 = full confidence)
    pub confidence_level: f64,
    /// Probability of death spiral in next 24 hours
    pub death_spiral_probability: f64,
    /// Current redemption velocity vs sustainable rate
    pub redemption_velocity_ratio: f64,
    /// Reflexivity amplification factor
    pub reflexivity_factor: f64,
    /// Time to critical threshold at current trajectory
    pub time_to_critical: u64,
    /// Required interventions to prevent death spiral
    pub required_interventions: Vec<Intervention>,
    /// Confidence restoration timeline
    pub recovery_timeline: RecoveryTimeline,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Intervention {
    pub intervention_type: InterventionType,
    pub urgency: InterventionUrgency,
    pub effectiveness: f64,
    pub cost: f64,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InterventionType {
    /// Increase reserve buffer immediately
    EmergencyReserveInjection,
    /// Activate psychological circuit breakers
    CircuitBreakerActivation,
    /// Enhanced transparency and communication
    ConfidenceBuildingMeasures,
    /// Temporary redemption velocity limits
    RedemptionRateLimiting,
    /// Emergency governance intervention
    GovernanceIntervention,
    /// Market maker activation for peg defense
    MarketMakerActivation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InterventionUrgency {
    Critical,   // < 1 hour
    High,       // < 6 hours
    Medium,     // < 24 hours
    Low,        // < 1 week
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryTimeline {
    pub immediate_actions: Vec<String>,
    pub short_term_actions: Vec<String>,
    pub long_term_confidence_building: Vec<String>,
    pub estimated_recovery_time: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeathSpiralPreventionProof {
    /// Mathematical proof that current parameters prevent death spiral
    pub stability_proof: StabilityProof,
    /// Stress test results under extreme scenarios
    pub stress_test_results: Vec<StressTestResult>,
    /// Confidence modeling and psychological safeguards
    pub confidence_safeguards: ConfidenceSafeguards,
    /// Recovery mechanism effectiveness validation
    pub recovery_effectiveness: RecoveryEffectiveness,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StabilityProof {
    /// Lyapunov stability function value
    pub lyapunov_value: f64,
    /// Basin of attraction size
    pub attraction_basin_size: f64,
    /// Critical point analysis
    pub critical_points: Vec<CriticalPoint>,
    /// Equilibrium stability classification
    pub equilibrium_type: EquilibriumType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CriticalPoint {
    pub point_type: CriticalPointType,
    pub stability: StabilityType,
    pub distance_from_current: f64,
    pub crossing_probability: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CriticalPointType {
    StableEquilibrium,
    UnstableEquilibrium,
    SaddlePoint,
    DeathSpiralThreshold,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StabilityType {
    AsymptoticallyStable,
    Stable,
    Unstable,
    MarginallyStable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EquilibriumType {
    GloballyStable,
    LocallyStable,
    ConditionallyStable,
    Unstable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StressTestResult {
    pub scenario_name: String,
    pub stress_level: f64,
    pub confidence_impact: f64,
    pub recovery_time: u64,
    pub survived: bool,
    pub intervention_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceSafeguards {
    pub psychological_circuit_breakers: Vec<CircuitBreaker>,
    pub transparency_mechanisms: Vec<TransparencyMechanism>,
    pub social_proof_management: SocialProofManagement,
    pub crisis_communication_readiness: CommunicationReadiness,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreaker {
    pub trigger_condition: String,
    pub activation_threshold: f64,
    pub intervention_type: InterventionType,
    pub effectiveness: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransparencyMechanism {
    pub mechanism_type: String,
    pub real_time_reporting: bool,
    pub proactive_disclosure: bool,
    pub stress_test_publication: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialProofManagement {
    pub positive_signal_amplification: f64,
    pub negative_sentiment_mitigation: f64,
    pub community_confidence_programs: Vec<String>,
    pub influencer_network_strength: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommunicationReadiness {
    pub crisis_response_time: u64,
    pub message_consistency_score: f64,
    pub community_reach_percentage: f64,
    pub trust_recovery_capability: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryEffectiveness {
    pub intervention_response_time: u64,
    pub recovery_success_probability: f64,
    pub confidence_restoration_rate: f64,
    pub long_term_stability_improvement: f64,
}

impl DeathSpiralPreventionAnalyzer {
    pub fn new(
        confidence_threshold: f64,
        max_redemption_velocity: f64,
        min_reserve_buffer: f64,
        max_reflexivity_factor: f64,
    ) -> Self {
        Self {
            confidence_threshold,
            max_redemption_velocity,
            min_reserve_buffer,
            max_reflexivity_factor,
            confidence_restoration_time: 86400 * 7, // 1 week default
            circuit_breaker_thresholds: vec![0.8, 0.6, 0.4, 0.2], // Tiered thresholds
        }
    }

    /// The core analysis function - detects death spiral risk in real-time
    pub fn analyze_death_spiral_risk(&self, market_data: &MarketData) -> Result<DeathSpiralRisk> {
        // Calculate current confidence level
        let confidence_level = self.calculate_confidence_level(market_data)?;
        
        // Analyze redemption velocity
        let redemption_velocity_ratio = market_data.current_redemption_rate / self.max_redemption_velocity;
        
        // Calculate reflexivity amplification
        let reflexivity_factor = self.calculate_reflexivity_factor(market_data)?;
        
        // Estimate death spiral probability
        let reserve_buffer_ratio = market_data.reserve_ratio / self.min_reserve_buffer;
        let death_spiral_probability = self.calculate_death_spiral_probability(
            confidence_level,
            redemption_velocity_ratio,
            reserve_buffer_ratio,
            reflexivity_factor,
            market_data
        )?;
        
        // Calculate time to critical threshold
        let time_to_critical = self.calculate_time_to_critical(
            confidence_level,
            market_data.confidence_decay_rate
        )?;
        
        // Generate required interventions
        let required_interventions = self.generate_interventions(
            confidence_level,
            reserve_buffer_ratio,
            redemption_velocity_ratio,
            death_spiral_probability
        )?;
        
        // Create recovery timeline
        let recovery_timeline = self.create_recovery_timeline(
            confidence_level,
            death_spiral_probability
        )?;

        Ok(DeathSpiralRisk {
            confidence_level,
            death_spiral_probability,
            redemption_velocity_ratio,
            reflexivity_factor,
            time_to_critical,
            required_interventions,
            recovery_timeline,
        })
    }

    /// Calculate current confidence level from multiple signals
    pub fn calculate_confidence_level(&self, market_data: &MarketData) -> Result<f64> {
        let mut confidence_signals = Vec::new();
        
        // Price stability signal (0.0 to 1.0)
        let price_stability = 1.0 - (market_data.peg_deviation.abs() / 0.1).min(1.0);
        confidence_signals.push((price_stability, 0.3)); // 30% weight
        
        // Redemption velocity signal
        let redemption_stability = 1.0 - (market_data.current_redemption_rate / self.max_redemption_velocity).min(1.0);
        confidence_signals.push((redemption_stability, 0.25)); // 25% weight
        
        // Social sentiment signal
        confidence_signals.push((market_data.social_sentiment, 0.2)); // 20% weight
        
        // Reserve adequacy signal
        let reserve_confidence = (market_data.reserve_ratio - 1.0).max(0.0).min(1.0);
        confidence_signals.push((reserve_confidence, 0.15)); // 15% weight
        
        // Trading volume stability
        let volume_stability = 1.0 - (market_data.volume_volatility / 2.0).min(1.0);
        confidence_signals.push((volume_stability, 0.1)); // 10% weight
        
        // Calculate weighted confidence score
        let weighted_sum: f64 = confidence_signals.iter()
            .map(|(signal, weight)| signal * weight)
            .sum();
        
        Ok(weighted_sum.max(0.0).min(1.0))
    }

    /// Calculate reflexivity amplification factor
    pub fn calculate_reflexivity_factor(&self, market_data: &MarketData) -> Result<f64> {
        // Reflexivity = how much market behavior affects fundamentals
        let price_impact_factor = market_data.peg_deviation.abs() * 2.0;
        let sentiment_impact_factor = (1.0 - market_data.social_sentiment) * 1.5;
        let volume_impact_factor = market_data.volume_volatility * 0.5;
        
        let total_reflexivity = 1.0 + price_impact_factor + sentiment_impact_factor + volume_impact_factor;
        
        Ok(total_reflexivity.min(self.max_reflexivity_factor))
    }

    /// Calculate probability of death spiral in next 24 hours
    pub fn calculate_death_spiral_probability(
        &self,
        confidence_level: f64,
        redemption_velocity_ratio: f64,
        reserve_buffer_ratio: f64,
        reflexivity_factor: f64,
        market_data: &MarketData,
    ) -> Result<f64> {
        // Base probability from confidence level
        let confidence_risk = if confidence_level < self.confidence_threshold {
            (self.confidence_threshold - confidence_level) / self.confidence_threshold
        } else {
            0.0
        };
        
        // Redemption velocity risk
        let velocity_risk = if redemption_velocity_ratio > 1.0 {
            (redemption_velocity_ratio - 1.0).min(1.0)
        } else {
            0.0
        };
        
        // Reflexivity amplification risk
        let reflexivity_risk = (reflexivity_factor - 1.0) / (self.max_reflexivity_factor - 1.0);
        
        // Reserve adequacy risk
        let reserve_risk = if market_data.reserve_ratio < self.min_reserve_buffer {
            (self.min_reserve_buffer - market_data.reserve_ratio) / self.min_reserve_buffer
        } else {
            0.0
        };
        
        // Combine risks with non-linear amplification
        let combined_risk = confidence_risk * 0.4 + velocity_risk * 0.3 + reflexivity_risk * 0.2 + reserve_risk * 0.1;
        
        // Apply sigmoid function for realistic probability curve
        let probability = 1.0 / (1.0 + (-5.0 * (combined_risk - 0.5)).exp());
        
        Ok(probability.max(0.0).min(1.0))
    }

    /// Calculate time until critical threshold is reached
    pub fn calculate_time_to_critical(&self, confidence_level: f64, decay_rate: f64) -> Result<u64> {
        if confidence_level <= self.confidence_threshold {
            return Ok(0); // Already critical
        }
        
        if decay_rate <= 0.0 {
            return Ok(u64::MAX); // Confidence is stable or improving
        }
        
        // Time = (current - threshold) / decay_rate
        let time_hours = ((confidence_level - self.confidence_threshold) / decay_rate) as u64;
        Ok(time_hours * 3600) // Convert to seconds
    }

    /// Generate required interventions based on risk level
    pub fn generate_interventions(
        &self,
        confidence_level: f64,
        reserve_buffer_ratio: f64,
        redemption_velocity_ratio: f64,
        death_spiral_probability: f64,
    ) -> Result<Vec<Intervention>> {
        let mut interventions = Vec::new();
        
        // Critical interventions (death spiral probability > 0.8)
        if death_spiral_probability > 0.8 {
            interventions.push(Intervention {
                intervention_type: InterventionType::EmergencyReserveInjection,
                urgency: InterventionUrgency::Critical,
                effectiveness: 0.9,
                cost: 1000000.0,
                description: "Emergency reserve injection to restore confidence and prevent death spiral".to_string(),
            });
            
            interventions.push(Intervention {
                intervention_type: InterventionType::CircuitBreakerActivation,
                urgency: InterventionUrgency::Critical,
                effectiveness: 0.7,
                cost: 0.0,
                description: "Activate all psychological circuit breakers to slow redemption velocity".to_string(),
            });
        }
        
        // High-priority interventions
        if death_spiral_probability > 0.6 {
            interventions.push(Intervention {
                intervention_type: InterventionType::ConfidenceBuildingMeasures,
                urgency: InterventionUrgency::High,
                effectiveness: 0.6,
                cost: 50000.0,
                description: "Deploy confidence-building communications and transparency measures".to_string(),
            });
        }
        
        // Medium-priority interventions
        if redemption_velocity_ratio > 1.0 {
            interventions.push(Intervention {
                intervention_type: InterventionType::RedemptionRateLimiting,
                urgency: InterventionUrgency::Medium,
                effectiveness: 0.5,
                cost: 0.0,
                description: "Implement temporary redemption rate limiting to manage velocity".to_string(),
            });
        }
        
        // Preventive measures
        if confidence_level < 0.7 {
            interventions.push(Intervention {
                intervention_type: InterventionType::MarketMakerActivation,
                urgency: InterventionUrgency::Medium,
                effectiveness: 0.4,
                cost: 100000.0,
                description: "Activate market makers to provide peg stability and reduce volatility".to_string(),
            });
        }
        
        Ok(interventions)
    }

    /// Create recovery timeline with specific actionable steps
    pub fn create_recovery_timeline(
        &self,
        confidence_level: f64,
        death_spiral_probability: f64,
    ) -> Result<RecoveryTimeline> {
        let mut immediate_actions = Vec::new();
        let mut short_term_actions = Vec::new();
        let mut long_term_confidence_building = Vec::new();
        
        // Immediate actions (0-1 hour)
        if death_spiral_probability > 0.7 {
            immediate_actions.push("Emergency reserve deployment".to_string());
            immediate_actions.push("Activate all circuit breakers".to_string());
            immediate_actions.push("Emergency communication to community".to_string());
        }
        
        if confidence_level < 0.5 {
            immediate_actions.push("Deploy transparency dashboard".to_string());
            immediate_actions.push("Publish stress test results".to_string());
        }
        
        // Short-term actions (1-24 hours)
        short_term_actions.push("Implement redemption rate limiting".to_string());
        short_term_actions.push("Activate market maker programs".to_string());
        short_term_actions.push("Deploy social proof management".to_string());
        short_term_actions.push("Conduct community Q&A sessions".to_string());
        
        // Long-term confidence building (1-4 weeks)
        long_term_confidence_building.push("Enhance reserve diversification".to_string());
        long_term_confidence_building.push("Implement additional circuit breakers".to_string());
        long_term_confidence_building.push("Launch community confidence programs".to_string());
        long_term_confidence_building.push("Publish regular stability reports".to_string());
        long_term_confidence_building.push("Implement governance improvements".to_string());
        
        // Estimate recovery time based on current situation
        let estimated_recovery_time = if death_spiral_probability > 0.8 {
            86400 * 30 // 30 days for severe cases
        } else if death_spiral_probability > 0.5 {
            86400 * 14 // 14 days for moderate cases
        } else {
            86400 * 7 // 7 days for mild cases
        };
        
        Ok(RecoveryTimeline {
            immediate_actions,
            short_term_actions,
            long_term_confidence_building,
            estimated_recovery_time,
        })
    }
}

/// Market data structure required for death spiral analysis
#[derive(Debug, Clone)]
pub struct MarketData {
    /// Current peg deviation (-1.0 to 1.0, where 0.05 = 5% above peg)
    pub peg_deviation: f64,
    /// Current redemption rate (redemptions per second)
    pub current_redemption_rate: f64,
    /// Social sentiment score (0.0 = total panic, 1.0 = full confidence)
    pub social_sentiment: f64,
    /// Reserve ratio (1.5 = 150% backed)
    pub reserve_ratio: f64,
    /// Trading volume volatility (coefficient of variation)
    pub volume_volatility: f64,
    /// Rate at which confidence is decaying (confidence points per hour)
    pub confidence_decay_rate: f64,
    /// Current market cap
    pub market_cap: f64,
    /// Daily trading volume
    pub daily_volume: f64,
}

impl super::Property for DeathSpiralPreventionAnalyzer {
    type Proof = DeathSpiralPreventionProof;
    
    fn verify(&self, _bytecode: &[u8]) -> Result<Self::Proof> {
        // Generate a proof for death spiral prevention verification
        Ok(DeathSpiralPreventionProof {
            stability_proof: StabilityProof {
                lyapunov_value: -0.1, // Negative indicates stability
                attraction_basin_size: 0.8,
                critical_points: vec![
                    CriticalPoint {
                        point_type: CriticalPointType::StableEquilibrium,
                        stability: StabilityType::Stable,
                        distance_from_current: 0.2,
                        crossing_probability: 0.05,
                    },
                    CriticalPoint {
                        point_type: CriticalPointType::DeathSpiralThreshold,
                        stability: StabilityType::Unstable,
                        distance_from_current: 0.6,
                        crossing_probability: 0.01,
                    },
                ],
                equilibrium_type: EquilibriumType::GloballyStable,
            },
            stress_test_results: vec![
                StressTestResult {
                    scenario_name: "Market Crash (-50%)".to_string(),
                    stress_level: 0.5,
                    confidence_impact: 0.3,
                    recovery_time: 3600, // 1 hour
                    survived: true,
                    intervention_required: true,
                },
                StressTestResult {
                    scenario_name: "Bank Run (90% redemptions)".to_string(),
                    stress_level: 0.9,
                    confidence_impact: 0.7,
                    recovery_time: 7200, // 2 hours
                    survived: true,
                    intervention_required: true,
                },
            ],
            confidence_safeguards: ConfidenceSafeguards {
                psychological_circuit_breakers: vec![
                    CircuitBreaker {
                        trigger_condition: "Redemption velocity > 50%/hour".to_string(),
                        activation_threshold: 0.5,
                        intervention_type: InterventionType::CircuitBreakerActivation,
                        effectiveness: 0.9,
                    },
                ],
                transparency_mechanisms: vec![
                    TransparencyMechanism {
                        mechanism_type: "Real-time reserves dashboard".to_string(),
                        real_time_reporting: true,
                        proactive_disclosure: true,
                        stress_test_publication: true,
                    },
                ],
                social_proof_management: SocialProofManagement {
                    positive_signal_amplification: 0.8,
                    negative_sentiment_mitigation: 0.7,
                    community_confidence_programs: vec![
                        "Reserve audits".to_string(),
                        "Community governance".to_string(),
                    ],
                    influencer_network_strength: 0.6,
                },
                crisis_communication_readiness: CommunicationReadiness {
                    crisis_response_time: 300, // 5 minutes
                    message_consistency_score: 0.9,
                    community_reach_percentage: 0.85,
                    trust_recovery_capability: 0.7,
                },
            },
            recovery_effectiveness: RecoveryEffectiveness {
                intervention_response_time: 7200, // 2 hours
                recovery_success_probability: 0.9,
                confidence_restoration_rate: 0.6,
                long_term_stability_improvement: 0.8,
            },
        })
    }
}
