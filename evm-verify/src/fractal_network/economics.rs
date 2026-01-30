// Economic Incentive System - Trustless Manifesto Principle #3
// "Viable incentives" - Make neutrality profitable, prevent centralization

use super::topology::ProverID;
use super::phi_optimizer::{PHI, PHI_INVERSE};
use super::aggregation::CompletedProof;
use super::frac_payment::{FracPaymentSystem, PaymentStrategy, PaymentReceipt};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Economic system that makes small-scale proving profitable
/// Prevents monopolization through φ-optimized reward distribution
pub struct ProvingEconomics {
    /// Base reward per transaction (in wei or smallest unit)
    base_reward: u64,
    
    /// φ-scaling factor for quality bonuses
    phi_scaling: f64,
    
    /// Reputation system for long-term incentives
    reputation_scores: HashMap<ProverID, ReputationScore>,
    
    /// Historic earnings (for preventing monopolization)
    earnings_history: HashMap<ProverID, Vec<EarningRecord>>,
    
    /// FRAC token payment system (optional - can be None before contracts deployed)
    payment_system: Option<Arc<RwLock<FracPaymentSystem>>>,
}

/// Reputation score for long-term participation incentives
#[derive(Clone, Debug)]
pub struct ReputationScore {
    pub total_proofs: u64,
    pub successful_proofs: u64,
    pub phi_efficiency_average: f64,
    pub uptime_percentage: f64,
    pub first_seen: u64,
}

/// Earning record for transparency
#[derive(Clone, Debug)]
pub struct EarningRecord {
    pub task_id: String,
    pub reward: u64,
    pub timestamp: u64,
    pub proof_quality: f64,
}

/// Reward breakdown showing how earnings are calculated
#[derive(Debug)]
pub struct RewardBreakdown {
    pub base_reward: u64,
    pub quality_bonus: u64,
    pub reputation_bonus: u64,
    pub early_completion_bonus: u64,
    pub total: u64,
    
    /// φ-weight factor applied
    pub phi_factor: f64,
}

impl ProvingEconomics {
    pub fn new(base_reward: u64) -> Self {
        Self {
            base_reward,
            phi_scaling: PHI,
            reputation_scores: HashMap::new(),
            earnings_history: HashMap::new(),
            payment_system: None,
        }
    }
    
    /// Set payment system (after initialization)
    pub fn set_payment_system(&mut self, payment_system: Arc<RwLock<FracPaymentSystem>>) {
        self.payment_system = Some(payment_system);
        println!("✅ FRAC payment system connected");
    }
    
    /// Calculate reward for completing a proof
    /// Designed to be profitable even for small provers
    pub fn calculate_reward(
        &self,
        prover: &ProverID,
        proof: &CompletedProof,
        task_complexity: u64,
    ) -> RewardBreakdown {
        // Base reward scales with task complexity
        let base = self.base_reward * task_complexity;
        
        // Quality bonus (φ-optimized proofs get more)
        let quality_bonus = self.calculate_quality_bonus(proof);
        
        // Reputation bonus (long-term participants rewarded)
        let reputation_bonus = self.calculate_reputation_bonus(prover);
        
        // Early completion bonus (faster proving = more reward)
        let early_completion_bonus = self.calculate_speed_bonus(proof);
        
        // φ-factor prevents monopolization
        let phi_factor = self.calculate_phi_factor(prover);
        
        let total = (base + quality_bonus + reputation_bonus + early_completion_bonus) as f64 * phi_factor;
        
        RewardBreakdown {
            base_reward: base,
            quality_bonus,
            reputation_bonus,
            early_completion_bonus,
            total: total as u64,
            phi_factor,
        }
    }
    
    /// Quality bonus based on proof efficiency
    fn calculate_quality_bonus(&self, proof: &CompletedProof) -> u64 {
        // Higher φ-efficiency = higher bonus
        if proof.phi_efficiency >= PHI {
            (self.base_reward as f64 * PHI) as u64
        } else if proof.phi_efficiency >= PHI_INVERSE {
            (self.base_reward as f64 * PHI_INVERSE) as u64
        } else {
            0
        }
    }
    
    /// Reputation bonus for consistent participation
    fn calculate_reputation_bonus(&self, prover: &ProverID) -> u64 {
        if let Some(rep) = self.reputation_scores.get(prover) {
            let success_rate = rep.successful_proofs as f64 / rep.total_proofs.max(1) as f64;
            let longevity_bonus = (rep.total_proofs as f64).log(PHI.exp());
            
            (self.base_reward as f64 * success_rate * longevity_bonus * PHI_INVERSE) as u64
        } else {
            0
        }
    }
    
    /// Speed bonus for fast completion
    fn calculate_speed_bonus(&self, proof: &CompletedProof) -> u64 {
        // Calculate expected time based on phi_efficiency
        // Expected time ~30ms for standard proof (11ms ZODA + accumulation)
        let expected_time_ms = 30.0 / proof.phi_efficiency.max(0.1);
        
        // Calculate actual completion time
        let now = std::time::SystemTime::now();
        let actual_time_ms = now.duration_since(proof.completion_time)
            .map(|d| d.as_millis() as f64)
            .unwrap_or(expected_time_ms);
        
        // Speed ratio: < 1.0 = faster than expected (bonus)
        let speed_ratio = actual_time_ms / expected_time_ms;
        
        // Exponential bonus for speed: faster = exponentially higher reward
        // If 2x faster (ratio = 0.5), bonus = phi^2 ≈ 2.618
        // If same speed (ratio = 1.0), bonus = phi^0 = 1.0
        // If 2x slower (ratio = 2.0), bonus = phi^(-2) ≈ 0.382
        let speed_multiplier = PHI.powf(-speed_ratio.log(2.0));
        
        (self.base_reward as f64 * speed_multiplier * PHI_INVERSE) as u64
    }
    
    /// φ-factor prevents monopolization
    /// High earners get diminishing returns (keeps network decentralized)
    fn calculate_phi_factor(&self, prover: &ProverID) -> f64 {
        if let Some(history) = self.earnings_history.get(prover) {
            let recent_earnings: u64 = history.iter()
                .take(100)  // Last 100 proofs
                .map(|r| r.reward)
                .sum();
            
            // If you've earned a lot recently, your factor decreases
            // This prevents monopolization - makes room for new provers
            let monopoly_factor = 1.0 / (1.0 + (recent_earnings as f64 / 1_000_000.0));
            
            // But never goes below PHI_INVERSE (always profitable)
            monopoly_factor.max(PHI_INVERSE)
        } else {
            // New provers get full rewards
            1.0
        }
    }
    
    /// Record earning (for transparency and history)
    pub fn record_earning(
        &mut self,
        prover: ProverID,
        task_id: String,
        reward: u64,
        proof_quality: f64,
    ) {
        let record = EarningRecord {
            task_id,
            reward,
            timestamp: Self::current_timestamp(),
            proof_quality,
        };
        
        self.earnings_history
            .entry(prover.clone())
            .or_insert_with(Vec::new)
            .push(record);
        
        // Update reputation
        self.update_reputation(prover, proof_quality);
    }
    
    /// Update reputation score
    fn update_reputation(&mut self, prover: ProverID, proof_quality: f64) {
        let rep = self.reputation_scores
            .entry(prover)
            .or_insert_with(|| ReputationScore {
                total_proofs: 0,
                successful_proofs: 0,
                phi_efficiency_average: 0.0,
                uptime_percentage: 100.0,
                first_seen: Self::current_timestamp(),
            });
        
        rep.total_proofs += 1;
        if proof_quality >= PHI_INVERSE {
            rep.successful_proofs += 1;
        }
        
        // Update rolling average
        rep.phi_efficiency_average = 
            (rep.phi_efficiency_average * (rep.total_proofs - 1) as f64 + proof_quality) / 
            rep.total_proofs as f64;
    }
    
    /// Get profitability estimate for a prover
    /// Shows if it's worth participating
    pub fn estimate_profitability(
        &self,
        prover: &ProverID,
        proofs_per_hour: u64,
    ) -> ProfitabilityEstimate {
        let phi_factor = self.calculate_phi_factor(prover);
        let avg_reward = (self.base_reward as f64 * phi_factor * PHI) as u64;
        
        let hourly_earnings = avg_reward * proofs_per_hour;
        let daily_earnings = hourly_earnings * 24;
        let monthly_earnings = daily_earnings * 30;
        
        // Estimate costs (electricity, hardware wear)
        let hourly_cost = 100;  // 0.1 unit per hour (adjustable)
        let hourly_profit = hourly_earnings.saturating_sub(hourly_cost);
        
        ProfitabilityEstimate {
            hourly_earnings,
            daily_earnings,
            monthly_earnings,
            hourly_cost,
            hourly_profit,
            roi_percentage: (hourly_profit as f64 / hourly_cost as f64) * 100.0,
        }
    }
    
    /// Get leaderboard (but designed not to centralize!)
    pub fn get_top_provers(&self, limit: usize) -> Vec<(ProverID, ReputationScore)> {
        let mut scores: Vec<_> = self.reputation_scores.iter()
            .map(|(id, score)| (id.clone(), score.clone()))
            .collect();
        
        // Sort by success rate, but weight by diversity
        scores.sort_by(|a, b| {
            let score_a = a.1.successful_proofs as f64 / a.1.total_proofs.max(1) as f64;
            let score_b = b.1.successful_proofs as f64 / b.1.total_proofs.max(1) as f64;
            score_b.partial_cmp(&score_a).unwrap()
        });
        
        scores.truncate(limit);
        scores
    }
    
    fn current_timestamp() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

#[derive(Debug)]
pub struct ProfitabilityEstimate {
    pub hourly_earnings: u64,
    pub daily_earnings: u64,
    pub monthly_earnings: u64,
    pub hourly_cost: u64,
    pub hourly_profit: u64,
    pub roi_percentage: f64,
}

/// Reward distribution strategy
pub enum RewardStrategy {
    /// Pay immediately on proof submission (fast, good for small provers)
    Immediate,
    
    /// Pay after confirmation (safer, slight delay)
    Confirmed,
    
    /// Batch payments (gas efficient, periodic)
    Batched { interval: u64 },
}

impl ProvingEconomics {
    /// Distribute rewards according to strategy
    pub fn distribute_rewards(
        &mut self,
        prover: ProverID,
        reward: u64,
        strategy: RewardStrategy,
    ) {
        match strategy {
            RewardStrategy::Immediate => {
                self.pay_immediately(prover, reward);
            }
            RewardStrategy::Confirmed => {
                self.queue_for_confirmation(prover, reward);
            }
            RewardStrategy::Batched { interval } => {
                self.add_to_batch(prover, reward, interval);
            }
        }
    }
    
    fn pay_immediately(&self, prover: ProverID, reward: u64) {
        println!("💰 Paying {} to {:?} immediately", reward, prover);
        
        if let Some(ref payment_system) = self.payment_system {
            // Async payment in background
            let payment_system = payment_system.clone();
            let prover_clone = prover.clone();
            let task_id = format!("task_{}", Self::current_timestamp());
            
            tokio::spawn(async move {
                let system = payment_system.read().await;
                match system.pay_immediately(prover_clone.clone(), reward, task_id).await {
                    Ok(receipt) => {
                        println!("✅ Payment successful! TX: {}", receipt.transaction_hash);
                    }
                    Err(e) => {
                        eprintln!("❌ Payment failed: {}", e);
                    }
                }
            });
        } else {
            println!("⚠️  Payment system not configured (contracts not deployed yet)");
        }
    }
    
    fn queue_for_confirmation(&self, prover: ProverID, reward: u64) {
        println!("⏳ Queueing {} for {:?} (awaiting confirmation)", reward, prover);
        
        if let Some(ref payment_system) = self.payment_system {
            let payment_system = payment_system.clone();
            let prover_clone = prover.clone();
            let task_id = format!("task_{}", Self::current_timestamp());
            
            tokio::spawn(async move {
                let system = payment_system.read().await;
                if let Err(e) = system.queue_payment(prover_clone, reward, task_id).await {
                    eprintln!("❌ Failed to queue payment: {}", e);
                }
            });
        }
    }
    
    fn add_to_batch(&self, prover: ProverID, reward: u64, _interval: u64) {
        println!("📦 Adding {} for {:?} to batch", reward, prover);
        
        if let Some(ref payment_system) = self.payment_system {
            let payment_system = payment_system.clone();
            let task_id = format!("task_{}", Self::current_timestamp());
            
            tokio::spawn(async move {
                let system = payment_system.read().await;
                if let Err(e) = system.queue_payment(prover, reward, task_id).await {
                    eprintln!("❌ Failed to add to batch: {}", e);
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;
    
    #[test]
    fn test_small_prover_profitability() {
        let economics = ProvingEconomics::new(1000);
        let prover = ProverID("small_prover".to_string());
        
        // Small prover doing 1 proof per hour
        let estimate = economics.estimate_profitability(&prover, 1);
        
        assert!(estimate.hourly_profit > 0, "Small proving should be profitable");
        assert!(estimate.roi_percentage > 0.0, "Should have positive ROI");
        
        println!("Small prover profitability:");
        println!("  Hourly: {} units", estimate.hourly_profit);
        println!("  ROI: {:.2}%", estimate.roi_percentage);
    }
    
    #[test]
    fn test_monopoly_prevention() {
        let mut economics = ProvingEconomics::new(1000);
        let big_prover = ProverID("whale".to_string());
        
        // Simulate high earner
        for i in 0..100 {
            economics.record_earning(
                big_prover.clone(),
                format!("task_{}", i),
                10000,
                PHI,
            );
        }
        
        // φ-factor should decrease for high earners
        let phi_factor = economics.calculate_phi_factor(&big_prover);
        assert!(phi_factor < 1.0, "High earners should get diminishing returns");
        assert!(phi_factor >= PHI_INVERSE, "But still profitable");
        
        println!("Monopoly prevention: φ-factor = {:.3}", phi_factor);
    }
    
    #[test]
    fn test_reputation_bonus() {
        let mut economics = ProvingEconomics::new(1000);
        let loyal_prover = ProverID("loyal".to_string());
        
        // Build reputation over time
        for i in 0..50 {
            economics.record_earning(
                loyal_prover.clone(),
                format!("task_{}", i),
                1000,
                PHI,
            );
        }
        
        let bonus = economics.calculate_reputation_bonus(&loyal_prover);
        assert!(bonus > 0, "Long-term participation should be rewarded");
        
        println!("Reputation bonus after 50 proofs: {} units", bonus);
    }
    
    #[test]
    fn test_reward_breakdown_transparency() {
        let economics = ProvingEconomics::new(1000);
        let prover = ProverID("test".to_string());
        
        let proof = CompletedProof {
            task_id: "test".to_string(),
            aggregated_proof: vec![],
            phi_efficiency: PHI,
            contributors: vec![prover.clone()],
            completion_time: SystemTime::now(),
        };
        
        let breakdown = economics.calculate_reward(&prover, &proof, 1);
        
        println!("Reward breakdown:");
        println!("  Base: {}", breakdown.base_reward);
        println!("  Quality: {}", breakdown.quality_bonus);
        println!("  Reputation: {}", breakdown.reputation_bonus);
        println!("  Speed: {}", breakdown.early_completion_bonus);
        println!("  φ-factor: {:.3}", breakdown.phi_factor);
        println!("  Total: {}", breakdown.total);
        
        assert!(breakdown.total > 0, "Should calculate positive reward");
    }
}
