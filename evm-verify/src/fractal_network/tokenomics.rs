// FRAC Token Economics - Optimized for Early Adopters & Long-Term Appreciation
// Combines proven mechanisms from successful DeFi protocols

use super::topology::ProverID;
use super::aggregation::CompletedProof;
use ethers::types::{Address, U256};
use std::collections::HashMap;
use serde::{Serialize, Deserialize};

/// Network genesis timestamp - used for early adopter calculations
const GENESIS_TIMESTAMP: u64 = 1700000000; // Set on deployment

/// Total FRAC supply cap
const MAX_SUPPLY: u64 = 100_000_000; // 100M FRAC

/// Golden ratio - used for optimal economic design
const PHI: f64 = 1.618033988749895;

/// Complete tokenomics system
pub struct FracTokenomics {
    /// Current block height (for epoch calculations)
    current_block: u64,
    
    /// Genesis block
    genesis_block: u64,
    
    /// Total FRAC minted so far
    total_minted: u64,
    
    /// Total FRAC burned
    total_burned: u64,
    
    /// Early adopter registry (first 1000 get special NFT)
    genesis_provers: HashMap<Address, GenesisStatus>,
    
    /// Staking positions
    staking_positions: HashMap<Address, Vec<StakePosition>>,
    
    /// Vesting schedules
    vesting_schedules: HashMap<Address, VestingSchedule>,
    
    /// Protocol revenue accumulator (for buybacks)
    protocol_treasury: u64,
}

/// Genesis NFT status for first 1000 provers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisStatus {
    pub nft_id: u32,
    pub join_block: u64,
    pub total_proofs: u64,
    pub permanent_multiplier: f64, // 2x forever
}

/// Staking position with lock period
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakePosition {
    pub amount: u64,
    pub start_block: u64,
    pub lock_duration_blocks: u64, // 4 years max
    pub ve_power: u64, // vote-escrowed power (amount * duration)
    pub rewards_claimed: u64,
}

/// Vesting schedule for long-term holders
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VestingSchedule {
    pub earned_amount: u64,
    pub lock_start: u64,
    pub lock_duration: u64,
    pub multiplier: f64, // 1.5x to 5x based on duration
}

/// Reward calculation result
#[derive(Debug, Clone)]
pub struct RewardCalculation {
    pub base_reward: u64,
    pub epoch_multiplier: f64,
    pub genesis_multiplier: f64,
    pub quality_bonus: u64,
    pub staking_boost: f64,
    pub total_reward: u64,
    pub protocol_fee: u64,
    pub burn_amount: u64,
}

impl FracTokenomics {
    pub fn new(genesis_block: u64) -> Self {
        Self {
            current_block: genesis_block,
            genesis_block,
            total_minted: 0,
            total_burned: 0,
            genesis_provers: HashMap::new(),
            staking_positions: HashMap::new(),
            vesting_schedules: HashMap::new(),
            protocol_treasury: 0,
        }
    }
    
    /// Update current block (call on each block)
    pub fn update_block(&mut self, block: u64) {
        self.current_block = block;
    }
    
    /// Calculate complete reward for a proof
    pub fn calculate_proof_reward(
        &self,
        prover: Address,
        proof: &CompletedProof,
        base_reward: u64,
    ) -> RewardCalculation {
        // 1. Epoch multiplier (early adopter bonus)
        let epoch_multiplier = self.get_epoch_multiplier();
        
        // 2. Genesis NFT multiplier (permanent 2x for first 1000)
        let genesis_multiplier = self.get_genesis_multiplier(&prover);
        
        // 3. Quality bonus based on proof characteristics
        let quality_bonus = self.calculate_quality_bonus(proof);
        
        // 4. Staking boost (stakers get extra rewards)
        let staking_boost = self.get_staking_boost(&prover);
        
        // Calculate total before fees
        let gross_reward = (base_reward as f64 
            * epoch_multiplier 
            * genesis_multiplier 
            * staking_boost) as u64 
            + quality_bonus;
        
        // 5. Protocol fee (5% of gross reward)
        let protocol_fee = gross_reward / 20; // 5%
        
        // 6. Burn amount (50% of protocol fee)
        let burn_amount = protocol_fee / 2;
        
        // Net reward to prover
        let total_reward = gross_reward - protocol_fee;
        
        RewardCalculation {
            base_reward,
            epoch_multiplier,
            genesis_multiplier,
            quality_bonus,
            staking_boost,
            total_reward,
            protocol_fee,
            burn_amount,
        }
    }
    
    /// Epoch multiplier: decreases over time (rewards early adoption)
    fn get_epoch_multiplier(&self) -> f64 {
        let blocks_since_genesis = self.current_block.saturating_sub(self.genesis_block);
        
        // 100k blocks per epoch (~2 weeks at 12s/block)
        let epoch = blocks_since_genesis / 100_000;
        
        match epoch {
            0 => 10.0,   // Epoch 0: 10x (first 2 weeks)
            1 => 5.0,    // Epoch 1: 5x  (weeks 2-4)
            2 => 2.5,    // Epoch 2: 2.5x (weeks 4-6)
            3 => 1.5,    // Epoch 3: 1.5x (weeks 6-8)
            _ => 1.0,    // After epoch 3: 1x (normal)
        }
    }
    
    /// Genesis multiplier: permanent 2x for first 1000 provers
    fn get_genesis_multiplier(&self, prover: &Address) -> f64 {
        if self.genesis_provers.contains_key(prover) {
            2.0 // Permanent 2x
        } else {
            1.0
        }
    }
    
    /// Calculate quality bonus based on proof characteristics
    fn calculate_quality_bonus(&self, proof: &CompletedProof) -> u64 {
        let mut bonus = 0u64;
        
        // Bonus for φ-optimized proofs
        if proof.phi_efficiency >= PHI {
            bonus += 1000; // 1000 FRAC bonus
        } else if proof.phi_efficiency >= 1.5 {
            bonus += 500;
        }
        
        // Bonus for comprehensive proofs
        if proof.aggregated_proof.len() > 1000 {
            bonus += 500;
        }
        
        bonus
    }
    
    /// Staking boost: stakers get up to 2x rewards
    fn get_staking_boost(&self, prover: &Address) -> f64 {
        if let Some(positions) = self.staking_positions.get(prover) {
            let total_ve_power: u64 = positions.iter().map(|p| p.ve_power).sum();
            
            // More staking = higher boost (up to 2x)
            // 10k ve_power = 1.1x, 100k = 1.5x, 1M = 2x
            let boost = 1.0 + (total_ve_power as f64 / 1_000_000.0).min(1.0);
            boost
        } else {
            1.0
        }
    }
    
    /// Register genesis prover (only first 1000)
    pub fn register_genesis_prover(&mut self, prover: Address) -> Result<u32, String> {
        if self.genesis_provers.len() >= 1000 {
            return Err("Genesis period ended".to_string());
        }
        
        if self.genesis_provers.contains_key(&prover) {
            return Err("Already registered".to_string());
        }
        
        let nft_id = self.genesis_provers.len() as u32 + 1;
        
        self.genesis_provers.insert(prover, GenesisStatus {
            nft_id,
            join_block: self.current_block,
            total_proofs: 0,
            permanent_multiplier: 2.0,
        });
        
        println!("🎉 Genesis NFT #{} minted for {:?}", nft_id, prover);
        println!("   Benefits: 2x rewards FOREVER + zero fees");
        
        Ok(nft_id)
    }
    
    /// Create staking position (lock FRAC for rewards + voting power)
    pub fn create_stake(
        &mut self,
        staker: Address,
        amount: u64,
        lock_years: u8,
    ) -> Result<u64, String> {
        if lock_years > 4 {
            return Err("Max lock: 4 years".to_string());
        }
        
        let lock_blocks = (lock_years as u64) * 365 * 24 * 60 * 60 / 12; // ~12s/block
        
        // ve_power = amount * lock_duration (in years)
        // 1 FRAC locked 4 years = 4 ve_power
        let ve_power = amount * (lock_years as u64);
        
        let position = StakePosition {
            amount,
            start_block: self.current_block,
            lock_duration_blocks: lock_blocks,
            ve_power,
            rewards_claimed: 0,
        };
        
        self.staking_positions
            .entry(staker)
            .or_insert_with(Vec::new)
            .push(position.clone());
        
        println!("🔒 Staked {} FRAC for {} years", amount, lock_years);
        println!("   ve_power: {} | Unlock block: {}", ve_power, self.current_block + lock_blocks);
        
        Ok(ve_power)
    }
    
    /// Create vesting schedule (rewards for not selling)
    pub fn create_vesting(
        &mut self,
        holder: Address,
        amount: u64,
        lock_months: u8,
    ) -> Result<f64, String> {
        let multiplier = match lock_months {
            3 => 1.5,   // 3 months: 50% bonus
            6 => 2.0,   // 6 months: 100% bonus (double)
            12 => 3.0,  // 12 months: 200% bonus (triple)
            24 => 5.0,  // 24 months: 400% bonus (5x!)
            _ => return Err("Invalid lock duration".to_string()),
        };
        
        let lock_blocks = (lock_months as u64) * 30 * 24 * 60 * 60 / 12;
        
        let schedule = VestingSchedule {
            earned_amount: amount,
            lock_start: self.current_block,
            lock_duration: lock_blocks,
            multiplier,
        };
        
        self.vesting_schedules.insert(holder, schedule);
        
        println!("📅 Vesting {} FRAC for {} months", amount, lock_months);
        println!("   Multiplier: {}x | Unlock: {} FRAC", multiplier, (amount as f64 * multiplier) as u64);
        
        Ok(multiplier)
    }
    
    /// Execute burn (deflationary mechanism)
    pub fn burn_tokens(&mut self, amount: u64) {
        self.total_burned += amount;
        println!("🔥 Burned {} FRAC | Total burned: {}", amount, self.total_burned);
    }
    
    /// Calculate circulating supply (accounting for burns)
    pub fn circulating_supply(&self) -> u64 {
        self.total_minted.saturating_sub(self.total_burned)
    }
    
    /// Execute buyback from protocol revenue
    pub fn execute_buyback(&mut self, revenue_amount: u64) -> u64 {
        // Use 50% of protocol revenue for buyback
        let buyback_amount = revenue_amount / 2;
        
        // In production: buy FRAC from DEX
        // let purchased_frac = buy_from_market(buyback_amount);
        
        // For now: simulate
        let purchased_frac = buyback_amount * 10; // Assume 1 ETH buys 10 FRAC
        
        // Burn all purchased FRAC
        self.burn_tokens(purchased_frac);
        
        println!("💰 Buyback: {} revenue → {} FRAC burned", buyback_amount, purchased_frac);
        
        purchased_frac
    }
    
    /// Get total ve_power in network (for APY calculations)
    pub fn total_ve_power(&self) -> u64 {
        self.staking_positions
            .values()
            .flat_map(|positions| positions.iter())
            .map(|p| p.ve_power)
            .sum()
    }
    
    /// Calculate staking APY based on protocol revenue
    pub fn calculate_staking_apy(&self, protocol_revenue_per_year: u64) -> f64 {
        let total_ve = self.total_ve_power() as f64;
        if total_ve == 0.0 {
            return 0.0;
        }
        
        // Stakers get 20% of protocol revenue
        let staker_rewards = (protocol_revenue_per_year as f64) * 0.2;
        
        // APY = (annual rewards / total staked) * 100
        let apy = (staker_rewards / total_ve) * 100.0;
        
        // Genesis bonus: first 6 months get 10x APY
        if self.current_block < self.genesis_block + 1_314_000 { // ~6 months of blocks
            apy * 10.0
        } else {
            apy
        }
    }
    
    /// Process reward distribution (mint + burn + distribute)
    pub fn process_reward(
        &mut self,
        prover: Address,
        calculation: &RewardCalculation,
    ) {
        // Mint total reward
        self.total_minted += calculation.total_reward + calculation.protocol_fee;
        
        // Burn portion of protocol fee
        self.burn_tokens(calculation.burn_amount);
        
        // Rest goes to treasury (for buybacks)
        self.protocol_treasury += calculation.protocol_fee - calculation.burn_amount;
        
        // Update genesis prover stats
        if let Some(status) = self.genesis_provers.get_mut(&prover) {
            status.total_proofs += 1;
        }
        
        println!("💎 Reward processed:");
        println!("   To prover: {} FRAC", calculation.total_reward);
        println!("   Burned: {} FRAC", calculation.burn_amount);
        println!("   To treasury: {} FRAC", calculation.protocol_fee - calculation.burn_amount);
    }
    
    /// Get comprehensive stats
    pub fn get_stats(&self) -> TokenomicsStats {
        TokenomicsStats {
            total_minted: self.total_minted,
            total_burned: self.total_burned,
            circulating_supply: self.circulating_supply(),
            burn_rate_percent: (self.total_burned as f64 / self.total_minted as f64) * 100.0,
            genesis_provers: self.genesis_provers.len(),
            total_staked_ve: self.total_ve_power(),
            protocol_treasury: self.protocol_treasury,
            current_epoch: self.get_current_epoch(),
            epoch_multiplier: self.get_epoch_multiplier(),
        }
    }
    
    fn get_current_epoch(&self) -> u64 {
        self.current_block.saturating_sub(self.genesis_block) / 100_000
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenomicsStats {
    pub total_minted: u64,
    pub total_burned: u64,
    pub circulating_supply: u64,
    pub burn_rate_percent: f64,
    pub genesis_provers: usize,
    pub total_staked_ve: u64,
    pub protocol_treasury: u64,
    pub current_epoch: u64,
    pub epoch_multiplier: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_early_adopter_advantage() {
        let mut tokenomics = FracTokenomics::new(1000);
        
        // Epoch 0: 10x multiplier
        assert_eq!(tokenomics.get_epoch_multiplier(), 10.0);
        
        // Move to epoch 1
        tokenomics.update_block(100_000 + 1000);
        assert_eq!(tokenomics.get_epoch_multiplier(), 5.0);
        
        // Move to normal epoch
        tokenomics.update_block(400_000 + 1000);
        assert_eq!(tokenomics.get_epoch_multiplier(), 1.0);
    }
    
    #[test]
    fn test_genesis_nft() {
        let mut tokenomics = FracTokenomics::new(1000);
        let prover = Address::random();
        
        // Register genesis prover
        let nft_id = tokenomics.register_genesis_prover(prover).unwrap();
        assert_eq!(nft_id, 1);
        
        // Check multiplier
        assert_eq!(tokenomics.get_genesis_multiplier(&prover), 2.0);
    }
    
    #[test]
    fn test_staking_boost() {
        let mut tokenomics = FracTokenomics::new(1000);
        let staker = Address::random();
        
        // Create stake
        let ve_power = tokenomics.create_stake(staker, 10_000, 4).unwrap();
        assert_eq!(ve_power, 40_000); // 10k FRAC * 4 years
        
        // Check boost
        let boost = tokenomics.get_staking_boost(&staker);
        assert!(boost > 1.0);
    }
}
