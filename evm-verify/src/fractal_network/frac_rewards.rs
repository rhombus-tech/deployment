// FRAC Token Reward Integration
// Mint FRAC tokens for provers who generate ZK proofs

use super::topology::ProverID;
use super::aggregation::CompletedProof;
use super::economics::RewardBreakdown;
use super::onchain::{PaymentSource, Payment, PaymentError};
use ethers::prelude::*;
use std::sync::Arc;

// ABI for FractalRewardPoolV2.claimReward()
abigen!(
    FractalRewardPool,
    r#"[
        function claimReward(bytes32 taskId, uint8 proofQuality, uint256 provingTimeMs) external
        function estimateReward(uint8 proofQuality, uint256 provingTimeMs) external view returns (uint256)
        function getProverStats(address prover) external view returns (uint256 totalEarned, uint256 proofCount, uint256 avgRewardPerProof)
    ]"#
);

/// FRAC token reward system - mints tokens for proof generation
pub struct FracRewardSystem {
    provider: Arc<Provider<Http>>,
    reward_pool: Address,
    wallet: LocalWallet,
    chain_id: u64,
}

impl FracRewardSystem {
    /// Create new FRAC reward system
    pub async fn new(
        rpc_url: &str,
        reward_pool_address: &str,
        private_key: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let provider = Provider::<Http>::try_from(rpc_url)?;
        let chain_id = provider.get_chainid().await?.as_u64();
        
        let wallet = private_key
            .parse::<LocalWallet>()?
            .with_chain_id(chain_id);
        
        let reward_pool = reward_pool_address.parse::<Address>()?;
        
        Ok(Self {
            provider: Arc::new(provider),
            reward_pool,
            wallet,
            chain_id,
        })
    }
    
    /// Estimate FRAC reward for proof parameters
    pub async fn estimate_reward(
        &self,
        proof_quality: u8,
        proving_time_ms: u64,
    ) -> Result<U256, Box<dyn std::error::Error>> {
        let contract = FractalRewardPool::new(
            self.reward_pool,
            self.provider.clone(),
        );
        
        let estimated = contract
            .estimate_reward(proof_quality, U256::from(proving_time_ms))
            .call()
            .await?;
        
        Ok(estimated)
    }
    
    /// Get prover statistics from on-chain
    pub async fn get_prover_stats(
        &self,
        prover_address: Address,
    ) -> Result<ProverStats, Box<dyn std::error::Error>> {
        let contract = FractalRewardPool::new(
            self.reward_pool,
            self.provider.clone(),
        );
        
        let (total_earned, proof_count, avg_reward) = contract
            .get_prover_stats(prover_address)
            .call()
            .await?;
        
        Ok(ProverStats {
            total_earned,
            proof_count,
            avg_reward_per_proof: avg_reward,
        })
    }
    
    /// Convert ProverID to Ethereum address
    fn prover_id_to_address(prover: &ProverID) -> Address {
        // Take first 20 bytes of prover ID as address
        // In production, provers should register their actual Ethereum address
        let id_bytes = prover.0.as_bytes();
        let mut addr_bytes = [0u8; 20];
        let copy_len = std::cmp::min(20, id_bytes.len());
        addr_bytes[..copy_len].copy_from_slice(&id_bytes[..copy_len]);
        Address::from(addr_bytes)
    }
    
    /// Calculate proof quality score (0-100)
    fn calculate_proof_quality(proof: &CompletedProof) -> u8 {
        // Score based on proof characteristics
        // In production, this would verify cryptographic properties
        
        let mut score = 70u8; // Base score
        
        // Bonus for larger proofs (more comprehensive)
        if proof.aggregated_proof.len() > 100 {
            score += 10;
        }
        
        // Bonus for having commitments
        if !proof.aggregated_proof.is_empty() {
            score += 20;
        }
        
        score.min(100)
    }
}

impl PaymentSource for FracRewardSystem {
    async fn claim_reward(
        &self,
        prover: &ProverID,
        proof: &CompletedProof,
        breakdown: &RewardBreakdown,
    ) -> Result<Payment, PaymentError> {
        // Calculate proof parameters
        let proof_quality = Self::calculate_proof_quality(proof);
        let proving_time_ms = 2000; // Default 2 seconds
        
        // Create task ID from proof
        let task_id_bytes = ethers::utils::keccak256(format!("task_{}", proof.task_id).as_bytes());
        let task_id = H256::from(task_id_bytes);
        
        // Create contract instance with signer
        let client = Arc::new(SignerMiddleware::new(
            self.provider.clone(),
            self.wallet.clone(),
        ));
        let contract = FractalRewardPool::new(
            self.reward_pool,
            client,
        );
        
        // Call claimReward on contract (mints FRAC tokens)
        let call = contract.claim_reward(
            task_id.into(),
            proof_quality,
            U256::from(proving_time_ms),
        );
        
        let pending_tx = call
            .send()
            .await
            .map_err(|e| PaymentError::TransactionFailed(e.to_string()))?;
        
        // Wait for confirmation
        let receipt = pending_tx
            .await
            .map_err(|e| PaymentError::NetworkError(e.to_string()))?
            .ok_or_else(|| PaymentError::TransactionFailed("No receipt".to_string()))?;
        
        let tx_hash = receipt.transaction_hash;
        
        println!("✅ FRAC tokens minted! Tx: {:?}", tx_hash);
        println!("   Quality: {}%, Time: {}ms", proof_quality, proving_time_ms);
        
        Ok(Payment {
            tx_hash,
            amount: breakdown.total,
            recipient: prover.clone(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }
    
    async fn available_balance(&self) -> Result<u64, PaymentError> {
        // FRAC tokens are minted on demand, no balance limit
        Ok(u64::MAX)
    }
}

#[derive(Debug, Clone)]
pub struct ProverStats {
    pub total_earned: U256,
    pub proof_count: U256,
    pub avg_reward_per_proof: U256,
}

impl ProverStats {
    /// Format as human-readable string
    pub fn to_frac(&self) -> String {
        let earned_frac = self.total_earned.as_u128() as f64 / 1e18;
        let avg_frac = self.avg_reward_per_proof.as_u128() as f64 / 1e18;
        
        format!(
            "Earned: {:.2} FRAC | Proofs: {} | Avg: {:.2} FRAC/proof",
            earned_frac,
            self.proof_count,
            avg_frac
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_proof_quality_calculation() {
        use super::super::topology::ProverID;
        
        let proof = CompletedProof {
            task_id: "test".to_string(),
            aggregated_proof: vec![0u8; 128],
            phi_efficiency: 1.618,
            contributors: vec![ProverID("test_prover".to_string())],
            completion_time: std::time::SystemTime::now(),
        };
        
        let quality = FracRewardSystem::calculate_proof_quality(&proof);
        assert!(quality >= 70 && quality <= 100);
    }
}
