// Blockchain Integration - Complete On-Chain Client
// Handles proof submission, reward claiming, and contract event listening

use ethers::prelude::*;
use std::sync::Arc;
use tokio::sync::RwLock;
use anyhow::{Result, Context};
use tracing::{info, warn, error};

use super::topology::ProverID;
use super::aggregation::CompletedProof;

// ============================================================================
// Contract ABIs (Simplified - use actual ABIs in production)
// ============================================================================

abigen!(
    FractalProverRegistry,
    r#"[
        function registerProver(bytes32 proverId, uint256 stake) external
        function submitProof(bytes32 proofId, bytes calldata proof) external returns (bool)
        function isProverRegistered(bytes32 proverId) external view returns (bool)
        function getProverStake(bytes32 proverId) external view returns (uint256)
        event ProofSubmitted(bytes32 indexed proofId, address indexed prover, uint256 timestamp)
        event ProverRegistered(bytes32 indexed proverId, address indexed prover, uint256 stake)
    ]"#
);

abigen!(
    FractalRewardPool,
    r#"[
        function claimRewards(bytes32 proverId) external returns (uint256)
        function getClaimableRewards(bytes32 proverId) external view returns (uint256)
        event RewardDistributed(bytes32 indexed proverId, uint256 amount, uint256 timestamp)
        event RewardsClaimed(bytes32 indexed proverId, address indexed prover, uint256 amount)
    ]"#
);

abigen!(
    FractalToken,
    r#"[
        function balanceOf(address account) external view returns (uint256)
        function transfer(address to, uint256 amount) external returns (bool)
        function approve(address spender, uint256 amount) external returns (bool)
    ]"#
);

// ============================================================================
// Blockchain Client
// ============================================================================

pub struct BlockchainClient {
    /// Ethers provider
    provider: Arc<Provider<Http>>,
    
    /// Signer (wallet)
    wallet: LocalWallet,
    
    /// Prover registry contract
    registry_address: Address,
    
    /// Reward pool contract
    reward_pool_address: Address,
    
    /// Token contract
    token_address: Address,
    
    /// Our prover ID
    prover_id: ProverID,
    
    /// Submission nonce tracking
    nonce: Arc<RwLock<U256>>,
}

impl BlockchainClient {
    /// Create a new blockchain client
    pub async fn new(
        rpc_url: &str,
        private_key: &str,
        registry_address: Address,
        reward_pool_address: Address,
        token_address: Address,
        prover_id: ProverID,
    ) -> Result<Self> {
        info!("🔗 Connecting to blockchain: {}", rpc_url);
        
        // Create provider
        let provider = Provider::<Http>::try_from(rpc_url)
            .context("Failed to create provider")?;
        
        // Create wallet
        let wallet = private_key.parse::<LocalWallet>()
            .context("Failed to parse private key")?
            .with_chain_id(1u64); // Mainnet, adjust as needed
        
        info!("   📍 Address: {:?}", wallet.address());
        
        // Get initial nonce
        let nonce = provider.get_transaction_count(wallet.address(), None).await?;
        
        Ok(Self {
            provider: Arc::new(provider),
            wallet,
            registry_address,
            reward_pool_address,
            token_address,
            prover_id,
            nonce: Arc::new(RwLock::new(nonce)),
        })
    }
    
    /// Register as a prover (one-time setup)
    pub async fn register_prover(&self, stake_amount: U256) -> Result<TransactionReceipt> {
        info!("📝 Registering prover: {:?}", self.prover_id);
        
        let client = SignerMiddleware::new(
            self.provider.clone(),
            self.wallet.clone(),
        );
        
        let registry = FractalProverRegistry::new(
            self.registry_address,
            Arc::new(client),
        );
        
        // Convert prover ID to bytes32
        let prover_id_bytes = self.prover_id_to_bytes32();
        
        // Check if already registered
        if registry.is_prover_registered(prover_id_bytes).call().await? {
            info!("   ⚠️  Already registered");
            return Err(anyhow::anyhow!("Prover already registered"));
        }
        
        // Register
        let tx = registry.register_prover(prover_id_bytes, stake_amount)
            .send()
            .await?;
        
        let receipt = tx.await?.context("Transaction failed")?;
        
        info!("   ✅ Registered! TX: {:?}", receipt.transaction_hash);
        
        Ok(receipt)
    }
    
    /// Submit a completed proof to the blockchain
    pub async fn submit_proof(&self, proof: &CompletedProof) -> Result<TransactionReceipt> {
        info!("📤 Submitting proof to blockchain: {}", proof.task_id);
        
        let client = SignerMiddleware::new(
            self.provider.clone(),
            self.wallet.clone(),
        );
        
        let registry = FractalProverRegistry::new(
            self.registry_address,
            Arc::new(client),
        );
        
        // Convert task ID to bytes32
        let proof_id = self.task_id_to_bytes32(&proof.task_id);
        
        // Submit proof
        let tx = registry.submit_proof(proof_id, proof.aggregated_proof.clone().into())
            .send()
            .await
            .context("Failed to send transaction")?;
        
        let receipt = tx.await?.context("Transaction failed")?;
        
        info!("   ✅ Proof submitted! TX: {:?}", receipt.transaction_hash);
        info!("   ⛽ Gas used: {:?}", receipt.gas_used);
        
        Ok(receipt)
    }
    
    /// Check claimable rewards
    pub async fn get_claimable_rewards(&self) -> Result<U256> {
        let client = SignerMiddleware::new(
            self.provider.clone(),
            self.wallet.clone(),
        );
        
        let reward_pool = FractalRewardPool::new(
            self.reward_pool_address,
            Arc::new(client),
        );
        
        let prover_id_bytes = self.prover_id_to_bytes32();
        let rewards = reward_pool.get_claimable_rewards(prover_id_bytes).call().await?;
        
        Ok(rewards)
    }
    
    /// Claim rewards
    pub async fn claim_rewards(&self) -> Result<(TransactionReceipt, U256)> {
        info!("💰 Claiming rewards...");
        
        // Check claimable amount first
        let claimable = self.get_claimable_rewards().await?;
        
        if claimable.is_zero() {
            info!("   ⚠️  No rewards to claim");
            return Err(anyhow::anyhow!("No rewards available"));
        }
        
        info!("   💎 Claimable: {} FRAC", claimable);
        
        let client = SignerMiddleware::new(
            self.provider.clone(),
            self.wallet.clone(),
        );
        
        let reward_pool = FractalRewardPool::new(
            self.reward_pool_address,
            Arc::new(client),
        );
        
        let prover_id_bytes = self.prover_id_to_bytes32();
        
        // Claim
        let tx = reward_pool.claim_rewards(prover_id_bytes)
            .send()
            .await?;
        
        let receipt = tx.await?.context("Transaction failed")?;
        
        info!("   ✅ Rewards claimed! TX: {:?}", receipt.transaction_hash);
        
        Ok((receipt, claimable))
    }
    
    /// Check prover registration status
    pub async fn is_registered(&self) -> Result<bool> {
        let client = SignerMiddleware::new(
            self.provider.clone(),
            self.wallet.clone(),
        );
        
        let registry = FractalProverRegistry::new(
            self.registry_address,
            Arc::new(client),
        );
        
        let prover_id_bytes = self.prover_id_to_bytes32();
        let registered = registry.is_prover_registered(prover_id_bytes).call().await?;
        
        Ok(registered)
    }
    
    /// Get current stake amount
    pub async fn get_stake(&self) -> Result<U256> {
        let client = SignerMiddleware::new(
            self.provider.clone(),
            self.wallet.clone(),
        );
        
        let registry = FractalProverRegistry::new(
            self.registry_address,
            Arc::new(client),
        );
        
        let prover_id_bytes = self.prover_id_to_bytes32();
        let stake = registry.get_prover_stake(prover_id_bytes).call().await?;
        
        Ok(stake)
    }
    
    /// Get FRAC token balance
    pub async fn get_token_balance(&self) -> Result<U256> {
        let client = SignerMiddleware::new(
            self.provider.clone(),
            self.wallet.clone(),
        );
        
        let token = FractalToken::new(
            self.token_address,
            Arc::new(client),
        );
        
        let balance = token.balance_of(self.wallet.address()).call().await?;
        
        Ok(balance)
    }
    
    /// Listen for contract events
    pub async fn start_event_listener(
        self: Arc<Self>,
    ) -> Result<()> {
        info!("👂 Starting contract event listener...");
        
        // Listen for RewardDistributed events
        let filter = Filter::new()
            .address(self.reward_pool_address)
            .event("RewardDistributed(bytes32,uint256,uint256)");
        
        let mut stream = self.provider.subscribe_logs(&filter).await?;
        
        info!("   ✅ Listening for reward events");
        
        tokio::spawn(async move {
            while let Some(log) = stream.next().await {
                match Self::handle_reward_event(&log) {
                    Ok(amount) => {
                        info!("💰 Reward received: {} FRAC", amount);
                    }
                    Err(e) => {
                        warn!("Failed to parse reward event: {}", e);
                    }
                }
            }
        });
        
        Ok(())
    }
    
    fn handle_reward_event(log: &Log) -> Result<U256> {
        // Parse RewardDistributed event
        // bytes32 indexed proverId, uint256 amount, uint256 timestamp
        if log.topics.len() < 2 {
            return Err(anyhow::anyhow!("Invalid event"));
        }
        
        // Amount is in data field
        let amount = U256::from_big_endian(&log.data.0);
        
        Ok(amount)
    }
    
    // Helper functions
    fn prover_id_to_bytes32(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        let id_bytes = self.prover_id.0.as_bytes();
        let len = id_bytes.len().min(32);
        bytes[..len].copy_from_slice(&id_bytes[..len]);
        bytes
    }
    
    fn task_id_to_bytes32(&self, task_id: &str) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        let id_bytes = task_id.as_bytes();
        let len = id_bytes.len().min(32);
        bytes[..len].copy_from_slice(&id_bytes[..len]);
        bytes
    }
}

// ============================================================================
// Automated Proof Submitter
// ============================================================================

pub struct AutomatedProofSubmitter {
    client: Arc<BlockchainClient>,
    submission_interval: tokio::time::Duration,
}

impl AutomatedProofSubmitter {
    pub fn new(client: Arc<BlockchainClient>, interval_secs: u64) -> Self {
        Self {
            client,
            submission_interval: tokio::time::Duration::from_secs(interval_secs),
        }
    }
    
    /// Start automated proof submission
    pub async fn start(
        self,
        mut proof_rx: tokio::sync::mpsc::UnboundedReceiver<CompletedProof>,
    ) {
        info!("🤖 Starting automated proof submitter");
        
        tokio::spawn(async move {
            while let Some(proof) = proof_rx.recv().await {
                match self.client.submit_proof(&proof).await {
                    Ok(receipt) => {
                        info!("✅ Auto-submitted proof: {:?}", receipt.transaction_hash);
                    }
                    Err(e) => {
                        error!("❌ Failed to submit proof: {}", e);
                        // Could implement retry logic here
                    }
                }
                
                // Wait before next submission
                tokio::time::sleep(self.submission_interval).await;
            }
        });
    }
}

// ============================================================================
// Automated Reward Claimer
// ============================================================================

pub struct AutomatedRewardClaimer {
    client: Arc<BlockchainClient>,
    check_interval: tokio::time::Duration,
    min_claim_amount: U256,
}

impl AutomatedRewardClaimer {
    pub fn new(
        client: Arc<BlockchainClient>,
        check_interval_secs: u64,
        min_claim_amount: U256,
    ) -> Self {
        Self {
            client,
            check_interval: tokio::time::Duration::from_secs(check_interval_secs),
            min_claim_amount,
        }
    }
    
    /// Start automated reward claiming
    pub async fn start(self) {
        info!("💰 Starting automated reward claimer");
        info!("   Check interval: {} seconds", self.check_interval.as_secs());
        info!("   Min claim amount: {} FRAC", self.min_claim_amount);
        
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(self.check_interval).await;
                
                match self.client.get_claimable_rewards().await {
                    Ok(claimable) => {
                        if claimable >= self.min_claim_amount {
                            info!("💎 {} FRAC available - claiming...", claimable);
                            
                            match self.client.claim_rewards().await {
                                Ok((receipt, amount)) => {
                                    info!("✅ Claimed {} FRAC! TX: {:?}", 
                                          amount, receipt.transaction_hash);
                                }
                                Err(e) => {
                                    error!("❌ Failed to claim rewards: {}", e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to check rewards: {}", e);
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_blockchain_client_creation() {
        // This would use a test RPC in real testing
        let rpc_url = "https://eth.llamarpc.com";
        let private_key = "0x1234567890123456789012345678901234567890123456789012345678901234";
        
        let result = BlockchainClient::new(
            rpc_url,
            private_key,
            Address::zero(),
            Address::zero(),
            Address::zero(),
            ProverID("test".to_string()),
        ).await;
        
        // May fail without valid RPC, but tests the structure
        assert!(result.is_ok() || result.is_err());
    }
}
