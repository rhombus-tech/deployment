// FRAC Token Payment System
// Handles on-chain FRAC rewards for provers
// Trustless: Uses resilient RPC with multiple fallbacks

use super::topology::ProverID;
use super::resilient_rpc::ResilientRpcProvider;
use ethers::prelude::*;
use ethers::providers::{Provider, Http};
use ethers::contract::abigen;
use ethereum_types::Address as EthAddress;
use std::sync::Arc;
use anyhow::{Result, Context};

// Generate contract bindings
abigen!(
    FracRewardContract,
    r#"[
        function mintReward(address prover, uint256 amount) external
        function claimReward() external
        function getPendingRewards(address prover) external view returns (uint256)
        function totalMinted() external view returns (uint256)
        event RewardMinted(address indexed prover, uint256 amount, uint256 timestamp)
    ]"#,
);

/// FRAC token payment handler
/// Manages on-chain reward distribution
/// Trustless: No single RPC point of failure
pub struct FracPaymentSystem {
    /// Resilient RPC provider (multiple endpoints, auto-failover)
    rpc_provider: Arc<ResilientRpcProvider>,
    
    /// FRAC reward contract
    reward_contract: Option<EthAddress>,
    
    /// Private key for signing transactions (optional)
    signer: Option<LocalWallet>,
    
    /// Payment queue for batching
    payment_queue: Arc<tokio::sync::RwLock<Vec<PendingPayment>>>,
    
    /// Transaction cache to avoid duplicates
    processed_txs: Arc<tokio::sync::RwLock<std::collections::HashSet<String>>>,
}

#[derive(Clone, Debug)]
pub struct PendingPayment {
    pub prover: ProverID,
    pub reward: u64,
    pub task_id: String,
    pub timestamp: u64,
    pub retry_count: u8,
}

#[derive(Clone, Debug)]
pub struct PaymentReceipt {
    pub transaction_hash: String,
    pub block_number: u64,
    pub gas_used: u64,
    pub prover: ProverID,
    pub amount: u64,
    pub timestamp: u64,
}

impl FracPaymentSystem {
    /// Create new payment system with resilient RPC
    /// Trustless: Automatically uses multiple RPC endpoints
    pub async fn new(
        reward_contract: Option<EthAddress>,
        private_key: Option<&str>,
    ) -> Result<Self> {
        // Create resilient RPC provider (handles multiple endpoints)
        let rpc_provider = Arc::new(ResilientRpcProvider::new());
        
        println!("🌐 Initialized resilient RPC provider");
        if rpc_provider.has_local_node().await {
            println!("   ✅ Local node available (MOST trustless!)");
        } else {
            println!("   ℹ️  Using public RPCs (consider running local node)");
        }
        
        let signer = if let Some(key) = private_key {
            Some(key.parse::<LocalWallet>()
                .context("Failed to parse private key")?)
        } else {
            None
        };
        
        Ok(Self {
            rpc_provider,
            reward_contract,
            signer,
            payment_queue: Arc::new(tokio::sync::RwLock::new(Vec::new())),
            processed_txs: Arc::new(tokio::sync::RwLock::new(std::collections::HashSet::new())),
        })
    }
    
    /// Add custom RPC endpoint
    /// Trustless: Users can add their own nodes
    pub async fn add_rpc_endpoint(&self, url: String, is_local: bool) {
        self.rpc_provider.add_endpoint(url, is_local).await;
    }
    
    /// Pay reward immediately (single transaction)
    pub async fn pay_immediately(
        &self,
        prover: ProverID,
        reward: u64,
        task_id: String,
    ) -> Result<PaymentReceipt> {
        println!("💰 Initiating immediate payment: {} FRAC to {:?}", reward, prover);
        
        // Check if already processed
        let tx_key = format!("{}-{}", task_id, prover.0);
        {
            let processed = self.processed_txs.read().await;
            if processed.contains(&tx_key) {
                return Err(anyhow::anyhow!("Payment already processed"));
            }
        }
        
        // Verify we have what we need
        let contract_addr = self.reward_contract
            .ok_or_else(|| anyhow::anyhow!("Reward contract not configured"))?;
        
        let signer = self.signer.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Signer not configured"))?;
        
        // Parse prover address from ProverID
        let prover_addr = Self::prover_id_to_address(&prover)?;
        
        // Get resilient provider (auto-selects best RPC endpoint)
        let provider = self.rpc_provider.get_provider().await?;
        
        // Create contract instance with resilient provider
        let client = Arc::new(SignerMiddleware::new(provider, signer.clone()));
        let contract = FracRewardContract::new(contract_addr, client);
        
        // Call mintReward with automatic retry on failure
        println!("   📤 Submitting transaction to blockchain...");
        let pending_tx = contract.mint_reward(prover_addr, U256::from(reward));
        let tx = pending_tx
            .send()
            .await
            .context("Failed to send transaction")?;
        
        println!("   ⏳ Transaction submitted: {:?}", tx.tx_hash());
        
        // Wait for confirmation
        let receipt = tx.await
            .context("Transaction failed")?
            .ok_or_else(|| anyhow::anyhow!("No receipt"))?;
        
        println!("   ✅ Payment confirmed in block {}", receipt.block_number.unwrap_or_default());
        
        // Mark as processed
        self.processed_txs.write().await.insert(tx_key);
        
        Ok(PaymentReceipt {
            transaction_hash: format!("{:?}", receipt.transaction_hash),
            block_number: receipt.block_number.unwrap_or_default().as_u64(),
            gas_used: receipt.gas_used.unwrap_or_default().as_u64(),
            prover,
            amount: reward,
            timestamp: Self::current_timestamp(),
        })
    }
    
    /// Queue payment for batch processing
    pub async fn queue_payment(
        &self,
        prover: ProverID,
        reward: u64,
        task_id: String,
    ) -> Result<()> {
        println!("📦 Queuing payment: {} FRAC to {:?}", reward, prover);
        
        let payment = PendingPayment {
            prover,
            reward,
            task_id,
            timestamp: Self::current_timestamp(),
            retry_count: 0,
        };
        
        self.payment_queue.write().await.push(payment);
        
        Ok(())
    }
    
    /// Process batch of payments
    pub async fn process_batch(&self) -> Result<Vec<PaymentReceipt>> {
        let mut queue = self.payment_queue.write().await;
        
        if queue.is_empty() {
            return Ok(Vec::new());
        }
        
        println!("🔄 Processing batch of {} payments...", queue.len());
        
        let mut receipts = Vec::new();
        let payments: Vec<_> = queue.drain(..).collect();
        
        for payment in payments {
            match self.pay_immediately(
                payment.prover.clone(),
                payment.reward,
                payment.task_id.clone(),
            ).await {
                Ok(receipt) => {
                    receipts.push(receipt);
                }
                Err(e) => {
                    eprintln!("❌ Payment failed: {}", e);
                    
                    // Re-queue if retries available
                    if payment.retry_count < 3 {
                        let mut retry = payment.clone();
                        retry.retry_count += 1;
                        queue.push(retry);
                    }
                }
            }
        }
        
        println!("✅ Batch processing complete: {} payments successful", receipts.len());
        
        Ok(receipts)
    }
    
    /// Check pending rewards for a prover
    pub async fn check_pending_rewards(&self, prover: &ProverID) -> Result<u64> {
        let contract_addr = self.reward_contract
            .ok_or_else(|| anyhow::anyhow!("Reward contract not configured"))?;
        
        let prover_addr = Self::prover_id_to_address(prover)?;
        
        // Use resilient provider for queries
        let provider = self.rpc_provider.get_provider().await?;
        
        let contract = FracRewardContract::new(
            contract_addr,
            provider,
        );
        
        let pending = contract
            .get_pending_rewards(prover_addr)
            .call()
            .await
            .context("Failed to query pending rewards")?;
        
        Ok(pending.as_u64())
    }
    
    /// Get total FRAC minted
    pub async fn get_total_minted(&self) -> Result<u64> {
        let contract_addr = self.reward_contract
            .ok_or_else(|| anyhow::anyhow!("Reward contract not configured"))?;
        
        // Use resilient provider
        let provider = self.rpc_provider.get_provider().await?;
        
        let contract = FracRewardContract::new(
            contract_addr,
            provider,
        );
        
        let total = contract
            .total_minted()
            .call()
            .await
            .context("Failed to query total minted")?;
        
        Ok(total.as_u64())
    }
    
    /// Convert ProverID to Ethereum address
    fn prover_id_to_address(prover: &ProverID) -> Result<H160> {
        // Extract address from prover ID
        // Format: "prover_<hex_address>"
        let addr_str = prover.0
            .strip_prefix("prover_")
            .ok_or_else(|| anyhow::anyhow!("Invalid prover ID format"))?;
        
        // If it's a full address, parse it
        if addr_str.starts_with("0x") {
            return addr_str.parse::<H160>()
                .context("Failed to parse address");
        }
        
        // Otherwise, pad it to 20 bytes
        let mut bytes = [0u8; 20];
        let hex_bytes = hex::decode(addr_str)
            .context("Failed to decode prover ID")?;
        
        let copy_len = hex_bytes.len().min(20);
        bytes[20 - copy_len..].copy_from_slice(&hex_bytes[..copy_len]);
        
        Ok(H160::from(bytes))
    }
    
    fn current_timestamp() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

/// Payment strategy for reward distribution
#[derive(Clone, Debug)]
pub enum PaymentStrategy {
    /// Pay immediately on proof submission (fast, good for small provers)
    Immediate,
    
    /// Pay after confirmation (safer, slight delay)
    Confirmed { confirmations: u64 },
    
    /// Batch payments (gas efficient, periodic)
    Batched { max_batch_size: usize, interval_seconds: u64 },
}

impl PaymentStrategy {
    pub fn default_immediate() -> Self {
        Self::Immediate
    }
    
    pub fn default_batched() -> Self {
        Self::Batched {
            max_batch_size: 10,
            interval_seconds: 300, // 5 minutes
        }
    }
    
    pub fn default_confirmed() -> Self {
        Self::Confirmed {
            confirmations: 3,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_prover_id_to_address() {
        let prover = ProverID("prover_1234567890abcdef".to_string());
        let result = FracPaymentSystem::prover_id_to_address(&prover);
        assert!(result.is_ok());
    }
    
    #[tokio::test]
    async fn test_payment_queue() {
        let system = FracPaymentSystem::new(
            "http://localhost:8545",
            None,
            None,
        ).await.unwrap();
        
        let prover = ProverID("test_prover".to_string());
        
        // Queue should start empty
        let queue = system.payment_queue.read().await;
        assert_eq!(queue.len(), 0);
    }
}
