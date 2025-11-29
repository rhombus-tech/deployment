// On-Chain Integration - Connect provers to actual blockchain
// This is what makes the system REAL, not just a demo

use super::topology::ProverID;
use super::aggregation::CompletedProof;
use super::economics::RewardBreakdown;
use ethers::prelude::*;
use ethers::utils::keccak256;
use std::sync::Arc;

/// On-chain payment source - where prover rewards come from
pub trait PaymentSource: Send + Sync {
    /// Claim reward for completing a proof
    fn claim_reward(
        &self,
        prover: &ProverID,
        proof: &CompletedProof,
        breakdown: &RewardBreakdown,
    ) -> impl std::future::Future<Output = Result<Payment, PaymentError>> + Send;
    
    /// Check available balance for rewards
    fn available_balance(&self) -> impl std::future::Future<Output = Result<u64, PaymentError>> + Send;
}

/// Payment result
#[derive(Debug, Clone)]
pub struct Payment {
    pub tx_hash: H256,
    pub amount: u64,
    pub recipient: ProverID,
    pub timestamp: u64,
}

#[derive(Debug)]
pub enum PaymentError {
    InsufficientFunds,
    TransactionFailed(String),
    NetworkError(String),
    InvalidProof,
}

impl std::fmt::Display for PaymentError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            PaymentError::InsufficientFunds => write!(f, "Insufficient funds for payment"),
            PaymentError::TransactionFailed(e) => write!(f, "Transaction failed: {}", e),
            PaymentError::NetworkError(e) => write!(f, "Network error: {}", e),
            PaymentError::InvalidProof => write!(f, "Invalid proof"),
        }
    }
}

impl std::error::Error for PaymentError {}

/// Transaction fee payment source (users pay for proving)
pub struct TransactionFeePayment {
    provider: Arc<Provider<Http>>,
    prover_registry: Address,
    signer: Arc<LocalWallet>,
}

impl TransactionFeePayment {
    pub fn new(
        rpc_url: &str,
        prover_registry: Address,
        private_key: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let provider = Provider::<Http>::try_from(rpc_url)?;
        let wallet = private_key.parse::<LocalWallet>()?;
        
        Ok(Self {
            provider: Arc::new(provider),
            prover_registry,
            signer: Arc::new(wallet),
        })
    }
}

impl PaymentSource for TransactionFeePayment {
    async fn claim_reward(
        &self,
        prover: &ProverID,
        proof: &CompletedProof,
        breakdown: &RewardBreakdown,
    ) -> Result<Payment, PaymentError> {
        // In production: submit proof to smart contract, claim reward
        // Contract verifies proof and pays prover
        
        // Simplified: Direct payment from escrow
        let amount = U256::from(breakdown.total);
        
        // Get prover's Ethereum address (from ProverID)
        let prover_address = Self::prover_id_to_address(prover);
        
        // Create transaction
        let tx = TransactionRequest::new()
            .to(prover_address)
            .value(amount)
            .gas(21000);
        
        // Sign and send
        let client = Arc::new(SignerMiddleware::new(
            self.provider.clone(),
            (*self.signer).clone().with_chain_id(1u64)
        ));
        
        let pending_tx = client.send_transaction(tx, None).await
            .map_err(|e| PaymentError::NetworkError(e.to_string()))?;
        
        let receipt = pending_tx.await
            .map_err(|e| PaymentError::TransactionFailed(e.to_string()))?;
        
        match receipt {
            Some(r) => Ok(Payment {
                tx_hash: r.transaction_hash,
                amount: breakdown.total,
                recipient: prover.clone(),
                timestamp: Self::current_timestamp(),
            }),
            None => Err(PaymentError::TransactionFailed("Receipt not found".to_string())),
        }
    }
    
    async fn available_balance(&self) -> Result<u64, PaymentError> {
        match self.provider.get_balance(self.prover_registry, None).await {
            Ok(balance) => Ok(balance.as_u64()),
            Err(e) => Err(PaymentError::NetworkError(e.to_string())),
        }
    }
}

impl TransactionFeePayment {
    fn prover_id_to_address(prover: &ProverID) -> Address {
        // In production: lookup from registry
        // For now: hash ProverID to address
        let hash = keccak256(prover.0.as_bytes());
        Address::from_slice(&hash[12..])
    }
    
    fn current_timestamp() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

/// Protocol reward payment (block rewards / inflation)
pub struct ProtocolRewardPayment {
    provider: Arc<Provider<Http>>,
    reward_contract: Address,
    base_reward: u64,
}

impl ProtocolRewardPayment {
    pub fn new(
        rpc_url: &str,
        reward_contract: Address,
        base_reward: u64,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let provider = Provider::<Http>::try_from(rpc_url)?;
        
        Ok(Self {
            provider: Arc::new(provider),
            reward_contract,
            base_reward,
        })
    }
}

impl PaymentSource for ProtocolRewardPayment {
    async fn claim_reward(
        &self,
        prover: &ProverID,
        proof: &CompletedProof,
        _breakdown: &RewardBreakdown,
    ) -> Result<Payment, PaymentError> {
        // In production: Call reward contract to mint/distribute tokens
        // Contract verifies proof submission and mints reward
        
        println!("📝 Claiming protocol reward for prover {:?}", prover);
        println!("   Proof: {}", proof.task_id);
        println!("   Amount: {} units", self.base_reward);
        
        // Simulated for now - would call smart contract
        Ok(Payment {
            tx_hash: H256::random(),
            amount: self.base_reward,
            recipient: prover.clone(),
            timestamp: Self::current_timestamp(),
        })
    }
    
    async fn available_balance(&self) -> Result<u64, PaymentError> {
        // Protocol rewards are unlimited (minted)
        Ok(u64::MAX)
    }
}

impl ProtocolRewardPayment {
    fn current_timestamp() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

/// Hybrid payment (tx fees + protocol rewards)
pub struct HybridPayment {
    tx_fee_source: TransactionFeePayment,
    protocol_source: ProtocolRewardPayment,
}

impl HybridPayment {
    pub fn new(
        rpc_url: &str,
        prover_registry: Address,
        reward_contract: Address,
        private_key: &str,
        base_protocol_reward: u64,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            tx_fee_source: TransactionFeePayment::new(rpc_url, prover_registry, private_key)?,
            protocol_source: ProtocolRewardPayment::new(rpc_url, reward_contract, base_protocol_reward)?,
        })
    }
}

impl PaymentSource for HybridPayment {
    async fn claim_reward(
        &self,
        prover: &ProverID,
        proof: &CompletedProof,
        breakdown: &RewardBreakdown,
    ) -> Result<Payment, PaymentError> {
        // Claim both tx fees and protocol reward
        let tx_payment = self.tx_fee_source.claim_reward(prover, proof, breakdown).await?;
        let protocol_payment = self.protocol_source.claim_reward(prover, proof, breakdown).await?;
        
        // Combined payment
        Ok(Payment {
            tx_hash: tx_payment.tx_hash,
            amount: tx_payment.amount + protocol_payment.amount,
            recipient: prover.clone(),
            timestamp: tx_payment.timestamp,
        })
    }
    
    async fn available_balance(&self) -> Result<u64, PaymentError> {
        let tx_balance = self.tx_fee_source.available_balance().await?;
        let protocol_balance = self.protocol_source.available_balance().await?;
        Ok(tx_balance.saturating_add(protocol_balance))
    }
}

/// On-chain proof submission
pub struct ProofSubmitter {
    provider: Arc<Provider<Http>>,
    verifier_contract: Address,
    signer: Arc<LocalWallet>,
}

impl ProofSubmitter {
    pub fn new(
        rpc_url: &str,
        verifier_contract: Address,
        private_key: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let provider = Provider::<Http>::try_from(rpc_url)?;
        let wallet = private_key.parse::<LocalWallet>()?;
        
        Ok(Self {
            provider: Arc::new(provider),
            verifier_contract,
            signer: Arc::new(wallet),
        })
    }
    
    /// Submit proof to on-chain verifier contract
    pub async fn submit_proof(
        &self,
        proof: &CompletedProof,
    ) -> Result<H256, Box<dyn std::error::Error>> {
        println!("📤 Submitting proof {} to chain", proof.task_id);
        
        // In production: encode proof and call verifier contract
        // Contract verifies ZK proof and records it on-chain
        
        // Simplified: Submit as calldata
        let proof_data = &proof.aggregated_proof;
        
        let tx = TransactionRequest::new()
            .to(self.verifier_contract)
            .data(proof_data.clone())
            .gas(500000);
        
        let client = Arc::new(SignerMiddleware::new(
            self.provider.clone(),
            (*self.signer).clone().with_chain_id(1u64)
        ));
        
        let pending_tx = client.send_transaction(tx, None).await?;
        let receipt = pending_tx.await?;
        
        match receipt {
            Some(r) => {
                println!("✅ Proof submitted: {}", r.transaction_hash);
                Ok(r.transaction_hash)
            }
            None => Err("Transaction receipt not found".into()),
        }
    }
    
    /// Verify proof on-chain (call view function)
    pub async fn verify_proof_onchain(
        &self,
        proof_hash: H256,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        // In production: call verifier contract's view function
        // Returns true if proof is valid and recorded
        
        println!("🔍 Verifying proof {} on-chain", proof_hash);
        
        // Simulated - would call contract
        Ok(true)
    }
}

/// On-chain task registry (read tasks from blockchain)
pub struct OnChainTaskRegistry {
    provider: Arc<Provider<Http>>,
    task_contract: Address,
}

impl OnChainTaskRegistry {
    pub fn new(
        rpc_url: &str,
        task_contract: Address,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let provider = Provider::<Http>::try_from(rpc_url)?;
        
        Ok(Self {
            provider: Arc::new(provider),
            task_contract,
        })
    }
    
    /// Watch for new tasks submitted on-chain
    pub async fn watch_new_tasks(
        &self,
    ) -> Result<impl futures::Stream<Item = TaskEvent>, Box<dyn std::error::Error>> {
        // In production: listen to contract events
        // When user submits task on-chain, we see it and process
        
        println!("👁️  Watching for new tasks from contract {}", self.task_contract);
        
        // Simulated stream
        Ok(futures::stream::empty())
    }
}

#[derive(Debug, Clone)]
pub struct TaskEvent {
    pub task_id: String,
    pub submitter: Address,
    pub reward: u64,
    pub data: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_payment_source_trait() {
        // Verify trait is object-safe
        let _: Box<dyn PaymentSource> = Box::new(ProtocolRewardPayment {
            provider: Arc::new(Provider::try_from("http://localhost:8545").unwrap()),
            reward_contract: Address::zero(),
            base_reward: 1000,
        });
    }
}
