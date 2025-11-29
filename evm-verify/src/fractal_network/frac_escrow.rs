// FRAC Token Escrow - Trustless Payment
// Trustless Manifesto: Economic security without trust

use ethers::{
    contract::abigen,
    core::types::{Address, U256, H256},
    providers::{Provider, Http, Middleware},
    signers::{LocalWallet, Signer},
    middleware::SignerMiddleware,
};
use std::sync::Arc;
use serde::{Serialize, Deserialize};

abigen!(
    FRACEscrow,
    r#"[
        function lockReward(bytes32 taskId, uint256 amount) external payable returns (bool)
        function releaseToProver(bytes32 taskId, address prover) external returns (bool)
        function refundSubmitter(bytes32 taskId) external returns (bool)
        function getEscrowStatus(bytes32 taskId) external view returns (uint256 amount, address submitter, bool locked, bool released)
    ]"#
);

#[derive(Clone)]
pub struct FRACEscrowManager {
    provider: Arc<Provider<Http>>,
    contract_address: Address,
    chain_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscrowStatus {
    pub amount: U256,
    pub submitter: Address,
    pub locked: bool,
    pub released: bool,
}

impl FRACEscrowManager {
    pub fn new(rpc_url: &str, contract_address: Address, chain_id: u64) -> Result<Self, String> {
        let provider = Provider::<Http>::try_from(rpc_url)
            .map_err(|e| format!("Failed to connect: {}", e))?;
        
        Ok(Self {
            provider: Arc::new(provider),
            contract_address,
            chain_id,
        })
    }
    
    /// Lock FRAC tokens in escrow (task submitter)
    pub async fn lock_reward(
        &self,
        task_id: [u8; 32],
        amount: U256,
        wallet: LocalWallet,
    ) -> Result<H256, String> {
        let client = Arc::new(SignerMiddleware::new(
            self.provider.clone(),
            wallet.with_chain_id(self.chain_id),
        ));
        
        let contract = FRACEscrow::new(self.contract_address, client);
        
        let call = contract.lock_reward(task_id, amount).value(amount);
        let pending_tx = call.send().await.map_err(|e| format!("Lock failed: {}", e))?;
        
        let receipt = pending_tx.await.map_err(|e| format!("TX failed: {}", e))?.ok_or("No receipt")?;
        
        Ok(receipt.transaction_hash)
    }
    
    /// Release escrowed tokens to prover (automatic on valid proof)
    pub async fn release_to_prover(
        &self,
        task_id: [u8; 32],
        prover: Address,
        wallet: LocalWallet,
    ) -> Result<H256, String> {
        let client = Arc::new(SignerMiddleware::new(
            self.provider.clone(),
            wallet.with_chain_id(self.chain_id),
        ));
        
        let contract = FRACEscrow::new(self.contract_address, client);
        
        let call = contract.release_to_prover(task_id, prover);
        let pending_tx = call.send().await.map_err(|e| format!("Release failed: {}", e))?;
        
        let receipt = pending_tx.await.map_err(|e| format!("TX failed: {}", e))?.ok_or("No receipt")?;
        
        Ok(receipt.transaction_hash)
    }
    
    /// Check escrow status (anyone can verify)
    pub async fn get_status(&self, task_id: [u8; 32]) -> Result<EscrowStatus, String> {
        let contract = FRACEscrow::new(self.contract_address, self.provider.clone());
        
        let (amount, submitter, locked, released) = contract
            .get_escrow_status(task_id)
            .call()
            .await
            .map_err(|e| format!("Status check failed: {}", e))?;
        
        Ok(EscrowStatus {
            amount,
            submitter,
            locked,
            released,
        })
    }
}
