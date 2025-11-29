// Bond & Slashing System
// Trustless Manifesto: Economic incentives for honesty

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
    ProverBondManager,
    r#"[
        function registerProver(uint256 bondAmount) external payable returns (bool)
        function slashProver(address prover, bytes32 taskId, bytes calldata evidence) external returns (uint256 slashedAmount)
        function withdrawBond() external returns (uint256)
        function getProverStatus(address prover) external view returns (uint256 bond, bool active, uint256 validProofs, uint256 invalidProofs)
    ]"#
);

const MIN_BOND: u128 = 100 * 1_000_000_000_000_000_000; // 100 FRAC

#[derive(Clone)]
pub struct BondManager {
    provider: Arc<Provider<Http>>,
    contract_address: Address,
    chain_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProverStatus {
    pub bond: U256,
    pub active: bool,
    pub valid_proofs: u64,
    pub invalid_proofs: u64,
    pub reputation_score: f64,
}

impl BondManager {
    pub fn new(rpc_url: &str, contract_address: Address, chain_id: u64) -> Result<Self, String> {
        let provider = Provider::<Http>::try_from(rpc_url)
            .map_err(|e| format!("Connection failed: {}", e))?;
        
        Ok(Self {
            provider: Arc::new(provider),
            contract_address,
            chain_id,
        })
    }
    
    /// Register as prover with bond (economic commitment)
    pub async fn register_prover(
        &self,
        bond_amount: U256,
        wallet: LocalWallet,
    ) -> Result<H256, String> {
        if bond_amount < U256::from(MIN_BOND) {
            return Err(format!("Bond too low, minimum: {} FRAC", MIN_BOND / 1_000_000_000_000_000_000));
        }
        
        let client = Arc::new(SignerMiddleware::new(
            self.provider.clone(),
            wallet.with_chain_id(self.chain_id),
        ));
        
        let contract = ProverBondManager::new(self.contract_address, client);
        
        let call = contract.register_prover(bond_amount).value(bond_amount);
        let pending_tx = call.send().await.map_err(|e| format!("Registration failed: {}", e))?;
        
        let receipt = pending_tx.await.map_err(|e| format!("TX failed: {}", e))?.ok_or("No receipt")?;
        
        Ok(receipt.transaction_hash)
    }
    
    /// Slash prover bond for invalid proof (trustless punishment)
    pub async fn slash_prover(
        &self,
        prover: Address,
        task_id: [u8; 32],
        evidence: Vec<u8>,
        wallet: LocalWallet,
    ) -> Result<(H256, U256), String> {
        let client = Arc::new(SignerMiddleware::new(
            self.provider.clone(),
            wallet.with_chain_id(self.chain_id),
        ));
        
        let contract = ProverBondManager::new(self.contract_address, client.clone());
        
        // Slash the prover
        let call = contract.slash_prover(prover, task_id, evidence.into());
        
        let tx = call
            .send()
            .await
            .map_err(|e| format!("Slash failed: {}", e))?;
        
        let receipt = tx.await.map_err(|e| format!("TX failed: {}", e))?.ok_or("No receipt")?;
        
        // Decode slashed amount from logs
        let slashed_amount = U256::from(0); // Would parse from logs
        
        Ok((receipt.transaction_hash, slashed_amount))
    }
    
    /// Get prover status (anyone can check reputation)
    pub async fn get_prover_status(&self, prover: Address) -> Result<ProverStatus, String> {
        let contract = ProverBondManager::new(self.contract_address, self.provider.clone());
        
        let (bond, active, valid_proofs_u256, invalid_proofs_u256) = contract
            .get_prover_status(prover)
            .call()
            .await
            .map_err(|e| format!("Status check failed: {}", e))?;
        
        let valid_proofs = valid_proofs_u256.as_u64();
        let invalid_proofs = invalid_proofs_u256.as_u64();
        let total_proofs = valid_proofs + invalid_proofs;
        
        let reputation_score = if total_proofs > 0 {
            (valid_proofs as f64) / (total_proofs as f64)
        } else {
            1.0
        };
        
        Ok(ProverStatus {
            bond,
            active,
            valid_proofs,
            invalid_proofs,
            reputation_score,
        })
    }
    
    /// Calculate required bond based on task value
    pub fn calculate_required_bond(task_reward: U256) -> U256 {
        // Bond must be >= 2x task reward (skin in the game)
        task_reward * U256::from(2)
    }
}
