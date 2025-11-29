// On-Chain Proof Verification
// Trustless Manifesto: "No unverifiable outcomes" - all proofs verified on-chain

use ethers::{
    contract::abigen,
    core::types::{Address, H256, U256, TransactionReceipt},
    providers::{Provider, Http, Middleware},
    signers::{LocalWallet, Signer},
    middleware::SignerMiddleware,
};
use std::sync::Arc;
use serde::{Serialize, Deserialize};

abigen!(
    ProofVerifier,
    r#"[
        function verifyZODAProof(bytes calldata proof, bytes32 taskId) external returns (bool)
        function getProofStatus(bytes32 taskId) external view returns (bool verified, address prover, uint256 timestamp)
        function isProofValid(bytes32 taskId) external view returns (bool)
    ]"#
);

#[derive(Clone)]
pub struct OnChainVerifier {
    provider: Arc<Provider<Http>>,
    contract_address: Address,
    chain_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub verified: bool,
    pub tx_hash: Option<H256>,
    pub block_number: Option<u64>,
    pub gas_used: Option<U256>,
}

impl OnChainVerifier {
    pub fn new(rpc_url: &str, contract_address: Address, chain_id: u64) -> Result<Self, String> {
        let provider = Provider::<Http>::try_from(rpc_url)
            .map_err(|e| format!("Failed to connect to RPC: {}", e))?;
        
        Ok(Self {
            provider: Arc::new(provider),
            contract_address,
            chain_id,
        })
    }
    
    /// Submit proof for on-chain verification (trustless)
    pub async fn verify_proof_onchain(
        &self,
        proof_data: Vec<u8>,
        task_id: [u8; 32],
        wallet: LocalWallet,
    ) -> Result<VerificationResult, String> {
        let client = Arc::new(SignerMiddleware::new(
            self.provider.clone(),
            wallet.with_chain_id(self.chain_id),
        ));
        
        let contract = ProofVerifier::new(self.contract_address, client);
        
        // Submit proof to contract
        let call = contract.verify_zoda_proof(proof_data.into(), task_id);
        let pending_tx = call.send().await.map_err(|e| format!("Failed to send verification tx: {}", e))?;
        
        // Wait for confirmation
        let receipt = pending_tx
            .await
            .map_err(|e| format!("Transaction failed: {}", e))?
            .ok_or("No receipt")?;
        
        Ok(VerificationResult {
            verified: receipt.status == Some(1.into()),
            tx_hash: Some(receipt.transaction_hash),
            block_number: receipt.block_number.map(|n| n.as_u64()),
            gas_used: receipt.gas_used,
        })
    }
    
    /// Check if proof was already verified on-chain (anyone can verify)
    pub async fn check_proof_status(&self, task_id: [u8; 32]) -> Result<bool, String> {
        let contract = ProofVerifier::new(self.contract_address, self.provider.clone());
        
        contract
            .is_proof_valid(task_id)
            .call()
            .await
            .map_err(|e| format!("Failed to check proof status: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_onchain_verification() {
        // Requires local testnet
        // Test on-chain proof verification
    }
}
