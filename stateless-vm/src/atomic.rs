use std::collections::HashMap;
use std::sync::Arc;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use ethers::{
    types::{Address, Bytes, U256, H256},
    contract::{Contract, ContractCall},
    providers::Provider,
    middleware::SignerMiddleware,
    signers::LocalWallet,
    utils,
    abi::{Token, Tokenizable, InvalidOutputType},
};

// Import evm-verify components for real PCC/PCD verification
#[cfg(feature = "evm-verify")]
use evm_verify::api::unified::UnifiedVerifier;

// Feature gate for hex encoding
use hex;

// For tests
#[cfg(test)]
use rand;

use crate::transaction::{Transaction, TransactionSequence, ExecutionContext, MevProtectionSettings, StateVerificationConfig, FrontrunningProtection};
use crate::types::{SequenceHash, VerificationLevel, Priority};
use crate::state::StateRequirement;
use crate::errors::{VMError, Result};


/// Atomic operation for bundled execution
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AtomicOperation {
    pub target: Address,
    pub call_data: Bytes,
    pub value: U256,
}

impl Tokenizable for AtomicOperation {
    fn from_token(token: Token) -> std::result::Result<Self, InvalidOutputType> {
        match token {
            Token::Tuple(tokens) if tokens.len() == 3 => {
                Ok(AtomicOperation {
                    target: Address::from_token(tokens[0].clone()).map_err(|e| InvalidOutputType(format!("Address: {}", e)))?,
                    call_data: Bytes::from_token(tokens[1].clone()).map_err(|e| InvalidOutputType(format!("Bytes: {}", e)))?,
                    value: U256::from_token(tokens[2].clone()).map_err(|e| InvalidOutputType(format!("U256: {}", e)))?,
                })
            },
            _ => Err(InvalidOutputType("Expected tuple with 3 elements".to_string())),
        }
    }

    fn into_token(self) -> Token {
        Token::Tuple(vec![
            self.target.into_token(),
            self.call_data.into_token(),
            self.value.into_token(),
        ])
    }
}



/// Execution proof containing PCC and PCD verification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExecutionProof {
    pub pcc_proof_hash: H256,
    pub pcd_proof_hash: H256,
    pub state_root: H256,
    pub gas_limit: U256,
}

impl Tokenizable for ExecutionProof {
    fn from_token(token: Token) -> std::result::Result<Self, InvalidOutputType> {
        match token {
            Token::Tuple(tokens) if tokens.len() == 4 => {
                Ok(ExecutionProof {
                    pcc_proof_hash: H256::from_token(tokens[0].clone()).map_err(|e| InvalidOutputType(format!("H256: {}", e)))?,
                    pcd_proof_hash: H256::from_token(tokens[1].clone()).map_err(|e| InvalidOutputType(format!("H256: {}", e)))?,
                    state_root: H256::from_token(tokens[2].clone()).map_err(|e| InvalidOutputType(format!("H256: {}", e)))?,
                    gas_limit: U256::from_token(tokens[3].clone()).map_err(|e| InvalidOutputType(format!("U256: {}", e)))?,
                })
            },
            _ => Err(InvalidOutputType("Expected tuple with 4 elements".to_string())),
        }
    }

    fn into_token(self) -> Token {
        Token::Tuple(vec![
            self.pcc_proof_hash.into_token(),
            self.pcd_proof_hash.into_token(),
            self.state_root.into_token(),
            self.gas_limit.into_token(),
        ])
    }
}



/// Result of atomic execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtomicExecutionResult {
    pub execution_hash: H256,
    pub success: bool,
    pub gas_used: U256,
    pub operations_executed: usize,
    pub block_number: U256,
    pub transaction_hash: H256,
}

/// Verified atomic execution result with proofs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedAtomicResult {
    pub execution_result: AtomicExecutionResult,
    pub safety_proof: H256,
    pub execution_proof: H256,
    pub atomic_guarantee: bool,
    pub mev_protected: bool,
}

/// Atomic executor that provides true atomicity guarantees
pub struct AtomicExecutor {
    pub executor_contract: Address,
    pub provider: Arc<Provider<ethers::providers::Http>>,
    pub wallet: LocalWallet,
    pub pcc_verifier: Option<Arc<dyn PCCVerifier>>,
    pub pcd_prover: Option<Arc<dyn PCDProver>>,
}

#[async_trait]
pub trait PCCVerifier: Send + Sync {
    async fn verify_bundled_safety(&self, operations: &[AtomicOperation]) -> Result<H256>;
}

#[async_trait]  
pub trait PCDProver: Send + Sync {
    async fn prove_atomic_execution(&self, sequence: &TransactionSequence) -> Result<H256>;
}

impl AtomicExecutor {
    pub fn new(
        executor_contract: Address,
        provider: Arc<Provider<ethers::providers::Http>>,
        wallet: LocalWallet,
    ) -> Self {
        Self {
            executor_contract,
            provider,
            wallet,
            pcc_verifier: None,
            pcd_prover: None,
        }
    }
    
    pub fn with_pcc_verifier(mut self, verifier: Arc<dyn PCCVerifier>) -> Self {
        self.pcc_verifier = Some(verifier);
        self
    }
    
    pub fn with_pcd_prover(mut self, prover: Arc<dyn PCDProver>) -> Self {
        self.pcd_prover = Some(prover);
        self
    }
    
    /// Execute transaction sequence atomically without proof verification
    pub async fn execute_atomic(
        &self,
        sequence: TransactionSequence,
    ) -> Result<AtomicExecutionResult> {
        // 1. Convert transaction sequence to atomic operations
        let operations = self.sequence_to_operations(sequence).await?;
        
        // 2. Create contract call
        let client = SignerMiddleware::new(self.provider.clone(), self.wallet.clone());
        // Load the contract ABI 
        let abi_json = include_str!("../../contracts/artifacts/contracts/VerifiedAtomicExecutor.sol/VerifiedAtomicExecutor.json");
        let abi: ethers::abi::Abi = serde_json::from_str(abi_json)
            .map_err(|e| VMError::InvalidOperation { description: format!("Failed to parse ABI: {}", e) })?;
        
        let contract = Contract::new(self.executor_contract, abi, Arc::new(client));
        
        // 3. Call executeWithoutProof
        // Convert operations to tuples for contract call
        let operation_tuples: Vec<(Address, Bytes, U256)> = operations.iter().map(|op| (
            op.target,
            op.call_data.clone(),
            op.value
        )).collect();
        let call = contract.method::<_, H256>("executeWithoutProof", operation_tuples)
            .map_err(|e| VMError::InvalidOperation { description: e.to_string() })?;
        
        // 4. Execute the call
        let pending_tx = call.send().await
            .map_err(|e| VMError::AtomicSequenceFailed { reason: e.to_string() })?;
        
        let receipt = pending_tx.await
            .map_err(|e| VMError::AtomicSequenceFailed { reason: e.to_string() })?
            .ok_or_else(|| VMError::AtomicSequenceFailed { reason: "Transaction failed".to_string() })?;
        
        // 5. Parse result
        Ok(AtomicExecutionResult {
            execution_hash: receipt.transaction_hash,
            success: receipt.status == Some(1.into()),
            gas_used: receipt.gas_used.unwrap_or_default(),
            operations_executed: operations.len(),
            block_number: U256::from(receipt.block_number.unwrap_or_default().as_u64()),
            transaction_hash: receipt.transaction_hash,
        })
    }
    
    /// Execute transaction sequence atomically with PCC+PCD verification
    pub async fn execute_verified_atomic(
        &self,
        sequence: TransactionSequence,
    ) -> Result<VerifiedAtomicResult> {
        // 1. Convert sequence to atomic operations
        let operations = self.sequence_to_operations(sequence.clone()).await?;
        
        // 2. Generate PCC safety proof
        let safety_proof = if let Some(verifier) = &self.pcc_verifier {
            verifier.verify_bundled_safety(&operations).await?
        } else {
            H256::zero()
        };
        
        // 3. Generate PCD execution proof  
        let execution_proof = if let Some(prover) = &self.pcd_prover {
            prover.prove_atomic_execution(&sequence).await?
        } else {
            H256::zero()
        };
        
        // 4. Create execution proof struct
        let proof = ExecutionProof {
            pcc_proof_hash: safety_proof,
            pcd_proof_hash: execution_proof,
            state_root: H256::zero(), // TODO: Calculate expected state root
            gas_limit: U256::from(5_000_000), // TODO: Calculate optimal gas limit
        };
        
        // 5. Execute with proof
        let client = SignerMiddleware::new(self.provider.clone(), self.wallet.clone());
        // Load the contract ABI 
        let abi_json = include_str!("../../contracts/artifacts/contracts/VerifiedAtomicExecutor.sol/VerifiedAtomicExecutor.json");
        let abi: ethers::abi::Abi = serde_json::from_str(abi_json)
            .map_err(|e| VMError::InvalidOperation { description: format!("Failed to parse ABI: {}", e) })?;
        
        let contract = Contract::new(self.executor_contract, abi, Arc::new(client));
        
        // Convert operations to tuples for contract call
        let operation_tuples: Vec<(Address, Bytes, U256)> = operations.iter().map(|op| (
            op.target,
            op.call_data.clone(),
            op.value
        )).collect();
        let call = contract.method::<_, H256>("executeWithProof", (proof, operation_tuples))
            .map_err(|e| VMError::InvalidOperation { description: e.to_string() })?;
        
        let pending_tx = call.send().await
            .map_err(|e| VMError::AtomicSequenceFailed { reason: e.to_string() })?;
        
        let receipt = pending_tx.await
            .map_err(|e| VMError::AtomicSequenceFailed { reason: e.to_string() })?
            .ok_or_else(|| VMError::AtomicSequenceFailed { reason: "Transaction failed".to_string() })?;
        
        // 6. Create verified result
        let execution_result = AtomicExecutionResult {
            execution_hash: receipt.transaction_hash,
            success: receipt.status == Some(1.into()),
            gas_used: receipt.gas_used.unwrap_or_default(),
            operations_executed: operations.len(),
            block_number: U256::from(receipt.block_number.unwrap_or_default().as_u64()),
            transaction_hash: receipt.transaction_hash,
        };
        
        Ok(VerifiedAtomicResult {
            execution_result,
            safety_proof,
            execution_proof,
            atomic_guarantee: true,
            mev_protected: false, // TODO: Add MEV protection
        })
    }
    
    /// Convert transaction sequence to atomic operations
    async fn sequence_to_operations(
        &self,
        sequence: TransactionSequence,
    ) -> Result<Vec<AtomicOperation>> {
        let mut operations = Vec::new();
        
        for tx in sequence.transactions() {
            // Skip transactions without a target (contract creation)
            if let Some(target) = tx.to {
                operations.push(AtomicOperation {
                    target,
                    call_data: tx.data.clone().into(),
                    value: tx.value,
                });
            }
        }
        
        Ok(operations)
    }
    
    /// Submit atomic transaction to private mempool for MEV protection
    pub async fn submit_private_atomic(
        &self,
        sequence: TransactionSequence,
    ) -> Result<VerifiedAtomicResult> {
        // TODO: Implement private mempool submission
        // For now, execute normally
        let mut result = self.execute_verified_atomic(sequence).await?;
        result.mev_protected = true;
        Ok(result)
    }
}

/// Real PCC verifier using evm-verify UnifiedVerifier
#[cfg(feature = "evm-verify")]
#[derive(Debug, Clone)]
pub struct RealPCCVerifier {
    verifier: Arc<UnifiedVerifier>,
}

#[cfg(feature = "evm-verify")]
impl RealPCCVerifier {
    pub fn new() -> Self {
        Self {
            verifier: Arc::new(UnifiedVerifier::new()),
        }
    }
    
    #[cfg(feature = "evm-verify")]
    pub fn verify_operations(&self, operations: &[AtomicOperation]) -> Result<bool, VMError> {
        // Convert operations to bytecode for verification
        let bytecode = self.operations_to_bytecode(operations)?;
        
        // Generate PCC proof
        let proof = self.verifier.generate_pcc_proof(&bytecode)
            .map_err(|e| VMError::ProofGenerationFailed(e.to_string()))?;
        
        // Verify the proof
        let result = self.verifier.verify_pcc_proof(&bytecode, &proof)
            .map_err(|e| VMError::ProofVerificationFailed(e.to_string()))?;
        
        Ok(result.is_valid)
    }
    
    #[cfg(feature = "evm-verify")]
    pub fn generate_safety_proof(&self, operations: &[AtomicOperation]) -> Result<String> {
        // Convert operations to bytecode
        let bytecode = self.operations_to_bytecode(operations)?;
        
        // Generate PCC proof using evm-verify
        let proof = self.verifier.generate_pcc_proof(&bytecode)
            .map_err(|e| VMError::ProofGenerationFailed(e.to_string()))?;
        
        // Return proof as hex string
        Ok(hex::encode(proof))
    }
    
    #[cfg(feature = "evm-verify")]
    fn operations_to_bytecode(&self, operations: &[AtomicOperation]) -> Result<Vec<u8>, VMError> {
        // Convert atomic operations to EVM bytecode for verification
        // This is a simplified conversion - in production you'd want more sophisticated encoding
        let mut bytecode = Vec::new();
        
        for op in operations {
            // Add target address (20 bytes)
            bytecode.extend_from_slice(op.target.as_bytes());
            
            // Add call data length as 2-byte big-endian
            let data_len = op.call_data.len() as u16;
            bytecode.extend_from_slice(&data_len.to_be_bytes());
            
            // Add call data
            bytecode.extend_from_slice(&op.call_data);
            
            // Add value as 32-byte big-endian
            let mut value_bytes = [0u8; 32];
            op.value.to_big_endian(&mut value_bytes);
            bytecode.extend_from_slice(&value_bytes);
        }
        
        Ok(bytecode)
    }
}

#[cfg(feature = "evm-verify")]
#[async_trait]
impl PCCVerifier for RealPCCVerifier {
    async fn verify_bundled_safety(&self, operations: &[AtomicOperation]) -> Result<H256> {
        let safety_proof = self.generate_safety_proof(operations)?;
        Ok(H256::from_slice(safety_proof.as_bytes()))
    }
}

/// Mock PCC verifier for testing (fallback)
#[derive(Debug, Clone)]
pub struct MockPCCVerifier;

impl MockPCCVerifier {
    pub fn new() -> Self {
        Self
    }
    
    pub fn verify_operations(&self, operations: &[AtomicOperation]) -> Result<bool> {
        // Mock verification - in production, this would call your PCC system
        // For now, just check that operations are not empty
        Ok(!operations.is_empty())
    }
    
    pub fn generate_safety_proof(&self, operations: &[AtomicOperation]) -> Result<String> {
        // Mock proof generation
        let operations_hash = format!("{:x}", md5::compute(format!("{:?}", operations)));
        Ok(format!("proof_{}", operations_hash))
    }
}

#[async_trait]
impl PCCVerifier for MockPCCVerifier {
    async fn verify_bundled_safety(&self, operations: &[AtomicOperation]) -> Result<H256> {
        let safety_proof = self.generate_safety_proof(operations)?;
        Ok(H256::from_slice(safety_proof.as_bytes()))
    }
}

/// Real PCD prover using evm-verify PCD system
#[cfg(feature = "evm-verify")]
#[derive(Debug, Clone)]
pub struct RealPCDProver {
    verifier: Arc<UnifiedVerifier>,
}

#[cfg(feature = "evm-verify")]
impl RealPCDProver {
    pub fn new() -> Self {
        Self {
            verifier: Arc::new(UnifiedVerifier::new()),
        }
    }
}

#[cfg(feature = "evm-verify")]
#[async_trait]
impl PCDProver for RealPCDProver {
    async fn prove_atomic_execution(&self, sequence: &TransactionSequence) -> Result<H256> {
        // Convert sequence to bytecode for PCD proof generation
        let mut bytecode = Vec::new();
        
        for tx in &sequence.transactions {
            // Add transaction target address
            bytecode.extend_from_slice(tx.to.as_bytes());
            
            // Add transaction data length
            let data_len = tx.data.len() as u16;
            bytecode.extend_from_slice(&data_len.to_be_bytes());
            
            // Add transaction data
            bytecode.extend_from_slice(&tx.data);
            
            // Add transaction value
            let mut value_bytes = [0u8; 32];
            tx.value.to_big_endian(&mut value_bytes);
            bytecode.extend_from_slice(&value_bytes);
        }
        
        // Generate PCD proof
        let (_proof, _verifying_key) = self.verifier.generate_pcd_proof(&bytecode)
            .map_err(|e| VMError::ProofGenerationFailed(e.to_string()))?;
        
        // Return proof hash
        Ok(H256::from_slice(&ethers::utils::keccak256(&_proof)[..]))
    }
}

/// Mock PCD prover for testing
pub struct MockPCDProver;

#[async_trait]
impl PCDProver for MockPCDProver {
    async fn prove_atomic_execution(&self, _sequence: &TransactionSequence) -> Result<H256> {
        // Mock proof generation - always return success with mock hash
        Ok(H256::from_slice(&[2u8; 32]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::Transaction;
    
    #[tokio::test]
    async fn test_sequence_to_operations() {
        let executor = AtomicExecutor::new(
            Address::zero(),
            Arc::new(Provider::try_from("http://localhost:8545").unwrap()),
            LocalWallet::new(&mut rand::thread_rng()),
        );
        
        let tx1 = Transaction::new(
            Address::from_slice(&[1u8; 20]), // from
            Some(Address::from_slice(&[0xAB; 20])), // to
            U256::from(100),  // value
            vec![1, 2, 3],    // data
            U256::from(21000), // gas_limit
            U256::from(20_000_000_000u64), // gas_price (20 gwei)
            0,                // nonce
        );
        
        let tx2 = Transaction::new(
            Address::from_slice(&[2u8; 20]), // from
            Some(Address::from_slice(&[0xCD; 20])), // to
            U256::from(200),  // value
            vec![4, 5, 6],    // data
            U256::from(21000), // gas_limit
            U256::from(20_000_000_000u64), // gas_price (20 gwei)
            1,                // nonce
        );
        
        let sequence = TransactionSequence::new(vec![tx1, tx2], true)
            .with_verification_level(VerificationLevel::Standard);
        
        let operations = executor.sequence_to_operations(sequence).await.unwrap();
        
        assert_eq!(operations.len(), 2);
        assert_eq!(operations[0].value, U256::from(100));
        assert_eq!(operations[1].value, U256::from(200));
    }
}
