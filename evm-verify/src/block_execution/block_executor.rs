// ZODA Block Executor - Core engine for full block execution
//
// Designed for 3-7 second proving times on CPU-only hardware
// Uses tensor optimization and accumulation for maximum efficiency

use anyhow::{Result, anyhow};
use ethers::types::{Block, Transaction, H256, U256, Bytes};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Instant, Duration};
use tokio::sync::Mutex;
use serde::{Serialize, Deserialize};

#[cfg(feature = "accumulation")]
use pcd::evm_accumulation::{EVMAccumulator, generate_evm_proof, verify_evm_proof};
use ark_bn254::Fr as Bn254Fr;

// Import secure FRI verification (feature gated)
#[cfg(feature = "accumulation")]
use crate::accumulation::warp::verification::{
    WarpVerificationStrategy, create_warp_verification_strategy,
    SecurityReport, SecurityWarning
};
#[cfg(feature = "accumulation")]
use crate::accumulation::warp::fri_commitment::SecureFRIError;

use crate::api::pcd_adapter::PCDAdapter;
#[cfg(feature = "accumulation")]
use crate::api::pcd_adapter::ProofGenerationResult;
use crate::block_execution::{BatchResult, AccumulationResult, BlockExecutionConfig};

/// Core block executor that handles complete block proving with secure FRI verification
pub struct BlockExecutor {
    /// Configuration for block execution
    config: Arc<BlockExecutionConfig>,
    
    /// Accumulator for processing multiple transactions
    #[cfg(feature = "accumulation")]
    accumulator: Arc<Mutex<EVMAccumulator>>,
    
    /// Adapter for PCD operations
    pcd_adapter: Arc<PCDAdapter>,
    
    /// Current execution state
    execution_state: Arc<Mutex<ExecutionState>>,
    
    /// Verification metrics
    metrics: Arc<Mutex<HashMap<String, u64>>>,
    
    /// Secure FRI-based WARP verification strategy
    #[cfg(feature = "accumulation")]
    warp_verifier: Arc<Mutex<WarpVerificationStrategy>>,
    
    /// Current block being processed
    current_block: Arc<Mutex<Option<Block<Transaction>>>>,
}

/// State tracking for block execution
#[derive(Debug, Clone)]
struct ExecutionState {
    /// Current phase of execution
    phase: ExecutionPhase,
    
    /// Start time of current block
    start_time: Option<Instant>,
    
    /// Gas used so far
    gas_used: U256,
    
    /// Number of transactions processed
    transactions_processed: usize,
    
    /// Generated proofs for verification
    generated_proofs: Vec<Vec<u8>>,
    
    /// State root progression
    state_roots: Vec<H256>,
}

#[derive(Debug, Clone, PartialEq)]
enum ExecutionPhase {
    Idle,
    Preprocessing,
    TransactionExecution,
    StateAccumulation,
    ProofGeneration,
    Finalization,
    Complete,
}

impl BlockExecutor {
    /// Create a new block executor with secure FRI verification
    pub fn new(config: BlockExecutionConfig) -> Result<Self> {
        #[cfg(feature = "accumulation")]
        let pcd_adapter = Arc::new(PCDAdapter::new());
        
        #[cfg(not(feature = "accumulation"))]
        let pcd_adapter = Arc::new(PCDAdapter::new(
            Arc::new(crate::api::pcd::DefaultPCDVerifier::new())
        ));
        
        #[cfg(feature = "accumulation")]
        let accumulator = Arc::new(Mutex::new(EVMAccumulator::new(false)));

        let execution_state = Arc::new(Mutex::new(ExecutionState {
            phase: ExecutionPhase::Idle,
            start_time: None,
            gas_used: U256::zero(),
            transactions_processed: 0,
            generated_proofs: Vec::new(),
            state_roots: Vec::new(),
        }));
        
        // Initialize secure FRI-based WARP verification strategy
        #[cfg(feature = "accumulation")]
        let warp_verifier = {
            let verifier = create_warp_verification_strategy()
                .map_err(|e| anyhow!("Failed to create WARP verifier: {:?}", e))?;
            Arc::new(Mutex::new(verifier))
        };
        
        let metrics = Arc::new(Mutex::new(HashMap::new()));

        Ok(Self {
            config: Arc::new(config),
            pcd_adapter,
            #[cfg(feature = "accumulation")]
            accumulator,
            execution_state,
            metrics,
            #[cfg(feature = "accumulation")]
            warp_verifier,
            current_block: Arc::new(Mutex::new(None)),
        })
    }

    /// Finalize block execution and generate the complete block proof
    pub async fn finalize_block_execution(
        &self,
        block: &Block<Transaction>,
        batch_result: &BatchResult,
        accumulation_result: &AccumulationResult,
    ) -> Result<BlockExecutionResult> {
        let start_time = Instant::now();
        
        // Update execution state
        {
            let mut state = self.execution_state.lock().await;
            state.phase = ExecutionPhase::ProofGeneration;
            state.start_time = Some(start_time);
        }

        // Store current block for reference
        {
            let mut current = self.current_block.lock().await;
            *current = Some(block.clone());
        }

        // Generate the complete block proof using ZODA tensor optimization
        let block_proof = self.generate_block_proof(block, batch_result, accumulation_result).await?;
        
        // Verify the generated proof
        let is_valid = self.verify_block_proof(&block_proof).await?;
        if !is_valid {
            return Err(anyhow!("Generated block proof verification failed"));
        }

        // Calculate final metrics
        let execution_time = start_time.elapsed();
        let gas_used = batch_result.total_gas_used;
        let transaction_count = block.transactions.len();

        // Update final execution state
        {
            let mut state = self.execution_state.lock().await;
            state.phase = ExecutionPhase::Complete;
            state.gas_used = gas_used;
            state.transactions_processed = transaction_count;
        }

        Ok(BlockExecutionResult {
            block_hash: block.hash.unwrap_or_default(),
            block_number: U256::from(block.number.unwrap_or_default().as_u64()),
            transaction_count,
            gas_used,
            execution_time,
            proof: block_proof.proof,
            verifying_key: block_proof.verifying_key,
            state_root: accumulation_result.final_state_root,
            is_valid: true,
            proving_time_ms: execution_time.as_millis() as u64,
            transactions_per_second: if execution_time.as_secs() > 0 {
                transaction_count as f64 / execution_time.as_secs_f64()
            } else {
                0.0
            },
            gas_per_second: if execution_time.as_secs() > 0 {
                gas_used.as_u64() as f64 / execution_time.as_secs_f64()
            } else {
                0.0
            },
        })
    }

    /// Generate the complete block proof using ZODA tensor operations
    async fn generate_block_proof(
        &self,
        block: &Block<Transaction>,
        batch_result: &BatchResult,
        accumulation_result: &AccumulationResult,
    ) -> Result<BlockProof> {
        #[cfg(feature = "accumulation")]
        {
            // Use ZODA tensor-optimized proof generation
            self.generate_zoda_block_proof(block, batch_result, accumulation_result).await
        }
        
        #[cfg(not(feature = "accumulation"))]
        {
            // Fallback to mock proof for testing
            self.generate_mock_block_proof(block, batch_result, accumulation_result).await
        }
    }

    #[cfg(feature = "accumulation")]
    async fn generate_zoda_block_proof(
        &self,
        block: &Block<Transaction>,
        batch_result: &BatchResult,
        accumulation_result: &AccumulationResult,
    ) -> Result<BlockProof> {
        use ark_std::rand::thread_rng;
        
        let mut rng = thread_rng();

        // Initialize accumulator with block data
        let mut accumulator = self.accumulator.lock().await;
        
        // Create comprehensive bytecode from all transactions
        let mut block_bytecode = Vec::new();
        for tx in &block.transactions {
            // tx.input is Bytes, not Option<Bytes>
            if !tx.input.is_empty() {
                block_bytecode.extend_from_slice(&tx.input);
            }
        }
        
        // Add block header information
        let block_header_bytes = self.encode_block_header(block)?;
        block_bytecode.extend_from_slice(&block_header_bytes);

        accumulator.initialize(Bytes::from(block_bytecode))?;

        // Create state transition representing the entire block
        let prev_state = Some(self.encode_state_vector(&accumulation_result.initial_state_root)?);
        let curr_state = self.encode_state_vector(&accumulation_result.final_state_root)?;

        // Generate proof with full block context
        accumulator.accumulate(prev_state, curr_state, &mut rng)?;

        // Verify the accumulated proof
        let is_valid = accumulator.verify()?;
        if !is_valid {
            return Err(anyhow!("ZODA accumulator verification failed"));
        }

        // Extract proof and verifying key
        let proof_bytes = if let Some(proof) = &accumulator.proof {
            crate::api::pcd_adapter::serialize_proof(proof)?
        } else {
            return Err(anyhow!("No proof generated by accumulator"));
        };

        let vk_bytes = if let Some(vk) = &accumulator.vk {
            crate::api::pcd_adapter::serialize_vk(vk)?
        } else {
            return Err(anyhow!("No verifying key generated by accumulator"));
        };

        Ok(BlockProof {
            proof: proof_bytes,
            verifying_key: vk_bytes,
            block_hash: block.hash.unwrap_or_default(),
            state_root: accumulation_result.final_state_root,
            gas_used: batch_result.total_gas_used,
            transaction_count: block.transactions.len(),
        })
    }

    #[cfg(not(feature = "accumulation"))]
    async fn generate_mock_block_proof(
        &self,
        block: &Block<Transaction>,
        batch_result: &BatchResult,
        accumulation_result: &AccumulationResult,
    ) -> Result<BlockProof> {
        // Generate deterministic mock proof for testing
        let proof_data = format!(
            "MOCK_BLOCK_PROOF_{}_{}_{}",
            block.hash.unwrap_or_default(),
            batch_result.total_gas_used,
            accumulation_result.final_state_root
        );
        
        Ok(BlockProof {
            proof: proof_data.as_bytes().to_vec(),
            verifying_key: b"MOCK_VERIFYING_KEY".to_vec(),
            block_hash: block.hash.unwrap_or_default(),
            state_root: accumulation_result.final_state_root,
            gas_used: batch_result.total_gas_used,
            transaction_count: block.transactions.len(),
        })
    }

    /// Verify the generated block proof
    async fn verify_block_proof(&self, proof: &BlockProof) -> Result<bool> {
        #[cfg(feature = "accumulation")]
        {
            // Use ZODA proof verification
            let deserialized_proof = crate::api::pcd_adapter::deserialize_proof(&proof.proof)?;
            let deserialized_vk = crate::api::pcd_adapter::deserialize_vk(&proof.verifying_key)?;
            
            // Create verification bytecode (simplified for block-level verification)
            let verification_bytecode = Bytes::from(format!("BLOCK_VERIFICATION_{}", proof.block_hash).as_bytes().to_vec());
            let curr_state = self.encode_state_vector(&proof.state_root)?;
            
            pcd::evm_accumulation::verify_evm_proof(
                verification_bytecode,
                curr_state,
                &deserialized_proof,
                &deserialized_vk,
            )
        }
        
        #[cfg(not(feature = "accumulation"))]
        {
            // Mock verification for testing
            Ok(!proof.proof.is_empty() && !proof.verifying_key.is_empty())
        }
    }

    /// Encode block header into bytes for proof generation
    fn encode_block_header(&self, block: &Block<Transaction>) -> Result<Vec<u8>> {
        let mut header_bytes = Vec::new();
        
        // Add key block header fields
        header_bytes.extend_from_slice(block.hash.unwrap_or_default().as_bytes());
        header_bytes.extend_from_slice(block.parent_hash.as_bytes());
        header_bytes.extend_from_slice(&block.number.unwrap_or_default().as_u64().to_be_bytes());
        header_bytes.extend_from_slice(&block.timestamp.as_u64().to_be_bytes());
        header_bytes.extend_from_slice(&block.gas_limit.as_u64().to_be_bytes());
        header_bytes.extend_from_slice(&block.gas_used.as_u64().to_be_bytes());
        
        Ok(header_bytes)
    }
    
    /// Verify block execution using secure FRI commitments
    #[cfg(feature = "accumulation")]
    pub async fn verify_block_with_fri(
        &self,
        block: &Block<Transaction>,
        proof: &BlockProof,
    ) -> Result<SecurityReport> {
        let mut warp_verifier = self.warp_verifier.lock().await;
        
        // Serialize block data for verification
        let block_data = self.serialize_block_for_verification(block)?;
        
        // Verify using WARP with FRI commitments
        let security_report = warp_verifier
            .verify_transaction(&block_data, 128) // 128-bit security for EF compliance
            .map_err(|e| anyhow!("WARP FRI verification failed: {}", e))?;
        
        // Update verification metrics
        {
            let mut metrics = self.metrics.lock().await;
            *metrics.entry("fri_verifications".to_string()).or_insert(0) += 1;
            if security_report.passed {
                *metrics.entry("fri_verifications_passed".to_string()).or_insert(0) += 1;
            }
            metrics.insert("last_verification_time_ms".to_string(), security_report.verification_time_ms);
        }
        
        Ok(security_report)
    }
    
    /// Generate FRI proof for block execution
    #[cfg(feature = "accumulation")]
    pub async fn generate_fri_proof_for_block(
        &self,
        block: &Block<Transaction>,
    ) -> Result<Vec<u8>> {
        let mut warp_verifier = self.warp_verifier.lock().await;
        
        // Serialize block data for proof generation
        let block_data = self.serialize_block_for_verification(block)?;
        
        // Generate proof using secure FRI commitments
        let proof = warp_verifier
            .generate_proof(&block_data)
            .await
            .map_err(|e| anyhow!("FRI proof generation failed: {}", e))?;
        
        // Update metrics
        {
            let mut metrics = self.metrics.lock().await;
            *metrics.entry("fri_proofs_generated".to_string()).or_insert(0) += 1;
        }
        
        Ok(proof)
    }
    
    /// Serialize block data in a format suitable for FRI verification
    fn serialize_block_for_verification(&self, block: &Block<Transaction>) -> Result<Vec<u8>> {
        use serde_json;
        
        // Create a simplified block representation for verification
        let block_summary = serde_json::json!({
            "number": block.number.map(|n| n.as_u64()),
            "timestamp": block.timestamp.as_u64(),
            "parent_hash": format!("{:?}", block.parent_hash),
            "gas_limit": block.gas_limit.as_u64(),
            "gas_used": block.gas_used.as_u64(),
            "transactions_count": block.transactions.len(),
            "state_root": format!("{:?}", block.state_root),
        });
        
        let serialized = serde_json::to_vec(&block_summary)
            .map_err(|e| anyhow!("Block serialization failed: {}", e))?;
        
        Ok(serialized)
    }
    
    /// Get FRI verification metrics
    pub async fn get_fri_metrics(&self) -> HashMap<String, u64> {
        let metrics = self.metrics.lock().await;
        metrics.clone()
    }

    /// Encode state root into field elements for ZODA operations
    fn encode_state_vector(&self, state_root: &H256) -> Result<Vec<Bn254Fr>> {
        let mut state_vector = Vec::new();
        
        // Convert state root bytes to field elements
        let chunks = state_root.as_bytes().chunks(8);
        for chunk in chunks {
            let mut padded = [0u8; 8];
            padded[..chunk.len()].copy_from_slice(chunk);
            let value = u64::from_be_bytes(padded);
            state_vector.push(Bn254Fr::from(value));
        }
        
        // Ensure we have at least one element
        if state_vector.is_empty() {
            state_vector.push(Bn254Fr::from(1u32));
        }
        
        Ok(state_vector)
    }

    /// Health check for the block executor
    pub async fn health_check(&self) -> Result<bool> {
        let state = self.execution_state.lock().await;
        
        // Check if executor is in a valid state
        match state.phase {
            ExecutionPhase::Idle | ExecutionPhase::Complete => Ok(true),
            _ => {
                // Check if execution has been running too long
                if let Some(start_time) = state.start_time {
                    let elapsed = start_time.elapsed();
                    let max_execution_time = Duration::from_secs(self.config.target_proving_time_seconds * 2);
                    Ok(elapsed < max_execution_time)
                } else {
                    Ok(true)
                }
            }
        }
    }

    /// Get current execution status
    pub async fn get_execution_status(&self) -> ExecutionStatus {
        let state = self.execution_state.lock().await;
        
        ExecutionStatus {
            phase: state.phase.clone(),
            start_time: state.start_time,
            gas_used: state.gas_used,
            transactions_processed: state.transactions_processed,
            elapsed_time: state.start_time.map(|t| t.elapsed()),
        }
    }
}

/// Result of block execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockExecutionResult {
    /// Hash of the executed block
    pub block_hash: H256,
    
    /// Block number
    pub block_number: U256,
    
    /// Number of transactions in the block
    pub transaction_count: usize,
    
    /// Total gas used
    pub gas_used: U256,
    
    /// Total execution time
    pub execution_time: Duration,
    
    /// Generated proof
    pub proof: Vec<u8>,
    
    /// Verifying key for the proof
    pub verifying_key: Vec<u8>,
    
    /// Final state root
    pub state_root: H256,
    
    /// Whether the execution was valid
    pub is_valid: bool,
    
    /// Proving time in milliseconds
    pub proving_time_ms: u64,
    
    /// Transactions processed per second
    pub transactions_per_second: f64,
    
    /// Gas processed per second
    pub gas_per_second: f64,
}

/// Proof generated for a complete block
#[derive(Debug, Clone)]
struct BlockProof {
    /// Serialized proof data
    proof: Vec<u8>,
    
    /// Serialized verifying key
    verifying_key: Vec<u8>,
    
    /// Block hash this proof corresponds to
    block_hash: H256,
    
    /// Final state root
    state_root: H256,
    
    /// Total gas used
    gas_used: U256,
    
    /// Number of transactions
    transaction_count: usize,
}

/// Current execution status
#[derive(Debug, Clone)]
pub struct ExecutionStatus {
    /// Current execution phase
    pub phase: ExecutionPhase,
    
    /// When execution started
    pub start_time: Option<Instant>,
    
    /// Gas used so far
    pub gas_used: U256,
    
    /// Transactions processed so far
    pub transactions_processed: usize,
    
    /// Elapsed execution time
    pub elapsed_time: Option<Duration>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::types::{Address, U64};

    fn create_test_block() -> Block<Transaction> {
        Block {
            hash: Some(H256::random()),
            parent_hash: H256::random(),
            number: Some(12345u64.into()),
            timestamp: U256::from(1640995200), // 2022-01-01
            gas_limit: U256::from(30000000),
            gas_used: U256::from(21000),
            transactions: vec![
                Transaction {
                    hash: H256::random(),
                    from: Address::random(),
                    to: Some(Address::random()),
                    value: U256::from(1000000000000000000u64), // 1 ETH
                    gas: U256::from(21000),
                    gas_price: Some(U256::from(20000000000u64)), // 20 gwei
                    input: Bytes::from(vec![0x60, 0x80, 0x60, 0x40]), // Simple bytecode
                    nonce: U256::zero(),
                    ..Default::default()
                }
            ],
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_block_executor_creation() {
        let config = BlockExecutionConfig::default();
        let executor = BlockExecutor::new(config);
        assert!(executor.is_ok());
    }

    #[tokio::test]
    async fn test_execution_status() {
        let config = BlockExecutionConfig::default();
        let executor = BlockExecutor::new(config).expect("Failed to create executor");
        
        let status = executor.get_execution_status().await;
        assert_eq!(status.phase, ExecutionPhase::Idle);
        assert_eq!(status.gas_used, U256::zero());
        assert_eq!(status.transactions_processed, 0);
    }

    #[tokio::test]
    async fn test_health_check() {
        let config = BlockExecutionConfig::default();
        let executor = BlockExecutor::new(config).expect("Failed to create executor");
        
        let health = executor.health_check().await;
        assert!(health.is_ok());
        assert!(health.unwrap());
    }

    #[tokio::test]
    async fn test_block_header_encoding() {
        let config = BlockExecutionConfig::default();
        let executor = BlockExecutor::new(config).expect("Failed to create executor");
        let block = create_test_block();
        
        let encoded = executor.encode_block_header(&block);
        assert!(encoded.is_ok());
        assert!(!encoded.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_state_vector_encoding() {
        let config = BlockExecutionConfig::default();
        let executor = BlockExecutor::new(config).expect("Failed to create executor");
        let state_root = H256::random();
        
        let encoded = executor.encode_state_vector(&state_root);
        assert!(encoded.is_ok());
        let vector = encoded.unwrap();
        assert!(!vector.is_empty());
        assert_eq!(vector.len(), 4); // 32 bytes / 8 bytes per chunk = 4 field elements
    }
}
