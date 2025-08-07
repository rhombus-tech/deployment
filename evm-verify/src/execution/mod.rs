use anyhow::Result;
use serde::{Deserialize, Serialize};
use ethers::types::H256;

/// StatelessVM for execution verification
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct StatelessVM {
    config: String,
}

impl StatelessVM {
    /// Create a new StatelessVM instance
    pub fn new() -> Result<Self> {
        Ok(Self {
            config: "default".to_string(),
        })
    }

    /// Execute a block with transactions
    pub async fn execute_block(
        &self,
        block_number: u64,
        tx_hashes: &[H256],
    ) -> Result<ExecutionResult> {
        // Mock execution for now
        Ok(ExecutionResult {
            block_number,
            gas_used: 21000 * tx_hashes.len() as u64,
            state_root: vec![0u8; 32],
            receipt_root: vec![0u8; 32],
            tx_count: tx_hashes.len(),
        })
    }
}

/// Result of block execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub block_number: u64,
    pub gas_used: u64,
    pub state_root: Vec<u8>,
    pub receipt_root: Vec<u8>,
    pub tx_count: usize,
}
