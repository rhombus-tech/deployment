pub mod utils;

use ethers::types::{Address, Bytes, H256, U256};
use serde::{Serialize, Deserialize};

/// Deployment data for contract verification
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeploymentData {
    /// Creation code
    pub creation_code: Bytes,
    /// Constructor arguments
    pub constructor_args: Bytes,
    /// Runtime code
    pub runtime_code: Bytes,
    /// Contract owner
    pub owner: Address,
    /// Initial storage state
    pub initial_state: Vec<(H256, U256)>,
    /// Final storage state
    pub final_state: Vec<(H256, U256)>,
}

/// Proof data for deployment verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentProofData {
    /// Proof bytes
    pub proof: Vec<u8>,
    /// Verifying key bytes
    pub vk: Vec<u8>,
}
