use ethers::types::{Address, H256, U256};
use serde::{Deserialize, Serialize};

/// Represents EVM contract deployment data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentData {
    /// Contract creation code (including constructor)
    pub creation_code: Vec<u8>,
    /// Constructor arguments
    pub constructor_args: Vec<u8>,
    /// Expected runtime bytecode
    pub runtime_code: Vec<u8>,
}

/// Represents initial contract state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractState {
    /// Contract address
    pub address: Address,
    /// Initial storage slots
    pub storage: Vec<(H256, H256)>,
    /// Initial balance
    pub balance: U256,
}

/// Property proof data for contract deployment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentProofData {
    /// Bytecode verification status
    pub bytecode_verified: bool,
    /// Constructor validation status
    pub constructor_valid: bool,
    /// Storage initialization status
    pub storage_initialized: bool,
    /// Access control verification status
    pub access_controls_valid: bool,
}
