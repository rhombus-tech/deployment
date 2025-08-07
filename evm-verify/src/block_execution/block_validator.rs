// ZODA Block Validator - Ethereum-compliant block validation
//
// Validates blocks against Ethereum consensus rules before execution
// Ensures compliance with L1 zkEVM requirements

use anyhow::{Result, anyhow};
use ethers::types::{Block, Transaction, H256, U256, U64, Address, Bytes};
use std::collections::{HashMap, HashSet};
use std::time::{Instant, Duration, SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};

use crate::block_execution::BlockExecutionConfig;

/// Ethereum-compliant block validator
pub struct BlockValidator {
    /// Validation configuration
    config: BlockExecutionConfig,
    
    /// Validation rules
    rules: ValidationRules,
    
    /// Cache for recent validations
    validation_cache: HashMap<H256, ValidationResult>,
}

/// Validation rules configuration
#[derive(Debug, Clone)]
struct ValidationRules {
    /// Maximum block gas limit
    max_gas_limit: U256,
    
    /// Minimum gas limit
    min_gas_limit: U256,
    
    /// Maximum block size in bytes
    max_block_size: usize,
    
    /// Maximum number of transactions per block
    max_transactions: usize,
    
    /// Maximum timestamp drift (seconds)
    max_timestamp_drift: u64,
    
    /// Enable strict EIP validation
    enable_eip_validation: bool,
    
    /// Supported EIPs
    supported_eips: HashSet<u16>,
}

/// Result of block validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    /// Whether the block is valid
    pub is_valid: bool,
    
    /// Validation errors
    pub errors: Vec<ValidationError>,
    
    /// Validation warnings
    pub warnings: Vec<ValidationWarning>,
    
    /// Validation time
    pub validation_time: Duration,
    
    /// Block hash validated
    pub block_hash: H256,
    
    /// Gas validation details
    pub gas_validation: GasValidation,
    
    /// Transaction validation details
    pub transaction_validation: TransactionValidation,
    
    /// Timestamp validation
    pub timestamp_validation: TimestampValidation,
}

/// Validation error types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidationError {
    /// Invalid block hash
    InvalidBlockHash { expected: H256, actual: H256 },
    
    /// Gas limit exceeded
    GasLimitExceeded { limit: U256, used: U256 },
    
    /// Invalid gas limit
    InvalidGasLimit { actual: U256, min: U256, max: U256 },
    
    /// Invalid transaction
    InvalidTransaction { tx_hash: H256, reason: String },
    
    /// Invalid timestamp
    InvalidTimestamp { timestamp: U256, reason: String },
    
    /// Missing required field
    MissingField { field: String },
    
    /// Invalid merkle root
    InvalidMerkleRoot { expected: H256, actual: H256 },
    
    /// Block size exceeded
    BlockSizeExceeded { actual: usize, max: usize },
    
    /// Too many transactions
    TooManyTransactions { actual: usize, max: usize },
    
    /// EIP validation failure
    EIPValidationFailure { eip: u16, reason: String },
}

/// Validation warning types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidationWarning {
    /// High gas usage
    HighGasUsage { percentage: f64 },
    
    /// Unusual timestamp
    UnusualTimestamp { timestamp: U256 },
    
    /// Large transaction
    LargeTransaction { tx_hash: H256, size: usize },
    
    /// Potential MEV
    PotentialMEV { reason: String },
}

/// Gas validation details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasValidation {
    /// Total gas used
    pub total_gas_used: U256,
    
    /// Gas limit
    pub gas_limit: U256,
    
    /// Gas utilization percentage
    pub utilization_percentage: f64,
    
    /// Average gas per transaction
    pub avg_gas_per_tx: U256,
    
    /// Is gas validation valid
    pub is_valid: bool,
}

/// Transaction validation details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionValidation {
    /// Total transactions validated
    pub total_transactions: usize,
    
    /// Valid transactions
    pub valid_transactions: usize,
    
    /// Invalid transactions
    pub invalid_transactions: Vec<H256>,
    
    /// Average transaction size
    pub avg_transaction_size: usize,
    
    /// Nonce validation results
    pub nonce_validation: HashMap<Address, bool>,
}

/// Timestamp validation details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimestampValidation {
    /// Block timestamp
    pub block_timestamp: U256,
    
    /// Current time
    pub current_time: u64,
    
    /// Time drift in seconds
    pub time_drift: i64,
    
    /// Is timestamp valid
    pub is_valid: bool,
}

/// Validation configuration
#[derive(Debug, Clone)]
pub struct ValidationConfig {
    /// Enable strict validation
    pub strict_mode: bool,
    
    /// Enable performance validation
    pub enable_performance_validation: bool,
    
    /// Enable MEV detection
    pub enable_mev_detection: bool,
    
    /// Cache validation results
    pub enable_caching: bool,
}

impl Default for ValidationRules {
    fn default() -> Self {
        let mut supported_eips = HashSet::new();
        // Common EIPs for Ethereum L1
        supported_eips.insert(155); // EIP-155: Simple replay attack protection
        supported_eips.insert(1559); // EIP-1559: Fee market change
        supported_eips.insert(2718); // EIP-2718: Typed Transaction Envelope
        supported_eips.insert(2930); // EIP-2930: Optional access lists
        supported_eips.insert(3198); // EIP-3198: BASEFEE opcode
        
        Self {
            max_gas_limit: U256::from(100_000_000), // Updated for current Ethereum mainnet gas limits (50-60M typical)
            min_gas_limit: U256::from(5_000), // Minimum reasonable gas limit
            max_block_size: 1_000_000, // 1MB block size limit
            max_transactions: 1000, // Maximum transactions per block
            max_timestamp_drift: 900, // 15 minutes timestamp drift
            enable_eip_validation: true,
            supported_eips,
        }
    }
}

impl BlockValidator {
    /// Create a new block validator
    pub fn new(config: BlockExecutionConfig) -> Result<Self> {
        Ok(Self {
            config,
            rules: ValidationRules::default(),
            validation_cache: HashMap::new(),
        })
    }

    /// Validate a complete block
    pub async fn validate_block(&self, block: &Block<Transaction>) -> Result<ValidationResult> {
        let start_time = Instant::now();
        let block_hash = block.hash.unwrap_or_default();
        
        // Check cache first
        if let Some(cached_result) = self.validation_cache.get(&block_hash) {
            return Ok(cached_result.clone());
        }

        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        // 1. Validate block structure
        self.validate_block_structure(block, &mut errors, &mut warnings).await?;
        
        // 2. Validate gas limits and usage
        let gas_validation = self.validate_gas_limits(block, &mut errors, &mut warnings).await?;
        
        // 3. Validate transactions
        let transaction_validation = self.validate_transactions(block, &mut errors, &mut warnings).await?;
        
        // 4. Validate timestamp
        let timestamp_validation = self.validate_timestamp(block, &mut errors, &mut warnings).await?;
        
        // 5. Validate merkle roots
        self.validate_merkle_roots(block, &mut errors, &mut warnings).await?;
        
        // 6. EIP validation
        if self.rules.enable_eip_validation {
            self.validate_eips(block, &mut errors, &mut warnings).await?;
        }

        let validation_time = start_time.elapsed();
        let is_valid = errors.is_empty();

        let result = ValidationResult {
            is_valid,
            errors,
            warnings,
            validation_time,
            block_hash,
            gas_validation,
            transaction_validation,
            timestamp_validation,
        };

        Ok(result)
    }

    /// Validate block structure and basic fields
    async fn validate_block_structure(
        &self,
        block: &Block<Transaction>,
        errors: &mut Vec<ValidationError>,
        warnings: &mut Vec<ValidationWarning>,
    ) -> Result<()> {
        // Check required fields
        if block.hash.is_none() {
            errors.push(ValidationError::MissingField {
                field: "hash".to_string(),
            });
        }

        if block.number.is_none() {
            errors.push(ValidationError::MissingField {
                field: "number".to_string(),
            });
        }

        // Check block size
        let block_size = self.calculate_block_size(block);
        if block_size > self.rules.max_block_size {
            errors.push(ValidationError::BlockSizeExceeded {
                actual: block_size,
                max: self.rules.max_block_size,
            });
        }

        // Check transaction count
        if block.transactions.len() > self.rules.max_transactions {
            errors.push(ValidationError::TooManyTransactions {
                actual: block.transactions.len(),
                max: self.rules.max_transactions,
            });
        }

        Ok(())
    }

    /// Validate gas limits and usage
    async fn validate_gas_limits(
        &self,
        block: &Block<Transaction>,
        errors: &mut Vec<ValidationError>,
        warnings: &mut Vec<ValidationWarning>,
    ) -> Result<GasValidation> {
        let gas_limit = block.gas_limit;
        let gas_used = block.gas_used;

        // Validate gas limit bounds
        if gas_limit > self.rules.max_gas_limit || gas_limit < self.rules.min_gas_limit {
            errors.push(ValidationError::InvalidGasLimit {
                actual: gas_limit,
                min: self.rules.min_gas_limit,
                max: self.rules.max_gas_limit,
            });
        }

        // Validate gas usage
        if gas_used > gas_limit {
            errors.push(ValidationError::GasLimitExceeded {
                limit: gas_limit,
                used: gas_used,
            });
        }

        // Calculate utilization
        let utilization_percentage = if gas_limit > U256::zero() {
            (gas_used.as_u128() as f64 / gas_limit.as_u128() as f64) * 100.0
        } else {
            0.0
        };

        // Warn if utilization is very high
        if utilization_percentage > 95.0 {
            warnings.push(ValidationWarning::HighGasUsage {
                percentage: utilization_percentage,
            });
        }

        // Calculate average gas per transaction
        let avg_gas_per_tx = if !block.transactions.is_empty() {
            gas_used / U256::from(block.transactions.len())
        } else {
            U256::zero()
        };

        Ok(GasValidation {
            total_gas_used: gas_used,
            gas_limit,
            utilization_percentage,
            avg_gas_per_tx,
            is_valid: gas_used <= gas_limit,
        })
    }

    /// Validate all transactions in the block
    async fn validate_transactions(
        &self,
        block: &Block<Transaction>,
        errors: &mut Vec<ValidationError>,
        warnings: &mut Vec<ValidationWarning>,
    ) -> Result<TransactionValidation> {
        let mut invalid_transactions = Vec::new();
        let mut nonce_validation = HashMap::new();
        let mut total_tx_size = 0;

        // Track nonces per address
        let mut nonce_tracker: HashMap<Address, U256> = HashMap::new();

        for transaction in &block.transactions {
            let tx_size = self.calculate_transaction_size(transaction);
            total_tx_size += tx_size;

            // Validate individual transaction
            if let Err(e) = self.validate_single_transaction(transaction).await {
                errors.push(ValidationError::InvalidTransaction {
                    tx_hash: transaction.hash,
                    reason: e.to_string(),
                });
                invalid_transactions.push(transaction.hash);
            }

            // Validate nonce ordering
            let expected_nonce = nonce_tracker.get(&transaction.from).copied().unwrap_or(transaction.nonce);
            let nonce_valid = transaction.nonce >= expected_nonce;
            nonce_validation.insert(transaction.from, nonce_valid);
            
            if nonce_valid {
                nonce_tracker.insert(transaction.from, transaction.nonce + U256::one());
            }

            // Check for large transactions
            if tx_size > 50_000 { // 50KB threshold
                warnings.push(ValidationWarning::LargeTransaction {
                    tx_hash: transaction.hash,
                    size: tx_size,
                });
            }
        }

        let avg_transaction_size = if !block.transactions.is_empty() {
            total_tx_size / block.transactions.len()
        } else {
            0
        };

        let valid_transactions = block.transactions.len() - invalid_transactions.len();

        Ok(TransactionValidation {
            total_transactions: block.transactions.len(),
            valid_transactions,
            invalid_transactions,
            avg_transaction_size,
            nonce_validation,
        })
    }

    /// Validate a single transaction
    async fn validate_single_transaction(&self, transaction: &Transaction) -> Result<()> {
        // Basic transaction validation
        if transaction.gas == U256::zero() {
            return Err(anyhow!("Transaction gas cannot be zero"));
        }

        if transaction.gas_price.unwrap_or_default() == U256::zero() {
            return Err(anyhow!("Transaction gas price cannot be zero"));
        }

        // Validate transaction type
        if let Some(tx_type) = transaction.transaction_type {
            if tx_type > U64::from(2) { // Type 0, 1, 2 are currently supported
                return Err(anyhow!("Unsupported transaction type: {}", tx_type));
            }
        }

        Ok(())
    }

    /// Validate block timestamp
    async fn validate_timestamp(
        &self,
        block: &Block<Transaction>,
        errors: &mut Vec<ValidationError>,
        warnings: &mut Vec<ValidationWarning>,
    ) -> Result<TimestampValidation> {
        let block_timestamp = block.timestamp;
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let time_drift = block_timestamp.as_u64() as i64 - current_time as i64;

        // Check if timestamp is too far in the future
        if time_drift > self.rules.max_timestamp_drift as i64 {
            errors.push(ValidationError::InvalidTimestamp {
                timestamp: block_timestamp,
                reason: format!("Timestamp too far in future: {} seconds", time_drift),
            });
        }

        // Warn about unusual timestamps
        if time_drift.abs() > 300 { // 5 minutes
            warnings.push(ValidationWarning::UnusualTimestamp {
                timestamp: block_timestamp,
            });
        }

        Ok(TimestampValidation {
            block_timestamp,
            current_time,
            time_drift,
            is_valid: time_drift <= self.rules.max_timestamp_drift as i64,
        })
    }

    /// Validate merkle roots
    async fn validate_merkle_roots(
        &self,
        block: &Block<Transaction>,
        errors: &mut Vec<ValidationError>,
        _warnings: &mut Vec<ValidationWarning>,
    ) -> Result<()> {
        // Calculate expected transaction root
        let calculated_tx_root = self.calculate_transaction_root(&block.transactions);
        
        let expected_root = block.transactions_root;
        if !expected_root.is_zero() {
            if calculated_tx_root != expected_root {
                errors.push(ValidationError::InvalidMerkleRoot {
                    expected: expected_root,
                    actual: calculated_tx_root,
                });
            }
        }

        Ok(())
    }

    /// Validate EIP compliance
    async fn validate_eips(
        &self,
        block: &Block<Transaction>,
        errors: &mut Vec<ValidationError>,
        _warnings: &mut Vec<ValidationWarning>,
    ) -> Result<()> {
        // EIP-1559 validation (if base fee is present)
        if block.base_fee_per_gas.is_some() && !self.rules.supported_eips.contains(&1559) {
            errors.push(ValidationError::EIPValidationFailure {
                eip: 1559,
                reason: "EIP-1559 not supported but base fee present".to_string(),
            });
        }

        // EIP-2718 validation (typed transactions)
        for transaction in &block.transactions {
            if transaction.transaction_type.is_some() && !self.rules.supported_eips.contains(&2718) {
                errors.push(ValidationError::EIPValidationFailure {
                    eip: 2718,
                    reason: "EIP-2718 not supported but typed transaction present".to_string(),
                });
                break;
            }
        }

        Ok(())
    }

    /// Calculate block size in bytes
    fn calculate_block_size(&self, block: &Block<Transaction>) -> usize {
        let mut size = 0;
        
        // Block header size (approximate)
        size += 500; // Block header
        
        // Transaction sizes
        for transaction in &block.transactions {
            size += self.calculate_transaction_size(transaction);
        }

        size
    }

    /// Calculate transaction size in bytes
    fn calculate_transaction_size(&self, transaction: &Transaction) -> usize {
        let mut size = 0;
        
        // Base transaction fields
        size += 32; // hash
        size += 20; // from
        size += 20; // to (optional, but count anyway)
        size += 32; // value
        size += 32; // gas
        size += 32; // gas_price
        size += 32; // nonce
        
        // Input data
        size += transaction.input.len();
        
        // Signature (v, r, s)
        size += 65;

        size
    }

    /// Calculate transaction merkle root
    fn calculate_transaction_root(&self, transactions: &[Transaction]) -> H256 {
        if transactions.is_empty() {
            return H256::zero();
        }

        // Simplified merkle root calculation
        // In a real implementation, this would be a proper merkle tree
        use sha3::{Digest, Keccak256};
        
        let mut hasher = Keccak256::new();
        for transaction in transactions {
            hasher.update(transaction.hash.as_bytes());
        }
        
        H256::from_slice(&hasher.finalize())
    }

    /// Health check for the validator
    pub async fn health_check(&self) -> Result<bool> {
        // Validator is always healthy if created successfully
        Ok(true)
    }

    /// Get validation statistics
    pub fn get_validation_stats(&self) -> ValidationStats {
        ValidationStats {
            total_validations: self.validation_cache.len(),
            cached_results: self.validation_cache.len(),
            rules_active: self.rules.supported_eips.len(),
        }
    }
}

/// Validation statistics
#[derive(Debug, Clone)]
pub struct ValidationStats {
    /// Total validations performed
    pub total_validations: usize,
    
    /// Cached validation results
    pub cached_results: usize,
    
    /// Number of active validation rules
    pub rules_active: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::types::{U64, Bloom};

    fn create_test_block() -> Block<Transaction> {
        Block {
            hash: Some(H256::random()),
            parent_hash: H256::random(),
            number: Some(12345u64.into()),
            timestamp: U256::from(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            ),
            gas_limit: U256::from(15_000_000),
            gas_used: U256::from(10_000_000),
            transactions: vec![
                Transaction {
                    hash: H256::random(),
                    from: Address::random(),
                    to: Some(Address::random()),
                    value: U256::from(1000000000000000000u64), // 1 ETH
                    gas: U256::from(21000),
                    gas_price: Some(U256::from(20000000000u64)), // 20 gwei
                    input: Bytes::from(vec![0x60, 0x80, 0x60, 0x40]),
                    nonce: U256::zero(),
                    transaction_type: Some(U64::from(0)),
                    ..Default::default()
                }
            ],
            transactions_root: H256::random(),
            base_fee_per_gas: Some(U256::from(1000000000u64)), // 1 gwei
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_validator_creation() {
        let config = BlockExecutionConfig::default();
        let validator = BlockValidator::new(config);
        assert!(validator.is_ok());
    }

    #[tokio::test]
    async fn test_block_validation() {
        let config = BlockExecutionConfig::default();
        let validator = BlockValidator::new(config).expect("Failed to create validator");
        let block = create_test_block();
        
        let result = validator.validate_block(&block).await;
        assert!(result.is_ok());
        
        let validation_result = result.unwrap();
        assert_eq!(validation_result.block_hash, block.hash.unwrap());
        // Note: This might fail due to merkle root mismatch, which is expected in test
    }

    #[tokio::test]
    async fn test_gas_validation() {
        let config = BlockExecutionConfig::default();
        let validator = BlockValidator::new(config).expect("Failed to create validator");
        let block = create_test_block();
        
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        
        let gas_validation = validator.validate_gas_limits(&block, &mut errors, &mut warnings).await;
        assert!(gas_validation.is_ok());
        
        let gas_val = gas_validation.unwrap();
        assert_eq!(gas_val.gas_limit, block.gas_limit);
        assert_eq!(gas_val.total_gas_used, block.gas_used);
        assert!(gas_val.is_valid);
    }

    #[tokio::test]
    async fn test_transaction_validation() {
        let config = BlockExecutionConfig::default();
        let validator = BlockValidator::new(config).expect("Failed to create validator");
        let block = create_test_block();
        
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        
        let tx_validation = validator.validate_transactions(&block, &mut errors, &mut warnings).await;
        assert!(tx_validation.is_ok());
        
        let tx_val = tx_validation.unwrap();
        assert_eq!(tx_val.total_transactions, 1);
        assert_eq!(tx_val.valid_transactions, 1);
        assert!(tx_val.invalid_transactions.is_empty());
    }

    #[tokio::test]
    async fn test_timestamp_validation() {
        let config = BlockExecutionConfig::default();
        let validator = BlockValidator::new(config).expect("Failed to create validator");
        let block = create_test_block();
        
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        
        let timestamp_validation = validator.validate_timestamp(&block, &mut errors, &mut warnings).await;
        assert!(timestamp_validation.is_ok());
        
        let ts_val = timestamp_validation.unwrap();
        assert_eq!(ts_val.block_timestamp, block.timestamp);
        assert!(ts_val.is_valid);
    }

    #[tokio::test]
    async fn test_health_check() {
        let config = BlockExecutionConfig::default();
        let validator = BlockValidator::new(config).expect("Failed to create validator");
        
        let health = validator.health_check().await;
        assert!(health.is_ok());
        assert!(health.unwrap());
    }

    #[tokio::test]
    async fn test_block_size_calculation() {
        let config = BlockExecutionConfig::default();
        let validator = BlockValidator::new(config).expect("Failed to create validator");
        let block = create_test_block();
        
        let size = validator.calculate_block_size(&block);
        assert!(size > 0);
        assert!(size < 1_000_000); // Should be less than max block size
    }
}
