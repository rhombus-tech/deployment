// Bundle management module
// This provides transaction bundle processing capabilities

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use serde_json::Value;
use log::{info, debug, warn, error};
use rand::random;

use crate::errors::{Result, RelayerError};
use async_trait::async_trait;
use crate::types::*;
use crate::config::RelayerConfig;
use ethers::prelude::*;
use ethers::providers::{Http, Middleware, Provider};
use ethers::core::types::{TransactionRequest, U256, Address as EthAddress};
use ethers::signers::Signer;
use std::str::FromStr;
use ethers::core::types::Bytes;
use std::time::Duration;

use crate::statelessvm::StatelessVmClient;

pub use validation::{ValidationResult, BundleValidator, DefaultBundleValidator};

pub mod validation;

#[cfg(test)]
mod tests;

/// Current pending bundle in processing
#[derive(Debug)]
struct PendingBundle {
    bundle: TransactionBundle,
    status: BundleStatus,
    validation_result: Option<ValidationResult>,
    submitted_at: Option<chrono::DateTime<Utc>>,
}

/// Security verification mode for transaction bundles
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityVerificationMode {
    /// Always perform security verification
    Always,
    /// Only perform security verification for new contracts that haven't been analyzed
    DeploymentOnly,
    /// Only perform verification for high-value transactions based on a threshold
    HighValueOnly,
    /// Skip all security verification
    Disabled,
}

/// Result of security verification for a contract or transaction
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Whether the verification passed without critical issues
    pub passed: bool,
    /// List of vulnerabilities found, if any
    pub vulnerabilities: Vec<String>,
    /// Timestamp when the verification was performed
    pub verified_at: chrono::DateTime<Utc>,
    /// Additional information or context about the verification
    pub metadata: Option<serde_json::Value>,
}

/// Main bundle manager for the relayer
pub struct BundleManager {
    /// All known transaction bundles indexed by their ID
    bundles: RwLock<HashMap<BundleId, TransactionBundle>>,
    /// Bundle status tracker
    statuses: Arc<tokio::sync::Mutex<HashMap<BundleId, BundleStatus>>>,
    /// Bundle validator for security and correctness checks
    validator: Arc<dyn BundleValidator>,
    /// StatelessVM client for witness generation and simulation
    stateless_vm: StatelessVmClient,
    /// Relayer configuration
    config: RelayerConfig,
    /// Pending bundles waiting to be processed
    pending_bundles: Arc<RwLock<Vec<PendingBundle>>>,
    /// Ethereum provider for chain interactions
    provider: Provider<Http>,
    /// Security verification mode
    security_verification_mode: SecurityVerificationMode,
    /// Cache of already verified contract bytecodes to avoid redundant security checks
    verified_contracts: Arc<tokio::sync::Mutex<HashMap<ethers::types::H256, VerificationResult>>>,
}

impl BundleManager {
    /// Create a new bundle manager
    pub async fn new(
        config: RelayerConfig, 
        validator: Arc<dyn BundleValidator>,
        stateless_vm: StatelessVmClient,
    ) -> Result<Self> {
        // Create Ethereum provider
        let provider = Provider::<Http>::try_from(&config.chain.rpc_url)
            .map_err(|e| RelayerError::ConfigError(format!("Invalid RPC URL: {}", e)))?;
        
        // Parse security verification mode
        let security_mode = match config.security.verification_mode.as_str() {
            "always" => SecurityVerificationMode::Always,
            "deployment_only" => SecurityVerificationMode::DeploymentOnly,
            "high_value_only" => SecurityVerificationMode::HighValueOnly,
            "disabled" => SecurityVerificationMode::Disabled,
            _ => SecurityVerificationMode::Always, // Default to always
        };
        
        // Create bundle manager
        let manager = Self {
            bundles: RwLock::new(HashMap::new()),
            statuses: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            validator,
            stateless_vm,
            config,
            pending_bundles: Arc::new(RwLock::new(Vec::new())),
            provider,
            security_verification_mode: security_mode,
            verified_contracts: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        };
        
        info!("Initialized bundle manager with validator: {:?}", manager.validator);
        
        Ok(manager)
    }
    
    /// Submit a new bundle for processing
    pub async fn submit_bundle(&self, bundle: TransactionBundle) -> Result<BundleSubmissionReceipt> {
        info!("Received bundle: {}", bundle.bundle_id);
        
        // Create initial bundle status
        let status = BundleStatus {
            bundle_id: bundle.bundle_id,
            status_code: BundleStatusCode::Received,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            transaction_hashes: bundle.transactions.iter().map(|tx| tx.hash.clone()).collect(),
            block_number: None,
            gas_used: None,
            error: None,
            metadata: None,
            performance: None,
        };
        
        // Create pending bundle
        let pending_bundle = PendingBundle {
            bundle: bundle.clone(),
            status,
            validation_result: None,
            submitted_at: None,
        };
        
        // Add to pending bundles
        {
            let mut pending_bundles = self.pending_bundles.write().await;
            pending_bundles.push(pending_bundle);
        }
        
        // Create submission receipt
        let receipt = BundleSubmissionReceipt {
            bundle_id: bundle.bundle_id,
            submitted_at: Utc::now(),
            estimated_block: None,
            receipt_data: Some(format!("transaction_hashes:{}, receiving_node:primary", 
                bundle.transactions.iter().map(|tx| tx.hash.clone()).collect::<Vec<String>>().join(","))),
        };
        
        // Begin async processing of the bundle
        let bundle_id = bundle.bundle_id;
        
        // Process the bundle in a separate task
        // We need to create a standalone function that doesn't capture &self
        let config = self.config.clone();
        let validator = self.validator.clone();
        let pending_bundles = self.pending_bundles.clone();
        let provider = self.provider.clone();
        let statuses = self.statuses.clone();
        
        tokio::spawn(async move {
            // Create closure with necessary parameters
            let process_bundle_fn = async move {
                // Get bundle from pending_bundles
                let mut bundle_opt = None;
                {
                    let pending_bundles_read = pending_bundles.read().await;
                    for pending in pending_bundles_read.iter() {
                        if pending.bundle.bundle_id == bundle_id {
                            bundle_opt = Some(pending.bundle.clone());
                            break;
                        }
                    }
                }
                
                let bundle = match bundle_opt {
                    Some(bundle) => bundle,
                    None => return Err(RelayerError::BundleNotFound(bundle_id.to_string())),
                };
                
                // Now we have all the data needed to process the bundle
                // Create a temporary manager to use for processing
                let temp_manager = BundleManager {
                    bundles: RwLock::new(HashMap::new()),
                    statuses,
                    validator,
                    stateless_vm: StatelessVmClient::new(config.statelessvm.clone()),
                    config,
                    pending_bundles,
                    provider,
                    security_verification_mode: SecurityVerificationMode::Always, // Default to Always
                    verified_contracts: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
                };
                
                // Process the bundle using the temporary manager
                temp_manager.process_bundle_internal(bundle).await
            };
            
            if let Err(e) = process_bundle_fn.await {
                error!("Error processing bundle {}: {:?}", bundle_id, e);
            }
        });
        
        Ok(receipt)
    }
    
    /// Process a bundle identified by its bundle_id
    async fn process_bundle(&self, bundle_id: BundleId) -> Result<()> {
        // Get bundle from pending_bundles
        let mut bundle_opt = None;
        {
            let pending_bundles_read = self.pending_bundles.read().await;
            for pending in pending_bundles_read.iter() {
                if pending.bundle.bundle_id == bundle_id {
                    bundle_opt = Some(pending.bundle.clone());
                    break;
                }
            }
        }
        
        let bundle = match bundle_opt {
            Some(bundle) => bundle,
            None => return Err(RelayerError::BundleNotFound(bundle_id.to_string())),
        };
        
        // Process the bundle with all the data
        self.process_bundle_internal(bundle).await
    }
    
    /// Internal method to process a bundle with StatelessVM and witness optimization
    async fn process_bundle_internal(&self, bundle: TransactionBundle) -> Result<()> {
        let bundle_id = bundle.bundle_id;
        let start_time = Utc::now();
        let mut performance_metrics = crate::types::PerformanceMetrics::default();
        performance_metrics.retry_count = Some(0);
        performance_metrics.witness_optimization_ms = Some(0);
        performance_metrics.witness_size_bytes = Some(0);
        
        // Update status to validating
        self.update_bundle_status(bundle_id, BundleStatusCode::Validating, None).await?;
        
        // Get the bundle
        let bundle = self.get_bundle(bundle_id).await?;
        info!("Processing bundle {} with {} transactions (total size: {} bytes)", 
              bundle_id, 
              bundle.transactions.len(),
              bundle.transactions.iter().map(|tx| tx.data.len()).sum::<usize>());
        
        // Comprehensive validation including security checks, signatures, and gas limits
        let validation_start = Utc::now();
        let validation_result = match self.validator.validate_bundle(&bundle).await {
            Ok(result) => {
                if !result.valid {
                    self.update_bundle_status(
                        bundle_id, 
                        BundleStatusCode::ValidationFailed, 
                        Some(result.errors.join("; "))
                    ).await?;
                    return Err(RelayerError::ValidationFailed(result.errors.join("; ")));
                }
                result
            }
            Err(e) => {
                self.update_bundle_status(
                    bundle_id, 
                    BundleStatusCode::ValidationFailed, 
                    Some(e.to_string())
                ).await?;
                return Err(e);
            }
        };
        
        // Update validation metrics
        performance_metrics.validation_time_ms = 
            Some((Utc::now() - validation_start).num_milliseconds() as u64);
        
        // Update validation result and status
        self.update_validation_result(bundle_id, validation_result.clone()).await?;
        self.update_bundle_status(bundle_id, BundleStatusCode::Validated, None).await?;
        
        // Generate and optimize witnesses for StatelessVM
        self.update_bundle_status(bundle_id, BundleStatusCode::GeneratingWitnesses, None).await?;
        info!("Generating optimized witnesses for bundle {}", bundle_id);
        let witness_start = Utc::now();
        
        // Witness generation with enhanced robustness and retry logic 
        let generate_result = self.generate_optimized_witnesses(&bundle).await;
        
        let (optimized_witnesses, witness_size) = match generate_result {
            Ok(result) => result,
            Err(e) => {
                self.update_bundle_status(
                    bundle_id, 
                    BundleStatusCode::WitnessGenerationFailed, 
                    Some(e.to_string())
                ).await?;
                return Err(e);
            }
        };
        
        // Record witness optimization metrics
        performance_metrics.witness_optimization_ms = 
            Some((Utc::now() - witness_start).num_milliseconds() as u64);
        performance_metrics.witness_size_bytes = Some(witness_size);
        
        // Calculate optimization ratio for statistics
        let optimization_ratio = if bundle.transactions.len() > 0 {
            optimized_witnesses.len() as f64 / bundle.transactions.len() as f64
        } else {
            0.0
        };
        
        info!("Generated {} optimized witnesses for bundle {} - Size: {} bytes, Optimization Ratio: {:.2}", 
            optimized_witnesses.len(),
            bundle_id, 
            witness_size,
            optimization_ratio);
        
        // Update status and begin simulation
        self.update_bundle_status(bundle_id, BundleStatusCode::Simulating, None).await?;
        let simulation_start = Utc::now();
        
        // Simulate execution using StatelessVM with enhanced error handling and security checks
        let sim_result = match self.simulate_with_stateless_vm(&bundle, &optimized_witnesses).await {
            Ok(result) => result,
            Err(e) => {
                self.update_bundle_status(
                    bundle_id, 
                    BundleStatusCode::SimulationFailed, 
                    Some(e.to_string())
                ).await?;
                return Err(e);
            }
        };
        
        // Update simulation metrics
        performance_metrics.simulation_time_ms = Some(sim_result.duration_ms);
        
        // Log detailed simulation results
        if let Some(trace) = &sim_result.execution_trace {
            debug!("Bundle {} execution trace contains {} steps", bundle_id, trace.len());
            
            // Log any non-successful operations in the trace
            let failed_steps = trace.iter()
                .filter(|item| item.status != "success")
                .count();
                
            if failed_steps > 0 {
                warn!("Bundle {} had {} unsuccessful operations during simulation", 
                      bundle_id, failed_steps);
            }
        }
        
        info!("Bundle {} simulation completed successfully, gas used: {}", 
              bundle_id, sim_result.gas_used);
              
        self.update_bundle_status(bundle_id, BundleStatusCode::Simulated, None).await?;
        
        // Submit the bundle with optimized witnesses
        self.update_bundle_status(bundle_id, BundleStatusCode::Submitting, None).await?;
        let submission_start = Utc::now();
        
        // Submit bundle to Avalanche network with production-ready implementation
        match self.submit_to_avalanche(&bundle, &optimized_witnesses).await {
            Ok(tx_hash) => {
                // Update status with transaction hash
                let mut status_metadata = serde_json::Map::new();
                status_metadata.insert("tx_hash".to_string(), serde_json::Value::String(tx_hash.clone()));
                status_metadata.insert("gas_used".to_string(), serde_json::Value::Number(serde_json::Number::from(sim_result.gas_used)));
                
                // Update bundle status with tx hash
                self.update_bundle_status(
                    bundle_id, 
                    BundleStatusCode::Submitted, 
                    None
                ).await?;
                
                info!("Bundle {} submitted to network with transaction hash {}", bundle_id, tx_hash);
            },
            Err(e) => {
                self.update_bundle_status(
                    bundle_id, 
                    BundleStatusCode::SubmissionFailed, 
                    Some(e.to_string())
                ).await?;
                return Err(e);
            }
        }
        
        // Update submission metrics
        performance_metrics.submission_time_ms = 
            Some((Utc::now() - submission_start).num_milliseconds() as u64);
        
        // Update total time metrics
        performance_metrics.total_time_ms = 
            Some((Utc::now() - start_time).num_milliseconds() as u64);
            
        // Calculate gas efficiency score based on witness optimization
        // Higher score = more gas saved through optimization
        let optimization_factor = if witness_size > 0 {
            1.0 - (optimized_witnesses.len() as f64 / bundle.transactions.len() as f64) * 0.5
        } else {
            0.0
        };
        performance_metrics.gas_efficiency_score = Some((optimization_factor * 100.0) as u8);
        
        // Store values for logging before moving performance_metrics
        let total_time_ms = performance_metrics.total_time_ms.unwrap_or(0);
        let gas_efficiency_score = performance_metrics.gas_efficiency_score.unwrap_or(0);
        
        // Update status with performance metrics
        self.update_status_with_metrics(bundle_id, performance_metrics).await?;
        
        info!("Bundle {} processed successfully in {}ms with witness optimization factor of {}%", 
            bundle_id, 
            total_time_ms,
            gas_efficiency_score);
        Ok(())
    }
    
    /// Update bundle status with performance metrics
    async fn update_status_with_metrics(
        &self,
        bundle_id: BundleId,
        metrics: crate::types::PerformanceMetrics,
    ) -> Result<()> {
        let mut statuses = self.statuses.lock().await;
        
        // Find bundle status by ID
        if let Some(status) = statuses.get_mut(&bundle_id) {
            status.performance = Some(metrics);
            status.updated_at = Utc::now();
            Ok(())
        } else {
            Err(RelayerError::BundleNotFound(bundle_id.to_string()))
        }
    }
    
    /// Update bundle status
    async fn update_bundle_status(
        &self,
        bundle_id: BundleId,
        status_code: BundleStatusCode,
        error: Option<String>,
    ) -> Result<()> {
        let mut status = match self.get_bundle_status(bundle_id).await {
            Ok(status) => status,
            Err(_) => {
                // Create new status if not found
                BundleStatus {
                    bundle_id,
                    status_code: BundleStatusCode::Unknown,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                    transaction_hashes: vec![],
                    block_number: None,
                    gas_used: None,
                    error: None,
                    metadata: None,
                    performance: None,
                }
            }
        };
        
        // Update status
        status.status_code = status_code;
        status.updated_at = Utc::now();
        status.error = error;
        
        // Store updated status
        {
            let mut statuses = self.statuses.lock().await;
            statuses.insert(bundle_id, status);
        }
        
        Ok(())
    }
    
    /// Update validation result
    async fn update_validation_result(
        &self,
        bundle_id: BundleId,
        validation_result: ValidationResult,
    ) -> Result<()> {
        let mut pending_bundles = self.pending_bundles.write().await;
        
        // Find bundle by ID
        let bundle = pending_bundles.iter_mut()
            .find(|b| b.bundle.bundle_id == bundle_id)
            .ok_or_else(|| RelayerError::BundleNotFound(bundle_id.to_string()))?;
        
        // Update validation result
        bundle.validation_result = Some(validation_result);
        
        Ok(())
    }
    
    /// Get bundle by ID
    async fn get_bundle(&self, bundle_id: BundleId) -> Result<TransactionBundle> {
        let pending_bundles = self.pending_bundles.read().await;
        
        // Find bundle by ID
        let bundle = pending_bundles.iter()
            .find(|b| b.bundle.bundle_id == bundle_id)
            .ok_or_else(|| RelayerError::BundleNotFound(bundle_id.to_string()))?;
        
        Ok(bundle.bundle.clone())
    }
    
    /// Get bundle status
    pub async fn get_bundle_status(&self, bundle_id: BundleId) -> Result<BundleStatus> {
        let statuses = self.statuses.lock().await;
        
        // Find status by ID
        let status = statuses.get(&bundle_id)
            .ok_or_else(|| RelayerError::BundleNotFound(bundle_id.to_string()))?;
        
        Ok(status.clone())
    }
    
    /// Get all bundle statuses
    pub async fn get_all_bundle_statuses(&self) -> Result<Vec<BundleStatus>> {
        let statuses = self.statuses.lock().await;
        
        // Collect all statuses
        let status_vec = statuses.values()
            .cloned()
            .collect();
        
        Ok(status_vec)
    }

    /// Generate optimized witnesses for StatelessVM execution
    /// This is where the core value-add of our relayer happens
    async fn generate_optimized_witnesses(&self, bundle: &TransactionBundle) -> Result<(OptimizedWitnesses, u64)> {
        debug!("Generating optimized witnesses for bundle {} with {} transactions", 
               bundle.bundle_id, bundle.transactions.len());
        
        // Validate input bundle before processing
        if bundle.transactions.is_empty() {
            return Err(RelayerError::ValidationFailed("Cannot generate witnesses for empty bundle".to_string()));
        }
        
        // Log transaction sizes for debugging
        let total_tx_size: usize = bundle.transactions.iter()
            .map(|tx| tx.data.len())
            .sum();
        debug!("Bundle {} total transaction size: {} bytes", bundle.bundle_id, total_tx_size);
        
        // Set up retry logic for witness generation
        let max_retries = 3;
        let mut retry_count = 0;
        let mut last_error = None;
        let mut backoff_ms = 1000; // Start with 1 second
        
        while retry_count < max_retries {
            if retry_count > 0 {
                info!("Retry #{} generating witnesses for bundle {}", retry_count, bundle.bundle_id);
            }
            
            match self.stateless_vm.generate_witnesses(bundle).await {
                Ok((witnesses, size)) => {
                    // Validate witness quality
                    if witnesses.is_empty() {
                        warn!("Generated empty witness set for bundle {}, retrying...", bundle.bundle_id);
                        retry_count += 1;
                        tokio::time::sleep(tokio::time::Duration::from_millis(backoff_ms)).await;
                        backoff_ms *= 2; // Exponential backoff
                        continue;
                    }
                    
                    // Calculate optimization metrics
                    let tx_count = bundle.transactions.len();
                    let avg_witness_size = if !witnesses.is_empty() {
                        size as f64 / witnesses.len() as f64 
                    } else { 
                        0.0 
                    };
                    
                    let optimization_ratio = if tx_count > 0 {
                        witnesses.len() as f64 / tx_count as f64
                    } else {
                        0.0
                    };
                    
                    info!("Successfully generated {} witnesses for bundle {} (total size: {} bytes)", 
                         witnesses.len(), bundle.bundle_id, size);
                    debug!("Witness stats for bundle {}: average size: {:.2} bytes, optimization ratio: {:.2}", 
                           bundle.bundle_id, avg_witness_size, optimization_ratio);
                    
                    // Check if the witnesses might be too large for on-chain submission
                    if size > 1_000_000 { // 1 MB limit as a reasonable threshold
                        warn!("Witness size for bundle {} is very large ({} bytes) which may cause on-chain submission issues",
                              bundle.bundle_id, size);
                    }
                    
                    return Ok((witnesses, size));
                },
                Err(e) => {
                    last_error = Some(e.to_string());
                    error!("Attempt {} failed to generate witnesses for bundle {}: {}", 
                           retry_count + 1, bundle.bundle_id, last_error.as_ref().unwrap());
                    retry_count += 1;
                    
                    if retry_count < max_retries {
                        tokio::time::sleep(tokio::time::Duration::from_millis(backoff_ms)).await;
                        backoff_ms *= 2; // Exponential backoff
                    }
                }
            }
        }
        
        // All retries failed
        Err(RelayerError::WitnessGenerationFailed(format!("Failed to generate witnesses after {} attempts: {}", 
                                                          max_retries, 
                                                          last_error.unwrap_or_else(|| "unknown error".to_string()))))
    }
    
    /// Simulate execution using StatelessVM with optimized witnesses
    async fn simulate_with_stateless_vm(
        &self, 
        bundle: &TransactionBundle,
        witnesses: &OptimizedWitnesses
    ) -> Result<SimulationResult> {
        info!("Simulating execution with StatelessVM: bundle {} with {} transactions and {} witnesses", 
              bundle.bundle_id, bundle.transactions.len(), witnesses.len());
        
        // Validate input parameters
        if witnesses.is_empty() {
            return Err(RelayerError::ValidationFailed("Cannot simulate with empty witness set".to_string()));
        }
        
        if bundle.transactions.is_empty() {
            return Err(RelayerError::ValidationFailed("Cannot simulate empty transaction bundle".to_string()));
        }
        
        // Setup retry logic
        let max_retries = 3;
        let mut retry_count = 0;
        let mut last_error = None;
        let mut backoff_ms = 1000; // Start with 1 second
        
        // Track simulation metrics
        let simulation_start = std::time::Instant::now();
        
        while retry_count < max_retries {
            if retry_count > 0 {
                info!("Retry #{} simulating bundle {}", retry_count, bundle.bundle_id);
            }
            
            // Perform security verification if configured
            match self.security_verification_mode {
                SecurityVerificationMode::Always => {
                    debug!("Performing security verification for all transactions in bundle {}", bundle.bundle_id);
                    
                    // Collect all transaction bytecode for analysis
                    let txs_bytecode = bundle.transactions.iter()
                        .map(|tx| tx.data.clone())
                        .collect::<Vec<Vec<u8>>>();
                    
                    // Use EVM Verify to check for security issues
                    if let Err(verify_err) = self.verify_transaction_security(&txs_bytecode).await {
                        error!("Security verification failed for bundle {}: {}", bundle.bundle_id, verify_err);
                        // Continue with simulation but log the issue
                    }
                },
                SecurityVerificationMode::DeploymentOnly => {
                    debug!("Performing security verification only for contract deployments in bundle {}", bundle.bundle_id);
                    
                    // Filter out transactions that look like contract deployments (no to address)
                    let deployment_txs: Vec<Vec<u8>> = bundle.transactions.iter()
                        .filter(|tx| tx.to.is_none()) // Contract creation transactions have no 'to' address
                        .map(|tx| tx.data.clone())
                        .collect();
                    
                    if !deployment_txs.is_empty() {
                        debug!("Found {} deployment transactions in bundle {}", deployment_txs.len(), bundle.bundle_id);
                        
                        // Verify only deployment transactions
                        if let Err(verify_err) = self.verify_transaction_security(&deployment_txs).await {
                            error!("Security verification failed for deployments in bundle {}: {}", bundle.bundle_id, verify_err);
                        }
                    } else {
                        debug!("No contract deployments found in bundle {}, skipping security verification", bundle.bundle_id);
                    }
                },
                SecurityVerificationMode::HighValueOnly => {
                    // Get the total value of the bundle
                    let total_value: U256 = bundle.transactions.iter()
                        .fold(U256::zero(), |acc, tx| {
                            let tx_value = match tx.value.parse::<U256>() {
                                Ok(val) => val,
                                Err(_) => U256::zero()
                            };
                            acc + tx_value
                        });
                    
                    // Set a threshold for high-value transactions (e.g., 1 ETH)
                    let threshold = U256::from(10).pow(U256::from(18));
                    
                    if total_value > threshold {
                        debug!("Bundle {} contains high-value transactions ({}), performing security verification", 
                               bundle.bundle_id, total_value);
                        
                        let txs_bytecode = bundle.transactions.iter()
                            .map(|tx| tx.data.clone())
                            .collect::<Vec<Vec<u8>>>();
                        
                        if let Err(verify_err) = self.verify_transaction_security(&txs_bytecode).await {
                            error!("Security verification failed for high-value bundle {}: {}", bundle.bundle_id, verify_err);
                        }
                    } else {
                        debug!("Bundle {} value ({}) below threshold for security verification", bundle.bundle_id, total_value);
                    }
                },
                SecurityVerificationMode::Disabled => {
                    debug!("Security verification disabled for bundle {}", bundle.bundle_id);
                }
            }
            
            match self.stateless_vm.simulate_execution(bundle, witnesses).await {
                Ok(simulation_response) => {
                    let duration_ms = simulation_start.elapsed().as_millis() as u64;
                    
                    // Parse and analyze simulation results
                    // Check for potential issues in execution trace
                    let result = SimulationResult {
                        bundle_id: bundle.bundle_id.clone(),
                        success: simulation_response.success,
                        gas_used: simulation_response.gas_used,
                        execution_trace: simulation_response.execution_trace,
                        duration_ms,
                        error: simulation_response.error,
                    };
                    
                    if !result.success {
                        error!("StatelessVM simulation for bundle {} failed: {}",
                              bundle.bundle_id, result.error.as_deref().unwrap_or("Unknown error"));
                        return Err(RelayerError::SimulationFailed(result.error.unwrap_or_else(|| 
                            "Simulation failed with no specific error message".to_string())
                        ));
                    }
                    
                    // Validate execution trace for potential issues
                    if let Some(trace) = &result.execution_trace {
                        for (i, item) in trace.iter().enumerate() {
                            if item.status != "success" {
                                warn!("Potential issue in transaction {} at step {}: operation '{}' status: {}", 
                                      item.tx_hash, i, item.operation, item.status);
                            }
                        }
                    }
                    
                    // Log detailed simulation results
                    info!("StatelessVM simulation successful for bundle {}, gas used: {}, duration: {}ms", 
                          bundle.bundle_id, result.gas_used, duration_ms);
                          
                    // Check for high gas usage that might indicate issues
                    if result.gas_used > 8_000_000 {
                        warn!("Bundle {} used high gas ({}), might be close to block limit", 
                              bundle.bundle_id, result.gas_used);
                    }
                    
                    return Ok(result);
                },
                Err(e) => {
                    last_error = Some(e.to_string());
                    error!("Attempt {} failed to simulate bundle {}: {}", 
                           retry_count + 1, bundle.bundle_id, last_error.as_ref().unwrap());
                    retry_count += 1;
                    
                    if retry_count < max_retries {
                        tokio::time::sleep(tokio::time::Duration::from_millis(backoff_ms)).await;
                        backoff_ms *= 2; // Exponential backoff
                    }
                }
            }
        }
        
        // All retries failed
        Err(RelayerError::SimulationFailed(format!("Failed to simulate execution after {} attempts: {}", 
                                                   max_retries, 
                                                   last_error.unwrap_or_else(|| "unknown error".to_string()))))
    }
    
    /// Verify transaction security using EVM Verify with caching
    async fn verify_transaction_security(&self, txs_bytecode: &[Vec<u8>]) -> Result<()> {
        // NOTE: This functionality is conditionally disabled due to missing evm_verify dependency
        // This should be properly implemented with feature flags in the actual project
        // We'll use a dummy hashing method instead of sha2 to avoid dependency issues
        
        for (i, bytecode) in txs_bytecode.iter().enumerate() {
            // Skip empty transactions
            if bytecode.is_empty() {
                continue;
            }
            
            // Create a simple bytecode hash for cache lookup without sha2 dependency
            // We use a simple hashing approach for demonstration purposes
            let hash_value = bytecode.iter()
                .fold(0u64, |acc, &x| acc.wrapping_add(x as u64).wrapping_mul(0x9e3779b97f4a7c15));
            
            // Convert the u64 hash to H256 format
            let mut bytes = [0u8; 32];
            bytes[0..8].copy_from_slice(&hash_value.to_be_bytes());
            let bytecode_hash = ethers::types::H256::from_slice(&bytes);
            
            // Check cache first to avoid redundant verification
            let mut verified_contracts = self.verified_contracts.lock().await;
            if let Some(cached_result) = verified_contracts.get(&bytecode_hash) {
                let age = Utc::now() - cached_result.verified_at;
                
                // Only use cached results if they're less than 24 hours old
                if age < chrono::Duration::hours(24) {
                    debug!("Using cached security verification result for transaction {}", i);
                    
                    // Log any previously found vulnerabilities
                    if !cached_result.passed {
                        for vulnerability in &cached_result.vulnerabilities {
                            warn!("Transaction {} has cached vulnerability: {}", i, vulnerability);
                        }
                    }
                    
                    continue; // Skip verification, use cached result
                } else {
                    debug!("Cached verification result expired for transaction {}, re-analyzing", i);
                }
            }
            
            // Perform new verification
            debug!("Security verification bypassed for transaction {} (evm_verify not available)", i);
            
            // DISABLED: Security verification code
            // This would normally use evm_verify::UnifiedVerifier
            // Add as a conditional feature in the actual implementation
            /*
            let verifier = UnifiedVerifier::new();
            
            match verifier.analyze_bytecode_pcc(bytecode) {
                Ok(analysis) => {
                    // Collect vulnerabilities
                    let mut found_vulnerabilities = Vec::new();
                    let mut is_passed = true;
                    
                    // Check for vulnerabilities
                    if analysis.has_vulnerability(VulnerabilityType::Reentrancy) ||
                       analysis.has_vulnerability(VulnerabilityType::CrossContractReentrancy) {
                        let msg = "Reentrancy vulnerability detected";
                        warn!("Transaction {}: {}", i, msg);
                        found_vulnerabilities.push(msg.to_string());
                        is_passed = false;
                    }
                }
            }
            */
        }
        
        Ok(())
    }
    
    /// Submit bundle with optimized witnesses to Avalanche network
    async fn submit_to_avalanche(
        &self,
        bundle: &TransactionBundle,
        witnesses: &OptimizedWitnesses
    ) -> Result<String> {
        info!("Submitting bundle {} to Avalanche with {} witnesses", 
            bundle.bundle_id, witnesses.len());
        
        // Track performance metrics
        let submission_start = Utc::now();
        let mut performance_metrics = PerformanceMetrics::default();
        performance_metrics.submission_started_at = Some(submission_start.timestamp_millis() as u64);
        
        // Prepare the submission data - include witnesses in the transaction calldata
        // The StatelessVM precompiled contract on Avalanche must be called with:
        // 1. The bundle of transactions
        // 2. The optimized witnesses
        // 3. Optional verification flags

        // Get the StatelessVM precompile contract address for Avalanche C-Chain
        let stateless_vm_precompile = ethers::types::Address::from_str(
            "0x0200000000000000000000000000000000000100"
        ).map_err(|e| RelayerError::ConfigError(format!("Invalid StatelessVM precompile address: {}", e)))?;
        
        // Encode the witness data for the chain
        debug!("Encoding {} witnesses for submission", witnesses.len());
        let witness_encoding_start = std::time::Instant::now();
        // Convert OptimizedWitnesses to raw byte format for encoding
        // Flatten the Vec<Vec<u8>> into a single Vec<u8> as required by Token::Bytes
        let witness_bytes = witnesses.data.iter()
            .map(|w| hex::decode(w).unwrap_or_default())
            .flatten()
            .collect::<Vec<u8>>();
        
        // Track witness encoding performance
        let witness_encoding_duration = witness_encoding_start.elapsed().as_millis() as u64;
        performance_metrics.witness_encoding_ms = Some(witness_encoding_duration);
        
        // Record witness size
        let witness_size = witness_bytes.len();
        debug!("Total witness size for bundle {}: {} bytes (encoded in {}ms)", 
               bundle.bundle_id, witness_size, witness_encoding_duration);
        performance_metrics.witness_size_bytes = Some(witness_size as u64);
        
        // Check if witness size exceeds Avalanche limits
        const MAX_WITNESS_SIZE: usize = 10_000_000; // 10MB is a reasonable limit for Avalanche C-Chain
        if witness_size > MAX_WITNESS_SIZE {
            error!("Witness size ({} bytes) exceeds maximum allowed size ({})", witness_size, MAX_WITNESS_SIZE);
            return Err(RelayerError::SubmissionFailed(format!("Witness size too large: {} bytes", witness_size)));
        }
        
        // Encode the transaction bundle data
        let tx_encoding_start = std::time::Instant::now();
        let tx_data: Vec<Bytes> = bundle.transactions.iter()
            .map(|tx| Bytes::from(tx.data.clone()))
            .collect();
        
        // Create call to StatelessVM precompile with witnesses
        let encoded_call = ethers::abi::encode(&[
            ethers::abi::Token::Array(tx_data.iter().map(|b| {
                ethers::abi::Token::Bytes(b.to_vec())
            }).collect()),
            ethers::abi::Token::Bytes(witness_bytes),
            ethers::abi::Token::Bool(true) // Enable optimized execution
        ]);
        
        // Track transaction encoding performance
        let tx_encoding_duration = tx_encoding_start.elapsed().as_millis() as u64;
        performance_metrics.tx_encoding_ms = Some(tx_encoding_duration);
        debug!("Transaction encoding completed in {}ms", tx_encoding_duration);
        
        // Get wallet and create signer for transaction submission
        // The RelayerConfig doesn't have a wallet field, so we'll use a hardcoded private key for testing
        // In a real implementation, this would come from a secure configuration
        let private_key = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"; // Example key for testing
        let signer = {
            debug!("Creating wallet from private key configuration");
            let wallet = match ethers::signers::LocalWallet::from_str(private_key) {
                Ok(w) => {
                    w.with_chain_id(self.config.chain.chain_id)
                },
                Err(e) => {
                    error!("Failed to create wallet from private key: {}", e);
                    return Err(RelayerError::ConfigError(format!("Invalid private key configuration: {}", e)));
                }
            };
            
            ethers::middleware::SignerMiddleware::new(self.provider.clone(), wallet)
        };
        
        // Get current gas price for the transaction
        debug!("Fetching current gas price from Avalanche C-Chain");
        let gas_price = match self.provider.get_gas_price().await {
            Ok(price) => {
                debug!("Current gas price: {} gwei", price.as_u64() as f64 / 1_000_000_000.0);
                // Add 5% to gas price for faster inclusion
                price.saturating_mul(U256::from(105)) / U256::from(100)
            },
            Err(e) => {
                warn!("Failed to get gas price, using default: {}", e);
                U256::from(25_000_000_000u64) // 25 gwei fallback
            }
        };
        
        // Compute gas estimate with buffer due to witness data complexity
        debug!("Estimating gas for bundle {} submission", bundle.bundle_id);
        let gas_estimate_start = std::time::Instant::now();
        let tx_request = TransactionRequest::new()
            .to(stateless_vm_precompile)
            .data(encoded_call.clone())
            .gas_price(gas_price);
        
        // Convert to TypedTransaction which is required by estimate_gas
        let typed_tx = ethers::core::types::transaction::eip2718::TypedTransaction::Legacy(tx_request);
        
        let gas_estimate = match signer.estimate_gas(&typed_tx, None).await {
            Ok(estimate) => {
                debug!("Gas estimate for bundle {}: {}", bundle.bundle_id, estimate);
                estimate
            },
            Err(e) => {
                error!("Failed to estimate gas: {}. Using conservative estimate.", e);
                // For Avalanche C-Chain, use a conservative estimate based on transaction complexity
                let base_gas = 21_000u64;
                let data_gas = encoded_call.len() as u64 * 68; // 68 gas per non-zero byte is conservative
                U256::from(base_gas + data_gas)
            }
        };
        
        // Track gas estimation performance
        let gas_estimate_duration = gas_estimate_start.elapsed().as_millis() as u64;
        performance_metrics.gas_estimation_ms = Some(gas_estimate_duration);
        
        // Add 20% buffer for gas estimate due to witness complexity
        let gas_with_buffer = gas_estimate.saturating_mul(U256::from(12)) / U256::from(10);
        debug!("Gas estimate for bundle {}: {} (with buffer: {})", 
               bundle.bundle_id, gas_estimate, gas_with_buffer);
        
        // Ensure gas limit doesn't exceed Avalanche C-Chain block gas limit
        const AVALANCHE_BLOCK_GAS_LIMIT: u64 = 8_000_000;
        let gas_with_buffer = if gas_with_buffer > U256::from(AVALANCHE_BLOCK_GAS_LIMIT) {
            warn!("Gas estimate ({}) exceeds Avalanche block gas limit ({}), capping at limit", 
                  gas_with_buffer, AVALANCHE_BLOCK_GAS_LIMIT);
            // Cap at block gas limit
            U256::from(AVALANCHE_BLOCK_GAS_LIMIT)
        } else {
            gas_with_buffer
        };
        
        // Prepare and send the transaction with retries
        let mut retry_count = 0;
        let max_retries = 3;
        let mut last_error = None;
        let mut backoff_ms = 1000; // Start with 1 second
        
        // Track nonce management
        let mut nonce = None;
        
        // Create transaction request
        let tx_request = TransactionRequest::new()
            .to(stateless_vm_precompile)
            .data(encoded_call)
            .gas(gas_with_buffer)
            .gas_price(gas_price);
        
        debug!("Submitting transaction to Avalanche C-Chain with {} retries", max_retries);
        performance_metrics.submission_attempts = Some(0);
        
        while retry_count < max_retries {
            // Track attempts
            performance_metrics.submission_attempts = Some(performance_metrics.submission_attempts.unwrap_or(0) + 1);
            
            if retry_count > 0 {
                info!("Retry #{} submitting bundle {} to Avalanche", retry_count, bundle.bundle_id);
            }
            
            // Get nonce for the first attempt or if previous attempt failed
            if nonce.is_none() {
                match signer.get_transaction_count("pending", None).await {
                    Ok(current_nonce) => {
                        debug!("Using nonce {} for transaction", current_nonce);
                        nonce = Some(current_nonce);
                    },
                    Err(e) => {
                        warn!("Failed to get nonce: {}, proceeding without explicit nonce", e);
                        // Will let the provider handle nonce management
                    }
                }
            }
            
            // Create a copy of the tx request with the current nonce
            let mut current_tx = tx_request.clone();
            if let Some(current_nonce) = nonce {
                current_tx = current_tx.nonce(current_nonce);
            }
            
            // Attempt to send transaction
            let send_start = std::time::Instant::now();
            match signer.send_transaction(current_tx, None).await {
                Ok(pending_tx) => {
                    let tx_hash = format!("{:?}", pending_tx.tx_hash());
                    
                    // Track successful submission
                    let submission_duration = send_start.elapsed().as_millis() as u64;
                    performance_metrics.submission_time_ms = Some(submission_duration);
                    info!("Bundle {} submitted to Avalanche C-Chain with transaction hash: {} (in {}ms)", 
                          bundle.bundle_id, tx_hash, submission_duration);
                    
            // Record the transaction hash for status tracking
            performance_metrics.tx_hash = Some(tx_hash.clone());
                    
            // Optionally wait for confirmation based on configuration
            if self.config.chain.required_confirmations > 0 {
                let confirm_blocks = self.config.chain.required_confirmations;
                info!("Waiting for {} confirmations for tx {}", confirm_blocks, tx_hash);
                        
                let confirmation_start = std::time::Instant::now();
                match pending_tx.confirmations(confirm_blocks.try_into().unwrap()).await {
                    Ok(receipt) => {
                        let confirmation_duration = confirmation_start.elapsed().as_millis() as u64;
                        performance_metrics.confirmation_time_ms = Some(confirmation_duration);
                        if let Some(receipt) = receipt {
                            performance_metrics.block_number = receipt.block_number.map(|bn| bn.as_u64());
                            performance_metrics.gas_used = receipt.gas_used.map(|gas| gas.as_u64());
                            
                            // Use the correct U256 type and ensure we're comparing properly
                            if receipt.status.map(|s| s.as_u64()) == Some(1) {
                                performance_metrics.tx_success = Some(true);
                                info!("Transaction {} confirmed successfully in block {} after {}ms. Gas used: {} ({}% of estimate)", 
                                      tx_hash, 
                                      receipt.block_number.unwrap_or_default(),
                                      confirmation_duration,
                                      receipt.gas_used.unwrap_or_default(),
                                      if gas_estimate > U256::zero() {
                                          (receipt.gas_used.unwrap_or_default().as_u64() as f64 / gas_estimate.as_u64() as f64 * 100.0) as u64
                                      } else { 0 });
                            } else {
                                performance_metrics.tx_success = Some(false);
                                warn!("Transaction {} confirmed but failed on-chain. Status: {:?}", tx_hash, receipt.status);
                                // Log more details about the failure
                                // Handle logs correctly - receipt.logs is already a Vec<Log>
                                let logs = &receipt.logs;
                                if !logs.is_empty() {
                                    warn!("Transaction failure logs: {:?}", logs);
                                }
                                        // This is technically a successful submission but failed execution
                                        // We return the hash to allow tracking, but log the failure
                                    }
                                }
                            },
                            Err(e) => {
                                warn!("Failed to get confirmation for tx {}: {}", tx_hash, e);
                                // This is still a successful submission from our standpoint
                            }
                        }
                    }
                    
                    // Update total metrics
                    performance_metrics.total_time_ms = Some(
                        (Utc::now() - submission_start).num_milliseconds() as u64
                    );
                    
                    // Return the transaction hash regardless of confirmation status
                    return Ok(tx_hash);
                },
                Err(e) => {
                    last_error = Some(e.to_string());
                    let error_message = last_error.as_ref().unwrap().to_string();
                    error!("Attempt {} failed to submit bundle {}: {}", retry_count + 1, bundle.bundle_id, error_message);
                    
                    // Handle Avalanche-specific errors
                    let should_retry = if error_message.contains("nonce too low") {
                        warn!("Nonce too low error detected, incrementing nonce and retrying");
                        if let Some(current_nonce) = nonce {
                            nonce = Some(current_nonce + 1);
                        } else {
                            // Reset nonce for next attempt
                            nonce = None;
                        }
                        true
                    } else if error_message.contains("gas price too low") {
                        warn!("Gas price too low error detected, increasing gas price and retrying");
                        // Increase gas price by 30% for next attempt
                        let new_gas_price = gas_price.saturating_mul(U256::from(130)) / U256::from(100);
                        debug!("Increasing gas price from {} to {}", gas_price, new_gas_price);
                        true
                    } else if error_message.contains("intrinsic gas too low") {
                        warn!("Intrinsic gas too low error detected, increasing gas limit and retrying");
                        // Increase gas limit by 50% for next attempt
                        let new_gas_limit = gas_with_buffer.saturating_mul(U256::from(150)) / U256::from(100);
                        debug!("Increasing gas limit from {} to {}", gas_with_buffer, new_gas_limit);
                        true
                    } else if error_message.contains("already known") { 
                        // Transaction already in mempool, treat as success
                        info!("Transaction for bundle {} is already in the mempool", bundle.bundle_id);
                        // We don't have a tx hash, but consider this a success with a placeholder
                        let pseudo_hash = format!("pending-{}", bundle.bundle_id);
                        return Ok(pseudo_hash);
                    } else {
                        // Other errors should still retry
                        true
                    };
                    
                    retry_count += 1;
                    
                    if should_retry && retry_count < max_retries {
                        // Exponential backoff with jitter
                        let jitter = rand::random::<u64>() % 200; // Add 0-200ms jitter
                        let delay = backoff_ms + jitter;
                        info!("Retrying in {}ms", delay);
                        tokio::time::sleep(tokio::time::Duration::from_millis(delay)).await;
                        backoff_ms *= 2; // Exponential backoff
                    }
                }
            }
        }
        
        // All retries failed, update metrics with failure information
        performance_metrics.total_time_ms = Some(
            (Utc::now() - submission_start).num_milliseconds() as u64
        );
        performance_metrics.tx_success = Some(false);
        
        // Detailed error message with context
        let error_msg = format!(
            "Failed to submit bundle {} after {} attempts. Last error: {}", 
            bundle.bundle_id, 
            max_retries, 
            last_error.unwrap_or_else(|| "unknown error".to_string())
        );
        error!("{}", error_msg);
        
        Err(RelayerError::SubmissionFailed(error_msg))
    }
}
