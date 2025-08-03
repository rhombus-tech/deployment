use crate::errors::{RelayerError, Result};
use crate::types::{BundleId, TransactionBundle, OptimizedWitnesses, SimulationResult, 
    TransactionSequence, MarketState, MevProtection, StateVerification, FallbackPlan, TransactionStatus, BlockValidityWindow};
use chrono::{DateTime, Utc};
use log::{debug, info, error, warn};
use serde::{Deserialize, Serialize};
use reqwest::Client;
use std::time::Duration;
use std::collections::HashMap;
use async_trait::async_trait;
use base64;

#[async_trait]
pub trait StatelessVmClientTrait: Send + Sync {
    /// Execute a transaction sequence with advanced features
    async fn execute_sequence(&self, sequence: &TransactionSequence) -> Result<Vec<TransactionStatus>>;
    
    /// Execute a transaction sequence and just return the transaction hash
    async fn execute_sequence_and_get_hash(&self, sequence: &TransactionSequence) -> Result<String>;
    
    /// Generate witness for a transaction sequence
    async fn generate_witness(&self, sequence: &TransactionSequence) -> Result<String>;
}

/// StatelessVM client for interacting with the VM
pub struct StatelessVmClient {
    /// HTTP client for API calls
    client: Client,
    /// Base URL for the StatelessVM node
    base_url: String,
    /// Optional auth token for secured endpoints
    auth_token: Option<String>,
}

#[derive(Debug, Serialize)]
struct WitnessGenerationRequest {
    bundle_id: BundleId,
    transactions: Vec<String>,
    execution_context: ExecutionContext,
}

#[derive(Debug, Serialize)]
struct ExecutionContext {
    chain_id: u64,
    block_number: Option<u64>,
    timestamp: u64,
    metadata: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct SimulationRequest {
    bundle_id: BundleId,
    transactions: Vec<String>,
    witnesses: Vec<Vec<u8>>,
    execution_context: ExecutionContext,
}

#[derive(Debug, Deserialize)]
pub struct WitnessGenerationResponse {
    pub bundle_id: BundleId,
    pub witnesses: Vec<Vec<u8>>,
    pub total_size: u64,
    pub optimization_stats: OptimizationStats,
}

#[derive(Debug, Deserialize)]
pub struct OptimizationStats {
    pub shared_states: u64,
    pub unique_states: u64,
    pub compression_ratio: f64,
}

#[derive(Debug, Deserialize)]
pub struct SimulationResponse {
    pub bundle_id: BundleId,
    pub success: bool,
    pub gas_used: u64,
    pub execution_trace: Option<Vec<TraceItem>>,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TraceItem {
    pub tx_hash: String,
    pub step: u32,
    pub operation: String,
    pub gas_used: u64,
    pub status: String,
}

#[derive(Debug, Serialize)]
struct SequenceExecutionRequest {
    sequence_id: String,
    transactions: Vec<String>,
    fallback_plans: Option<Vec<FallbackPlanRequest>>,
    market_conditions: Option<serde_json::Value>,
    mev_protection: Option<MevProtectionRequest>,
    state_verification: Option<Vec<StateVerificationRequest>>,
    execution_context: ExecutionContext,
    timeout_seconds: u64,
    atomic: bool,
}

#[derive(Debug, Serialize)]
struct FallbackPlanRequest {
    transactions: Vec<String>,
    trigger_conditions: serde_json::Value,
    priority: u8,
    description: String,
}

#[derive(Debug, Serialize)]
struct MevProtectionRequest {
    use_private_mempool: bool,
    frontrunning_protection: u8,
    max_slippage_percent: f64,
    monitor_sandwich_attacks: bool,
    use_commit_reveal: bool,
}

#[derive(Debug, Serialize)]
struct StateVerificationRequest {
    contracts: Vec<String>,
    storage_slots: HashMap<String, Vec<String>>,
    balance_requirements: HashMap<String, String>,
    custom_requirements: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct SequenceExecutionResponse {
    pub sequence_id: String,
    pub success: bool,
    pub transaction_statuses: Vec<TransactionExecutionStatus>,
    pub market_state: Option<MarketStateData>,
    pub mev_protection_results: Option<MevProtectionResults>,
    pub state_verification_results: Option<Vec<StateVerificationResult>>,
    pub fallback_executed: bool,
    pub fallback_results: Option<Vec<FallbackExecutionResult>>,
    pub error: Option<String>,
    pub gas_used: u64,
    pub execution_time_ms: u64,
}

#[derive(Debug, Deserialize)]
pub struct TransactionExecutionStatus {
    pub tx_hash: String,
    pub success: bool,
    pub gas_used: u64,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct MarketStateData {
    pub prices: HashMap<String, f64>,
    pub liquidity: HashMap<String, u64>,
    pub gas_price: u64,
    pub volatility: HashMap<String, f64>,
    pub timestamp: u64,
}

#[derive(Debug, Deserialize)]
pub struct MevProtectionResults {
    pub frontrunning_detected: bool,
    pub sandwich_attack_detected: bool,
    pub slippage_exceeded: bool,
    pub protection_actions_taken: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct StateVerificationResult {
    pub step: u32,
    pub success: bool,
    pub verified_contracts: Vec<String>,
    pub failed_verifications: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
pub struct FallbackExecutionResult {
    pub plan_id: u8,
    pub success: bool,
    pub transactions_executed: Vec<String>,
    pub gas_used: u64,
    pub error: Option<String>,
}

#[async_trait]
impl StatelessVmClientTrait for StatelessVmClient {
    async fn execute_sequence(&self, sequence: &TransactionSequence) -> Result<Vec<TransactionStatus>> {
        // This is an implementation of the trait method that delegates to the actual implementation
        self.execute_sequence_internal(sequence).await
    }
    
    async fn execute_sequence_and_get_hash(&self, sequence: &TransactionSequence) -> Result<String> {
        // Implementation that returns just the transaction hash
        let statuses = self.execute_sequence_internal(sequence).await?;
        if !statuses.is_empty() {
            Ok(statuses[0].hash.clone())
        } else {
            Err(RelayerError::InternalError("No transaction hash available".to_string()))
        }
    }
    
    async fn generate_witness(&self, sequence: &TransactionSequence) -> Result<String> {
        // Simple implementation to generate and return a witness
        let bundle = TransactionBundle {
            bundle_id: BundleId::new(),
            transactions: sequence.transactions.clone(),
            submitter: None,
            created_at: chrono::Utc::now(),
            metadata: sequence.metadata.clone(),
            validity_window: BlockValidityWindow {
                start_block: Some(0),
                end_block: Some(100),
            },
        };
        
        let (witnesses, _) = self.generate_witnesses(&bundle).await?;
        // For simplicity, convert the first witness to a base64 string
        if let Some(witness) = witnesses.data.first() {
            Ok(base64::encode(witness))
        } else {
            Err(RelayerError::InternalError("Failed to generate witnesses".to_string()))
        }
    }
}

impl StatelessVmClient {
    /// Create a new StatelessVM client
    pub fn new(config: crate::config::StatelessVmConfig) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_seconds))
            .build()
            .expect("Failed to build HTTP client");
            
        Self {
            client,
            base_url: config.endpoint_url.clone(),
            auth_token: None, // No auth token in config currently
        }
    }
    
    /// Create a new StatelessVM client with a custom HTTP client (for testing)
    #[cfg(test)]
    pub fn with_http_client(base_url: String, client: Client) -> Self {
        Self {
            client,
            base_url,
            auth_token: None,
        }
    }
    
    /// Execute a transaction sequence with advanced features
    /// Handles market condition monitoring, MEV protection, state verification, and fallback plans
    pub async fn execute_sequence_internal(&self, sequence: &TransactionSequence) -> Result<Vec<TransactionStatus>> {
        info!("Executing transaction sequence {} with {} transactions", 
              sequence.sequence_id, sequence.transactions.len());
        
        let execution_start = std::time::Instant::now();
        
        // Convert transaction bytes to hex strings
        let transactions = sequence.transactions.iter()
            .map(|tx| hex::encode(&tx.data))
            .collect();
            
        // Convert fallback plans if present
        let fallback_plans = if let Some(plans) = &sequence.fallback_plans {
            Some(plans.iter().map(|plan| {
                FallbackPlanRequest {
                    transactions: plan.transactions.iter()
                        .map(|tx| hex::encode(&tx.data))
                        .collect(),
                    trigger_conditions: plan.trigger_conditions.clone(),
                    priority: plan.priority,
                    description: plan.description.clone(),
                }
            }).collect())
        } else {
            None
        };
        
        // Convert MEV protection settings if present
        let mev_protection = sequence.mev_protection.as_ref().map(|mev| {
            MevProtectionRequest {
                use_private_mempool: mev.use_private_mempool,
                frontrunning_protection: mev.frontrunning_protection,
                max_slippage_percent: mev.max_slippage_percent,
                monitor_sandwich_attacks: mev.monitor_sandwich_attacks,
                use_commit_reveal: mev.use_commit_reveal,
            }
        });
        
        // Convert state verification requirements if present
        let state_verification = if let Some(verifications) = &sequence.state_verification {
            Some(verifications.iter().map(|verification| {
                StateVerificationRequest {
                    contracts: verification.contracts.clone(),
                    storage_slots: verification.storage_slots.clone(),
                    balance_requirements: verification.balance_requirements.clone(),
                    custom_requirements: verification.custom_requirements.clone(),
                }
            }).collect())
        } else {
            None
        };
        
        // Prepare the request
        let request = SequenceExecutionRequest {
            sequence_id: sequence.sequence_id.clone(),
            transactions,
            fallback_plans,
            market_conditions: sequence.market_conditions.clone(),
            mev_protection,
            state_verification,
            execution_context: ExecutionContext {
                chain_id: 43114, // Avalanche C-Chain
                block_number: None, // Use latest block
                timestamp: chrono::Utc::now().timestamp() as u64,
                metadata: sequence.metadata.clone()
                    .map(|m| serde_json::to_value(m).unwrap_or(serde_json::json!({})))
                    .unwrap_or(serde_json::json!({})),
            },
            timeout_seconds: sequence.timeout_seconds,
            atomic: sequence.atomic,
        };
        
        // Implement retry logic for sequence execution request
        let max_retries = 3;
        let mut retry_count = 0;
        let mut last_error = None;
        let mut backoff_ms = 1000; // Start with 1 second backoff
        
        while retry_count < max_retries {
            if retry_count > 0 {
                debug!("Retry #{} for sequence execution {}", retry_count, sequence.sequence_id);
            }
            
            // Build the request with proper headers
            let mut req_builder = self.client.post(format!("{}/api/v1/sequence/execute", self.base_url))
                .timeout(Duration::from_secs(120)) // Longer timeout for sequence execution
                .json(&request);
                
            if let Some(token) = &self.auth_token {
                req_builder = req_builder.header("Authorization", format!("Bearer {}", token));
            }
            
            // Send the request and process the response
            match req_builder.send().await {
                Ok(response) => {
                    if !response.status().is_success() {
                        let status = response.status();
                        let error_text = response.text().await
                            .unwrap_or_else(|_| "Unable to read error response".to_string());
                            
                        error!("Sequence execution failed: HTTP {}: {}", status, error_text);
                        
                        // Determine if we should retry based on status code
                        let should_retry = match status.as_u16() {
                            408 | 429 | 500 | 502 | 503 | 504 => true, // Retryable server errors
                            _ => false, // Other errors are not retryable
                        };
                        
                        if should_retry && retry_count < max_retries - 1 {
                            last_error = Some(format!("HTTP {}: {}", status, error_text));
                            retry_count += 1;
                            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                            backoff_ms *= 2; // Exponential backoff
                            continue;
                        }
                        
                        return Err(RelayerError::TransactionSequenceError(format!("HTTP {}: {}", status, error_text)));
                    }
                    
                    // Parse the response
                    match response.json::<SequenceExecutionResponse>().await {
                        Ok(sequence_response) => {
                            let duration_ms = execution_start.elapsed().as_millis() as u64;
                            
                            // Handle sequence execution failure
                            if !sequence_response.success {
                                let error_msg = sequence_response.error
                                    .unwrap_or_else(|| "Sequence execution failed without specific error".to_string());
                                
                                // Check if the failure was due to market conditions
                                if sequence_response.market_state.is_some() && 
                                   error_msg.contains("market condition") {
                                    return Err(RelayerError::MarketConditionViolation(error_msg));
                                }
                                
                                // Check if the failure was due to MEV protection
                                if let Some(mev_results) = &sequence_response.mev_protection_results {
                                    if mev_results.frontrunning_detected || 
                                       mev_results.sandwich_attack_detected || 
                                       mev_results.slippage_exceeded {
                                        return Err(RelayerError::MevProtectionFailure(error_msg));
                                    }
                                }
                                
                                // Check if the failure was due to state verification
                                if let Some(verifications) = &sequence_response.state_verification_results {
                                    if verifications.iter().any(|v| !v.success) {
                                        return Err(RelayerError::StateVerificationFailed(error_msg));
                                    }
                                }
                                
                                // Check if a fallback was executed
                                if sequence_response.fallback_executed {
                                    if let Some(fallbacks) = &sequence_response.fallback_results {
                                        // If any fallback failed, report that
                                        if fallbacks.iter().any(|f| !f.success) {
                                            return Err(RelayerError::FallbackExecutionFailed(error_msg));
                                        }
                                        
                                        // Otherwise, log that fallbacks were executed successfully
                                        info!("Transaction sequence {} failed but fallbacks executed successfully", 
                                              sequence.sequence_id);
                                    }
                                } else {
                                    // No fallbacks were executed, return the sequence error
                                    return Err(RelayerError::TransactionSequenceError(error_msg));
                                }
                            }
                            
                            // Log market state if available
                            if let Some(market_state) = &sequence_response.market_state {
                                debug!("Market state during execution: {} price entries, gas price: {}", 
                                       market_state.prices.len(), market_state.gas_price);
                            }
                            
                            // Log MEV protection results if available
                            if let Some(mev_results) = &sequence_response.mev_protection_results {
                                if !mev_results.protection_actions_taken.is_empty() {
                                    info!("MEV protection actions taken: {}", 
                                          mev_results.protection_actions_taken.join(", "));
                                }
                            }
                            
                            // Log state verification results if available
                            if let Some(verifications) = &sequence_response.state_verification_results {
                                debug!("State verification results: {} steps verified", verifications.len());
                                
                                for (i, verification) in verifications.iter().enumerate() {
                                    if !verification.success {
                                        if let Some(failures) = &verification.failed_verifications {
                                            for (contract, reason) in failures {
                                                warn!("State verification failed at step {}: contract {} - {}", 
                                                      i, contract, reason);
                                            }
                                        }
                                    }
                                }
                            }
                            
                            // Convert to our TransactionStatus type
                            let transaction_statuses = sequence_response.transaction_statuses.iter()
                                .map(|status| {
                                    crate::types::TransactionStatus {
                                        hash: status.tx_hash.clone(),
                                        status_code: if status.success {
                                            crate::types::TransactionStatusCode::Mined
                                        } else {
                                            crate::types::TransactionStatusCode::Failed
                                        },
                                        gas_used: Some(status.gas_used.to_string()),
                                        error: status.error.clone(),
                                        block_number: None,
                                        transaction_index: None,
                                    }
                                })
                                .collect();
                                
                            info!("Sequence {} execution completed in {}ms, gas used: {}", 
                                  sequence.sequence_id, duration_ms, sequence_response.gas_used);
                                  
                            return Ok(transaction_statuses);
                        },
                        Err(e) => {
                            error!("Failed to parse sequence execution response: {}", e);
                            last_error = Some(format!("Failed to parse response: {}", e));
                            retry_count += 1;
                            
                            if retry_count < max_retries {
                                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                                backoff_ms *= 2; // Exponential backoff
                                continue;
                            }
                            
                            return Err(RelayerError::NetworkError(format!("Failed to parse sequence execution response after {} attempts: {}", 
                                                                           max_retries, e)));
                        }
                    }
                },
                Err(e) => {
                    error!("Network error during sequence execution request: {}", e);
                    last_error = Some(format!("Network error: {}", e));
                    retry_count += 1;
                    
                    if retry_count < max_retries {
                        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                        backoff_ms *= 2; // Exponential backoff
                        continue;
                    }
                    
                    return Err(RelayerError::NetworkError(format!("Failed to send sequence execution request after {} attempts: {}", 
                                                                   max_retries, e)));
                }
            }
        }
        
        // This code shouldn't be reached due to the return statements in the loop,
        // but we provide a fallback error just in case
        Err(RelayerError::TransactionSequenceError(format!("Failed to execute sequence after {} attempts: {}", 
                                                          max_retries, 
                                                          last_error.unwrap_or_else(|| "Unknown error".to_string()))))
    }
    
    /// Generate optimized witnesses for a transaction bundle
    pub async fn generate_witnesses(&self, bundle: &TransactionBundle) -> Result<(OptimizedWitnesses, u64)> {
        info!("Requesting witness generation for bundle {}", bundle.bundle_id);
        
        let generation_start = std::time::Instant::now();
        
        // Convert transaction bytes to hex strings
        let transactions = bundle.transactions.iter()
            .map(|tx| hex::encode(&tx.data))
            .collect();
            
        // Prepare the request
        let request = WitnessGenerationRequest {
            bundle_id: bundle.bundle_id.clone(),
            transactions,
            execution_context: ExecutionContext {
                chain_id: 43114, // Avalanche C-Chain
                block_number: None, // Use latest block
                timestamp: chrono::Utc::now().timestamp() as u64,
                metadata: bundle.metadata.clone()
                    .map(|m| serde_json::to_value(m).unwrap_or(serde_json::json!({})))
                    .unwrap_or(serde_json::json!({})),
            },
        };
        
        // Implement retry logic for witness generation request
        let max_retries = 3;
        let mut retry_count = 0;
        let mut last_error = None;
        let mut backoff_ms = 1000; // Start with 1 second backoff
        
        while retry_count < max_retries {
            if retry_count > 0 {
                debug!("Retry #{} for witness generation of bundle {}", retry_count, bundle.bundle_id);
            }
            
            // Build the request with proper headers
            let mut req_builder = self.client.post(format!("{}/api/v1/witnesses/generate", self.base_url))
                .timeout(Duration::from_secs(60)) // Add timeout - witness generation can take longer
                .json(&request);
                
            if let Some(token) = &self.auth_token {
                req_builder = req_builder.header("Authorization", format!("Bearer {}", token));
            }
            
            // Send the request and process the response
            match req_builder.send().await {
                Ok(response) => {
                    if !response.status().is_success() {
                        let status = response.status();
                        let error_text = response.text().await
                            .unwrap_or_else(|_| "Unable to read error response".to_string());
                            
                        error!("Witness generation failed: HTTP {}: {}", status, error_text);
                        
                        // Determine if we should retry based on status code
                        let should_retry = match status.as_u16() {
                            408 | 429 | 500 | 502 | 503 | 504 => true, // Retryable server errors
                            _ => false, // Other errors are not retryable
                        };
                        
                        if should_retry && retry_count < max_retries - 1 {
                            last_error = Some(format!("HTTP {}: {}", status, error_text));
                            retry_count += 1;
                            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                            backoff_ms *= 2; // Exponential backoff
                            continue;
                        }
                        
                        return Err(RelayerError::WitnessGenerationFailed(format!("HTTP {}: {}", status, error_text)));
                    }
                    
                    // Parse the response
                    match response.json::<WitnessGenerationResponse>().await {
                        Ok(witness_response) => {
                            let duration_ms = generation_start.elapsed().as_millis() as u64;
                            
                            // Validate witness response data
                            if witness_response.witnesses.is_empty() {
                                warn!("Received empty witness set for bundle {}", bundle.bundle_id);
                                if retry_count < max_retries - 1 {
                                    retry_count += 1;
                                    last_error = Some("Received empty witness set".to_string());
                                    tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                                    backoff_ms *= 2; // Exponential backoff
                                    continue;
                                }
                                return Err(RelayerError::WitnessGenerationFailed("Received empty witness set".to_string()));
                            }
                            
                            info!("Successfully generated {} witnesses totaling {} bytes for bundle {} in {}ms", 
                                  witness_response.witnesses.len(), 
                                  witness_response.total_size, 
                                  bundle.bundle_id,
                                  duration_ms);
                                  
                            // Log optimization details
                            debug!("Optimization stats: shared states: {}, unique states: {}, compression ratio: {:.2}", 
                                    witness_response.optimization_stats.shared_states,
                                    witness_response.optimization_stats.unique_states,
                                    witness_response.optimization_stats.compression_ratio);
                                    
                            // Check compression ratio - if it's too low, log a warning but don't fail
                            if witness_response.optimization_stats.compression_ratio < 1.2 {
                                warn!("Low witness compression ratio ({:.2}) for bundle {}", 
                                      witness_response.optimization_stats.compression_ratio,
                                      bundle.bundle_id);
                            }
                            
                            // Convert from Vec<Vec<u8>> to OptimizedWitnesses
                            let optimized_witnesses = crate::types::OptimizedWitnesses {
                                data: witness_response.witnesses.iter()
                                    .map(|w| hex::encode(w))
                                    .collect(),
                                total_size: witness_response.total_size,
                            };
                            return Ok((optimized_witnesses, witness_response.total_size));
                        },
                        Err(e) => {
                            error!("Failed to parse witness generation response: {}", e);
                            last_error = Some(format!("Failed to parse response: {}", e));
                            retry_count += 1;
                            
                            if retry_count < max_retries {
                                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                                backoff_ms *= 2; // Exponential backoff
                                continue;
                            }
                            
                            return Err(RelayerError::NetworkError(format!("Failed to parse witness generation response after {} attempts: {}", 
                                                                           max_retries, e)));
                        }
                    }
                },
                Err(e) => {
                    error!("Network error during witness generation request: {}", e);
                    last_error = Some(format!("Network error: {}", e));
                    retry_count += 1;
                    
                    if retry_count < max_retries {
                        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                        backoff_ms *= 2; // Exponential backoff
                        continue;
                    }
                    
                    return Err(RelayerError::NetworkError(format!("Failed to send witness generation request after {} attempts: {}", 
                                                                   max_retries, e)));
                }
            }
        }
        
        // This code shouldn't be reached due to the return statements in the loop,
        // but we provide a fallback error just in case
        Err(RelayerError::WitnessGenerationFailed(format!("Failed to generate witnesses after {} attempts: {}", 
                                                          max_retries, 
                                                          last_error.unwrap_or_else(|| "Unknown error".to_string()))))
    }
    
    /// Simulate execution using StatelessVM with optimized witnesses
    /// Returns a detailed SimulationResult with execution traces and performance metrics
    pub async fn simulate_execution(&self, bundle: &TransactionBundle, witnesses: &OptimizedWitnesses) -> Result<SimulationResult> {
        info!("Simulating execution with StatelessVM for bundle {}", bundle.bundle_id);
        
        let simulation_start = std::time::Instant::now();
        
        // Convert transaction bytes to hex strings
        let transactions = bundle.transactions.iter()
            .map(|tx| hex::encode(&tx.data))
            .collect();
            
        // Prepare the request
        let request = SimulationRequest {
            bundle_id: bundle.bundle_id.clone(),
            transactions,
            // Convert from OptimizedWitnesses to Vec<Vec<u8>>
            witnesses: witnesses.data.iter()
                .map(|w| hex::decode(w).unwrap_or_default())
                .collect(),
            execution_context: ExecutionContext {
                chain_id: 43114, // Avalanche C-Chain
                block_number: None, // Use latest block
                timestamp: chrono::Utc::now().timestamp() as u64,
                metadata: bundle.metadata.clone()
                    .map(|m| serde_json::to_value(m).unwrap_or(serde_json::json!({})))
                    .unwrap_or(serde_json::json!({})),
            },
        };
        
        // Implement retry logic for simulation request
        let max_retries = 3;
        let mut retry_count = 0;
        let mut last_error = None;
        let mut backoff_ms = 1000; // Start with 1 second backoff
        
        while retry_count < max_retries {
            if retry_count > 0 {
                debug!("Retry #{} for simulation of bundle {}", retry_count, bundle.bundle_id);
            }
            
            // Build the request with proper headers
            let mut req_builder = self.client.post(format!("{}/api/v1/simulate", self.base_url))
                .timeout(Duration::from_secs(30)) // Add timeout
                .json(&request);
                
            if let Some(token) = &self.auth_token {
                req_builder = req_builder.header("Authorization", format!("Bearer {}", token));
            }
            
            // Send the request and process the response
            match req_builder.send().await {
                Ok(response) => {
                    if !response.status().is_success() {
                        let status = response.status();
                        let error_text = response.text().await
                            .unwrap_or_else(|_| "Unable to read error response".to_string());
                            
                        error!("Simulation failed: HTTP {}: {}", status, error_text);
                        
                        // Determine if we should retry based on status code
                        let should_retry = match status.as_u16() {
                            408 | 429 | 500 | 502 | 503 | 504 => true, // Retryable server errors
                            _ => false, // Other errors are not retryable
                        };
                        
                        if should_retry && retry_count < max_retries - 1 {
                            last_error = Some(format!("HTTP {}: {}", status, error_text));
                            retry_count += 1;
                            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                            backoff_ms *= 2; // Exponential backoff
                            continue;
                        }
                        
                        return Err(RelayerError::SimulationFailed(format!("HTTP {}: {}", status, error_text)));
                    }
                    
                    // Parse the response
                    match response.json::<SimulationResponse>().await {
                        Ok(simulation_response) => {
                            let duration_ms = simulation_start.elapsed().as_millis() as u64;
                            
                            // Create a detailed simulation result
                            // Convert from client::TraceItem to types::TraceItem
                            let converted_trace = match &simulation_response.execution_trace {
                                None => None,
                                Some(trace) if trace.is_empty() => None,
                                Some(trace) => Some(
                                    trace.iter()
                                        .map(|item| crate::types::TraceItem {
                                            tx_hash: item.tx_hash.clone(),
                                            step: item.step,
                                            operation: item.operation.clone(),
                                            gas_used: item.gas_used,
                                            status: item.status.clone(),
                                        })
                                        .collect()
                                ),
                            };

                            let result = SimulationResult {
                                bundle_id: bundle.bundle_id.clone(),
                                success: simulation_response.success,
                                gas_used: simulation_response.gas_used,
                                execution_trace: converted_trace,
                                duration_ms,
                                error: simulation_response.error,
                            };
                            
                            // Log appropriate message based on success/failure
                            if !result.success {
                                error!("StatelessVM simulation failed for bundle {}: {}", 
                                    bundle.bundle_id, 
                                    result.error.as_deref().unwrap_or("Unknown error"));
                                
                                return Err(RelayerError::SimulationFailed(
                                    result.error.unwrap_or_else(|| "StatelessVM execution failed".to_string())
                                ));
                            }
                            
                            // Log execution analysis
                            if let Some(trace) = &result.execution_trace {
                                debug!("Execution trace contains {} operations for bundle {}", 
                                      trace.len(), bundle.bundle_id);
                                      
                                // Look for any warnings in the execution trace
                                let warnings = trace.iter()
                                    .filter(|item| item.status != "success")
                                    .collect::<Vec<_>>();
                                    
                                if !warnings.is_empty() {
                                    warn!("Found {} potential issues in execution trace for bundle {}", 
                                          warnings.len(), bundle.bundle_id);
                                          
                                    for (i, item) in warnings.iter().enumerate().take(5) { // Show at most 5 warnings
                                        warn!("Trace issue #{}: operation '{}' status: {}", 
                                              i + 1, item.operation, item.status);
                                    }
                                    
                                    if warnings.len() > 5 {
                                        warn!("...and {} more issues", warnings.len() - 5);
                                    }
                                }
                            }
                            
                            info!("StatelessVM simulation successful for bundle {}, gas used: {}, duration: {}ms", 
                                bundle.bundle_id, result.gas_used, duration_ms);
                                
                            return Ok(result);
                        },
                        Err(e) => {
                            error!("Failed to parse simulation response: {}", e);
                            last_error = Some(format!("Failed to parse response: {}", e));
                            retry_count += 1;
                            
                            if retry_count < max_retries {
                                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                                backoff_ms *= 2; // Exponential backoff
                                continue;
                            }
                            
                            return Err(RelayerError::NetworkError(format!("Failed to parse simulation response after {} attempts: {}", 
                                                                         max_retries, e)));
                        }
                    }
                },
                Err(e) => {
                    error!("Network error during simulation request: {}", e);
                    last_error = Some(format!("Network error: {}", e));
                    retry_count += 1;
                    
                    if retry_count < max_retries {
                        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                        backoff_ms *= 2; // Exponential backoff
                        continue;
                    }
                    
                    return Err(RelayerError::NetworkError(format!("Failed to send simulation request after {} attempts: {}", 
                                                                 max_retries, e)));
                }
            }
        }
        
        // This code shouldn't be reached due to the return statements in the loop,
        // but we provide a fallback error just in case
        Err(RelayerError::SimulationFailed(format!("Failed to simulate after {} attempts: {}", 
                                                  max_retries, 
                                                  last_error.unwrap_or_else(|| "Unknown error".to_string()))))
    }
}
