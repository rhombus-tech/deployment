use crate::prelude::*;
use crate::transaction::{TransactionSequence, Transaction, TransactionStatus, MarketState, FallbackPlan};
use crate::core::StatelessVM;
use crate::errors::VMError;
use crate::realtime::{RealTimeProcessor, RealTimeConfig, RealTimeStatusResponse, ProcessingMode};

// Re-export these explicitly to avoid proc-macro resolution issues
use serde::{Serialize, Deserialize};
use thiserror::Error;

use std::sync::Arc;
use tokio::sync::RwLock;
use axum::{
    routing::{get, post},
    Router, Json, extract::State, http::StatusCode,
};
use ethereum_types::Address;
use axum::response::{IntoResponse, Response};
use std::collections::HashMap;
use serde_json::Value;

// API Error types
#[derive(Debug, Error)]
pub enum ApiError {
    #[error("VM error: {0}")]
    VMError(#[from] VMError),
    
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
    
    #[error("Market condition violation: {0}")]
    MarketConditionViolation(String),
    
    #[error("MEV protection failure: {0}")]
    MevProtectionFailure(String),
    
    #[error("State verification failed: {0}")]
    StateVerificationFailed(String),
    
    #[error("Internal server error: {0}")]
    InternalError(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            ApiError::VMError(ref e) => (StatusCode::BAD_REQUEST, e.to_string()),
            ApiError::InvalidRequest(ref e) => (StatusCode::BAD_REQUEST, e.to_string()),
            ApiError::MarketConditionViolation(ref e) => (StatusCode::BAD_REQUEST, e.to_string()),
            ApiError::MevProtectionFailure(ref e) => (StatusCode::BAD_REQUEST, e.to_string()),
            ApiError::StateVerificationFailed(ref e) => (StatusCode::BAD_REQUEST, e.to_string()),
            ApiError::InternalError(ref e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        };
        
        (status, Json(serde_json::json!({ "error": error_message }))).into_response()
    }
}

pub type Result<T> = std::result::Result<T, ApiError>;

// API Context - holds StatelessVM instance
pub struct ApiContext {
    pub vm: Arc<RwLock<StatelessVM>>,
}

// API Request/Response types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessGenerationRequest {
    pub bundle_id: String,
    pub transactions: Vec<String>,
    pub execution_context: ExecutionContext,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionContext {
    pub chain_id: u64,
    pub block_number: Option<u64>,
    pub timestamp: u64,
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessGenerationResponse {
    pub bundle_id: String,
    pub witnesses: Vec<Vec<u8>>,
    pub total_size: u64,
    pub optimization_stats: OptimizationStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationStats {
    pub shared_states: u64,
    pub unique_states: u64,
    pub compression_ratio: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationRequest {
    pub bundle_id: String,
    pub transactions: Vec<String>,
    pub witnesses: Vec<Vec<u8>>,
    pub execution_context: ExecutionContext,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationResponse {
    pub bundle_id: String,
    pub success: bool,
    pub gas_used: u64,
    pub execution_trace: Option<Vec<TraceItem>>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceItem {
    pub tx_hash: String,
    pub step: u32,
    pub operation: String,
    pub gas_used: u64,
    pub status: String,
}

// New types for sequence execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequenceExecutionRequest {
    pub sequence_id: String,
    pub transactions: Vec<String>,
    pub fallback_plans: Option<Vec<FallbackPlanRequest>>,
    pub market_conditions: Option<Value>,
    pub mev_protection: Option<MevProtectionRequest>,
    pub state_verification: Option<Vec<StateVerificationRequest>>,
    pub execution_context: ExecutionContext,
    pub timeout_seconds: u64,
    pub atomic: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FallbackPlanRequest {
    pub transactions: Vec<String>,
    pub trigger_conditions: Value,
    pub priority: u8,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MevProtectionRequest {
    pub use_private_mempool: bool,
    pub frontrunning_protection: u8,
    pub max_slippage_percent: f64,
    pub monitor_sandwich_attacks: bool,
    pub use_commit_reveal: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateVerificationRequest {
    pub contracts: Vec<String>,
    pub storage_slots: HashMap<String, Vec<String>>,
    pub balance_requirements: HashMap<String, String>,
    pub custom_requirements: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionExecutionStatus {
    pub tx_hash: String,
    pub success: bool,
    pub gas_used: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketStateData {
    pub prices: HashMap<String, f64>,
    pub liquidity: HashMap<String, u64>,
    pub gas_price: u64,
    pub volatility: HashMap<String, f64>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MevProtectionResults {
    pub frontrunning_detected: bool,
    pub sandwich_attack_detected: bool,
    pub slippage_exceeded: bool,
    pub protection_actions_taken: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateVerificationResult {
    pub step: u32,
    pub success: bool,
    pub verified_contracts: Vec<String>,
    pub failed_verifications: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FallbackExecutionResult {
    pub plan_id: u8,
    pub success: bool,
    pub transactions_executed: Vec<String>,
    pub gas_used: u64,
    pub error: Option<String>,
}

// API Handler implementations
async fn health_check() -> &'static str {
    "StatelessVM API is running"
}

async fn generate_witnesses(
    State(ctx): State<Arc<ApiContext>>,
    Json(request): Json<WitnessGenerationRequest>,
) -> Result<Json<WitnessGenerationResponse>> {
    // Simplified implementation - in a real-world scenario, this would
    // convert the request to proper Transaction objects and use the VM
    
    let mut transactions = Vec::new();
    for tx_hex in request.transactions {
        let tx_data = hex::decode(&tx_hex)
            .map_err(|e| ApiError::InvalidRequest(format!("Invalid transaction hex: {}", e)))?;
        
        // Simple implementation - in real world, would parse tx_data properly
        let tx = Transaction::new(
            Address::zero(), // sender
            Some(Address::zero()), // receiver
            0.into(), // value
            tx_data, // data
            100000.into(), // gas
            1000000000.into(), // gas price
            0, // nonce
        );
        
        transactions.push(tx);
    }
    
    // Mock optimization stats
    let optimization_stats = OptimizationStats {
        shared_states: 5,
        unique_states: 10,
        compression_ratio: 2.5,
    };
    
    // Mock response with dummy witnesses
    let witnesses: Vec<Vec<u8>> = transactions.iter()
        .map(|tx| tx.data.clone())
        .collect();
    
    let total_size = witnesses.iter().map(|w| w.len() as u64).sum();
    
    Ok(Json(WitnessGenerationResponse {
        bundle_id: request.bundle_id,
        witnesses,
        total_size,
        optimization_stats,
    }))
}

async fn simulate_execution(
    State(ctx): State<Arc<ApiContext>>,
    Json(request): Json<SimulationRequest>,
) -> Result<Json<SimulationResponse>> {
    // Simplified implementation - in a real-world scenario, this would
    // convert the request to proper Transaction objects and use the VM
    
    let mut transactions = Vec::new();
    for tx_hex in request.transactions {
        let tx_data = hex::decode(&tx_hex)
            .map_err(|e| ApiError::InvalidRequest(format!("Invalid transaction hex: {}", e)))?;
        
        // Simple implementation - in real world, would parse tx_data properly
        let tx = Transaction::new(
            Address::zero(), // sender
            Some(Address::zero()), // receiver
            0.into(), // value
            tx_data, // data
            100000.into(), // gas
            1000000000.into(), // gas price
            0, // nonce
        );
        
        transactions.push(tx);
    }
    
    // In a real implementation, would use the VM to execute the transactions
    // using the provided witnesses
    
    // Mock response
    Ok(Json(SimulationResponse {
        bundle_id: request.bundle_id,
        success: true,
        gas_used: 100000,
        execution_trace: Some(vec![
            TraceItem {
                tx_hash: "0x1234567890abcdef".to_string(),
                step: 1,
                operation: "CALL".to_string(),
                gas_used: 50000,
                status: "success".to_string(),
            }
        ]),
        error: None,
    }))
}

async fn execute_sequence(
    State(ctx): State<Arc<ApiContext>>,
    Json(request): Json<SequenceExecutionRequest>,
) -> Result<Json<SequenceExecutionResponse>> {
    let execution_start = std::time::Instant::now();
    
    // Convert request transactions to Transaction objects
    let mut transactions = Vec::new();
    for (i, tx_hex) in request.transactions.iter().enumerate() {
        let tx_data = hex::decode(tx_hex)
            .map_err(|e| ApiError::InvalidRequest(format!("Invalid transaction hex at index {}: {}", i, e)))?;
        
        // Simple implementation - in real world, would parse tx_data properly
        let tx = Transaction::new(
            Address::zero(), // sender
            Some(Address::zero()), // receiver
            0.into(), // value
            tx_data, // data
            100000.into(), // gas
            1000000000.into(), // gas price
            i as u64, // nonce
        );
        
        transactions.push(tx);
    }
    
    // Convert fallback plans if present
    let fallback_plans = if let Some(plans) = request.fallback_plans {
        let mut converted_plans = Vec::new();
        
        for plan in plans {
            let mut fallback_txs = Vec::new();
            for (i, tx_hex) in plan.transactions.iter().enumerate() {
                let tx_data = hex::decode(tx_hex)
                    .map_err(|e| ApiError::InvalidRequest(format!("Invalid fallback transaction hex: {}", e)))?;
                
                let tx = Transaction::new(
                    Address::zero(), // sender
                    Some(Address::zero()), // receiver
                    0.into(), // value
                    tx_data, // data
                    100000.into(), // gas
                    1000000000.into(), // gas price
                    i as u64, // nonce
                );
                
                fallback_txs.push(tx);
            }
            
            let fallback_plan = FallbackPlan {
                tx_index: 0, // Use appropriate index from plan if available
                alternate_transactions: fallback_txs,
                error_types: vec![crate::transaction::FallbackErrorType::Any], // Use appropriate error types
                abort_on_fallback: false, // Set based on plan settings if available
            };
            
            converted_plans.push(fallback_plan);
        }
        
        Some(converted_plans)
    } else {
        None
    };
    
    // Create the transaction sequence
    let mut sequence = TransactionSequence::new(transactions, request.atomic);
    
    // Add fallback plans if present
    if let Some(plans) = fallback_plans {
        for plan in plans {
            sequence = sequence.with_fallback_plan(plan);
        }
    }
    
    // Add market conditions if present
    if let Some(market_conditions) = request.market_conditions {
        // Create the proper MarketConditions object
        let market_conditions_obj = crate::transaction::MarketConditions {
            price_conditions: Vec::new(),
            gas_conditions: crate::transaction::GasCondition {
                max_gas_price: None,
                max_gas_price_increase_percent: None,
            },
            block_conditions: crate::transaction::BlockCondition {
                max_blocks: None,
                max_time_seconds: None,
            },
            on_violation: crate::transaction::ConditionViolationAction::Abort,
        };
        sequence = sequence.with_market_conditions(market_conditions_obj);
    }
    
    // Add MEV protection if present
    if let Some(mev) = request.mev_protection {
        let settings = crate::transaction::MevProtectionSettings {
            enabled: true,
            use_private_tx_pool: mev.use_private_mempool,
            // Convert u8 to proper enum variant
            frontrunning_protection: match mev.frontrunning_protection {
                0 => crate::transaction::FrontrunningProtection::None,
                1 => crate::transaction::FrontrunningProtection::Basic,
                2 => crate::transaction::FrontrunningProtection::CommitReveal,
                3 => crate::transaction::FrontrunningProtection::Full,
                _ => crate::transaction::FrontrunningProtection::None,
            },
            max_slippage_percent: mev.max_slippage_percent as u8,
        };
        sequence = sequence.with_mev_protection(settings);
    }
    
    // Convert state verification requirements if present
    if let Some(verifications) = request.state_verification {
        for verification in verifications {
            // In a real implementation, would convert the verification requirements
            // and add them to the sequence
            let config = crate::transaction::StateVerificationConfig {
                verify_between_steps: true,
                intermediate_verification_level: Some(crate::types::VerificationLevel::Standard),
                state_predicates: Vec::new(), // Add predicates if needed
            };
            sequence = sequence.with_state_verification(config);
        }
    }
    
    // In a real implementation, would execute the sequence using the VM
    // For now, we'll just create a mock response
    
    // Mock market state data
    let market_state = MarketStateData {
        prices: [
            ("0x1234567890abcdef".to_string(), 1500.0),
            ("0xfedcba0987654321".to_string(), 25.5),
        ].iter().cloned().collect(),
        liquidity: [
            ("0x1234567890abcdef".to_string(), 1000000),
            ("0xfedcba0987654321".to_string(), 500000),
        ].iter().cloned().collect(),
        gas_price: 20000000000,
        volatility: [
            ("0x1234567890abcdef".to_string(), 0.05),
            ("0xfedcba0987654321".to_string(), 0.1),
        ].iter().cloned().collect(),
        timestamp: request.execution_context.timestamp,
    };
    
    // Mock MEV protection results
    let mev_protection_results = MevProtectionResults {
        frontrunning_detected: false,
        sandwich_attack_detected: false,
        slippage_exceeded: false,
        protection_actions_taken: vec!["Used private mempool".to_string()],
    };
    
    // Mock state verification results
    let state_verification_results = vec![
        StateVerificationResult {
            step: 0,
            success: true,
            verified_contracts: vec!["0x1234567890abcdef".to_string()],
            failed_verifications: None,
        },
        StateVerificationResult {
            step: 1,
            success: true,
            verified_contracts: vec!["0xfedcba0987654321".to_string()],
            failed_verifications: None,
        },
    ];
    
    // Mock transaction statuses
    let transaction_statuses = request.transactions.iter().enumerate()
        .map(|(i, _)| TransactionExecutionStatus {
            tx_hash: format!("0x{:016x}", i),
            success: true,
            gas_used: 75000 + (i as u64 * 10000),
            error: None,
        })
        .collect();
    
    let duration_ms = execution_start.elapsed().as_millis() as u64;
    
    // Create the response
    Ok(Json(SequenceExecutionResponse {
        sequence_id: request.sequence_id,
        success: true,
        transaction_statuses,
        market_state: Some(market_state),
        mev_protection_results: Some(mev_protection_results),
        state_verification_results: Some(state_verification_results),
        fallback_executed: false,
        fallback_results: None,
        error: None,
        gas_used: 250000,
        execution_time_ms: duration_ms,
    }))
}

// Real-time processing endpoints
use serde_json::json;

#[derive(Serialize, Deserialize)]
pub struct RealTimeStartRequest {
    pub eth_ws_url: Option<String>,
    pub processing_mode: ProcessingMode,
    pub realtime_timeout_secs: Option<u64>,
    pub max_workers: Option<usize>,
}

static mut REALTIME_PROCESSOR: Option<Arc<RealTimeProcessor>> = None;

// Start real-time processing
pub async fn start_realtime_processing(
    State(ctx): State<Arc<ApiContext>>,
    Json(request): Json<RealTimeStartRequest>,
) -> Result<Json<serde_json::Value>, axum::response::Response<axum::body::Body>> {
    println!("Starting real-time processing with mode: {:?}", request.processing_mode);
    
    let config = RealTimeConfig {
        eth_ws_url: request.eth_ws_url.unwrap_or_else(|| "ws://localhost:8546".to_string()),
        max_workers: request.max_workers.unwrap_or(4),
        realtime_timeout_secs: request.realtime_timeout_secs.unwrap_or(60),
        max_queue_size: 1000,
        target_lag_secs: 5,
        max_retries: 3,
    };
    
    let processor = RealTimeProcessor::new(ctx.vm.clone(), config.clone());
    processor.start().await
        .map_err(|e| {
            let error_response = json!({
                "error": format!("Failed to start real-time processor: {}", e),
                "success": false
            });
            axum::response::Response::builder()
                .status(500)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(serde_json::to_string(&error_response).unwrap()))
                .unwrap()
        })?;
    
    unsafe {
        REALTIME_PROCESSOR = Some(Arc::new(processor));
    }
    
    let response = json!({
        "success": true,
        "message": "Real-time processing started successfully",
        "config": {
            "eth_ws_url": config.eth_ws_url,
            "realtime_timeout_secs": config.realtime_timeout_secs,
            "max_workers": config.max_workers
        }
    });
    
    Ok(Json(response))
}

// Get real-time processing status
pub async fn get_realtime_status() -> Result<Json<RealTimeStatusResponse>, axum::response::Response<axum::body::Body>> {
    unsafe {
        if let Some(processor) = &REALTIME_PROCESSOR {
            let stats = processor.get_stats().await;
            let status = RealTimeStatusResponse {
                stats,
                is_realtime: true,
                current_head: Some(0), // TODO: Get actual current head
                processing_lag_seconds: 0, // TODO: Calculate actual lag
                queue_breakdown: HashMap::new(), // TODO: Get actual queue breakdown
            };
            Ok(Json(status))
        } else {
            let default_stats = RealTimeStats {
                total_blocks_processed: 0,
                realtime_blocks_processed: 0,
                recent_blocks_processed: 0,
                historical_blocks_processed: 0,
                average_processing_time_ms: 0.0,
                blocks_per_second: 0.0,
                current_lag_seconds: 0,
                queue_size: 0,
                failed_blocks: 0,
            };
            let error_response = RealTimeStatusResponse {
                stats: default_stats,
                is_realtime: false,
                current_head: None,
                processing_lag_seconds: 0,
                queue_breakdown: HashMap::new(),
            };
            Ok(Json(error_response))
        }
    }
}

// Stop real-time processing
pub async fn stop_realtime_processing() -> Result<Json<serde_json::Value>, axum::response::Response<axum::body::Body>> {
    unsafe {
        if let Some(processor) = REALTIME_PROCESSOR.take() {
            processor.stop().await
                .map_err(|e| {
                    let error_response = json!({
                        "error": format!("Failed to stop real-time processor: {}", e),
                        "success": false
                    });
                    axum::response::Response::builder()
                        .status(500)
                        .header("content-type", "application/json")
                        .body(axum::body::Body::from(serde_json::to_string(&error_response).unwrap()))
                        .unwrap()
                })?;
            
            let response = json!({
                "success": true,
                "message": "Real-time processing stopped successfully"
            });
            Ok(Json(response))
        } else {
            let response = json!({
                "success": false,
                "message": "Real-time processor was not running"
            });
            Ok(Json(response))
        }
    }
}

// Configure API routes
pub fn create_api_router(ctx: Arc<ApiContext>) -> Router {
    Router::new()
        .route("/health", get(health_check))
        .route("/api/v1/witnesses/generate", post(generate_witnesses))
        .route("/api/v1/simulate", post(simulate_execution))
        .route("/api/v1/sequence/execute", post(execute_sequence))
        .route("/api/v1/realtime/start", post(start_realtime_processing))
        .route("/api/v1/realtime/status", get(get_realtime_status))
        .route("/api/v1/realtime/stop", post(stop_realtime_processing))
        .with_state(ctx)
}

// API server setup
pub async fn run_api_server(vm: Arc<RwLock<StatelessVM>>, addr: &str) -> std::io::Result<()> {
    let ctx = Arc::new(ApiContext { vm });
    let app = create_api_router(ctx);
    
    println!("Starting API server on {}", addr);
    axum::Server::bind(&addr.parse().unwrap())
        .serve(app.into_make_service())
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
}
