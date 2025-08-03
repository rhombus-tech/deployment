use stateless_vm::prelude::*;
use stateless_vm::api::*;
use std::sync::Arc;
use tokio::sync::RwLock;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use tower::ServiceExt;
use ethereum_types::{U256, H256, Address};
use serde_json::json;
use http_body_util::BodyExt;

// Define a simple implementation of SecurityVerifier for tests
struct TestSecurityVerifier;

#[async_trait::async_trait]
impl SecurityVerifier for TestSecurityVerifier {
    async fn verify_transaction(
        &self, 
        _transaction: &Transaction,
        _level: VerificationLevel,
    ) -> Result<VerificationResult, VMError> {
        // For tests, assume all transactions are secure
        Ok(VerificationResult::success())
    }
    
    async fn verify_sequence(
        &self,
        _sequence: &TransactionSequence,
        _level: VerificationLevel,
    ) -> Result<VerificationResult, VMError> {
        // For tests, assume all sequences are secure
        Ok(VerificationResult::success())
    }
}

// Define a simple implementation of StateProvider for tests
struct TestStateProvider;

#[async_trait::async_trait]
impl StateProvider for TestStateProvider {
    async fn fetch_state(&self, _requirement: &StateRequirement) -> Result<Vec<u8>, VMError> {
        // Return dummy state data for tests
        Ok(vec![0; 32])
    }
}

// Helper function to create a test VM
fn create_test_vm() -> StatelessVM {
    let state_provider = Arc::new(TestStateProvider);
    let state_bundler = Arc::new(RwLock::new(StateBundler::new(state_provider)));
    let security_verifier = Arc::new(TestSecurityVerifier);
    
    let initial_state_root = H256::from_slice(&[0xFF; 32]);
    let initial_block_height = 12345;
    
    StatelessVM::new(
        state_bundler,
        security_verifier,
        initial_state_root,
        initial_block_height,
    )
}

// Helper function to build an API router
async fn create_api_router() -> axum::Router {
    let vm = create_test_vm();
    let shared_vm = Arc::new(RwLock::new(vm));
    build_api_router(shared_vm)
}

async fn read_body_json(response: Response) -> serde_json::Value {
    let body = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
async fn test_generate_witnesses_endpoint() {
    // Build the API router
    let app = create_api_router().await;
    
    // Create a test request for generating witnesses
    let request_body = json!({
        "transactions": [
            "0xf86c0a85046c7cef81948a8eafb1cf62bfbeb1741769dae1a9dd479961928080"
        ],
        "execution_context": {
            "chain_id": 43114,
            "block_number": 12345,
            "timestamp": 1625097600,
            "metadata": {}
        }
    });
    
    let request = Request::builder()
        .uri("/api/generate_witnesses")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(request_body.to_string()))
        .unwrap();
    
    // Send the request and get the response
    let response = app.oneshot(request).await.unwrap();
    
    // Check that the response is successful
    assert_eq!(response.status(), StatusCode::OK);
    
    // Parse the response body as JSON
    let body = read_body_json(response).await;
    
    // Check that the response contains the expected fields
    assert_eq!(body["status"], "success");
    assert!(body["result"]["witnesses"].is_array());
}

#[tokio::test]
async fn test_execute_sequence_endpoint() {
    // Build the API router
    let app = create_api_router().await;
    
    // Create a test transaction sequence
    let sender = Address::from_slice(&[0xaa; 20]);
    let receiver = Address::from_slice(&[0xbb; 20]);
    let tx_hex = "0xf86c0a85046c7cef81948a8eafb1cf62bfbeb1741769dae1a9dd479961928080";
    
    let request_body = json!({
        "sequence_id": "test-sequence-1",
        "transactions": [tx_hex],
        "fallback_plans": [{
            "condition": "timeout",
            "actions": ["retry", "increment_gas"],
            "max_attempts": 3
        }],
        "market_conditions": {
            "max_base_fee": "30000000000",
            "max_priority_fee": "2000000000"
        },
        "mev_protection": {
            "protection_level": "standard",
            "max_extraction_pct": 5
        },
        "state_verification": {
            "verification_level": "standard",
            "verification_params": {
                "checksum_validation": true,
                "code_hash_validation": true
            }
        },
        "execution_context": {
            "chain_id": 43114,
            "block_number": 12345,
            "timestamp": 1625097600,
            "metadata": {
                "description": "Test sequence for unit tests",
                "app": "test-app"
            }
        },
        "timeout_seconds": 30,
        "atomic": true
    });
    
    let request = Request::builder()
        .uri("/api/execute_sequence")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(request_body.to_string()))
        .unwrap();
    
    // Send the request and get the response
    let response = app.oneshot(request).await.unwrap();
    
    // Check that the response is successful
    assert_eq!(response.status(), StatusCode::OK);
    
    // Parse the response body as JSON
    let body = read_body_json(response).await;
    
    // Check that the response contains the expected fields
    assert_eq!(body["status"], "success");
    assert_eq!(body["result"]["sequence_id"], "test-sequence-1");
    assert!(body["result"]["transactions"].is_array());
}

#[tokio::test]
async fn test_execute_sequence_market_conditions_not_met() {
    // Build the API router
    let app = create_api_router().await;
    
    // Create a test transaction sequence with very low max_base_fee
    // This should trigger a market conditions not met error
    let tx_hex = "0xf86c0a85046c7cef81948a8eafb1cf62bfbeb1741769dae1a9dd479961928080";
    
    let request_body = json!({
        "sequence_id": "test-sequence-2",
        "transactions": [tx_hex],
        "market_conditions": {
            "max_base_fee": "1", // Very low max base fee
            "max_priority_fee": "1"
        },
        "execution_context": {
            "chain_id": 43114,
            "block_number": 12345,
            "timestamp": 1625097600,
            "metadata": {}
        },
        "timeout_seconds": 30,
        "atomic": true
    });
    
    let request = Request::builder()
        .uri("/api/execute_sequence")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(request_body.to_string()))
        .unwrap();
    
    // Send the request and get the response
    let response = app.oneshot(request).await.unwrap();
    
    // Check that the response is an error
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    
    // Parse the response body as JSON
    let body = read_body_json(response).await;
    
    // Check that the response contains the expected fields
    assert_eq!(body["status"], "error");
    assert!(body["error"]["code"].as_str().unwrap().contains("market_conditions_not_met"));
}

#[tokio::test]
async fn test_simulate_execution_endpoint() {
    // Build the API router
    let app = create_api_router().await;
    
    // Create a test transaction for simulation
    let tx_hex = "0xf86c0a85046c7cef81948a8eafb1cf62bfbeb1741769dae1a9dd479961928080";
    
    let request_body = json!({
        "transactions": [tx_hex],
        "execution_context": {
            "chain_id": 43114,
            "block_number": 12345,
            "timestamp": 1625097600,
            "metadata": {}
        }
    });
    
    let request = Request::builder()
        .uri("/api/simulate_execution")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(request_body.to_string()))
        .unwrap();
    
    // Send the request and get the response
    let response = app.oneshot(request).await.unwrap();
    
    // Check that the response is successful
    assert_eq!(response.status(), StatusCode::OK);
    
    // Parse the response body as JSON
    let body = read_body_json(response).await;
    
    // Check that the response contains the expected fields
    assert_eq!(body["status"], "success");
    assert!(body["result"]["simulation_results"].is_array());
    assert!(body["result"]["simulation_results"][0]["gas_used"].is_number());
}

#[tokio::test]
async fn test_invalid_transaction_format() {
    // Build the API router
    let app = create_api_router().await;
    
    // Create a test request with invalid transaction format
    let request_body = json!({
        "transactions": [
            "invalid_hex_string" // Not a valid hex string
        ],
        "execution_context": {
            "chain_id": 43114,
            "block_number": 12345,
            "timestamp": 1625097600,
            "metadata": {}
        }
    });
    
    let request = Request::builder()
        .uri("/api/generate_witnesses")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(request_body.to_string()))
        .unwrap();
    
    // Send the request and get the response
    let response = app.oneshot(request).await.unwrap();
    
    // Check that the response is an error
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    
    // Parse the response body as JSON
    let body = read_body_json(response).await;
    
    // Check that the response contains the expected fields
    assert_eq!(body["status"], "error");
    assert!(body["error"]["message"].as_str().unwrap().contains("Invalid transaction hex"));
}
