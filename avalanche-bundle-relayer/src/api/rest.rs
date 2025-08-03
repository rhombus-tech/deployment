// REST API implementation

use std::convert::Infallible;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::collections::HashMap;
use warp::{Filter, Rejection, Reply};
use warp::filters::BoxedFilter;
use warp::filters::cors::Cors;
use serde_json::json;
use log::{debug, error, info, warn};
use chrono::Utc;
use uuid::Uuid;
use tokio::sync::broadcast;

use crate::bundle::BundleManager;
use crate::config::{ApiConfig, RelayerConfig, ServerConfig, ChainConfig, DatabaseConfig};
use crate::errors::{RelayerError, ApiError, Result as RelayerResult};
use crate::types::{BundleId, BundleStatus, BundleSubmissionReceipt, TransactionBundle, SecurityConfig, SecurityValidationLevel, BlockValidityWindow};
use crate::api::types::{ApiResponse, BundleSubmissionRequest, BundleStatusResponse};

type WarpResult<T> = std::result::Result<T, Rejection>;

/// API authentication function
fn with_auth(
    auth_required: bool,
    api_keys: Vec<String>,
) -> BoxedFilter<((),)> {
    let api_keys_clone = api_keys.clone();
    warp::header::optional::<String>("x-api-key").and_then(move |key: Option<String>| {  
        let api_keys_inner = api_keys_clone.clone();
        let auth_required_inner = auth_required;
        async move {
            if auth_required_inner && !api_keys_inner.is_empty() {
                if let Some(provided_key) = key {
                    if api_keys_inner.contains(&provided_key) {
                        return Ok(());
                    } else {
                        return Err(warp::reject::custom(ApiError("Invalid API key".to_string())));
                    }
                } else {
                    return Err(warp::reject::custom(ApiError("API key required".to_string())));
                }
            }
            
            Ok(())
        }
    })
    .boxed()
}

/// Configure CORS for API
fn cors_config() -> Cors {
    warp::cors()
        .allow_any_origin()
        .allow_methods(vec!["GET", "POST", "OPTIONS"])
        .allow_headers(vec!["Content-Type", "X-API-KEY", "Authorization"])
        .build()
}

/// Start the REST API server
pub async fn start_api_server(
    config: RelayerConfig,
    bundle_manager: Arc<BundleManager>,
) -> RelayerResult<()> {
    let addr: std::net::SocketAddr = ([0, 0, 0, 0], config.server.rest_port).into();
    let auth_required = config.server.auth_required;
    let api_keys = config.server.api_keys.clone();
    
    info!("Starting API server on {}", addr);
    
    // Define return type explicitly to make both branches compatible
    let auth: BoxedFilter<((),)> = if auth_required {
        with_auth(auth_required, api_keys.clone())
    } else {
        // Use the same function type as with_auth for type compatibility
        warp::any()
            .map(|| ())
            .and_then(|()| async { Ok::<_, Rejection>(()) })
            .boxed()
    };
    
    // Define the API routes
    
    // Health check endpoint - no auth required
    let health_route = warp::path!("health")
        .and(warp::get())
        .and_then(handle_health_check);
    
    // Bundle submission endpoint
    let submit_route = warp::path!("bundles")
        .and(warp::post())
        .and(auth.clone())
        .and(warp::body::json())
        .and(with_bundle_manager(bundle_manager.clone()))
        .and_then(handle_submit_bundle);
    
    // Get bundle status endpoint
    let status_route = warp::path!("bundles" / String)
        .and(warp::get())
        .and(auth.clone())
        .and(with_bundle_manager(bundle_manager.clone()))
        .and_then(handle_get_bundle_status);
    
    // Get all bundles endpoint
    let bundles_route = warp::path!("bundles")
        .and(warp::get())
        .and(auth.clone())
        .and(with_bundle_manager(bundle_manager.clone()))
        .and_then(handle_get_all_bundles);
    
    // Combine routes
    let routes = health_route
        .or(submit_route)
        .or(status_route)
        .or(bundles_route)
        .recover(handle_rejection)
        .with(cors_config())
        .with(warp::log("api"));
    
    // Start the server
    warp::serve(routes)
        .bind(addr)
        .await;
    
    Ok(())
}

/// Helper function to pass bundle manager to handlers
fn with_bundle_manager(
    bundle_manager: Arc<BundleManager>
) -> impl Filter<Extract = (Arc<BundleManager>,), Error = Infallible> + Clone {
    warp::any().map(move || bundle_manager.clone())
}

/// Handle health check requests
async fn handle_health_check() -> WarpResult<impl Reply> {
    let response = ApiResponse::<serde_json::Value>::success(
        json!({
            "status": "ok",
            "timestamp": Utc::now().to_rfc3339(),
            "version": env!("CARGO_PKG_VERSION"),
        }),
        None,
    );
    
    Ok(warp::reply::json(&response))
}

/// Handle bundle submission
async fn handle_submit_bundle(
    _: (),  // Auth result
    submission: BundleSubmissionRequest,
    bundle_manager: Arc<BundleManager>,
) -> WarpResult<impl Reply> {
    // Create new bundle ID
    let bundle_id = BundleId::new();
    
    // Convert transactions into a bundle
    let bundle = TransactionBundle {
        bundle_id,
        transactions: submission.transactions,
        submitter: None, // Could extract from JWT token if we had auth
        created_at: Utc::now(),
        metadata: Some(json!({
            "agent": submission.agent,
            "source": "api",
        }).as_object().unwrap().iter().map(|(k, v)| (k.clone(), v.clone())).collect()),
        validity_window: submission.validity_window.unwrap_or(BlockValidityWindow {
            start_block: None,
            end_block: None,
        }),
    };
    
    // Submit bundle for processing
    match bundle_manager.submit_bundle(bundle).await {
        Ok(receipt) => {
            let response = ApiResponse::success(
                json!({
                    "bundle_id": receipt.bundle_id,
                    "submitted_at": receipt.submitted_at,
                    "estimated_block": receipt.estimated_block,
                    "receipt_data": receipt.receipt_data,
                }),
                None,
            );
            
            Ok(warp::reply::json(&response))
        }
        Err(e) => {
            error!("Failed to submit bundle: {}", e);
            
            let response = ApiResponse::<serde_json::Value>::error(
                format!("Failed to submit bundle: {}", e),
                None,
            );
            
            Ok(warp::reply::json(&response))
        }
    }
}

/// Handle get bundle status
async fn handle_get_bundle_status(
    bundle_id_str: String,
    _: (),  // Auth result
    bundle_manager: Arc<BundleManager>,
) -> WarpResult<impl Reply> {
    // Parse bundle ID
    let bundle_id = match bundle_id_str.parse::<BundleId>() {
        Ok(id) => id,
        Err(_) => {
            let response = ApiResponse::<serde_json::Value>::error(
                "Invalid bundle ID format",
                None,
            );
            
            return Ok(warp::reply::json(&response));
        }
    };
    
    // Get bundle status
    match bundle_manager.get_bundle_status(bundle_id).await {
        Ok(status) => {
            let response = ApiResponse::success(
                BundleStatusResponse::from(status),
                None,
            );
            
            Ok(warp::reply::json(&response))
        }
        Err(e) => {
            let response = ApiResponse::<serde_json::Value>::error(
                format!("Failed to get bundle status: {}", e),
                None,
            );
            
            Ok(warp::reply::json(&response))
        }
    }
}

/// Handle get all bundles
async fn handle_get_all_bundles(
    _: (),  // Auth result
    bundle_manager: Arc<BundleManager>,
) -> WarpResult<impl Reply> {
    // Get all bundle statuses
    match bundle_manager.get_all_bundle_statuses().await {
        Ok(statuses) => {
            let status_responses: Vec<BundleStatusResponse> = 
                statuses.into_iter().map(BundleStatusResponse::from).collect();
            
            let response = ApiResponse::success(
                status_responses,
                None,
            );
            
            Ok(warp::reply::json(&response))
        }
        Err(e) => {
            let response = ApiResponse::<serde_json::Value>::error(
                format!("Failed to get bundle statuses: {}", e),
                None,
            );
            
            Ok(warp::reply::json(&response))
        }
    }
}

/// Handle API rejections
async fn handle_rejection(err: Rejection) -> WarpResult<impl Reply> {
    let code;
    let message;

    if err.is_not_found() {
        code = warp::http::StatusCode::NOT_FOUND;
        message = "Not found";
    } else if let Some(api_err) = err.find::<ApiError>() {
        code = warp::http::StatusCode::BAD_REQUEST;
        message = api_err.0.as_str();
    } else if err.find::<warp::filters::body::BodyDeserializeError>().is_some() {
        code = warp::http::StatusCode::BAD_REQUEST;
        message = "Invalid request body";
    } else {
        error!("Unhandled rejection: {:?}", err);
        code = warp::http::StatusCode::INTERNAL_SERVER_ERROR;
        message = "Internal server error";
    }

    Ok(warp::reply::with_status(
        warp::reply::json(&json!({
            "success": false,
            "error": message
        })),
        code,
    ))
}

/// Setup REST API server
pub async fn setup_rest_api(
    port: u16,
    api_keys: Vec<String>,
    bundles: Arc<Mutex<HashMap<BundleId, TransactionBundle>>>,
    statuses: Arc<Mutex<HashMap<BundleId, crate::types::BundleStatus>>>,
    validator: Arc<dyn crate::bundle::BundleValidator>
) -> tokio::task::JoinHandle<()> {
    // Create relayer config
    let config = RelayerConfig {
        server: ServerConfig {
            host: "127.0.0.1".to_string(),
            rest_port: 3000,
            ws_port: 3001,
            auth_required: !api_keys.is_empty(),
            api_keys: api_keys.clone(),
            log_level: "info".to_string(),
        },
        chain: ChainConfig {
            rpc_url: "http://localhost:9650/ext/bc/C/rpc".to_string(),
            chain_id: 43114, // Avalanche C-Chain
            ws_url: Some("ws://localhost:9650/ext/bc/C/ws".to_string()),
            required_confirmations: 3,
            gas_price_multiplier: 1.1,
            simulation_gas_limit: 10000000,
        },
        security: SecurityConfig {
            validation_level: SecurityValidationLevel::Standard,
            max_bundle_gas: 15_000_000,
            max_bundle_size: 100,
            verification_mode: "always".to_string(),
        },
        database: DatabaseConfig {
            path: "bundles.db".to_string(),
            max_connections: Some(10),
        },
        api: ApiConfig {
            enable_submit: true,
            enable_status: true,
            enable_metrics: true,
            cors_allow_origin: "*".to_string(),
            max_body_size: 1024 * 1024, // 1MB
            request_timeout: 30,
            bundle_timeout_seconds: 60,
        },
        statelessvm: crate::config::StatelessVmConfig {
            endpoint_url: "http://localhost:8080".to_string(),
            timeout_seconds: 60,
            max_retries: 3,
            validate_traces: true,
        },
    };
    
    // Create StatelessVmClient
    let stateless_vm = crate::statelessvm::StatelessVmClient::new(config.statelessvm.clone());
    
    // Create bundle manager
    let bundle_manager = BundleManager::new(config, validator, stateless_vm)
        .await
        .expect("Failed to initialize bundle manager");
    
    // Wrap it in Arc for thread sharing
    let bundle_manager = Arc::new(bundle_manager);
    
    // Create API routes
    let routes = health_check_route()
        .or(submit_bundle_route(bundle_manager.clone(), api_keys.clone()))
        .or(get_bundle_status_route(bundle_manager.clone(), api_keys.clone()))
        .or(get_all_bundles_route(bundle_manager.clone(), api_keys))
        .with(cors_config())
        .recover(handle_rejection);

    // Start server
    let server = warp::serve(routes);
    let (addr, server) = server.bind_ephemeral(([0, 0, 0, 0], port));
    
    info!("REST API server started on {}", addr);
    
    // Return join handle
    tokio::spawn(server)
}

/// Health check route
fn health_check_route() -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp::path("health")
        .and(warp::get())
        .and_then(handle_health_check)
}

/// Submit bundle route
fn submit_bundle_route(
    bundle_manager: Arc<BundleManager>,
    api_keys: Vec<String>
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp::path("bundles")
        .and(warp::post())
        .and(with_auth(true, api_keys.clone()))
        .and(warp::body::json())
        .and(with_bundle_manager(bundle_manager))
        .and_then(handle_submit_bundle)
}

/// Get bundle status route
fn get_bundle_status_route(
    bundle_manager: Arc<BundleManager>,
    api_keys: Vec<String>
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp::path!("bundles" / String)
        .and(warp::get())
        .and(with_auth(true, api_keys.clone()))
        .and(with_bundle_manager(bundle_manager))
        .and_then(handle_get_bundle_status)
}

/// Get all bundles route
fn get_all_bundles_route(
    bundle_manager: Arc<BundleManager>,
    api_keys: Vec<String>
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp::path("bundles")
        .and(warp::get())
        .and(with_auth(true, api_keys.clone()))
        .and(with_bundle_manager(bundle_manager))
        .and_then(handle_get_all_bundles)
}
