// FRAC RPC - Production-Grade Ethereum RPC for Proving Networks
// Optimized for high throughput, low latency, and proving-specific workloads

use axum::{
    extract::{ConnectInfo, Json, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{info, warn};

mod config;
mod cache;
mod postgres_cache;
mod router;
mod nodes;
mod proving_optimizer;
mod metrics;
mod health;
mod geo_router;
mod rate_limiter;
mod websocket;
mod circuit_breaker;

use config::FracRPCConfig;
use router::RPCRouter;

#[derive(Clone)]
struct AppState {
    router: Arc<RPCRouter>,
    metrics: Arc<metrics::MetricsCollector>,
    rate_limiter: Arc<rate_limiter::RateLimiter>,
    ws_handler: Arc<websocket::WebSocketHandler>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_target(false)
        .with_thread_ids(true)
        .with_level(true)
        .json()
        .init();

    info!("🚀 Starting FRAC RPC Server...");

    // Load configuration
    let config = FracRPCConfig::from_env()?;
    info!("✅ Configuration loaded");

    // Initialize metrics
    let metrics = Arc::new(metrics::MetricsCollector::new());
    info!("✅ Metrics initialized");

    // Initialize rate limiter
    let rate_limiter = Arc::new(rate_limiter::RateLimiter::new(
        Some(1000), // 1000 requests per minute
        Some(60),   // 60 second window
    ));
    info!("✅ Rate limiter initialized (1000 req/min)");

    // Initialize WebSocket handler
    let ws_handler = Arc::new(websocket::WebSocketHandler::new());
    info!("✅ WebSocket handler initialized");

    // Initialize RPC router with intelligent routing
    let router = Arc::new(RPCRouter::new(config.clone()).await?);
    info!("✅ RPC router initialized");

    // Health check on startup
    router.health_check().await?;
    info!("✅ All nodes healthy");

    let state = AppState {
        router: router.clone(),
        metrics: metrics.clone(),
        rate_limiter: rate_limiter.clone(),
        ws_handler: ws_handler.clone(),
    };

    // Build axum app
    let app = Router::new()
        // Main RPC endpoint (JSON-RPC 2.0)
        .route("/", post(handle_rpc))
        .route("/v1/rpc", post(handle_rpc))
        
        // Health & metrics
        .route("/health", get(health_check))
        .route("/metrics", get(get_metrics))
        .route("/stats", get(get_stats))
        
        // Proving-specific optimized endpoints
        .route("/v1/proving/block/:number", get(get_proving_data))
        .route("/v1/proving/batch", post(get_batch_proving_data))
        
        // WebSocket endpoint for subscriptions
        .route("/ws", get(handle_websocket))
        
        .with_state(state)
        .layer(
            tower_http::trace::TraceLayer::new_for_http()
                .make_span_with(tower_http::trace::DefaultMakeSpan::new().include_headers(true))
        )
        .layer(tower_http::compression::CompressionLayer::new())
        .layer(tower_http::cors::CorsLayer::permissive());

    // Start server
    let addr = format!("{}:{}", config.server.host, config.server.port);
    let listener = TcpListener::bind(&addr).await?;
    
    info!("🌐 FRAC RPC listening on {}", addr);
    info!("📊 Metrics available at http://{}/metrics", addr);
    info!("💚 Health check at http://{}/health", addr);
    
    axum::serve(listener, app).await?;

    Ok(())
}

// Main JSON-RPC 2.0 handler with rate limiting
async fn handle_rpc(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Json(request): Json<serde_json::Value>,
) -> impl IntoResponse {
    let start = std::time::Instant::now();
    
    // Check rate limit
    if let Err(e) = state.rate_limiter.check_rate_limit(addr.ip()) {
        warn!("Rate limit exceeded for IP: {}", addr.ip());
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "jsonrpc": "2.0",
                "error": {
                    "code": -32005,
                    "message": e.to_string()
                },
                "id": null
            }))
        );
    }
    
    // Route through intelligent router
    match state.router.route_request(request).await {
        Ok(response) => {
            let elapsed = start.elapsed();
            state.metrics.record_request(elapsed, true).await;
            (StatusCode::OK, Json(response))
        }
        Err(e) => {
            let elapsed = start.elapsed();
            state.metrics.record_request(elapsed, false).await;
            warn!("RPC error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32603,
                        "message": e.to_string()
                    },
                    "id": null
                }))
            )
        }
    }
}

// Health check endpoint
async fn health_check(State(state): State<AppState>) -> impl IntoResponse {
    match state.router.health_check().await {
        Ok(_) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "healthy",
                "timestamp": chrono::Utc::now().to_rfc3339()
            }))
        ),
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "status": "unhealthy",
                "error": e.to_string(),
                "timestamp": chrono::Utc::now().to_rfc3339()
            }))
        ),
    }
}

// Prometheus metrics endpoint
async fn get_metrics(State(state): State<AppState>) -> impl IntoResponse {
    let metrics = state.metrics.export_prometheus().await;
    (StatusCode::OK, metrics)
}

// Stats endpoint (JSON format)
async fn get_stats(State(state): State<AppState>) -> impl IntoResponse {
    let stats = state.router.get_stats().await;
    (StatusCode::OK, Json(stats))
}

// Proving-optimized endpoint: Get all data needed for proving a block
async fn get_proving_data(
    State(state): State<AppState>,
    axum::extract::Path(block_number): axum::extract::Path<u64>,
) -> impl IntoResponse {
    match state.router.get_proving_data(block_number).await {
        Ok(data) => (StatusCode::OK, Json(data)),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": e.to_string()
            }))
        ),
    }
}

// Batch proving data endpoint: Get multiple blocks at once
async fn get_batch_proving_data(
    State(state): State<AppState>,
    Json(request): Json<serde_json::Value>,
) -> impl IntoResponse {
    let block_numbers: Vec<u64> = match serde_json::from_value(request["blocks"].clone()) {
        Ok(nums) => nums,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": format!("Invalid request: {}", e)
                }))
            )
        }
    };

    match state.router.get_batch_proving_data(block_numbers).await {
        Ok(data) => (StatusCode::OK, Json(data)),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": e.to_string()
            }))
        ),
    }
}

// WebSocket handler for eth_subscribe
async fn handle_websocket(
    ws: axum::extract::WebSocketUpgrade,
    State(state): State<AppState>,
) -> axum::response::Response {
    websocket::WebSocketHandler::handle_upgrade(ws, State(state))
}
