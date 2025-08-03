// WebSocket API for real-time bundle status updates

use std::convert::Infallible;
use crate::config::StatelessVmConfig;
use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::Mutex;
use futures::{FutureExt, StreamExt, SinkExt};
use tokio::sync::{mpsc, broadcast, RwLock};
use tokio::time::{interval, Duration};
use warp::ws::{Message, WebSocket};
use warp::{Filter, Rejection, Reply};
use chrono::Utc;
use log::{debug, error, info, warn};
use serde_json::json;

use crate::bundle::BundleManager;
use crate::config::{RelayerConfig, ServerConfig, ChainConfig, DatabaseConfig, ApiConfig, Config};
use crate::errors::{ApiError, RelayerError, Result as RelayerResult};
use crate::types::{BundleId, BundleStatusCode, TransactionStatusCode, TxHash};
use crate::types::{SecurityConfig, SecurityValidationLevel};
use crate::api::types::WebSocketEvent;
use crate::statelessvm::StatelessVmClient;

/// Maximum number of connections to track
const MAX_CONNECTIONS: usize = 1000;

/// Status update sender
#[derive(Clone)]
pub struct StatusUpdateSender {
    tx: broadcast::Sender<WebSocketEvent>,
}

impl StatusUpdateSender {
    /// Create a new status update sender
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(100);
        Self { tx }
    }
    
    /// Send a status update
    pub fn send(&self, event: WebSocketEvent) -> Result<(), broadcast::error::SendError<WebSocketEvent>> {
        self.tx.send(event).map(|_| ())
    }
    
    /// Get a receiver for status updates
    pub fn subscribe(&self) -> broadcast::Receiver<WebSocketEvent> {
        self.tx.subscribe()
    }
}

/// Connection state
struct ConnectionState {
    /// Connected clients
    connections: HashMap<String, mpsc::UnboundedSender<Result<Message, warp::Error>>>,
    /// Client subscriptions (client_id -> bundle_ids)
    subscriptions: HashMap<String, Vec<BundleId>>,
}

impl ConnectionState {
    /// Create new connection state
    fn new() -> Self {
        Self {
            connections: HashMap::new(),
            subscriptions: HashMap::new(),
        }
    }
    
    /// Add a connection
    fn add_connection(&mut self, client_id: String, tx: mpsc::UnboundedSender<Result<Message, warp::Error>>) {
        self.connections.insert(client_id.clone(), tx);
        self.subscriptions.insert(client_id, Vec::new());
    }
    
    /// Remove a connection
    fn remove_connection(&mut self, client_id: &str) {
        self.connections.remove(client_id);
        self.subscriptions.remove(client_id);
    }
    
    /// Subscribe to bundle updates
    fn subscribe(&mut self, client_id: &str, bundle_id: BundleId) {
        if let Some(subscriptions) = self.subscriptions.get_mut(client_id) {
            if !subscriptions.contains(&bundle_id) {
                subscriptions.push(bundle_id);
            }
        }
    }
    
    /// Unsubscribe from bundle updates
    fn unsubscribe(&mut self, client_id: &str, bundle_id: BundleId) {
        if let Some(subscriptions) = self.subscriptions.get_mut(client_id) {
            subscriptions.retain(|id| id != &bundle_id);
        }
    }
    
    /// Get clients subscribed to a bundle
    fn get_subscribers(&self, bundle_id: &BundleId) -> Vec<String> {
        self.subscriptions
            .iter()
            .filter_map(|(client_id, bundles)| {
                if bundles.contains(bundle_id) {
                    Some(client_id.clone())
                } else {
                    None
                }
            })
            .collect()
    }
}

/// Start the WebSocket server
pub async fn start_websocket_server(
    config: RelayerConfig,
    bundle_manager: Arc<BundleManager>,
    status_sender: StatusUpdateSender,
) -> RelayerResult<()> {
    let addr: std::net::SocketAddr = ([0, 0, 0, 0], config.server.ws_port).into();
    let auth_required = config.server.auth_required;
    let api_keys = config.server.api_keys.clone();
    
    let connections = Arc::new(RwLock::new(ConnectionState::new()));
    
    // Helper functions
    let with_connections = |connections: Arc<RwLock<ConnectionState>>| warp::any().map(move || connections.clone());
    let with_status_sender = |status_sender: StatusUpdateSender| warp::any().map(move || status_sender.clone());
    let with_bundle_manager = |bundle_manager: Arc<BundleManager>| warp::any().map(move || bundle_manager.clone());
    
    // Use auth filter if auth is required
    let auth = if auth_required {
        let api_keys_clone = api_keys.clone();
        warp::header::optional::<String>("x-api-key").and_then(move |key: Option<String>| {
            let api_keys = api_keys_clone.clone();
            async move {
                if !api_keys.is_empty() {
                    if let Some(provided_key) = key {
                        if api_keys.contains(&provided_key) {
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
    } else {
        warp::any().map(|| ()).boxed()
    };
    
    // Create WebSocket route
    let ws_route = warp::path("ws")
        .and(warp::ws())
        .and(auth)
        .and(with_connections(connections.clone()))
        .and(with_status_sender(status_sender.clone()))
        .and(with_bundle_manager(bundle_manager.clone()))
        .map(|ws: warp::ws::Ws, _, connections, status_sender, bundle_manager| {
            ws.on_upgrade(move |socket| handle_websocket_connection(socket, connections, status_sender, bundle_manager))
        });
    
    // Start status update listener in the background
    tokio::spawn(status_listener(status_sender.clone(), connections.clone()));
    
    // Start heartbeat sender in the background
    tokio::spawn(heartbeat_sender(connections.clone()));
    
    // Start WebSocket server
    info!("Starting WebSocket server on {}/ws", addr);
    warp::serve(ws_route).bind(addr).await;
    
    Ok(())
}

/// Handle a WebSocket connection
async fn handle_websocket_connection(
    ws: WebSocket,
    connections: Arc<RwLock<ConnectionState>>,
    status_sender: StatusUpdateSender,
    bundle_manager: Arc<BundleManager>,
) {
    // Generate a unique client ID
    let client_id = uuid::Uuid::new_v4().to_string();
    
    info!("New WebSocket connection: {}", client_id);
    
    // Split the WebSocket into sender and receiver
    let (mut ws_tx, mut ws_rx) = ws.split();
    
    // Create a channel for sending messages to the WebSocket
    let (tx, mut rx) = mpsc::unbounded_channel();
    
    // Add the connection to our state
    {
        let mut connections = connections.write().await;
        connections.add_connection(client_id.clone(), tx);
    }
    
    // Forward messages from our channel to the WebSocket
    tokio::task::spawn(async move {
        while let Some(message) = rx.recv().await {
            // Ensure we have a valid Message to send
            let result = match message {
                Ok(msg) => ws_tx.send(msg).await,
                Err(e) => {
                    error!("Invalid message: {}", e);
                    continue;
                }
            };
            
            if let Err(e) = result {
                error!("WebSocket send error: {}", e);
                break;
            }
        }
    });
    
    // Process incoming WebSocket messages
    while let Some(result) = ws_rx.next().await {
        let msg = match result {
            Ok(msg) => msg,
            Err(e) => {
                error!("WebSocket error: {}", e);
                break;
            }
        };
        
        // Skip non-text messages
        if !msg.is_text() {
            continue;
        }
        
        // Parse the message
        let text = msg.to_str().unwrap_or("");
        process_ws_message(
            &client_id,
            text,
            bundle_manager.clone(),
            connections.clone(),
            status_sender.clone(),
        )
        .await;
    }
    
    // Remove the connection on disconnect
    {
        let mut connections = connections.write().await;
        connections.remove_connection(&client_id);
    }
    
    info!("WebSocket connection closed: {}", client_id);
}

/// Process a WebSocket message
async fn process_ws_message(
    client_id: &str,
    text: &str,
    bundle_manager: Arc<BundleManager>,
    connections: Arc<RwLock<ConnectionState>>,
    _status_sender: StatusUpdateSender,
) {
    // Parse the message as JSON
    let value = match serde_json::from_str::<serde_json::Value>(text) {
        Ok(v) => v,
        Err(e) => {
            error!("Invalid JSON message from client {}: {}", client_id, e);
            
            // Send error message back to the client
            let error_event = WebSocketEvent::Error {
                code: "invalid_json".to_string(),
                message: format!("Invalid JSON message: {}", e),
                timestamp: Utc::now(),
            };
            send_to_client(client_id, &error_event, connections).await;
            return;
        }
    };
    
    // Extract the action
    let action = match value.get("action").and_then(|a| a.as_str()) {
        Some(a) => a,
        None => {
            error!("Missing action in WebSocket message from client {}", client_id);
            
            // Send error message back to the client
            let error_event = WebSocketEvent::Error {
                code: "missing_action".to_string(),
                message: "Missing 'action' field".to_string(),
                timestamp: Utc::now(),
            };
            send_to_client(client_id, &error_event, connections).await;
            return;
        }
    };
    
    // Process the action
    match action {
        "subscribe" => {
            if let Some(bundle_id_str) = value.get("bundle_id").and_then(|b| b.as_str()) {
                match bundle_id_str.parse::<BundleId>() {
                    Ok(bundle_id) => {
                        // Add subscription
                        {
                            let mut connections = connections.write().await;
                            connections.subscribe(client_id, bundle_id);
                        }
                        
                        info!("Client {} subscribed to bundle {}", client_id, bundle_id);
                        
                        // Fetch and send current status
                        match bundle_manager.get_bundle_status(bundle_id).await {
                            Ok(status) => {
                                let event = WebSocketEvent::BundleStatus {
                                    bundle_id,
                                    status: status.status_code,
                                    timestamp: Utc::now(),
                                    details: Some(json!({
                                        "block_number": status.block_number,
                                        "error": status.error,
                                    })),
                                };
                                send_to_client(client_id, &event, connections).await;
                            }
                            Err(e) => {
                                error!("Failed to get bundle status: {}", e);
                                
                                let error_event = WebSocketEvent::Error {
                                    code: "bundle_not_found".to_string(),
                                    message: format!("Bundle not found: {}", bundle_id),
                                    timestamp: Utc::now(),
                                };
                                send_to_client(client_id, &error_event, connections).await;
                            }
                        }
                    }
                    Err(e) => {
                        error!("Invalid bundle ID from client {}: {}", client_id, e);
                        
                        let error_event = WebSocketEvent::Error {
                            code: "invalid_bundle_id".to_string(),
                            message: format!("Invalid bundle ID: {}", e),
                            timestamp: Utc::now(),
                        };
                        send_to_client(client_id, &error_event, connections).await;
                    }
                }
            } else {
                error!("Missing bundle_id in subscribe message from client {}", client_id);
                
                let error_event = WebSocketEvent::Error {
                    code: "missing_bundle_id".to_string(),
                    message: "Missing 'bundle_id' field".to_string(),
                    timestamp: Utc::now(),
                };
                send_to_client(client_id, &error_event, connections).await;
            }
        }
        "unsubscribe" => {
            if let Some(bundle_id_str) = value.get("bundle_id").and_then(|b| b.as_str()) {
                match bundle_id_str.parse::<BundleId>() {
                    Ok(bundle_id) => {
                        // Remove subscription
                        {
                            let mut connections = connections.write().await;
                            connections.unsubscribe(client_id, bundle_id);
                        }
                        
                        info!("Client {} unsubscribed from bundle {}", client_id, bundle_id);
                    }
                    Err(e) => {
                        error!("Invalid bundle ID from client {}: {}", client_id, e);
                        
                        let error_event = WebSocketEvent::Error {
                            code: "invalid_bundle_id".to_string(),
                            message: format!("Invalid bundle ID: {}", e),
                            timestamp: Utc::now(),
                        };
                        send_to_client(client_id, &error_event, connections).await;
                    }
                }
            } else {
                error!("Missing bundle_id in unsubscribe message from client {}", client_id);
                
                let error_event = WebSocketEvent::Error {
                    code: "missing_bundle_id".to_string(),
                    message: "Missing 'bundle_id' field".to_string(),
                    timestamp: Utc::now(),
                };
                send_to_client(client_id, &error_event, connections).await;
            }
        }
        "ping" => {
            // Send pong message
            let heartbeat = WebSocketEvent::Heartbeat {
                timestamp: Utc::now(),
            };
            send_to_client(client_id, &heartbeat, connections).await;
        }
        _ => {
            error!("Unknown action '{}' from client {}", action, client_id);
            
            let error_event = WebSocketEvent::Error {
                code: "unknown_action".to_string(),
                message: format!("Unknown action: {}", action),
                timestamp: Utc::now(),
            };
            send_to_client(client_id, &error_event, connections).await;
        }
    }
}

/// Send an event to a specific client
async fn send_to_client(
    client_id: &str,
    event: &WebSocketEvent,
    connections: Arc<RwLock<ConnectionState>>,
) {
    let connections = connections.read().await;
    
    if let Some(tx) = connections.connections.get(client_id) {
        if let Ok(json) = serde_json::to_string(event) {
            if let Err(e) = tx.send(Ok(Message::text(json))) {
                error!("Failed to send message to client {}: {}", client_id, e);
            }
        }
    }
}

/// Send an event to all subscribers of a bundle
async fn send_to_subscribers(
    bundle_id: &BundleId,
    event: &WebSocketEvent,
    connections: Arc<RwLock<ConnectionState>>,
) {
    let connections_guard = connections.read().await;
    let subscribers = connections_guard.get_subscribers(bundle_id);
    
    if let Ok(json) = serde_json::to_string(event) {
        for client_id in subscribers {
            if let Some(tx) = connections_guard.connections.get(&client_id) {
                if let Err(e) = tx.send(Ok(Message::text(json.clone()))) {
                    error!("Failed to send message to client {}: {}", client_id, e);
                }
            }
        }
    }
}

/// Listen for status updates and forward them to WebSocket clients
async fn status_listener(
    status_sender: StatusUpdateSender,
    connections: Arc<RwLock<ConnectionState>>,
) {
    let mut receiver = status_sender.subscribe();
    
    while let Ok(event) = receiver.recv().await {
        match &event {
            WebSocketEvent::BundleStatus { bundle_id, .. } => {
                send_to_subscribers(bundle_id, &event, connections.clone()).await;
            }
            WebSocketEvent::TransactionStatus { bundle_id: Some(bundle_id), .. } => {
                send_to_subscribers(bundle_id, &event, connections.clone()).await;
            }
            _ => {
                // Ignore other events
            }
        }
    }
}

/// Send periodic heartbeats to all connected clients
async fn heartbeat_sender(
    connections: Arc<RwLock<ConnectionState>>,
) {
    let mut interval = interval(Duration::from_secs(30));
    
    loop {
        interval.tick().await;
        
        let heartbeat_event = WebSocketEvent::Heartbeat {
            timestamp: Utc::now(),
        };
        
        let connections_read = connections.read().await;
        for (client_id, client_tx) in connections_read.connections.iter() {
            if let Err(e) = client_tx.send(Ok(Message::text(serde_json::to_string(&heartbeat_event).unwrap()))) {
                warn!("Failed to send heartbeat to client {}: {}", client_id, e);
            } else {
                debug!("Sent heartbeat to client {}", client_id);
            }
        }
        
        debug!("Heartbeat sent to {} clients", connections_read.connections.len());
    }
}

/// Setup WebSocket API server
pub fn setup_websocket_api(
    port: u16,
    api_keys: Vec<String>,
    _statuses: Arc<Mutex<HashMap<BundleId, crate::types::BundleStatus>>>
) -> tokio::task::JoinHandle<()> {
    // Create state for WebSocket connections
    let connections = Arc::new(RwLock::new(ConnectionState::new()));
    let connections_for_status = connections.clone();
    let connections_for_heartbeat = connections.clone();
    
    // Create status update sender
    let status_sender = StatusUpdateSender::new();
    let status_sender_clone = status_sender.clone();
    
    // Create routes
    // Capture api_keys and port for use in the closure
    let api_keys_clone = api_keys.clone();
    let ws_port = port;
    
    let routes = warp::path("ws")
        .and(warp::ws())
        .and(warp::any().map(move || connections.clone()))
        .and(warp::any().map(move || status_sender.clone()))
        .and(warp::any().map(move || api_keys_clone.clone()))
        .and(warp::any().map(move || ws_port))
        .map(|ws: warp::ws::Ws, connections, status_sender, api_keys: Vec<String>, port| {
            ws.on_upgrade(async move |socket| {
                // Create relayer config
                let config = RelayerConfig {
                    server: ServerConfig {
                        host: "127.0.0.1".to_string(),
                        rest_port: 3000,
                        ws_port: port,
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
                        request_timeout: 60,
                        bundle_timeout_seconds: 60,
                    },
                    statelessvm: StatelessVmConfig {
                        endpoint_url: "http://localhost:8080".to_string(),
                        timeout_seconds: 30,
                        max_retries: 3,
                        validate_traces: true,
                    },
                };
                
                // Create validator
                let validator = Arc::new(crate::bundle::DefaultBundleValidator::new(
                    config.security.clone(),
                    config.chain.chain_id,
                    config.security.max_bundle_size,
                    1024 * 1024 // max_transaction_size
                ));
                
                // Initialize StatelessVM client
                let stateless_vm = StatelessVmClient::new(config.statelessvm.clone());

                // Create bundle manager
                let bundle_manager = BundleManager::new(config, validator, stateless_vm)
                    .await
                    .expect("Failed to initialize bundle manager");
                
                // Handle WebSocket connection
                handle_websocket_connection(
                    socket, 
                    connections, 
                    status_sender, 
                    Arc::new(bundle_manager)
                ).await
            })
        });
    
    // Start the WebSocket server
    let server = warp::serve(routes);
    let (addr, server) = server.bind_ephemeral(([0, 0, 0, 0], port));
    
    info!("WebSocket server started on {}", addr);
    
    // Start status listener and heartbeat sender
    tokio::spawn(status_listener(status_sender_clone, connections_for_status));
    tokio::spawn(heartbeat_sender(connections_for_heartbeat));
    
    // Return join handle
    tokio::spawn(server)
}
