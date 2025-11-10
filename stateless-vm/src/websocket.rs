// WebSocket Streaming API for Continuous Proving
// Real-time transaction streaming and proof delivery

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast, mpsc};
use tokio_tungstenite::{accept_async, tungstenite::Message};
use futures::{SinkExt, StreamExt};
use futures::{StreamExt as FuturesStreamExt, SinkExt as FuturesSinkExt};
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use anyhow::Result;

use crate::streaming::{
    ContinuousProvingEngine, StreamingEvent, StreamingTransaction, 
    TransactionPriority, IncrementalProof, StreamingMetrics
};
use crate::transaction::Transaction;
use crate::errors::VMError;

/// WebSocket message types for streaming API
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum WSMessage {
    // Client -> Server messages
    Subscribe { 
        stream_types: Vec<StreamType>,
        session_id: String 
    },
    SubmitTransaction { 
        transaction: Transaction,
        stream_id: String,
        priority: TransactionPriority 
    },
    GetMetrics { request_id: String },
    GetProofChain { 
        start_sequence: Option<u64>,
        limit: Option<usize>,
        request_id: String 
    },
    
    // Server -> Client messages
    Event { 
        event: StreamingEvent,
        timestamp: u64 
    },
    TransactionAccepted { 
        tx_id: String,
        stream_id: String,
        sequence_number: u64 
    },
    Error { 
        error: String,
        request_id: Option<String> 
    },
    MetricsResponse { 
        metrics: StreamingMetrics,
        request_id: String 
    },
    ProofChainResponse { 
        proofs: Vec<IncrementalProof>,
        total_count: usize,
        request_id: String 
    },
}

/// Stream subscription types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum StreamType {
    TransactionEvents,
    ProofGeneration,
    StateUpdates,
    Metrics,
    Errors,
    All,
}

/// WebSocket client connection state
#[derive(Debug, Clone)]
pub struct WSClientConnection {
    pub client_id: String,
    pub subscriptions: Vec<StreamType>,
    pub session_id: String,
    pub connected_at: chrono::DateTime<chrono::Utc>,
    pub last_activity: chrono::DateTime<chrono::Utc>,
    pub message_count: u64,
}

/// WebSocket streaming server
pub struct WSStreamingServer {
    proving_engine: Arc<ContinuousProvingEngine>,
    clients: Arc<RwLock<HashMap<String, WSClientConnection>>>,
    event_receiver: Arc<RwLock<Option<broadcast::Receiver<StreamingEvent>>>>,
}

impl WSStreamingServer {
    /// Create new WebSocket streaming server
    pub fn new(proving_engine: Arc<ContinuousProvingEngine>) -> Self {
        let event_receiver = proving_engine.subscribe_events();
        
        Self {
            proving_engine,
            clients: Arc::new(RwLock::new(HashMap::new())),
            event_receiver: Arc::new(RwLock::new(Some(event_receiver))),
        }
    }
    
    /// Start the WebSocket server
    pub async fn start(&self, bind_addr: &str) -> Result<(), Box<dyn std::error::Error>> {
        let listener = tokio::net::TcpListener::bind(bind_addr).await?;
        println!("WebSocket streaming server listening on: {}", bind_addr);
        
        // Start event broadcaster
        self.start_event_broadcaster().await;
        
        while let Ok((stream, addr)) = listener.accept().await {
            println!("New WebSocket connection from: {}", addr);
            let server = self.clone();
            
            tokio::spawn(async move {
                if let Err(e) = server.handle_connection(stream).await {
                    eprintln!("WebSocket connection error: {}", e);
                }
            });
        }
        
        Ok(())
    }
    
    /// Handle individual WebSocket connection
    async fn handle_connection(
        &self, 
        stream: tokio::net::TcpStream
    ) -> Result<(), Box<dyn std::error::Error>> {
        let ws_stream = accept_async(stream).await?;
        let (mut ws_sender, mut ws_receiver) = FuturesStreamExt::split(ws_stream);
        
        let client_id = Uuid::new_v4().to_string();
        let (client_tx, mut client_rx) = mpsc::channel::<WSMessage>(1000);
        
        // Add client to active connections
        {
            let mut clients = self.clients.write().await;
            clients.insert(client_id.clone(), WSClientConnection {
                client_id: client_id.clone(),
                subscriptions: vec![],
                session_id: String::new(),
                connected_at: chrono::Utc::now(),
                last_activity: chrono::Utc::now(),
                message_count: 0,
            });
        }
        
        let server = self.clone();
        let client_id_clone = client_id.clone();
        
        // Handle outgoing messages to client
        let outgoing_task = tokio::spawn(async move {
            while let Some(message) = client_rx.recv().await {
                let json = match serde_json::to_string(&message) {
                    Ok(json) => json,
                    Err(e) => {
                        eprintln!("Failed to serialize message: {}", e);
                        continue;
                    }
                };
                
                if ws_sender.send(Message::Text(json)).await.is_err() {
                    break;
                }
            }
        });
        
        // Handle incoming messages from client
        while let Some(msg) = ws_receiver.next().await {
            match msg {
                Ok(Message::Text(text)) => {
                    if let Err(e) = self.handle_message(&client_id, &text, &client_tx).await {
                        let error_msg = WSMessage::Error { 
                            error: e.to_string(), 
                            request_id: None 
                        };
                        let _ = client_tx.send(error_msg).await;
                    }
                }
                Ok(Message::Close(_)) => {
                    println!("Client {} disconnected", client_id);
                    break;
                }
                Err(e) => {
                    eprintln!("WebSocket error: {}", e);
                    break;
                }
                _ => {}
            }
        }
        
        // Cleanup on disconnect
        outgoing_task.abort();
        {
            let mut clients = self.clients.write().await;
            clients.remove(&client_id_clone);
        }
        
        Ok(())
    }
    
    /// Handle incoming WebSocket message
    async fn handle_message(
        &self,
        client_id: &str,
        text: &str,
        client_tx: &mpsc::Sender<WSMessage>,
    ) -> Result<(), VMError> {
        let message: WSMessage = serde_json::from_str(text)
            .map_err(|e| VMError::Serialization(format!("Invalid message format: {}", e)))?;
        
        // Update client activity
        {
            let mut clients = self.clients.write().await;
            if let Some(client) = clients.get_mut(client_id) {
                client.last_activity = chrono::Utc::now();
                client.message_count += 1;
            }
        }
        
        match message {
            WSMessage::Subscribe { stream_types, session_id } => {
                let mut clients = self.clients.write().await;
                if let Some(client) = clients.get_mut(client_id) {
                    client.subscriptions = stream_types;
                    client.session_id = session_id;
                }
                Ok(())
            }
            
            WSMessage::SubmitTransaction { transaction, stream_id, priority } => {
                let tx_id = self.proving_engine.submit_transaction(
                    transaction, 
                    stream_id.clone(), 
                    priority
                ).await?;
                
                let sequence = self.proving_engine.get_current_sequence().await;
                let response = WSMessage::TransactionAccepted { 
                    tx_id, 
                    stream_id, 
                    sequence_number: sequence 
                };
                
                client_tx.send(response).await.map_err(|e| 
                    VMError::InvalidOperation { 
                        description: format!("Failed to send response: {}", e) 
                    })?;
                Ok(())
            }
            
            WSMessage::GetMetrics { request_id } => {
                let metrics = self.proving_engine.get_metrics().await;
                let response = WSMessage::MetricsResponse { metrics, request_id };
                
                client_tx.send(response).await.map_err(|e| 
                    VMError::InvalidOperation { 
                        description: format!("Failed to send metrics: {}", e) 
                    })?;
                Ok(())
            }
            
            WSMessage::GetProofChain { start_sequence, limit, request_id } => {
                let proof_chain = self.proving_engine.get_proof_chain().await;
                let start = start_sequence.unwrap_or(0);
                let limit = limit.unwrap_or(100).min(1000); // Cap at 1000
                
                let proofs: Vec<IncrementalProof> = proof_chain
                    .iter()
                    .filter(|p| p.sequence_number >= start)
                    .take(limit)
                    .cloned()
                    .collect();
                
                let total_count = proof_chain.len();
                
                let response = WSMessage::ProofChainResponse { 
                    proofs, 
                    total_count, 
                    request_id 
                };
                
                client_tx.send(response).await.map_err(|e| 
                    VMError::InvalidOperation { 
                        description: format!("Failed to send proof chain: {}", e) 
                    })?;
                Ok(())
            }
            
            // Server->Client messages should not be received
            _ => Err(VMError::InvalidOperation { 
                description: "Invalid message direction".to_string() 
            })
        }
    }
    
    /// Start broadcasting events to subscribed clients
    async fn start_event_broadcaster(&self) {
        // Placeholder implementation - in real use, this would listen to events
        // and broadcast to connected clients based on their subscriptions
    }
    
    /// Check if event should be sent to client based on subscriptions
    fn should_send_event(event: &StreamingEvent, subscriptions: &[StreamType]) -> bool {
        if subscriptions.contains(&StreamType::All) {
            return true;
        }
        
        match event {
            StreamingEvent::TransactionReceived { .. } | 
            StreamingEvent::BatchFormed { .. } => {
                subscriptions.contains(&StreamType::TransactionEvents)
            }
            StreamingEvent::ProofGenerated { .. } | 
            StreamingEvent::ProofVerified { .. } => {
                subscriptions.contains(&StreamType::ProofGeneration)
            }
            StreamingEvent::StateUpdated { .. } => {
                subscriptions.contains(&StreamType::StateUpdates)
            }
            StreamingEvent::MetricsUpdate { .. } => {
                subscriptions.contains(&StreamType::Metrics)
            }
            StreamingEvent::Error { .. } => {
                subscriptions.contains(&StreamType::Errors)
            }
        }
    }
    
    /// Get connected clients count
    pub async fn get_client_count(&self) -> usize {
        self.clients.read().await.len()
    }
    
    /// Get client connection info
    pub async fn get_client_info(&self) -> Vec<WSClientConnection> {
        self.clients.read().await.values().cloned().collect::<Vec<_>>()
    }
}

impl Clone for WSStreamingServer {
    fn clone(&self) -> Self {
        Self {
            proving_engine: self.proving_engine.clone(),
            clients: self.clients.clone(),
            event_receiver: self.event_receiver.clone(),
        }
    }
}

/// High-performance WebSocket client for testing and integration
pub struct WSStreamingClient {
    url: String,
    client_id: String,
    event_handler: Arc<dyn Fn(StreamingEvent) + Send + Sync>,
}

impl WSStreamingClient {
    /// Create new WebSocket client
    pub fn new<F>(url: String, event_handler: F) -> Self 
    where 
        F: Fn(StreamingEvent) + Send + Sync + 'static 
    {
        Self {
            url,
            client_id: Uuid::new_v4().to_string(),
            event_handler: Arc::new(event_handler),
        }
    }
    
    /// Connect to WebSocket server
    pub async fn connect(&self) -> Result<WSClientHandle, Box<dyn std::error::Error>> {
        let (ws_stream, _) = tokio_tungstenite::connect_async(&self.url).await?;
        let (mut ws_sender, mut ws_receiver) = FuturesStreamExt::split(ws_stream);
        
        let (command_tx, mut command_rx) = mpsc::channel::<WSMessage>(100);
        let event_handler = self.event_handler.clone();
        
        // Handle outgoing messages
        let outgoing_task = tokio::spawn(async move {
            while let Some(message) = command_rx.recv().await {
                let json = serde_json::to_string(&message).unwrap();
                if ws_sender.send(Message::Text(json)).await.is_err() {
                    break;
                }
            }
        });
        
        // Handle incoming messages
        let incoming_task = tokio::spawn(async move {
            while let Some(msg) = ws_receiver.next().await {
                if let Ok(Message::Text(text)) = msg {
                    if let Ok(ws_message) = serde_json::from_str::<WSMessage>(&text) {
                        match ws_message {
                            WSMessage::Event { event, .. } => {
                                event_handler(event);
                            }
                            _ => {
                                // Handle other message types as needed
                            }
                        }
                    }
                }
            }
        });
        
        Ok(WSClientHandle {
            command_sender: command_tx,
            _outgoing_task: outgoing_task,
            _incoming_task: incoming_task,
        })
    }
}

/// Handle for WebSocket client operations
pub struct WSClientHandle {
    command_sender: mpsc::Sender<WSMessage>,
    _outgoing_task: tokio::task::JoinHandle<()>,
    _incoming_task: tokio::task::JoinHandle<()>,
}

impl WSClientHandle {
    /// Subscribe to event streams
    pub async fn subscribe(&self, stream_types: Vec<StreamType>) -> Result<(), Box<dyn std::error::Error>> {
        let message = WSMessage::Subscribe { 
            stream_types, 
            session_id: Uuid::new_v4().to_string() 
        };
        self.command_sender.send(message).await?;
        Ok(())
    }
    
    /// Submit transaction through WebSocket
    pub async fn submit_transaction(
        &self, 
        transaction: Transaction,
        stream_id: String,
        priority: TransactionPriority,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let message = WSMessage::SubmitTransaction { 
            transaction, 
            stream_id, 
            priority 
        };
        self.command_sender.send(message).await?;
        Ok(())
    }
    
    /// Request current metrics
    pub async fn get_metrics(&self) -> Result<(), Box<dyn std::error::Error>> {
        let message = WSMessage::GetMetrics { 
            request_id: Uuid::new_v4().to_string() 
        };
        self.command_sender.send(message).await?;
        Ok(())
    }
    
    /// Request proof chain
    pub async fn get_proof_chain(
        &self,
        start_sequence: Option<u64>,
        limit: Option<usize>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let message = WSMessage::GetProofChain { 
            start_sequence, 
            limit,
            request_id: Uuid::new_v4().to_string() 
        };
        self.command_sender.send(message).await?;
        Ok(())
    }
}
