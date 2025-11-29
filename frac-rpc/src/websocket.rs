// WebSocket Support for eth_subscribe
use anyhow::Result;
use axum::{
    extract::{State, WebSocketUpgrade},
    extract::ws::{Message, WebSocket},
    response::Response,
};
use futures::{sink::SinkExt, stream::StreamExt};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{debug, warn};

const MAX_SUBSCRIPTIONS_PER_CLIENT: usize = 100;
const CHANNEL_CAPACITY: usize = 1000;

#[derive(Clone)]
pub struct WebSocketHandler {
    tx: broadcast::Sender<SubscriptionEvent>,
}

#[derive(Clone, Debug)]
pub struct SubscriptionEvent {
    pub subscription_id: String,
    pub data: Value,
}

impl WebSocketHandler {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(CHANNEL_CAPACITY);
        Self { tx }
    }

    pub fn handle_upgrade<S: Clone + Send + Sync + 'static>(
        ws: WebSocketUpgrade,
        state: State<S>,
    ) -> Response {
        ws.on_upgrade(move |socket| Self::handle_socket(socket, state.0))
    }

    async fn handle_socket<S: Send + Sync + 'static>(socket: WebSocket, _state: S) {
        let (mut sender, mut receiver) = socket.split();
        let mut subscriptions: Vec<String> = Vec::new();

        while let Some(msg) = receiver.next().await {
            match msg {
                Ok(Message::Text(text)) => {
                    if let Ok(request) = serde_json::from_str::<Value>(&text) {
                        let response = Self::handle_request(&request, &mut subscriptions).await;
                        
                        if let Ok(json) = serde_json::to_string(&response) {
                            if sender.send(Message::Text(json)).await.is_err() {
                                break;
                            }
                        }
                    }
                }
                Ok(Message::Close(_)) => {
                    debug!("WebSocket closed by client");
                    break;
                }
                Ok(Message::Ping(data)) => {
                    if sender.send(Message::Pong(data)).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    warn!("WebSocket error: {}", e);
                    break;
                }
                _ => {}
            }
        }

        debug!("WebSocket connection closed, had {} subscriptions", subscriptions.len());
    }

    async fn handle_request(request: &Value, subscriptions: &mut Vec<String>) -> Value {
        let method = request["method"].as_str().unwrap_or("");
        let id = request["id"].clone();

        match method {
            "eth_subscribe" => {
                if subscriptions.len() >= MAX_SUBSCRIPTIONS_PER_CLIENT {
                    return json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32000,
                            "message": "Max subscriptions reached"
                        }
                    });
                }

                let params = request["params"].as_array();
                let sub_type = params
                    .and_then(|p| p.get(0))
                    .and_then(|v| v.as_str())
                    .unwrap_or("newHeads");

                let subscription_id = Self::generate_subscription_id();
                subscriptions.push(subscription_id.clone());

                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": subscription_id
                })
            }
            "eth_unsubscribe" => {
                let params = request["params"].as_array();
                let sub_id = params
                    .and_then(|p| p.get(0))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                let removed = subscriptions.iter().position(|s| s == sub_id).is_some();
                if removed {
                    subscriptions.retain(|s| s != sub_id);
                }

                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": removed
                })
            }
            _ => {
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": -32601,
                        "message": "Method not supported"
                    }
                })
            }
        }
    }

    fn generate_subscription_id() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("0x{:x}", timestamp)
    }

    pub async fn broadcast_event(&self, event: SubscriptionEvent) -> Result<()> {
        self.tx.send(event)?;
        Ok(())
    }
}
