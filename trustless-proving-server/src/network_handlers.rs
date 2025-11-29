// Network Communication Handlers for Multi-Node Coordination

use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

use evm_verify::fractal_network::simple_multinode::{
    SimpleMultiNode, PeerNode, TaskAnnouncement, ProofShare,
};
use evm_verify::fractal_network::production_coordinator::{
    ProductionCoordinator, Task, TaskPriority, ProofSubmission, CoordinatorStats,
};

#[derive(Debug, Deserialize)]
pub struct AnnounceRequest {
    pub node_id: String,
    pub address: String,
}

#[derive(Debug, Serialize)]
pub struct AnnounceResponse {
    pub status: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct PeersResponse {
    pub peers: Vec<PeerInfo>,
    pub count: usize,
}

#[derive(Debug, Serialize)]
pub struct PeerInfo {
    pub node_id: String,
    pub address: String,
    pub last_seen: u64,
}

#[derive(Debug, Deserialize)]
pub struct TaskRequest {
    pub task_id: String,
    pub task_data: Vec<u8>,
    pub announced_by: String,
}

#[derive(Debug, Serialize)]
pub struct TaskResponse {
    pub status: String,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct ProofShareRequest {
    pub task_id: String,
    pub proof_data: Vec<u8>,
    pub from_node: String,
}

#[derive(Debug, Serialize)]
pub struct ProofShareResponse {
    pub status: String,
    pub message: String,
}

// Handler: Announce this node to the network
pub async fn handle_announce(
    multinode: Arc<RwLock<SimpleMultiNode>>,
    Json(payload): Json<AnnounceRequest>,
) -> impl IntoResponse {
    info!("📡 Peer announcement from: {}", payload.node_id);
    
    multinode
        .write()
        .await
        .register_peer(payload.node_id.clone(), payload.address)
        .await;
    
    Json(AnnounceResponse {
        status: "ok".to_string(),
        message: format!("Peer {} registered", payload.node_id),
    })
}

// Handler: Get list of known peers
pub async fn handle_get_peers(
    multinode: Arc<RwLock<SimpleMultiNode>>,
) -> impl IntoResponse {
    let peers = multinode.read().await.get_peers().await;
    
    let peer_infos: Vec<PeerInfo> = peers
        .into_iter()
        .map(|p| PeerInfo {
            node_id: p.node_id,
            address: p.address,
            last_seen: p.last_seen,
        })
        .collect();
    
    let count = peer_infos.len();
    
    Json(PeersResponse {
        peers: peer_infos,
        count,
    })
}

// Handler: Receive task announcement
pub async fn handle_task(
    multinode: Arc<RwLock<SimpleMultiNode>>,
    Json(payload): Json<TaskRequest>,
) -> impl IntoResponse {
    info!("📋 Task received: {} from {}", payload.task_id, payload.announced_by);
    
    // In production, this would add the task to a queue
    // For now, just acknowledge receipt
    
    Json(TaskResponse {
        status: "ok".to_string(),
        message: format!("Task {} queued", payload.task_id),
    })
}

// Handler: Receive proof share
pub async fn handle_proof_share(
    multinode: Arc<RwLock<SimpleMultiNode>>,
    Json(payload): Json<ProofShareRequest>,
) -> impl IntoResponse {
    info!("🔐 Proof share received: {} from {}", payload.task_id, payload.from_node);
    
    // In production, this would aggregate the proof
    // For now, just acknowledge receipt
    
    Json(ProofShareResponse {
        status: "ok".to_string(),
        message: format!("Proof share for {} accepted", payload.task_id),
    })
}

// Handler: Bootstrap from a peer
pub async fn handle_bootstrap(
    multinode: Arc<RwLock<SimpleMultiNode>>,
    Json(peer_address): Json<String>,
) -> Result<impl IntoResponse, StatusCode> {
    info!("🌱 Bootstrapping from peer: {}", peer_address);
    
    let node = multinode.read().await;
    
    // Announce ourselves to the bootstrap peer
    match node.announce_to_peer(&peer_address).await {
        Ok(_) => {
            info!("✅ Successfully bootstrapped from {}", peer_address);
            Ok(Json(serde_json::json!({
                "status": "ok",
                "message": format!("Bootstrapped from {}", peer_address)
            })))
        }
        Err(e) => {
            warn!("❌ Failed to bootstrap: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// ============================================================================
// Production Coordination Handlers
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct AddTaskRequest {
    pub task_id: String,
    pub task_data: Vec<u8>,
    pub priority: String,
}

#[derive(Debug, Deserialize)]
pub struct ClaimTaskRequest {
    pub task_id: String,
    pub node_id: String,
}

#[derive(Debug, Serialize)]
pub struct ClaimTaskResponse {
    pub status: String,
    pub task: Option<Task>,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct SubmitProofRequest {
    pub task_id: String,
    pub proof_data: Vec<u8>,
    pub node_id: String,
}

#[derive(Debug, Serialize)]
pub struct SubmitProofResponse {
    pub status: String,
    pub accepted: bool,
    pub message: String,
}

// Handler: Add task to coordinator
pub async fn handle_add_task(
    coordinator: Arc<RwLock<ProductionCoordinator>>,
    Json(payload): Json<AddTaskRequest>,
) -> impl IntoResponse {
    // Check leader health first (quick, no HTTP)
    coordinator.write().await.check_leader_health();
    
    let priority = match payload.priority.as_str() {
        "low" => TaskPriority::Low,
        "normal" => TaskPriority::Normal,
        "high" => TaskPriority::High,
        "critical" => TaskPriority::Critical,
        _ => TaskPriority::Normal,
    };
    
    let task = Task {
        task_id: payload.task_id.clone(),
        task_data: payload.task_data,
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        priority,
    };
    
    match coordinator.write().await.add_task(task) {
        Ok(_) => {
            info!("📋 Task added: {}", payload.task_id);
            Json(serde_json::json!({
                "status": "ok",
                "message": format!("Task {} added", payload.task_id)
            }))
        }
        Err(e) => {
            warn!("❌ Failed to add task: {}", e);
            Json(serde_json::json!({
                "status": "error",
                "message": e
            }))
        }
    }
}

// Handler: Claim task for processing
pub async fn handle_claim_task(
    coordinator: Arc<RwLock<ProductionCoordinator>>,
    Json(payload): Json<ClaimTaskRequest>,
) -> impl IntoResponse {
    coordinator.write().await.check_leader_health();
    match coordinator.write().await.claim_task(&payload.task_id, &payload.node_id) {
        Ok(task) => {
            info!("🎯 Task claimed: {} by {}", payload.task_id, payload.node_id);
            Json(ClaimTaskResponse {
                status: "ok".to_string(),
                task: Some(task),
                message: format!("Task {} claimed", payload.task_id),
            })
        }
        Err(e) => {
            warn!("❌ Claim failed: {}", e);
            Json(ClaimTaskResponse {
                status: "error".to_string(),
                task: None,
                message: e,
            })
        }
    }
}

// Handler: Get available tasks
pub async fn handle_get_tasks(
    coordinator: Arc<RwLock<ProductionCoordinator>>,
) -> impl IntoResponse {
    let tasks = coordinator.read().await.get_available_tasks(10);
    Json(serde_json::json!({
        "status": "ok",
        "tasks": tasks,
        "count": tasks.len()
    }))
}

// Handler: Submit proof with coordination
pub async fn handle_submit_coordinated_proof(
    coordinator: Arc<RwLock<ProductionCoordinator>>,
    Json(payload): Json<SubmitProofRequest>,
) -> impl IntoResponse {
    let submission = ProofSubmission {
        task_id: payload.task_id.clone(),
        proof_hash: String::new(),
        submitted_by: payload.node_id.clone(),
        submitted_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        proof_data: payload.proof_data,
    };
    
    match coordinator.write().await.submit_proof(submission) {
        Ok(accepted) => {
            if accepted {
                info!("✅ Proof accepted: {} by {}", payload.task_id, payload.node_id);
                Json(SubmitProofResponse {
                    status: "ok".to_string(),
                    accepted: true,
                    message: format!("Proof for {} accepted", payload.task_id),
                })
            } else {
                info!("⚠️  Proof duplicate: {} by {}", payload.task_id, payload.node_id);
                Json(SubmitProofResponse {
                    status: "ok".to_string(),
                    accepted: false,
                    message: "Duplicate proof rejected".to_string(),
                })
            }
        }
        Err(e) => {
            warn!("❌ Proof submission failed: {}", e);
            Json(SubmitProofResponse {
                status: "error".to_string(),
                accepted: false,
                message: e,
            })
        }
    }
}

// Handler: Get coordinator stats
pub async fn handle_coordinator_stats(
    coordinator: Arc<RwLock<ProductionCoordinator>>,
) -> impl IntoResponse {
    let stats = coordinator.read().await.get_stats();
    Json(stats)
}

// Handler: Leader election
pub async fn handle_nominate_leader(
    coordinator: Arc<RwLock<ProductionCoordinator>>,
    Json(node_id): Json<String>,
) -> impl IntoResponse {
    let is_leader = coordinator.write().await.nominate_leader(&node_id);
    Json(serde_json::json!({
        "status": "ok",
        "is_leader": is_leader,
        "node_id": node_id
    }))
}

// Handler: Leader heartbeat
pub async fn handle_leader_heartbeat(
    coordinator: Arc<RwLock<ProductionCoordinator>>,
    Json(node_id): Json<String>,
) -> impl IntoResponse {
    let accepted = coordinator.write().await.leader_heartbeat(&node_id);
    Json(serde_json::json!({
        "status": if accepted { "ok" } else { "not_leader" },
        "node_id": node_id
    }))
}
