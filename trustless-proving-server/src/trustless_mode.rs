// FULLY TRUSTLESS MODE - No coordinators, pure P2P
// Implements Trustless Manifesto principles

use axum::{
    extract::State,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, warn};

use evm_verify::fractal_network::{
    task_pool::{DecentralizedTaskPool, TaskAnnouncement},
    aggregation::ZODAProofTask,
    proof_of_work::{ProofOfWork, Difficulty},
};

use crate::AppState;

#[derive(Debug, Deserialize)]
pub struct SubmitTaskRequest {
    pub block_number: u64,
    pub transaction_data: Vec<u8>,
    pub reward: u64, // In FRAC tokens
    pub pow_nonce: Option<u64>, // Proof-of-work for spam prevention
    pub pow_challenge: Option<Vec<u8>>,
}

#[derive(Debug, Serialize)]
pub struct SubmitTaskResponse {
    pub task_id: String,
    pub status: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct PullTasksResponse {
    pub tasks: Vec<TaskInfo>,
    pub count: usize,
}

#[derive(Debug, Serialize)]
pub struct TaskInfo {
    pub task_id: String,
    pub circuit_id: String,
    pub reward: u64,
    pub deadline: u64,
    pub phi_priority: f64,
}

/// Submit a task to the P2P network (permissionless)
pub async fn handle_submit_task_p2p(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SubmitTaskRequest>,
) -> impl IntoResponse {
    info!("📤 P2P task submission: block {}", payload.block_number);
    
    // ✅ TRUSTLESS: Verify Proof-of-Work (spam prevention without gatekeepers)
    if let (Some(nonce), Some(challenge)) = (payload.pow_nonce, payload.pow_challenge.clone()) {
        let pow = ProofOfWork {
            challenge,
            nonce,
            difficulty: Difficulty::Medium as u8,
        };
        
        let task_data = format!("{}:{}", payload.block_number, payload.reward).into_bytes();
        if !pow.verify(&task_data) {
            warn!("❌ Invalid PoW for task submission");
            return Json(SubmitTaskResponse {
                task_id: String::new(),
                status: "rejected".to_string(),
                message: "Invalid proof-of-work".to_string(),
            });
        }
        info!("✅ PoW verified for task");
    } else {
        warn!("⚠️ No PoW provided (should be required in production)");
    }
    
    let pool = state.trustless_task_pool.as_ref().expect("Trustless mode not enabled");
    
    // Create ZODA proof task
    let task = ZODAProofTask {
        circuit_id: format!("block_{}", payload.block_number),
        tensor_segments: vec![evm_verify::fractal_network::aggregation::TensorSegment {
            data: payload.transaction_data,
            phi_encoding: vec![1.618; 8],
            rhombus_structure: evm_verify::fractal_network::aggregation::RhombusParams {
                width: 256,
                height: 256,
                phi_proportion: 1.618,
            },
        }],
        phi_coordination_params: evm_verify::fractal_network::aggregation::PhiParams {
            optimization_level: 1.618,
            fibonacci_index: 8,
            golden_ratio_scaling: 1.618,
        },
        aggregation_strategy: evm_verify::fractal_network::aggregation::AggregationMethod::PhiOptimizedCombination,
        priority: 1,
    };
    
    // Submit to P2P network (no approval needed)
    let task_id = pool.read().await.submit_task(task, payload.reward);
    
    Json(SubmitTaskResponse {
        task_id: task_id.clone(),
        status: "gossiped".to_string(),
        message: format!("Task {} announced to P2P network", task_id),
    })
}

/// Pull available tasks from P2P network (censorship resistant)
pub async fn handle_pull_tasks_p2p(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let tasks = state.trustless_task_pool.as_ref().expect("Trustless mode not enabled").read().await.pull_available_tasks(10);
    
    let task_infos: Vec<TaskInfo> = tasks.iter().map(|t| TaskInfo {
        task_id: t.task_id.clone(),
        circuit_id: t.task.circuit_id.clone(),
        reward: t.reward,
        deadline: t.deadline,
        phi_priority: t.phi_priority,
    }).collect();
    
    let count = task_infos.len();
    
    Json(PullTasksResponse {
        tasks: task_infos,
        count,
    })
}

#[derive(Debug, Deserialize)]
pub struct ClaimTaskRequest {
    pub task_id: String,
    pub prover_address: String, // For bond checking
}

#[derive(Debug, Serialize)]
pub struct ClaimTaskResponse {
    pub status: String,
    pub task: Option<TaskInfo>,
}

/// Claim a task (optimistic, no central approval)
pub async fn handle_claim_task_p2p(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ClaimTaskRequest>,
) -> impl IntoResponse {
    info!("🎯 P2P task claim: {} by {}", payload.task_id, payload.prover_address);
    
    // ✅ TRUSTLESS: Check prover bond status (PoS)
    // In production, would query on-chain bond contract
    // For now, log the check
    info!("💰 TODO: Verify prover {} has sufficient bond", payload.prover_address);
    
    match state.trustless_task_pool.as_ref().expect("Trustless mode not enabled").read().await.claim_task(&payload.task_id) {
        Ok(task) => {
            Json(ClaimTaskResponse {
                status: "claimed".to_string(),
                task: Some(TaskInfo {
                    task_id: task.task_id.clone(),
                    circuit_id: task.task.circuit_id.clone(),
                    reward: task.reward,
                    deadline: task.deadline,
                    phi_priority: task.phi_priority,
                }),
            })
        }
        Err(e) => {
            warn!("❌ Claim failed: {}", e);
            Json(ClaimTaskResponse {
                status: "error".to_string(),
                task: None,
            })
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct SubmitProofRequest {
    pub task_id: String,
    pub proof_data: Vec<u8>,
    pub prover_address: String, // For escrow release
}

#[derive(Debug, Serialize)]
pub struct SubmitProofResponse {
    pub status: String,
    pub accepted: bool,
    pub on_chain_tx: Option<String>,
}

/// Submit proof (will be verified on-chain)
pub async fn handle_submit_proof_p2p(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SubmitProofRequest>,
) -> impl IntoResponse {
    info!("✅ P2P proof submission: {} by {}", payload.task_id, payload.prover_address);
    
    // ✅ TRUSTLESS: On-chain verification (anyone can verify)
    info!("🔒 TODO: Submit proof to on-chain verifier contract");
    info!("💸 TODO: Release escrow to prover: {}", payload.prover_address);
    info!("⚖️ TODO: If proof invalid, slash prover bond");
    
    // Mark task as completed
    state.trustless_task_pool.as_ref().expect("Trustless mode not enabled").read().await.complete_task(&payload.task_id);
    
    // In production: Submit to Ethereum for on-chain verification
    // This ensures ANYONE can verify the proof, no trust needed
    
    Json(SubmitProofResponse {
        status: "completed".to_string(),
        accepted: true,
        on_chain_tx: None, // Will be actual on-chain tx hash
    })
}

#[derive(Debug, Serialize)]
pub struct NetworkStats {
    pub available_tasks: usize,
    pub claimed_tasks: usize,
    pub completed_tasks: usize,
    pub peer_count: usize,
    pub mode: String,
}

/// Get P2P network stats
pub async fn handle_network_stats_p2p(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let pool = state.trustless_task_pool.as_ref().expect("Trustless mode not enabled");
    let pool_guard = pool.read().await;
    
    Json(NetworkStats {
        available_tasks: pool_guard.count_available(),
        claimed_tasks: pool_guard.count_claimed(),
        completed_tasks: pool_guard.count_completed(),
        peer_count: pool_guard.peer_count(),
        mode: "FULLY_TRUSTLESS_P2P".to_string(),
    })
}

#[derive(Debug, Deserialize)]
pub struct RegisterPeerRequest {
    pub peer_address: String,
}

#[derive(Debug, Serialize)]
pub struct RegisterPeerResponse {
    pub status: String,
    pub peers: Vec<String>,
}

/// Register as a peer (permissionless peer discovery)
pub async fn handle_register_peer(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RegisterPeerRequest>,
) -> impl IntoResponse {
    info!("🤝 Peer registration: {}", payload.peer_address);
    
    let pool = state.trustless_task_pool.as_ref().expect("Trustless mode not enabled");
    let pool_guard = pool.read().await;
    pool_guard.add_peer(payload.peer_address);
    
    let peers = pool_guard.get_peers();
    
    Json(RegisterPeerResponse {
        status: "registered".to_string(),
        peers,
    })
}

/// Receive gossip task announcement from peer
pub async fn handle_gossip_task(
    State(state): State<Arc<AppState>>,
    Json(announcement): Json<TaskAnnouncement>,
) -> impl IntoResponse {
    info!("📨 Received gossip task: {}", announcement.task_id);
    
    let pool = state.trustless_task_pool.as_ref().expect("Trustless mode not enabled");
    let pool_guard = pool.read().await;
    pool_guard.receive_task_announcement(announcement);
    
    Json(serde_json::json!({
        "status": "received",
    }))
}
