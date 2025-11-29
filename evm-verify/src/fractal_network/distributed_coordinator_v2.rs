// TRUE Distributed Coordinator - Leader forwarding + state replication
// All nodes know about each other and forward to leader

use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};
use std::path::PathBuf;
use std::sync::Arc;
use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use reqwest::Client;
use tokio::sync::RwLock;

const TASK_CLAIM_TTL: u64 = 30;
const PROOF_DEDUPE_WINDOW: u64 = 300;
const LEADER_HEARTBEAT_TIMEOUT: u64 = 15;
const LEADER_ELECTION_INTERVAL: u64 = 20;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub task_id: String,
    pub task_data: Vec<u8>,
    pub created_at: u64,
    pub priority: TaskPriority,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum TaskPriority {
    Low,
    Normal,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TaskClaim {
    claimed_by: String,
    claimed_at: u64,
    expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofSubmission {
    pub task_id: String,
    pub proof_hash: String,
    pub submitted_by: String,
    pub submitted_at: u64,
    pub proof_data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LeaderInfo {
    node_id: String,
    address: String,
    elected_at: u64,
    last_heartbeat: u64,
    election_term: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CoordinatorState {
    pending_tasks: HashMap<String, Task>,
    active_claims: HashMap<String, TaskClaim>,
    completed_proofs: HashMap<String, ProofSubmission>,
    proof_hashes: HashSet<String>,
    leader: Option<LeaderInfo>,
    election_term: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub node_id: String,
    pub address: String,
    pub last_seen: u64,
}

pub struct DistributedCoordinator {
    state: Arc<RwLock<CoordinatorState>>,
    node_id: String,
    node_address: String,
    peers: Arc<RwLock<HashMap<String, PeerInfo>>>,
    persistence_path: Option<PathBuf>,
    auth_token: Option<String>,
    last_election_check: Arc<RwLock<u64>>,
    client: Client,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CoordinatorStats {
    pub pending_tasks: usize,
    pub active_claims: usize,
    pub completed_proofs: usize,
    pub current_leader: Option<String>,
    pub election_term: u64,
    pub is_healthy: bool,
    pub is_leader: bool,
    pub peer_count: usize,
}

impl DistributedCoordinator {
    pub fn new(node_id: String, node_address: String) -> Self {
        Self {
            state: Arc::new(RwLock::new(CoordinatorState {
                pending_tasks: HashMap::new(),
                active_claims: HashMap::new(),
                completed_proofs: HashMap::new(),
                proof_hashes: HashSet::new(),
                leader: None,
                election_term: 0,
            })),
            node_id,
            node_address,
            peers: Arc::new(RwLock::new(HashMap::new())),
            persistence_path: None,
            auth_token: None,
            last_election_check: Arc::new(RwLock::new(current_timestamp())),
            client: Client::new(),
        }
    }
    
    pub fn with_persistence(mut self, path: PathBuf) -> Self {
        self.persistence_path = Some(path.clone());
        // Try to load existing state
        if let Ok(data) = fs::read_to_string(&path) {
            if let Ok(loaded_state) = serde_json::from_str::<CoordinatorState>(&data) {
                *self.state.blocking_write() = loaded_state;
                tracing::info!("📂 Loaded coordinator state from disk");
            }
        }
        
        self
    }
    
    pub fn with_auth(mut self, token: String) -> Self {
        self.auth_token = Some(token);
        self
    }
    
    pub fn verify_auth(&self, provided_token: &str) -> bool {
        match &self.auth_token {
            Some(token) => token == provided_token,
            None => true,
        }
    }
    
    /// Register a peer node
    pub async fn register_peer(&self, node_id: String, address: String) {
        let mut peers = self.peers.write().await;
        peers.insert(node_id.clone(), PeerInfo {
            node_id,
            address,
            last_seen: current_timestamp(),
        });
        let count = peers.len();
        drop(peers);
        tracing::info!("👥 Registered peer: {} peers total", count);
    }
    
    /// Check if this node is the leader
    pub async fn is_leader(&self) -> bool {
        let state = self.state.read().await;
        if let Some(ref leader) = state.leader {
            leader.node_id == self.node_id
        } else {
            false
        }
    }
    
    /// Get leader address for forwarding
    fn get_leader_address(&self) -> Option<String> {
        self.state.leader.as_ref().map(|l| l.address.clone())
    }
    
    /// Check and handle leader health/election
    pub fn check_leader_health(&mut self) {
        let now = current_timestamp();
        
        if now - self.last_election_check < LEADER_ELECTION_INTERVAL {
            return;
        }
        
        self.last_election_check = now;
        
        if let Some(leader) = &self.state.leader {
            if now - leader.last_heartbeat > LEADER_HEARTBEAT_TIMEOUT {
                tracing::warn!("🚨 Leader {} is dead, initiating re-election", leader.node_id);
                self.state.leader = None;
                self.state.election_term += 1;
                
                // Try to become leader
                let _ = self.nominate_leader_internal(&self.node_id.clone(), &self.node_address.clone());
            }
        } else {
            // No leader, try to become one
            let _ = self.nominate_leader_internal(&self.node_id.clone(), &self.node_address.clone());
        }
    }
    
    fn persist_state(&self) {
        if let Some(path) = &self.persistence_path {
            if let Ok(json) = serde_json::to_string(&self.state) {
                if let Ok(mut file) = fs::File::create(path) {
                    let _ = file.write_all(json.as_bytes());
                }
            }
        }
    }
    
    // Local operations (only leader executes these)
    
    fn add_task_local(&mut self, task: Task) -> Result<(), String> {
        if self.state.pending_tasks.contains_key(&task.task_id) {
            return Err("Task already exists".to_string());
        }
        
        self.state.pending_tasks.insert(task.task_id.clone(), task);
        self.persist_state();
        Ok(())
    }
    
    fn claim_task_local(&mut self, task_id: &str, node_id: &str) -> Result<Task, String> {
        self.cleanup_expired_claims();
        
        let task = self.state.pending_tasks.get(task_id)
            .ok_or_else(|| "Task not found".to_string())?
            .clone();
        
        if let Some(claim) = self.state.active_claims.get(task_id) {
            if claim.expires_at > current_timestamp() {
                return Err(format!("Task already claimed by {}", claim.claimed_by));
            }
        }
        
        let now = current_timestamp();
        let claim = TaskClaim {
            claimed_by: node_id.to_string(),
            claimed_at: now,
            expires_at: now + TASK_CLAIM_TTL,
        };
        
        self.state.active_claims.insert(task_id.to_string(), claim);
        self.state.pending_tasks.remove(task_id);
        self.persist_state();
        
        Ok(task)
    }
    
    fn submit_proof_local(&mut self, submission: ProofSubmission) -> Result<bool, String> {
        let claim = self.state.active_claims.get(&submission.task_id)
            .ok_or_else(|| "No active claim for this task".to_string())?;
        
        if claim.claimed_by != submission.submitted_by {
            return Err(format!(
                "Task claimed by {} but submitted by {}",
                claim.claimed_by, submission.submitted_by
            ));
        }
        
        let proof_hash = calculate_proof_hash(&submission.proof_data);
        
        if self.state.proof_hashes.contains(&proof_hash) {
            return Ok(false);
        }
        
        let mut final_submission = submission;
        final_submission.proof_hash = proof_hash.clone();
        
        let task_id = final_submission.task_id.clone();
        self.state.completed_proofs.insert(task_id.clone(), final_submission);
        self.state.proof_hashes.insert(proof_hash);
        self.state.active_claims.remove(&task_id);
        
        self.cleanup_old_proofs();
        self.persist_state();
        
        Ok(true)
    }
    
    // Public API with automatic forwarding
    
    pub async fn add_task(&mut self, task: Task) -> Result<(), String> {
        if self.is_leader() {
            self.add_task_local(task)
        } else {
            self.forward_add_task(task).await
        }
    }
    
    pub async fn claim_task(&mut self, task_id: &str, node_id: &str) -> Result<Task, String> {
        if self.is_leader() {
            self.claim_task_local(task_id, node_id)
        } else {
            self.forward_claim_task(task_id, node_id).await
        }
    }
    
    pub async fn submit_proof(&mut self, submission: ProofSubmission) -> Result<bool, String> {
        if self.is_leader() {
            self.submit_proof_local(submission)
        } else {
            self.forward_submit_proof(submission).await
        }
    }
    
    pub fn get_available_tasks(&self, limit: usize) -> Vec<Task> {
        let mut tasks: Vec<Task> = self.state.pending_tasks.values().cloned().collect();
        
        tasks.sort_by(|a, b| {
            b.priority.cmp(&a.priority)
                .then(a.created_at.cmp(&b.created_at))
        });
        
        tasks.into_iter().take(limit).collect()
    }
    
    pub fn get_stats(&self) -> CoordinatorStats {
        let is_healthy = if let Some(leader) = &self.state.leader {
            current_timestamp() - leader.last_heartbeat < LEADER_HEARTBEAT_TIMEOUT
        } else {
            false
        };
        
        CoordinatorStats {
            pending_tasks: self.state.pending_tasks.len(),
            active_claims: self.state.active_claims.len(),
            completed_proofs: self.state.completed_proofs.len(),
            current_leader: self.state.leader.as_ref().map(|l| l.node_id.clone()),
            election_term: self.state.election_term,
            is_healthy,
            is_leader: self.is_leader(),
            peer_count: self.peers.len(),
        }
    }
    
    // Leader election
    
    fn nominate_leader_internal(&mut self, node_id: &str, address: &str) -> bool {
        let now = current_timestamp();
        
        if let Some(leader) = &self.state.leader {
            if now - leader.last_heartbeat < LEADER_HEARTBEAT_TIMEOUT {
                return false;
            }
        }
        
        self.state.leader = Some(LeaderInfo {
            node_id: node_id.to_string(),
            address: address.to_string(),
            elected_at: now,
            last_heartbeat: now,
            election_term: self.state.election_term + 1,
        });
        
        self.state.election_term += 1;
        self.persist_state();
        
        tracing::info!("🎖️  Node {} elected as leader (term {})", node_id, self.state.election_term);
        
        true
    }
    
    pub fn nominate_leader(&mut self, node_id: &str, address: &str) -> bool {
        self.nominate_leader_internal(node_id, address)
    }
    
    pub fn leader_heartbeat(&mut self, node_id: &str) -> bool {
        if let Some(ref mut leader) = self.state.leader {
            if leader.node_id == node_id {
                leader.last_heartbeat = current_timestamp();
                self.persist_state();
                return true;
            }
        }
        false
    }
    
    // HTTP forwarding to leader
    
    async fn forward_add_task(&self, task: Task) -> Result<(), String> {
        let leader_addr = self.get_leader_address()
            .ok_or_else(|| "No leader available".to_string())?;
        
        let url = format!("{}/coordinator/tasks/add", leader_addr);
        
        let response = self.client
            .post(&url)
            .json(&serde_json::json!({
                "task_id": task.task_id,
                "task_data": task.task_data,
                "priority": format!("{:?}", task.priority).to_lowercase()
            }))
            .send()
            .await
            .map_err(|e| format!("Failed to forward to leader: {}", e))?;
        
        if response.status().is_success() {
            Ok(())
        } else {
            Err("Leader rejected task".to_string())
        }
    }
    
    async fn forward_claim_task(&self, task_id: &str, node_id: &str) -> Result<Task, String> {
        let leader_addr = self.get_leader_address()
            .ok_or_else(|| "No leader available".to_string())?;
        
        let url = format!("{}/coordinator/tasks/claim", leader_addr);
        
        let response = self.client
            .post(&url)
            .json(&serde_json::json!({
                "task_id": task_id,
                "node_id": node_id
            }))
            .send()
            .await
            .map_err(|e| format!("Failed to forward to leader: {}", e))?;
        
        if response.status().is_success() {
            let result: serde_json::Value = response.json().await
                .map_err(|e| format!("Failed to parse response: {}", e))?;
            
            if result["status"] == "ok" {
                let task: Task = serde_json::from_value(result["task"].clone())
                    .map_err(|e| format!("Failed to parse task: {}", e))?;
                Ok(task)
            } else {
                Err(result["message"].as_str().unwrap_or("Unknown error").to_string())
            }
        } else {
            Err("Leader rejected claim".to_string())
        }
    }
    
    async fn forward_submit_proof(&self, submission: ProofSubmission) -> Result<bool, String> {
        let leader_addr = self.get_leader_address()
            .ok_or_else(|| "No leader available".to_string())?;
        
        let url = format!("{}/coordinator/proof/submit", leader_addr);
        
        let response = self.client
            .post(&url)
            .json(&serde_json::json!({
                "task_id": submission.task_id,
                "proof_data": submission.proof_data,
                "node_id": submission.submitted_by
            }))
            .send()
            .await
            .map_err(|e| format!("Failed to forward to leader: {}", e))?;
        
        if response.status().is_success() {
            let result: serde_json::Value = response.json().await
                .map_err(|e| format!("Failed to parse response: {}", e))?;
            Ok(result["accepted"].as_bool().unwrap_or(false))
        } else {
            Err("Leader rejected proof".to_string())
        }
    }
    
    // Maintenance
    
    fn cleanup_expired_claims(&mut self) {
        let now = current_timestamp();
        let expired: Vec<String> = self.state.active_claims.iter()
            .filter(|(_, claim)| claim.expires_at < now)
            .map(|(task_id, _)| task_id.clone())
            .collect();
        
        if !expired.is_empty() {
            for task_id in expired {
                self.state.active_claims.remove(&task_id);
            }
            self.persist_state();
        }
    }
    
    fn cleanup_old_proofs(&mut self) {
        let now = current_timestamp();
        let cutoff = now.saturating_sub(PROOF_DEDUPE_WINDOW);
        
        let old_tasks: Vec<String> = self.state.completed_proofs.iter()
            .filter(|(_, submission)| submission.submitted_at < cutoff)
            .map(|(task_id, _)| task_id.clone())
            .collect();
        
        if !old_tasks.is_empty() {
            for task_id in old_tasks {
                if let Some(submission) = self.state.completed_proofs.remove(&task_id) {
                    self.state.proof_hashes.remove(&submission.proof_hash);
                }
            }
            self.persist_state();
        }
    }
    
    /// Sync state from leader (for followers)
    pub async fn sync_from_leader(&mut self) -> Result<(), String> {
        if self.is_leader() {
            return Ok(()); // Leaders don't sync
        }
        
        let leader_addr = self.get_leader_address()
            .ok_or_else(|| "No leader available".to_string())?;
        
        let url = format!("{}/coordinator/state", leader_addr);
        
        let response = self.client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("Failed to sync from leader: {}", e))?;
        
        if response.status().is_success() {
            let state: CoordinatorState = response.json().await
                .map_err(|e| format!("Failed to parse state: {}", e))?;
            
            self.state = state;
            self.persist_state();
            
            tracing::debug!("🔄 Synced state from leader");
            Ok(())
        } else {
            Err("Failed to get state from leader".to_string())
        }
    }
    
    /// Get full state (for leader to share)
    pub fn get_state(&self) -> CoordinatorState {
        self.state.clone()
    }
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn calculate_proof_hash(proof_data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(proof_data);
    format!("{:x}", hasher.finalize())
}
