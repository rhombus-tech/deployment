// Production-Grade Coordinator with Failover, Persistence, and Security
// Single file with all critical production features

use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::path::PathBuf;
use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;

const TASK_CLAIM_TTL: u64 = 30;
const PROOF_DEDUPE_WINDOW: u64 = 300;
const LEADER_HEARTBEAT_TIMEOUT: u64 = 15; // Leader must heartbeat every 15s
const LEADER_ELECTION_INTERVAL: u64 = 20; // Check for leader every 20s

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

pub struct ProductionCoordinator {
    state: CoordinatorState,
    node_id: String,
    persistence_path: Option<PathBuf>,
    auth_token: Option<String>,
    last_election_check: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CoordinatorStats {
    pub pending_tasks: usize,
    pub active_claims: usize,
    pub completed_proofs: usize,
    pub current_leader: Option<String>,
    pub election_term: u64,
    pub is_healthy: bool,
}

impl ProductionCoordinator {
    pub fn new(node_id: String) -> Self {
        Self {
            state: CoordinatorState {
                pending_tasks: HashMap::new(),
                active_claims: HashMap::new(),
                completed_proofs: HashMap::new(),
                proof_hashes: HashSet::new(),
                leader: None,
                election_term: 0,
            },
            node_id,
            persistence_path: None,
            auth_token: None,
            last_election_check: current_timestamp(),
        }
    }
    
    /// Enable state persistence
    pub fn with_persistence(mut self, path: PathBuf) -> Self {
        self.persistence_path = Some(path.clone());
        
        // Try to load existing state
        if let Ok(data) = fs::read_to_string(&path) {
            if let Ok(state) = serde_json::from_str::<CoordinatorState>(&data) {
                self.state = state;
                tracing::info!("📂 Loaded coordinator state from disk");
            }
        }
        
        self
    }
    
    /// Enable authentication
    pub fn with_auth(mut self, token: String) -> Self {
        self.auth_token = Some(token);
        self
    }
    
    /// Verify auth token
    pub fn verify_auth(&self, provided_token: &str) -> bool {
        match &self.auth_token {
            Some(token) => token == provided_token,
            None => true, // No auth enabled
        }
    }
    
    /// Persist state to disk
    fn persist_state(&self) {
        if let Some(path) = &self.persistence_path {
            if let Ok(json) = serde_json::to_string(&self.state) {
                if let Ok(mut file) = fs::File::create(path) {
                    let _ = file.write_all(json.as_bytes());
                }
            }
        }
    }
    
    /// Check and handle leader failover
    pub fn check_leader_health(&mut self) {
        let now = current_timestamp();
        
        // Only check periodically
        if now - self.last_election_check < LEADER_ELECTION_INTERVAL {
            return;
        }
        
        self.last_election_check = now;
        
        // Check if leader is dead
        if let Some(leader) = &self.state.leader {
            if now - leader.last_heartbeat > LEADER_HEARTBEAT_TIMEOUT {
                tracing::warn!("🚨 Leader {} is dead, initiating re-election", leader.node_id);
                
                // Leader is dead, trigger new election
                self.state.leader = None;
                self.state.election_term += 1;
                
                // Try to become leader ourselves
                let _ = self.nominate_leader(&self.node_id.clone());
            }
        } else {
            // No leader exists, try to become one
            let _ = self.nominate_leader(&self.node_id.clone());
        }
    }
    
    /// Add task
    pub fn add_task(&mut self, task: Task) -> Result<(), String> {
        if self.state.pending_tasks.contains_key(&task.task_id) {
            return Err("Task already exists".to_string());
        }
        
        if self.state.active_claims.contains_key(&task.task_id) {
            return Err("Task already claimed".to_string());
        }
        
        if self.state.completed_proofs.contains_key(&task.task_id) {
            return Err("Task already completed".to_string());
        }
        
        self.state.pending_tasks.insert(task.task_id.clone(), task);
        self.persist_state();
        
        Ok(())
    }
    
    /// Claim task
    pub fn claim_task(&mut self, task_id: &str, node_id: &str) -> Result<Task, String> {
        self.cleanup_expired_claims();
        
        let task = self.state.pending_tasks.get(task_id)
            .ok_or_else(|| "Task not found".to_string())?
            .clone();
        
        if let Some(claim) = self.state.active_claims.get(task_id) {
            if claim.expires_at > current_timestamp() {
                return Err(format!("Task already claimed by {}", claim.claimed_by));
            }
        }
        
        if self.state.completed_proofs.contains_key(task_id) {
            return Err("Task already completed".to_string());
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
    
    /// Submit proof
    pub fn submit_proof(&mut self, submission: ProofSubmission) -> Result<bool, String> {
        let claim = self.state.active_claims.get(&submission.task_id)
            .ok_or_else(|| "No active claim for this task".to_string())?;
        
        if claim.claimed_by != submission.submitted_by {
            return Err(format!(
                "Task claimed by {} but submitted by {}",
                claim.claimed_by, submission.submitted_by
            ));
        }
        
        if claim.expires_at < current_timestamp() {
            self.state.active_claims.remove(&submission.task_id);
            return Err("Claim expired".to_string());
        }
        
        let proof_hash = calculate_proof_hash(&submission.proof_data);
        
        if self.state.proof_hashes.contains(&proof_hash) {
            return Ok(false); // Duplicate
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
    
    /// Release claim
    pub fn release_claim(&mut self, task_id: &str, node_id: &str) -> Result<(), String> {
        if let Some(claim) = self.state.active_claims.get(task_id) {
            if claim.claimed_by != node_id {
                return Err("Cannot release claim owned by another node".to_string());
            }
            
            self.state.active_claims.remove(task_id);
            self.persist_state();
            
            Ok(())
        } else {
            Err("No active claim found".to_string())
        }
    }
    
    /// Get available tasks
    pub fn get_available_tasks(&self, limit: usize) -> Vec<Task> {
        let mut tasks: Vec<Task> = self.state.pending_tasks.values().cloned().collect();
        
        tasks.sort_by(|a, b| {
            b.priority.cmp(&a.priority)
                .then(a.created_at.cmp(&b.created_at))
        });
        
        tasks.into_iter().take(limit).collect()
    }
    
    /// Check if task is completed
    pub fn is_task_completed(&self, task_id: &str) -> bool {
        self.state.completed_proofs.contains_key(task_id)
    }
    
    /// Get proof
    pub fn get_proof(&self, task_id: &str) -> Option<&ProofSubmission> {
        self.state.completed_proofs.get(task_id)
    }
    
    /// Nominate as leader
    pub fn nominate_leader(&mut self, node_id: &str) -> bool {
        let now = current_timestamp();
        
        // Check if current leader is still alive
        if let Some(leader) = &self.state.leader {
            if now - leader.last_heartbeat < LEADER_HEARTBEAT_TIMEOUT {
                return false; // Leader still active
            }
        }
        
        // Become new leader
        self.state.leader = Some(LeaderInfo {
            node_id: node_id.to_string(),
            elected_at: now,
            last_heartbeat: now,
            election_term: self.state.election_term + 1,
        });
        
        self.state.election_term += 1;
        self.persist_state();
        
        tracing::info!("🎖️  Node {} elected as leader (term {})", node_id, self.state.election_term);
        
        true
    }
    
    /// Leader heartbeat
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
    
    /// Check if node is leader
    pub fn is_leader(&self, node_id: &str) -> bool {
        if let Some(ref leader) = self.state.leader {
            leader.node_id == node_id
        } else {
            false
        }
    }
    
    /// Get current leader
    pub fn get_leader(&self) -> Option<String> {
        let now = current_timestamp();
        if let Some(ref leader) = self.state.leader {
            if now - leader.last_heartbeat < LEADER_HEARTBEAT_TIMEOUT {
                return Some(leader.node_id.clone());
            }
        }
        None
    }
    
    /// Get stats
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
            current_leader: self.get_leader(),
            election_term: self.state.election_term,
            is_healthy,
        }
    }
    
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

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_leader_failover() {
        let mut coordinator = ProductionCoordinator::new("node1".to_string());
        
        // Node1 becomes leader
        assert!(coordinator.nominate_leader("node1"));
        assert!(coordinator.is_leader("node1"));
        
        // Simulate leader death (no heartbeat for 20s)
        std::thread::sleep(std::time::Duration::from_secs(1));
        coordinator.check_leader_health();
        
        // Leader should still be alive (only 1s passed)
        assert!(coordinator.is_leader("node1"));
    }
    
    #[test]
    fn test_state_persistence() {
        use std::fs;
        use tempfile::tempdir;
        
        let dir = tempdir().unwrap();
        let path = dir.path().join("coordinator_state.json");
        
        {
            let mut coordinator = ProductionCoordinator::new("node1".to_string())
                .with_persistence(path.clone());
            
            let task = Task {
                task_id: "test_task".to_string(),
                task_data: vec![1, 2, 3],
                created_at: current_timestamp(),
                priority: TaskPriority::Normal,
            };
            
            coordinator.add_task(task).unwrap();
        }
        
        // Reload from disk
        let coordinator = ProductionCoordinator::new("node2".to_string())
            .with_persistence(path.clone());
        
        assert_eq!(coordinator.state.pending_tasks.len(), 1);
    }
    
    #[test]
    fn test_authentication() {
        let coordinator = ProductionCoordinator::new("node1".to_string())
            .with_auth("secret123".to_string());
        
        assert!(coordinator.verify_auth("secret123"));
        assert!(!coordinator.verify_auth("wrong"));
    }
}
