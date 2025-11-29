// Production-Grade Task Coordination
// Handles task claiming, deduplication, and conflict resolution

use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};
use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize};

const TASK_CLAIM_TTL: u64 = 30; // 30 seconds to complete task
const PROOF_DEDUPE_WINDOW: u64 = 300; // 5 minutes deduplication window

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

#[derive(Debug, Clone)]
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

pub struct TaskCoordinator {
    // Pending tasks waiting to be claimed
    pending_tasks: HashMap<String, Task>,
    
    // Active claims with TTL
    active_claims: HashMap<String, TaskClaim>,
    
    // Completed proofs (deduplicated)
    completed_proofs: HashMap<String, ProofSubmission>,
    
    // Proof hashes for deduplication
    proof_hashes: HashSet<String>,
    
    // Node that's currently leader (simple election)
    current_leader: Option<String>,
    
    // Last heartbeat from leader
    leader_last_seen: u64,
}

impl TaskCoordinator {
    pub fn new() -> Self {
        Self {
            pending_tasks: HashMap::new(),
            active_claims: HashMap::new(),
            completed_proofs: HashMap::new(),
            proof_hashes: HashSet::new(),
            current_leader: None,
            leader_last_seen: 0,
        }
    }
    
    /// Add a new task to the queue
    pub fn add_task(&mut self, task: Task) -> Result<(), String> {
        if self.pending_tasks.contains_key(&task.task_id) {
            return Err("Task already exists".to_string());
        }
        
        if self.active_claims.contains_key(&task.task_id) {
            return Err("Task already claimed".to_string());
        }
        
        if self.completed_proofs.contains_key(&task.task_id) {
            return Err("Task already completed".to_string());
        }
        
        self.pending_tasks.insert(task.task_id.clone(), task);
        Ok(())
    }
    
    /// Attempt to claim a task
    pub fn claim_task(&mut self, task_id: &str, node_id: &str) -> Result<Task, String> {
        // Clean up expired claims first
        self.cleanup_expired_claims();
        
        // Check if task exists
        let task = self.pending_tasks.get(task_id)
            .ok_or_else(|| "Task not found".to_string())?
            .clone();
        
        // Check if already claimed
        if let Some(claim) = self.active_claims.get(task_id) {
            if claim.expires_at > current_timestamp() {
                return Err(format!("Task already claimed by {}", claim.claimed_by));
            }
        }
        
        // Check if already completed
        if self.completed_proofs.contains_key(task_id) {
            return Err("Task already completed".to_string());
        }
        
        // Create claim
        let now = current_timestamp();
        let claim = TaskClaim {
            claimed_by: node_id.to_string(),
            claimed_at: now,
            expires_at: now + TASK_CLAIM_TTL,
        };
        
        self.active_claims.insert(task_id.to_string(), claim);
        self.pending_tasks.remove(task_id);
        
        Ok(task)
    }
    
    /// Submit a completed proof
    pub fn submit_proof(&mut self, submission: ProofSubmission) -> Result<bool, String> {
        // Verify claim exists and matches submitter
        let claim = self.active_claims.get(&submission.task_id)
            .ok_or_else(|| "No active claim for this task".to_string())?;
        
        if claim.claimed_by != submission.submitted_by {
            return Err(format!(
                "Task claimed by {} but submitted by {}",
                claim.claimed_by, submission.submitted_by
            ));
        }
        
        // Check if claim expired
        if claim.expires_at < current_timestamp() {
            self.active_claims.remove(&submission.task_id);
            return Err("Claim expired".to_string());
        }
        
        // Calculate proof hash for deduplication
        let proof_hash = calculate_proof_hash(&submission.proof_data);
        
        // Check for duplicate proof
        if self.proof_hashes.contains(&proof_hash) {
            return Ok(false); // Duplicate, but not an error
        }
        
        // Store proof
        let mut final_submission = submission;
        final_submission.proof_hash = proof_hash.clone();
        
        let task_id = final_submission.task_id.clone();
        self.completed_proofs.insert(task_id.clone(), final_submission);
        self.proof_hashes.insert(proof_hash);
        self.active_claims.remove(&task_id);
        
        // Clean up old proofs
        self.cleanup_old_proofs();
        
        Ok(true)
    }
    
    /// Release a claim (if node crashes or gives up)
    pub fn release_claim(&mut self, task_id: &str, node_id: &str) -> Result<(), String> {
        if let Some(claim) = self.active_claims.get(task_id) {
            if claim.claimed_by != node_id {
                return Err("Cannot release claim owned by another node".to_string());
            }
            
            self.active_claims.remove(task_id);
            
            // Put task back in pending queue
            if self.completed_proofs.contains_key(task_id) {
                // Don't re-queue completed tasks
                return Ok(());
            }
            
            Ok(())
        } else {
            Err("No active claim found".to_string())
        }
    }
    
    /// Get list of available tasks (not claimed or completed)
    pub fn get_available_tasks(&self, limit: usize) -> Vec<Task> {
        let mut tasks: Vec<Task> = self.pending_tasks.values().cloned().collect();
        
        // Sort by priority, then creation time
        tasks.sort_by(|a, b| {
            b.priority.cmp(&a.priority)
                .then(a.created_at.cmp(&b.created_at))
        });
        
        tasks.into_iter().take(limit).collect()
    }
    
    /// Check if a task is completed
    pub fn is_task_completed(&self, task_id: &str) -> bool {
        self.completed_proofs.contains_key(task_id)
    }
    
    /// Get proof for completed task
    pub fn get_proof(&self, task_id: &str) -> Option<&ProofSubmission> {
        self.completed_proofs.get(task_id)
    }
    
    /// Leader election: Nominate this node as leader
    pub fn nominate_leader(&mut self, node_id: &str) -> bool {
        let now = current_timestamp();
        
        // If no leader or leader hasn't been seen in 60s, take over
        if self.current_leader.is_none() || (now - self.leader_last_seen > 60) {
            self.current_leader = Some(node_id.to_string());
            self.leader_last_seen = now;
            return true;
        }
        
        false
    }
    
    /// Leader heartbeat
    pub fn leader_heartbeat(&mut self, node_id: &str) -> bool {
        if let Some(ref leader) = self.current_leader {
            if leader == node_id {
                self.leader_last_seen = current_timestamp();
                return true;
            }
        }
        false
    }
    
    /// Check if node is leader
    pub fn is_leader(&self, node_id: &str) -> bool {
        if let Some(ref leader) = self.current_leader {
            leader == node_id
        } else {
            false
        }
    }
    
    /// Get current leader
    pub fn get_leader(&self) -> Option<String> {
        let now = current_timestamp();
        if now - self.leader_last_seen > 60 {
            None // Leader is stale
        } else {
            self.current_leader.clone()
        }
    }
    
    /// Clean up expired claims
    fn cleanup_expired_claims(&mut self) {
        let now = current_timestamp();
        let expired: Vec<String> = self.active_claims.iter()
            .filter(|(_, claim)| claim.expires_at < now)
            .map(|(task_id, _)| task_id.clone())
            .collect();
        
        for task_id in expired {
            self.active_claims.remove(&task_id);
            // Task goes back to pending (will be re-added by network)
        }
    }
    
    /// Clean up old completed proofs (keep only recent ones)
    fn cleanup_old_proofs(&mut self) {
        let now = current_timestamp();
        let cutoff = now.saturating_sub(PROOF_DEDUPE_WINDOW);
        
        let old_tasks: Vec<String> = self.completed_proofs.iter()
            .filter(|(_, submission)| submission.submitted_at < cutoff)
            .map(|(task_id, _)| task_id.clone())
            .collect();
        
        for task_id in old_tasks {
            if let Some(submission) = self.completed_proofs.remove(&task_id) {
                self.proof_hashes.remove(&submission.proof_hash);
            }
        }
    }
    
    /// Get statistics
    pub fn get_stats(&self) -> CoordinatorStats {
        CoordinatorStats {
            pending_tasks: self.pending_tasks.len(),
            active_claims: self.active_claims.len(),
            completed_proofs: self.completed_proofs.len(),
            current_leader: self.get_leader(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CoordinatorStats {
    pub pending_tasks: usize,
    pub active_claims: usize,
    pub completed_proofs: usize,
    pub current_leader: Option<String>,
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
    fn test_task_claiming() {
        let mut coordinator = TaskCoordinator::new();
        
        let task = Task {
            task_id: "task1".to_string(),
            task_data: vec![1, 2, 3],
            created_at: current_timestamp(),
            priority: TaskPriority::Normal,
        };
        
        coordinator.add_task(task.clone()).unwrap();
        
        // Node 1 claims
        let claimed = coordinator.claim_task("task1", "node1").unwrap();
        assert_eq!(claimed.task_id, "task1");
        
        // Node 2 tries to claim - should fail
        let result = coordinator.claim_task("task1", "node2");
        assert!(result.is_err());
    }
    
    #[test]
    fn test_proof_deduplication() {
        let mut coordinator = TaskCoordinator::new();
        
        let task = Task {
            task_id: "task1".to_string(),
            task_data: vec![1, 2, 3],
            created_at: current_timestamp(),
            priority: TaskPriority::Normal,
        };
        
        coordinator.add_task(task).unwrap();
        coordinator.claim_task("task1", "node1").unwrap();
        
        let submission = ProofSubmission {
            task_id: "task1".to_string(),
            proof_hash: String::new(),
            submitted_by: "node1".to_string(),
            submitted_at: current_timestamp(),
            proof_data: vec![4, 5, 6],
        };
        
        let result1 = coordinator.submit_proof(submission.clone());
        assert!(result1.is_ok());
        assert_eq!(result1.unwrap(), true); // First submission
        
        // Try to submit duplicate - should be rejected
        coordinator.add_task(Task {
            task_id: "task2".to_string(),
            task_data: vec![1, 2, 3],
            created_at: current_timestamp(),
            priority: TaskPriority::Normal,
        }).unwrap();
        coordinator.claim_task("task2", "node2").unwrap();
        
        let submission2 = ProofSubmission {
            task_id: "task2".to_string(),
            proof_hash: String::new(),
            submitted_by: "node2".to_string(),
            submitted_at: current_timestamp(),
            proof_data: vec![4, 5, 6], // Same proof data
        };
        
        let result2 = coordinator.submit_proof(submission2);
        assert!(result2.is_ok());
        assert_eq!(result2.unwrap(), false); // Duplicate
    }
    
    #[test]
    fn test_leader_election() {
        let mut coordinator = TaskCoordinator::new();
        
        // Node1 nominates itself
        assert!(coordinator.nominate_leader("node1"));
        assert!(coordinator.is_leader("node1"));
        
        // Node2 tries to take over - should fail (leader active)
        assert!(!coordinator.nominate_leader("node2"));
        assert!(coordinator.is_leader("node1"));
        
        // Leader heartbeat
        assert!(coordinator.leader_heartbeat("node1"));
    }
}
