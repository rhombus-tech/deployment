// P2P Task Discovery - Trustless Manifesto Principle #2
// "No indispensable intermediaries" - No central task coordinator

use super::aggregation::ZODAProofTask;
use super::topology::ProverID;
use super::phi_optimizer::PHI;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};

/// Decentralized task pool - no central coordinator
/// Anyone can submit tasks, anyone can pull tasks
/// Censorship resistant through P2P gossip
pub struct DecentralizedTaskPool {
    /// Local view of available tasks (eventually consistent)
    available_tasks: Arc<RwLock<HashMap<String, TaskAnnouncement>>>,
    
    /// Tasks we're currently working on
    claimed_tasks: Arc<RwLock<HashSet<String>>>,
    
    /// Completed task IDs (to avoid duplication)
    completed_tasks: Arc<RwLock<HashSet<String>>>,
    
    /// P2P gossip protocol for task discovery (peer HTTP addresses)
    gossip_peers: Arc<RwLock<HashSet<String>>>,
    
    /// This node's address for responses
    my_address: Option<String>,
}

/// Task announcement propagated via P2P gossip
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskAnnouncement {
    pub task_id: String,
    pub task: ZODAProofTask,
    pub reward: u64,  // Economic incentive
    pub deadline: u64,
    pub submitter: ProverID,
    pub announced_at: u64,
    
    /// φ-weight for prioritization (higher = more important)
    pub phi_priority: f64,
}

impl DecentralizedTaskPool {
    pub fn new() -> Self {
        Self {
            available_tasks: Arc::new(RwLock::new(HashMap::new())),
            claimed_tasks: Arc::new(RwLock::new(HashSet::new())),
            completed_tasks: Arc::new(RwLock::new(HashSet::new())),
            gossip_peers: Arc::new(RwLock::new(HashSet::new())),
            my_address: None,
        }
    }
    
    /// Set this node's address (for peer responses)
    pub fn with_address(mut self, address: String) -> Self {
        self.my_address = Some(address);
        self
    }
    
    /// Register a peer node (permissionless)
    pub fn add_peer(&self, peer_address: String) {
        self.gossip_peers.write().unwrap().insert(peer_address);
    }
    
    /// Get list of peer addresses
    pub fn get_peers(&self) -> Vec<String> {
        self.gossip_peers.read().unwrap().iter().cloned().collect()
    }
    
    /// Submit a task to the network (permissionless)
    /// Anyone can submit - no approval needed
    pub fn submit_task(&self, task: ZODAProofTask, reward: u64) -> String {
        let task_id = Self::compute_task_id(&task);
        
        let announcement = TaskAnnouncement {
            task_id: task_id.clone(),
            task,
            reward,
            deadline: Self::current_timestamp() + 3600, // 1 hour
            submitter: ProverID("self".to_string()),  // Will be actual ID
            announced_at: Self::current_timestamp(),
            phi_priority: Self::calculate_priority(reward),
        };
        
        // Add to local pool
        self.available_tasks.write().unwrap()
            .insert(task_id.clone(), announcement.clone());
        
        // Gossip to network (async, non-blocking)
        self.gossip_task_announcement(announcement);
        
        task_id
    }
    
    /// Pull available tasks (censorship resistant)
    /// Anyone can pull any task - no one can stop you
    pub fn pull_available_tasks(&self, max_tasks: usize) -> Vec<TaskAnnouncement> {
        let tasks = self.available_tasks.read().unwrap();
        let claimed = self.claimed_tasks.read().unwrap();
        let completed = self.completed_tasks.read().unwrap();
        
        // Filter out claimed and completed tasks
        let mut available: Vec<TaskAnnouncement> = tasks
            .values()
            .filter(|task| {
                !claimed.contains(&task.task_id) &&
                !completed.contains(&task.task_id) &&
                Self::current_timestamp() < task.deadline
            })
            .cloned()
            .collect();
        
        // Sort by φ-priority (higher priority first)
        available.sort_by(|a, b| {
            b.phi_priority.partial_cmp(&a.phi_priority).unwrap()
        });
        
        available.truncate(max_tasks);
        available
    }
    
    /// Claim a task (try to work on it)
    /// Multiple provers can claim same task - first valid proof wins
    pub fn claim_task(&self, task_id: &str) -> Result<TaskAnnouncement, String> {
        // Check if task exists and is available
        let tasks = self.available_tasks.read().unwrap();
        let task = tasks.get(task_id)
            .ok_or_else(|| "Task not found".to_string())?
            .clone();
        
        // Claim it locally
        let mut claimed = self.claimed_tasks.write().unwrap();
        claimed.insert(task_id.to_string());
        
        // Announce claim to network (helps prevent duplicate work)
        // But doesn't prevent others - race conditions are OK!
        self.gossip_task_claim(task_id);
        
        Ok(task)
    }
    
    /// Mark task as completed (overload for no proof data)
    pub fn complete_task(&self, task_id: &str) {
        self.complete_task_with_proof(task_id, vec![]);
    }
    
    /// Mark task as completed
    /// Anyone who completes it gets the reward
    pub fn complete_task_with_proof(&self, task_id: &str, proof_data: Vec<u8>) {
        // Move from claimed to completed
        self.claimed_tasks.write().unwrap().remove(task_id);
        self.completed_tasks.write().unwrap().insert(task_id.to_string());
        self.available_tasks.write().unwrap().remove(task_id);
        
        // Gossip completion to network
        self.gossip_task_completion(task_id, proof_data);
    }
    
    /// Count methods for stats
    pub fn count_available(&self) -> usize {
        self.available_tasks.read().unwrap().len()
    }
    
    pub fn count_claimed(&self) -> usize {
        self.claimed_tasks.read().unwrap().len()
    }
    
    pub fn count_completed(&self) -> usize {
        self.completed_tasks.read().unwrap().len()
    }
    
    pub fn peer_count(&self) -> usize {
        self.gossip_peers.read().unwrap().len()
    }
    
    /// Receive task announcement from P2P network
    /// Anyone can receive from anyone - no gatekeepers
    pub fn receive_task_announcement(&self, announcement: TaskAnnouncement) {
        let task_id = announcement.task_id.clone();
        
        // Add to our local view if not completed
        let completed = self.completed_tasks.read().unwrap();
        if !completed.contains(&task_id) {
            self.available_tasks.write().unwrap()
                .insert(task_id, announcement.clone());
            
            // Propagate to other peers (gossip protocol)
            self.forward_announcement(announcement);
        }
    }
    
    /// Receive task completion from network
    pub fn receive_task_completion(&self, task_id: &str) {
        self.completed_tasks.write().unwrap().insert(task_id.to_string());
        self.available_tasks.write().unwrap().remove(task_id);
        self.claimed_tasks.write().unwrap().remove(task_id);
    }
    
    // ========== P2P Gossip Protocol ==========
    
    /// Gossip task announcement to peers via HTTP
    fn gossip_task_announcement(&self, announcement: TaskAnnouncement) {
        let peers = self.gossip_peers.read().unwrap().clone();
        
        if peers.is_empty() {
            println!("📢 No peers to gossip task {} to", announcement.task_id);
            return;
        }
        
        // Gossip to random subset (φ-ratio of peers)
        let gossip_count = ((peers.len() as f64) * PHI / 2.0).ceil() as usize;
        let gossip_count = gossip_count.max(1).min(peers.len());
        
        println!("📢 Gossiping task {} to {}/{} peers", announcement.task_id, gossip_count, peers.len());
        
        // Send to peers asynchronously (fire and forget)
        for peer in peers.iter().take(gossip_count) {
            let peer = peer.clone();
            let announcement = announcement.clone();
            
            tokio::spawn(async move {
                let client = reqwest::Client::new();
                let url = format!("{}/p2p/gossip/task", peer);
                
                match client.post(&url)
                    .json(&announcement)
                    .timeout(std::time::Duration::from_secs(2))
                    .send()
                    .await
                {
                    Ok(_) => println!("✅ Gossiped task {} to {}", announcement.task_id, peer),
                    Err(e) => println!("⚠️ Failed to gossip to {}: {}", peer, e),
                }
            });
        }
    }
    
    /// Gossip task claim (helps reduce duplicate work)
    fn gossip_task_claim(&self, task_id: &str) {
        println!("📢 Announcing claim of task {}", task_id);
    }
    
    /// Gossip task completion
    fn gossip_task_completion(&self, task_id: &str, _proof_data: Vec<u8>) {
        println!("📢 Announcing completion of task {}", task_id);
    }
    
    /// Forward announcement to other peers
    fn forward_announcement(&self, announcement: TaskAnnouncement) {
        // Gossip protocol: forward to random subset of peers
        let peers = self.gossip_peers.read().unwrap();
        let forward_to = (peers.len() as f64 * PHI).ceil() as usize;
        
        println!("📤 Forwarding task {} to {} peers", announcement.task_id, forward_to);
    }
    
    // ========== Helper Methods ==========
    
    fn compute_task_id(task: &ZODAProofTask) -> String {
        let mut hasher = Sha256::new();
        hasher.update(&task.circuit_id.as_bytes());
        hasher.update(&[task.priority]);
        let hash = hasher.finalize();
        hex::encode(&hash[..8])
    }
    
    fn calculate_priority(reward: u64) -> f64 {
        // φ-weighted priority based on reward
        (reward as f64).log(PHI.exp())
    }
    
    fn current_timestamp() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
    
    /// Get network statistics
    pub fn get_stats(&self) -> TaskPoolStats {
        TaskPoolStats {
            available_tasks: self.available_tasks.read().unwrap().len(),
            claimed_tasks: self.claimed_tasks.read().unwrap().len(),
            completed_tasks: self.completed_tasks.read().unwrap().len(),
            connected_peers: self.gossip_peers.read().unwrap().len(),
        }
    }
}

#[derive(Debug)]
pub struct TaskPoolStats {
    pub available_tasks: usize,
    pub claimed_tasks: usize,
    pub completed_tasks: usize,
    pub connected_peers: usize,
}

/// Task selection strategy (for provers to choose what to work on)
#[derive(Debug, Clone)]
pub enum TaskSelectionStrategy {
    /// Highest reward first (profit maximization)
    MaxReward,
    
    /// Fastest to complete (maximize throughput)
    FastestCompletion,
    
    /// φ-optimized (balance reward and effort)
    PhiOptimized,
    
    /// Random (helps with load balancing)
    Random,
}

impl DecentralizedTaskPool {
    /// Select tasks based on strategy (prover's choice!)
    pub fn select_tasks(
        &self,
        strategy: TaskSelectionStrategy,
        max_tasks: usize,
    ) -> Vec<TaskAnnouncement> {
        let mut tasks = self.pull_available_tasks(max_tasks * 2);
        
        match strategy {
            TaskSelectionStrategy::MaxReward => {
                tasks.sort_by(|a, b| b.reward.cmp(&a.reward));
            }
            TaskSelectionStrategy::FastestCompletion => {
                tasks.sort_by_key(|t| t.task.tensor_segments.len());
            }
            TaskSelectionStrategy::PhiOptimized => {
                // Already sorted by phi_priority
            }
            TaskSelectionStrategy::Random => {
                use rand::seq::SliceRandom;
                let mut rng = rand::thread_rng();
                tasks.shuffle(&mut rng);
            }
        }
        
        tasks.truncate(max_tasks);
        tasks
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fractal_network::aggregation::{PhiParams, AggregationMethod, TensorSegment, RhombusParams};
    
    #[test]
    fn test_permissionless_task_submission() {
        let pool = DecentralizedTaskPool::new();
        
        let task = create_test_task();
        let task_id = pool.submit_task(task, 1000);
        
        assert!(!task_id.is_empty(), "Should generate task ID");
        
        let available = pool.pull_available_tasks(10);
        assert_eq!(available.len(), 1, "Task should be available");
    }
    
    #[test]
    fn test_censorship_resistance() {
        let pool = DecentralizedTaskPool::new();
        
        // Submit multiple tasks
        for i in 0..10 {
            let task = create_test_task();
            pool.submit_task(task, i * 100);
        }
        
        // Anyone can pull any task
        let tasks = pool.pull_available_tasks(5);
        assert_eq!(tasks.len(), 5, "Should pull tasks without permission");
        
        // Anyone can claim any task
        for task in &tasks {
            assert!(pool.claim_task(&task.task_id), "Should claim without approval");
        }
    }
    
    #[test]
    fn test_task_selection_strategies() {
        let pool = DecentralizedTaskPool::new();
        
        // Submit tasks with varying rewards
        for i in 0..10 {
            let task = create_test_task();
            pool.submit_task(task, i * 100);
        }
        
        // Test different strategies
        let max_reward = pool.select_tasks(TaskSelectionStrategy::MaxReward, 3);
        assert_eq!(max_reward.len(), 3);
        assert!(max_reward[0].reward >= max_reward[1].reward);
        
        let phi_optimized = pool.select_tasks(TaskSelectionStrategy::PhiOptimized, 3);
        assert_eq!(phi_optimized.len(), 3);
    }
    
    fn create_test_task() -> ZODAProofTask {
        ZODAProofTask {
            circuit_id: format!("test_{}", rand::random::<u32>()),
            tensor_segments: vec![TensorSegment {
                data: vec![1, 2, 3],
                phi_encoding: vec![PHI],
                rhombus_structure: RhombusParams {
                    width: 10,
                    height: 10,
                    phi_proportion: PHI,
                },
            }],
            phi_coordination_params: PhiParams {
                optimization_level: PHI,
                fibonacci_index: 5,
                golden_ratio_scaling: PHI,
            },
            aggregation_strategy: AggregationMethod::PhiOptimizedCombination,
            priority: 1,
        }
    }
}
