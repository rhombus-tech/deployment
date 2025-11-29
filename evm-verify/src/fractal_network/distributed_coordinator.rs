// Distributed Coordinator - Leader-based coordination
// All nodes forward requests to leader for centralized state

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use reqwest::Client;

use super::task_coordinator::{TaskCoordinator, Task, ProofSubmission, CoordinatorStats};

pub struct DistributedCoordinator {
    // Local coordinator (only used if this node is leader)
    local_coordinator: TaskCoordinator,
    
    // Network information
    node_id: String,
    peer_addresses: HashMap<String, String>,
    
    // HTTP client for forwarding
    client: Client,
}

impl DistributedCoordinator {
    pub fn new(node_id: String) -> Self {
        Self {
            local_coordinator: TaskCoordinator::new(),
            node_id,
            peer_addresses: HashMap::new(),
            client: Client::new(),
        }
    }
    
    /// Register a peer
    pub fn register_peer(&mut self, node_id: String, address: String) {
        self.peer_addresses.insert(node_id, address);
    }
    
    /// Add task - forwards to leader or handles locally
    pub async fn add_task(&mut self, task: Task) -> Result<(), String> {
        if self.is_local_leader() {
            // We are leader, handle locally
            self.local_coordinator.add_task(task)
        } else {
            // Forward to leader
            self.forward_add_task(task).await
        }
    }
    
    /// Claim task - forwards to leader or handles locally
    pub async fn claim_task(&mut self, task_id: &str, node_id: &str) -> Result<Task, String> {
        if self.is_local_leader() {
            self.local_coordinator.claim_task(task_id, node_id)
        } else {
            self.forward_claim_task(task_id, node_id).await
        }
    }
    
    /// Submit proof - forwards to leader or handles locally
    pub async fn submit_proof(&mut self, submission: ProofSubmission) -> Result<bool, String> {
        if self.is_local_leader() {
            self.local_coordinator.submit_proof(submission)
        } else {
            self.forward_submit_proof(submission).await
        }
    }
    
    /// Get available tasks
    pub async fn get_available_tasks(&self, limit: usize) -> Vec<Task> {
        if self.is_local_leader() {
            self.local_coordinator.get_available_tasks(limit)
        } else {
            self.forward_get_tasks(limit).await.unwrap_or_default()
        }
    }
    
    /// Get stats
    pub async fn get_stats(&self) -> CoordinatorStats {
        if self.is_local_leader() {
            self.local_coordinator.get_stats()
        } else {
            self.forward_get_stats().await.unwrap_or(CoordinatorStats {
                pending_tasks: 0,
                active_claims: 0,
                completed_proofs: 0,
                current_leader: None,
            })
        }
    }
    
    /// Nominate as leader
    pub fn nominate_leader(&mut self, node_id: &str) -> bool {
        self.local_coordinator.nominate_leader(node_id)
    }
    
    /// Leader heartbeat
    pub fn leader_heartbeat(&mut self, node_id: &str) -> bool {
        self.local_coordinator.leader_heartbeat(node_id)
    }
    
    /// Check if this node is the current leader
    fn is_local_leader(&self) -> bool {
        self.local_coordinator.is_leader(&self.node_id)
    }
    
    /// Get leader address
    fn get_leader_address(&self) -> Option<String> {
        let leader_id = self.local_coordinator.get_leader()?;
        self.peer_addresses.get(&leader_id).cloned()
    }
    
    // Forwarding methods
    
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
            .map_err(|e| e.to_string())?;
        
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
            .map_err(|e| e.to_string())?;
        
        if response.status().is_success() {
            let result: serde_json::Value = response.json().await.map_err(|e| e.to_string())?;
            
            if result["status"] == "ok" {
                let task_data: Task = serde_json::from_value(result["task"].clone())
                    .map_err(|e| e.to_string())?;
                Ok(task_data)
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
            .map_err(|e| e.to_string())?;
        
        if response.status().is_success() {
            let result: serde_json::Value = response.json().await.map_err(|e| e.to_string())?;
            Ok(result["accepted"].as_bool().unwrap_or(false))
        } else {
            Err("Leader rejected proof".to_string())
        }
    }
    
    async fn forward_get_tasks(&self, limit: usize) -> Result<Vec<Task>, String> {
        let leader_addr = self.get_leader_address()
            .ok_or_else(|| "No leader available".to_string())?;
        
        let url = format!("{}/coordinator/tasks/available", leader_addr);
        
        let response = self.client
            .get(&url)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        
        if response.status().is_success() {
            let result: serde_json::Value = response.json().await.map_err(|e| e.to_string())?;
            let tasks: Vec<Task> = serde_json::from_value(result["tasks"].clone())
                .unwrap_or_default();
            Ok(tasks)
        } else {
            Err("Failed to get tasks from leader".to_string())
        }
    }
    
    async fn forward_get_stats(&self) -> Result<CoordinatorStats, String> {
        let leader_addr = self.get_leader_address()
            .ok_or_else(|| "No leader available".to_string())?;
        
        let url = format!("{}/coordinator/stats", leader_addr);
        
        let response = self.client
            .get(&url)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        
        if response.status().is_success() {
            let stats: CoordinatorStats = response.json().await.map_err(|e| e.to_string())?;
            Ok(stats)
        } else {
            Err("Failed to get stats from leader".to_string())
        }
    }
}
