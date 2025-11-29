// Simple Multi-Node Coordinator
// HTTP-based node discovery and task distribution

use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use reqwest::Client;

use super::identity::NodeIdentity;

#[derive(Clone, Serialize, Deserialize)]
pub struct PeerNode {
    pub node_id: String,
    pub address: String,
    pub last_seen: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TaskAnnouncement {
    pub task_id: String,
    pub task_data: Vec<u8>,
    pub announced_by: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ProofShare {
    pub task_id: String,
    pub proof_data: Vec<u8>,
    pub from_node: String,
}

pub struct SimpleMultiNode {
    identity: NodeIdentity,
    peers: Arc<RwLock<HashMap<String, PeerNode>>>,
    my_address: String,
    http_client: Client,
}

impl SimpleMultiNode {
    pub fn new(identity: NodeIdentity, listen_address: String) -> Self {
        Self {
            identity,
            peers: Arc::new(RwLock::new(HashMap::new())),
            my_address: listen_address,
            http_client: Client::new(),
        }
    }
    
    /// Announce ourselves to a bootstrap peer
    pub async fn announce_to_peer(&self, peer_address: &str) -> Result<(), Box<dyn std::error::Error>> {
        let announce = serde_json::json!({
            "node_id": self.identity.node_id,
            "address": self.my_address,
        });
        
        self.http_client
            .post(format!("{}/announce", peer_address))
            .json(&announce)
            .send()
            .await?;
        
        Ok(())
    }
    
    /// Register a peer
    pub async fn register_peer(&self, node_id: String, address: String) {
        let peer = PeerNode {
            node_id: node_id.clone(),
            address,
            last_seen: current_timestamp(),
        };
        
        self.peers.write().await.insert(node_id, peer);
    }
    
    /// Get all active peers
    pub async fn get_peers(&self) -> Vec<PeerNode> {
        self.peers.read().await.values().cloned().collect()
    }
    
    /// Broadcast task to all peers
    pub async fn broadcast_task(&self, task: TaskAnnouncement) {
        let peers = self.get_peers().await;
        
        for peer in peers {
            let client = self.http_client.clone();
            let task = task.clone();
            
            tokio::spawn(async move {
                let _ = client
                    .post(format!("{}/task", peer.address))
                    .json(&task)
                    .send()
                    .await;
            });
        }
    }
    
    /// Send proof share to specific peer
    pub async fn send_proof_share(&self, peer_id: &str, proof: ProofShare) -> Result<(), Box<dyn std::error::Error>> {
        let peers = self.peers.read().await;
        if let Some(peer) = peers.get(peer_id) {
            self.http_client
                .post(format!("{}/proof", peer.address))
                .json(&proof)
                .send()
                .await?;
        }
        Ok(())
    }
    
    pub fn node_id(&self) -> &str {
        &self.identity.node_id
    }
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_peer_registration() {
        let identity = NodeIdentity {
            public_key: vec![1, 2, 3],
            node_id: "test_node".to_string(),
        };
        
        let multinode = SimpleMultiNode::new(identity, "http://localhost:8080".to_string());
        multinode.register_peer("peer1".to_string(), "http://localhost:8081".to_string()).await;
        
        let peers = multinode.get_peers().await;
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].node_id, "peer1");
    }
}
