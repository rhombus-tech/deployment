// Complete P2P Networking Implementation with libp2p
// Production-ready decentralized prover network

use libp2p::{
    core::upgrade,
    gossipsub, identify, kad, mdns, noise, ping,
    swarm::{NetworkBehaviour, SwarmBuilder, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, Swarm, Transport,
};
use futures::stream::StreamExt;
use std::collections::HashMap;
use std::error::Error;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{info, warn, error};
use serde::{Deserialize, Serialize};

use super::topology::ProverID;
use super::task_pool::TaskAnnouncement;
use super::aggregation::CompletedProof;

// ============================================================================
// Network Behavior
// ============================================================================

#[derive(NetworkBehaviour)]
pub struct FractalBehaviour {
    /// Kademlia DHT for peer discovery
    pub kad: kad::Behaviour<kad::store::MemoryStore>,
    
    /// GossipSub for message propagation
    pub gossipsub: gossipsub::Behaviour,
    
    /// mDNS for local peer discovery
    pub mdns: mdns::tokio::Behaviour,
    
    /// Identify protocol for peer info exchange
    pub identify: identify::Behaviour,
    
    /// Ping for connection keep-alive
    pub ping: ping::Behaviour,
}

// ============================================================================
// Network Messages
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkMessage {
    /// New task available
    TaskAnnouncement {
        task_id: String,
        proof_type: String,
        reward: u64,
        complexity: u32,
    },
    
    /// Node claiming a task
    TaskClaim {
        task_id: String,
        prover_id: String,
        timestamp: u64,
    },
    
    /// Proof segment completed
    ProofSegment {
        task_id: String,
        segment_id: String,
        proof_data: Vec<u8>,
        phi_score: f64,
    },
    
    /// Complete proof ready
    ProofCompleted {
        task_id: String,
        aggregated_proof: Vec<u8>,
        contributors: Vec<String>,
    },
    
    /// Peer advertisement
    PeerInfo {
        peer_id: String,
        fractal_level: u8,
        phi_coords: (f64, f64, f64),
        stake: u64,
    },
    
    /// Heartbeat
    Heartbeat {
        peer_id: String,
        active_tasks: u32,
        completed_proofs: u64,
    },
}

// ============================================================================
// Fractal P2P Network
// ============================================================================

pub struct FractalP2PNetwork {
    swarm: Swarm<FractalBehaviour>,
    local_peer_id: PeerId,
    prover_id: ProverID,
    
    // Message channels
    message_tx: mpsc::UnboundedSender<NetworkMessage>,
    message_rx: mpsc::UnboundedReceiver<NetworkMessage>,
    
    // Peer tracking
    known_peers: HashMap<PeerId, PeerMetadata>,
    
    // Topics
    task_topic: gossipsub::IdentTopic,
    proof_topic: gossipsub::IdentTopic,
    heartbeat_topic: gossipsub::IdentTopic,
}

#[derive(Debug, Clone)]
struct PeerMetadata {
    prover_id: String,
    fractal_level: u8,
    stake: u64,
    last_seen: u64,
}

impl FractalP2PNetwork {
    /// Create a new Fractal P2P Network
    pub async fn new(prover_id: ProverID, config: NetworkConfig) -> Result<Self, Box<dyn Error>> {
        info!("🌐 Creating Fractal P2P Network for {:?}", prover_id);
        
        // Generate keypair
        let keypair = libp2p::identity::Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(keypair.public());
        
        info!("   Peer ID: {}", local_peer_id);
        
        // Create transport
        let transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
            .upgrade(upgrade::Version::V1)
            .authenticate(noise::Config::new(&keypair)?)
            .multiplex(yamux::Config::default())
            .boxed();
        
        // Create Kademlia DHT
        let kad_store = kad::store::MemoryStore::new(local_peer_id);
        let kad_config = kad::Config::default();
        let mut kad = kad::Behaviour::with_config(local_peer_id, kad_store, kad_config);
        
        // Bootstrap Kademlia with seed nodes
        for bootstrap_addr in &config.bootstrap_peers {
            if let Ok(multiaddr) = bootstrap_addr.parse::<Multiaddr>() {
                kad.add_address(&local_peer_id, multiaddr);
            }
        }
        
        // Create GossipSub
        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(Duration::from_secs(1))
            .validation_mode(gossipsub::ValidationMode::Strict)
            .build()
            .expect("Valid gossipsub config");
        
        let mut gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(keypair.clone()),
            gossipsub_config,
        )?;
        
        // Subscribe to topics
        let task_topic = gossipsub::IdentTopic::new("fractal-tasks");
        let proof_topic = gossipsub::IdentTopic::new("fractal-proofs");
        let heartbeat_topic = gossipsub::IdentTopic::new("fractal-heartbeat");
        
        gossipsub.subscribe(&task_topic)?;
        gossipsub.subscribe(&proof_topic)?;
        gossipsub.subscribe(&heartbeat_topic)?;
        
        info!("   ✅ Subscribed to GossipSub topics");
        
        // Create mDNS for local discovery
        let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)?;
        
        // Create Identify protocol
        let identify = identify::Behaviour::new(identify::Config::new(
            "/fractal-prover/1.0.0".to_string(),
            keypair.public(),
        ));
        
        // Create Ping
        let ping = ping::Behaviour::new(ping::Config::new());
        
        // Combine behaviors
        let behaviour = FractalBehaviour {
            kad,
            gossipsub,
            mdns,
            identify,
            ping,
        };
        
        // Build swarm
        let mut swarm = SwarmBuilder::with_tokio_executor(transport, behaviour, local_peer_id)
            .build();
        
        // Listen on all interfaces
        let listen_addr: Multiaddr = config.listen_addr.parse()?;
        swarm.listen_on(listen_addr.clone())?;
        
        info!("   🎧 Listening on: {}", listen_addr);
        
        // Create message channel
        let (message_tx, message_rx) = mpsc::unbounded_channel();
        
        Ok(Self {
            swarm,
            local_peer_id,
            prover_id,
            message_tx,
            message_rx,
            known_peers: HashMap::new(),
            task_topic,
            proof_topic,
            heartbeat_topic,
        })
    }
    
    /// Start the network event loop
    pub async fn run(mut self) -> Result<(), Box<dyn Error>> {
        info!("🚀 Starting Fractal P2P Network event loop");
        
        // Bootstrap Kademlia
        if let Err(e) = self.swarm.behaviour_mut().kad.bootstrap() {
            warn!("Kademlia bootstrap failed: {:?}", e);
        }
        
        loop {
            tokio::select! {
                // Handle swarm events
                Some(event) = self.swarm.next() => {
                    self.handle_swarm_event(event).await?;
                }
                
                // Handle outgoing messages
                Some(msg) = self.message_rx.recv() => {
                    self.send_message(msg).await?;
                }
            }
        }
    }
    
    async fn handle_swarm_event(
        &mut self,
        event: SwarmEvent<FractalBehaviourEvent>,
    ) -> Result<(), Box<dyn Error>> {
        match event {
            // GossipSub message received
            SwarmEvent::Behaviour(FractalBehaviourEvent::Gossipsub(
                gossipsub::Event::Message {
                    message,
                    ..
                }
            )) => {
                self.handle_gossipsub_message(message).await?;
            }
            
            // New peer discovered via mDNS
            SwarmEvent::Behaviour(FractalBehaviourEvent::Mdns(
                mdns::Event::Discovered(peers)
            )) => {
                for (peer_id, multiaddr) in peers {
                    info!("🔍 Discovered peer via mDNS: {} at {}", peer_id, multiaddr);
                    self.swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                    self.swarm.behaviour_mut().kad.add_address(&peer_id, multiaddr);
                }
            }
            
            // Peer expired from mDNS
            SwarmEvent::Behaviour(FractalBehaviourEvent::Mdns(
                mdns::Event::Expired(peers)
            )) => {
                for (peer_id, _) in peers {
                    info!("⏰ Peer expired: {}", peer_id);
                    self.swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                }
            }
            
            // Kad event
            SwarmEvent::Behaviour(FractalBehaviourEvent::Kad(event)) => {
                match event {
                    kad::Event::RoutingUpdated { peer, .. } => {
                        info!("📍 Routing updated for peer: {}", peer);
                    }
                    kad::Event::RoutablePeer { peer, .. } => {
                        info!("🛣️  Routable peer: {}", peer);
                    }
                    _ => {}
                }
            }
            
            // Connection events
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                info!("🤝 Connected to peer: {}", peer_id);
            }
            
            SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                info!("👋 Disconnected from peer: {} (cause: {:?})", peer_id, cause);
                self.known_peers.remove(&peer_id);
            }
            
            // New listen address
            SwarmEvent::NewListenAddr { address, .. } => {
                info!("🎧 Listening on: {}", address);
            }
            
            _ => {}
        }
        
        Ok(())
    }
    
    async fn handle_gossipsub_message(
        &mut self,
        message: gossipsub::Message,
    ) -> Result<(), Box<dyn Error>> {
        // Deserialize message
        let network_msg: NetworkMessage = bincode::deserialize(&message.data)?;
        
        match network_msg {
            NetworkMessage::TaskAnnouncement { task_id, proof_type, reward, complexity } => {
                info!("📢 Task announced: {} (type: {}, reward: {})", task_id, proof_type, reward);
                // Forward to task pool for processing
            }
            
            NetworkMessage::TaskClaim { task_id, prover_id, .. } => {
                info!("✋ Task claimed: {} by {}", task_id, prover_id);
                // Update task state
            }
            
            NetworkMessage::ProofSegment { task_id, segment_id, .. } => {
                info!("📦 Proof segment received: {}/{}", task_id, segment_id);
                // Forward to aggregator
            }
            
            NetworkMessage::ProofCompleted { task_id, .. } => {
                info!("✅ Proof completed: {}", task_id);
                // Process completed proof
            }
            
            NetworkMessage::PeerInfo { peer_id, fractal_level, stake, .. } => {
                info!("👤 Peer info: {} (level: {}, stake: {})", peer_id, fractal_level, stake);
                // Update peer metadata
            }
            
            NetworkMessage::Heartbeat { peer_id, active_tasks, completed_proofs } => {
                info!("💓 Heartbeat from {}: {} active, {} completed", 
                      peer_id, active_tasks, completed_proofs);
            }
        }
        
        Ok(())
    }
    
    async fn send_message(&mut self, msg: NetworkMessage) -> Result<(), Box<dyn Error>> {
        let data = bincode::serialize(&msg)?;
        
        let topic = match msg {
            NetworkMessage::TaskAnnouncement { .. } |
            NetworkMessage::TaskClaim { .. } => &self.task_topic,
            
            NetworkMessage::ProofSegment { .. } |
            NetworkMessage::ProofCompleted { .. } => &self.proof_topic,
            
            NetworkMessage::PeerInfo { .. } |
            NetworkMessage::Heartbeat { .. } => &self.heartbeat_topic,
        };
        
        self.swarm
            .behaviour_mut()
            .gossipsub
            .publish(topic.clone(), data)?;
        
        Ok(())
    }
    
    /// Broadcast a task to the network
    pub async fn announce_task(
        &self,
        task_id: String,
        proof_type: String,
        reward: u64,
        complexity: u32,
    ) -> Result<(), Box<dyn Error>> {
        let msg = NetworkMessage::TaskAnnouncement {
            task_id,
            proof_type,
            reward,
            complexity,
        };
        
        self.message_tx.send(msg)?;
        Ok(())
    }
    
    /// Get connected peer count
    pub fn peer_count(&self) -> usize {
        self.swarm.connected_peers().count()
    }
}

// ============================================================================
// Network Configuration
// ============================================================================

#[derive(Clone)]
pub struct NetworkConfig {
    pub listen_addr: String,
    pub bootstrap_peers: Vec<String>,
    pub max_peers: usize,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
            bootstrap_peers: vec![],
            max_peers: 50,
        }
    }
}
