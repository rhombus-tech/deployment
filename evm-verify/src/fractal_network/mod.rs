// φ-Optimized Fractal ZODA Prover Network
// First large-scale fractal network with mathematical optimization
// NOW WITH 10/10 TRUSTLESSNESS - Trustless Manifesto Compliant

pub mod prover;
pub mod topology;
pub mod consensus;
pub mod aggregation;
pub mod phi_optimizer;

// 🚀 NEW: Trustless infrastructure modules
pub mod permissionless;  // Anyone can join without permission
pub mod task_pool;        // P2P task discovery, no coordinator
pub mod economics;        // Economic incentives for all participants
pub mod onchain;          // Blockchain integration for payments & proofs
pub mod identity;         // Key management & identity - WORKS
pub mod simple_multinode;  // Simple HTTP-based multi-node - WORKS (DEPRECATED: use p2p_libp2p)
pub mod task_coordinator;  // Basic task coordination - WORKS
pub mod production_coordinator;  // PRODUCTION: Failover, persistence, auth - WORKS
// pub mod distributed_coordinator_v2;  // DISABLED: Has Arc/RwLock deadlock - use production_coordinator instead
pub mod p2p_libp2p;       // 🚀 PRODUCTION P2P: Kademlia DHT + GossipSub + mDNS - FULLY IMPLEMENTED
pub mod monitoring;       // Metrics and monitoring for production
pub mod frac_rewards;     // FRAC token rewards - mint tokens for provers
pub mod frac_payment;     // FRAC token payment system - actual blockchain transactions
pub mod resilient_rpc;    // Multi-RPC failover - no single point of failure
pub mod stateless_vm_adapter;  // StatelessVM integration adapter
pub mod proof_of_work;    // PoW spam prevention - trustless rate limiting
pub mod onchain_verifier; // On-chain proof verification - no trust needed
pub mod frac_escrow;      // FRAC token escrow - trustless payments
pub mod bonds_slashing;   // Bond & slashing - economic security
pub mod tokenomics;       // Complete tokenomics system - early adopter rewards & token appreciation

pub use self::prover::FractalZODAProver;
pub use self::topology::{PhiCoordinates, FractalConnection, ConnectionType};
pub use self::consensus::{ConsensusMessage, Vote, ConsensusProposal};
pub use self::aggregation::{ProofAggregator, TensorSegment, ZODAProofTask, CompletedProof, PhiParams, AggregationMethod, RhombusParams};
pub use self::phi_optimizer::{GoldenRatioOptimizer, PHI, PHI_INVERSE};

// Export trustless primitives
pub use self::permissionless::{PermissionlessBootstrap, NodeIdentity, PeerInfo};
pub use self::task_pool::{DecentralizedTaskPool, TaskAnnouncement, TaskSelectionStrategy};
pub use self::economics::{ProvingEconomics, RewardBreakdown, ProfitabilityEstimate};
pub use self::onchain::{ProofSubmitter, OnChainTaskRegistry, TransactionFeePayment, ProtocolRewardPayment, HybridPayment};
pub use self::p2p_libp2p::{FractalP2PNetwork, NetworkConfig, NetworkMessage}; // 🚀 PRODUCTION P2P ENABLED
pub use self::monitoring::{FractalMetrics, start_metrics_server};
pub use self::frac_rewards::{FracRewardSystem, ProverStats};
pub use self::stateless_vm_adapter::StatelessVMAdapter;
pub use self::tokenomics::{FracTokenomics, RewardCalculation, GenesisStatus, StakePosition, VestingSchedule, TokenomicsStats};

use std::fmt;

#[derive(Debug)]
pub enum NetworkError {
    ConnectionFailed,
    InvalidPhiCoordinates,
    ProofDecompositionError,
    ConsensusTimeout,
    TopologyAdaptationFailed,
}

impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            NetworkError::ConnectionFailed => write!(f, "Network connection failed"),
            NetworkError::InvalidPhiCoordinates => write!(f, "Invalid φ-coordinates"),
            NetworkError::ProofDecompositionError => write!(f, "Proof decomposition failed"),
            NetworkError::ConsensusTimeout => write!(f, "Consensus timeout"),
            NetworkError::TopologyAdaptationFailed => write!(f, "Topology adaptation failed"),
        }
    }
}

impl std::error::Error for NetworkError {}
