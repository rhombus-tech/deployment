// φ-Optimized Fractal ZODA Prover Network
// First large-scale fractal network with mathematical optimization

pub mod prover;
pub mod topology;
pub mod consensus;
pub mod aggregation;
pub mod phi_optimizer;

pub use self::prover::FractalZODAProver;
pub use self::topology::{PhiCoordinates, FractalConnection, ConnectionType};
pub use self::consensus::{ConsensusMessage, Vote, ConsensusProposal};
pub use self::aggregation::{ProofAggregator, TensorSegment};
pub use self::phi_optimizer::{GoldenRatioOptimizer, PHI, PHI_INVERSE};

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
