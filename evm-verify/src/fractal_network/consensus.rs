// φ-Weighted Consensus Protocol for Fractal Networks

use super::topology::ProverID;
use super::phi_optimizer::{PHI, PHI_INVERSE};

#[derive(Debug, Clone)]
pub struct ConsensusMessage {
    pub proposal: ConsensusProposal,
    pub vote: Vote,
    pub phi_weight: f64,
}

#[derive(Debug, Clone)]
pub enum ConsensusProposal {
    NetworkParameterUpdate(NetworkParams),
    NodeReputation(ReputationUpdate),
    ProofValidation(ProofValidationRequest),
}

#[derive(Debug, Clone)]
pub enum Vote {
    Approve,
    Reject,
    Abstain,
}

#[derive(Debug, Clone)]
pub struct NetworkParams {
    pub phi_optimization_threshold: f64,
    pub fibonacci_branching_factor: u8,
    pub cluster_size_limits: (u8, u8),
}

#[derive(Debug, Clone)]
pub struct ReputationUpdate {
    pub node: ProverID,
    pub reputation_delta: i32,
    pub phi_efficiency_bonus: f64,
}

#[derive(Debug, Clone)]
pub struct ProofValidationRequest {
    pub proof_data: Vec<u8>,
    pub claimed_efficiency: f64,
    pub requester: ProverID,
}

pub struct ConsensusEngine {
    pub active_proposals: Vec<ConsensusProposal>,
    pub vote_tallies: std::collections::HashMap<String, VoteTally>,
    pub phi_weight_threshold: f64,
}

pub struct VoteTally {
    pub approve_weight: f64,
    pub reject_weight: f64,
    pub abstain_weight: f64,
    pub total_participants: usize,
}

impl ConsensusEngine {
    pub fn new() -> Self {
        Self {
            active_proposals: Vec::new(),
            vote_tallies: std::collections::HashMap::new(),
            phi_weight_threshold: PHI * PHI, // Require strong φ-weighted consensus
        }
    }

    pub fn submit_proposal(&mut self, proposal: ConsensusProposal) -> String {
        let proposal_id = format!("proposal_{}", self.active_proposals.len());
        self.active_proposals.push(proposal);
        
        self.vote_tallies.insert(proposal_id.clone(), VoteTally {
            approve_weight: 0.0,
            reject_weight: 0.0,
            abstain_weight: 0.0,
            total_participants: 0,
        });
        
        proposal_id
    }

    pub fn cast_vote(&mut self, proposal_id: &str, vote: Vote, phi_weight: f64) -> Result<(), String> {
        if let Some(tally) = self.vote_tallies.get_mut(proposal_id) {
            match vote {
                Vote::Approve => tally.approve_weight += phi_weight,
                Vote::Reject => tally.reject_weight += phi_weight,
                Vote::Abstain => tally.abstain_weight += phi_weight,
            }
            tally.total_participants += 1;
            Ok(())
        } else {
            Err("Proposal not found".to_string())
        }
    }

    pub fn check_consensus(&self, proposal_id: &str) -> Option<ConsensusResult> {
        if let Some(tally) = self.vote_tallies.get(proposal_id) {
            let total_weight = tally.approve_weight + tally.reject_weight + tally.abstain_weight;
            
            // Require minimum participation and φ-weighted majority
            if total_weight >= self.phi_weight_threshold {
                let approval_ratio = tally.approve_weight / total_weight;
                
                if approval_ratio >= PHI_INVERSE {
                    Some(ConsensusResult::Approved)
                } else if tally.reject_weight / total_weight >= PHI_INVERSE {
                    Some(ConsensusResult::Rejected)
                } else {
                    Some(ConsensusResult::Pending)
                }
            } else {
                Some(ConsensusResult::InsufficientParticipation)
            }
        } else {
            None
        }
    }

    pub fn finalize_proposal(&mut self, proposal_id: &str) -> Option<(ConsensusProposal, ConsensusResult)> {
        if let Some(result) = self.check_consensus(proposal_id) {
            if matches!(result, ConsensusResult::Approved | ConsensusResult::Rejected) {
                if let Some(index) = self.active_proposals.iter().position(|_| true) {
                    let proposal = self.active_proposals.remove(index);
                    self.vote_tallies.remove(proposal_id);
                    return Some((proposal, result));
                }
            }
        }
        None
    }
}

#[derive(Debug, Clone)]
pub enum ConsensusResult {
    Approved,
    Rejected,
    Pending,
    InsufficientParticipation,
}

impl NetworkParams {
    pub fn default_phi_optimized() -> Self {
        Self {
            phi_optimization_threshold: PHI_INVERSE,
            fibonacci_branching_factor: PHI.floor() as u8,
            cluster_size_limits: (5, 13), // Fibonacci numbers
        }
    }

    pub fn validates_phi_principles(&self) -> bool {
        self.phi_optimization_threshold >= PHI_INVERSE &&
        self.fibonacci_branching_factor <= 3 &&
        self.cluster_size_limits.0 >= 3 &&
        self.cluster_size_limits.1 <= 21 // Reasonable Fibonacci upper bound
    }
}
