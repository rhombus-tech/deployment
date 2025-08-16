use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet};
use crate::circuits::execution_trace::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GovernanceAttackType {
    FlashLoanGovernanceAttack,
    QuorumManipulation,
    ProposalTimingAttack,
    EmergencyBypassExploit,
    CrossProtocolGovernanceAttack,
    VotingTokenManipulation,
    DelayedExecutionExploit,
    AdminKeyCompromise,
    MultiSigManipulation,
    GovernanceTokenFlashMint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceVulnerability {
    pub attack_type: GovernanceAttackType,
    pub severity: SecuritySeverity,
    pub governance_system: String,
    pub voting_power_required: f64,
    pub execution_window_seconds: u64,
    pub economic_cost_eth: f64,
    pub success_probability: f32,
    pub detection_confidence: f32,
    pub affected_functions: Vec<[u8; 4]>,
    pub mitigation_strategies: Vec<String>,
    pub attack_description: String,
}

pub struct GovernanceAttackDetector {
    bytecode: Vec<u8>,
    governance_functions: HashSet<[u8; 4]>,
    voting_functions: HashSet<[u8; 4]>,
    admin_functions: HashSet<[u8; 4]>,
    timelock_functions: HashSet<[u8; 4]>,
    execution_trace: Option<EVMExecutionTrace>,
}

impl GovernanceAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        let mut governance_functions = HashSet::new();
        governance_functions.insert([0x40, 0xe5, 0x8e, 0xe5]); // propose()
        governance_functions.insert([0x15, 0x37, 0x3e, 0x3d]); // vote()
        governance_functions.insert([0xfe, 0x0d, 0x94, 0xc1]); // execute()
        governance_functions.insert([0x59, 0x2f, 0x6e, 0x62]); // cancel()

        let mut voting_functions = HashSet::new();
        voting_functions.insert([0x56, 0x78, 0x1d, 0x4a]); // castVote()
        voting_functions.insert([0x25, 0x95, 0x0c, 0x8c]); // castVoteWithReason()
        voting_functions.insert([0x3b, 0xcc, 0xfa, 0x2b]); // castVoteBySig()

        let mut admin_functions = HashSet::new();
        admin_functions.insert([0x8d, 0xa5, 0xcb, 0x5b]); // pause()
        admin_functions.insert([0x3f, 0x4b, 0xa8, 0x3a]); // unpause()
        admin_functions.insert([0xf2, 0xfd, 0xe3, 0x8b]); // transferOwnership()

        let mut timelock_functions = HashSet::new();
        timelock_functions.insert([0xc1, 0xa2, 0x87, 0xc2]); // schedule()
        timelock_functions.insert([0x1d, 0x4d, 0xbc, 0x12]); // scheduleBatch()
        timelock_functions.insert([0x13, 0x4e, 0xf6, 0xba]); // executeBatch()

        Self {
            bytecode,
            governance_functions,
            voting_functions,
            admin_functions,
            timelock_functions,
            execution_trace: None,
        }
    }

    pub fn with_execution_trace(mut self, trace: EVMExecutionTrace) -> Self {
        self.execution_trace = Some(trace);
        self
    }

    pub fn detect_governance_vulnerabilities(&self) -> Vec<GovernanceVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_flash_loan_governance_attacks());
        vulnerabilities.extend(self.detect_quorum_manipulation());
        vulnerabilities.extend(self.detect_proposal_timing_attacks());
        vulnerabilities.extend(self.detect_emergency_bypass_exploits());
        vulnerabilities.extend(self.detect_voting_token_manipulation());
        vulnerabilities.extend(self.detect_admin_key_risks());

        vulnerabilities
    }

    fn detect_flash_loan_governance_attacks(&self) -> Vec<GovernanceVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for governance tokens that can be flash borrowed
        if self.has_governance_functions() && self.has_flash_loan_vulnerable_tokens() {
            vulnerabilities.push(GovernanceVulnerability {
                attack_type: GovernanceAttackType::FlashLoanGovernanceAttack,
                severity: SecuritySeverity::Critical,
                governance_system: "Flash Loan Vulnerable Governance".to_string(),
                voting_power_required: 51.0, // 51% voting power via flash loan
                execution_window_seconds: 15, // Single block execution
                economic_cost_eth: 1000.0, // Flash loan fee + gas
                success_probability: 0.85,
                detection_confidence: 0.9,
                affected_functions: self.governance_functions.iter().cloned().collect(),
                mitigation_strategies: vec![
                    "Implement voting delays".to_string(),
                    "Require token lock periods".to_string(),
                    "Use snapshot-based voting".to_string(),
                ],
                attack_description: "Attacker flash loans governance tokens to gain temporary voting power".to_string(),
            });
        }

        vulnerabilities
    }

    fn detect_quorum_manipulation(&self) -> Vec<GovernanceVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_low_quorum_threshold() {
            vulnerabilities.push(GovernanceVulnerability {
                attack_type: GovernanceAttackType::QuorumManipulation,
                severity: SecuritySeverity::High,
                governance_system: "Low Quorum Governance".to_string(),
                voting_power_required: 10.0, // Low quorum threshold
                execution_window_seconds: 86400, // 1 day voting period
                economic_cost_eth: 100.0,
                success_probability: 0.7,
                detection_confidence: 0.8,
                affected_functions: self.voting_functions.iter().cloned().collect(),
                mitigation_strategies: vec![
                    "Increase minimum quorum requirements".to_string(),
                    "Implement dynamic quorum adjustment".to_string(),
                ],
                attack_description: "Coordinate attack during low participation to meet quorum".to_string(),
            });
        }

        vulnerabilities
    }

    fn detect_proposal_timing_attacks(&self) -> Vec<GovernanceVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_predictable_proposal_timing() {
            vulnerabilities.push(GovernanceVulnerability {
                attack_type: GovernanceAttackType::ProposalTimingAttack,
                severity: SecuritySeverity::Medium,
                governance_system: "Predictable Timing Governance".to_string(),
                voting_power_required: 25.0,
                execution_window_seconds: 3600, // 1 hour window
                economic_cost_eth: 50.0,
                success_probability: 0.6,
                detection_confidence: 0.75,
                affected_functions: vec![[0x40, 0xe5, 0x8e, 0xe5]], // propose()
                mitigation_strategies: vec![
                    "Randomize proposal submission timing".to_string(),
                    "Implement proposal batching".to_string(),
                ],
                attack_description: "Submit malicious proposals during low community attention".to_string(),
            });
        }

        vulnerabilities
    }

    fn detect_emergency_bypass_exploits(&self) -> Vec<GovernanceVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_emergency_functions() && !self.has_multi_sig_protection() {
            vulnerabilities.push(GovernanceVulnerability {
                attack_type: GovernanceAttackType::EmergencyBypassExploit,
                severity: SecuritySeverity::Critical,
                governance_system: "Unprotected Emergency Functions".to_string(),
                voting_power_required: 0.0, // Admin key only
                execution_window_seconds: 0, // Immediate execution
                economic_cost_eth: 10.0, // Just gas costs
                success_probability: 0.95,
                detection_confidence: 0.95,
                affected_functions: self.admin_functions.iter().cloned().collect(),
                mitigation_strategies: vec![
                    "Implement multi-sig for emergency functions".to_string(),
                    "Add time delays even for emergencies".to_string(),
                    "Require community override capability".to_string(),
                ],
                attack_description: "Abuse emergency admin powers to bypass normal governance".to_string(),
            });
        }

        vulnerabilities
    }

    fn detect_voting_token_manipulation(&self) -> Vec<GovernanceVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_manipulable_voting_tokens() {
            vulnerabilities.push(GovernanceVulnerability {
                attack_type: GovernanceAttackType::VotingTokenManipulation,
                severity: SecuritySeverity::High,
                governance_system: "Manipulable Voting Tokens".to_string(),
                voting_power_required: 30.0,
                execution_window_seconds: 86400,
                economic_cost_eth: 500.0,
                success_probability: 0.75,
                detection_confidence: 0.8,
                affected_functions: self.voting_functions.iter().cloned().collect(),
                mitigation_strategies: vec![
                    "Use non-transferable voting tokens".to_string(),
                    "Implement voting power caps".to_string(),
                    "Add sybil resistance mechanisms".to_string(),
                ],
                attack_description: "Manipulate voting token distribution to gain control".to_string(),
            });
        }

        vulnerabilities
    }

    fn detect_admin_key_risks(&self) -> Vec<GovernanceVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_centralized_admin_control() {
            vulnerabilities.push(GovernanceVulnerability {
                attack_type: GovernanceAttackType::AdminKeyCompromise,
                severity: SecuritySeverity::Critical,
                governance_system: "Centralized Admin Control".to_string(),
                voting_power_required: 0.0,
                execution_window_seconds: 0,
                economic_cost_eth: 0.0, // If key is compromised
                success_probability: 1.0, // If compromised, attack succeeds
                detection_confidence: 0.9,
                affected_functions: self.admin_functions.iter().cloned().collect(),
                mitigation_strategies: vec![
                    "Implement progressive decentralization".to_string(),
                    "Use multi-sig with hardware security modules".to_string(),
                    "Add governance override mechanisms".to_string(),
                ],
                attack_description: "Single admin key controls critical protocol functions".to_string(),
            });
        }

        vulnerabilities
    }

    // Helper methods
    fn has_governance_functions(&self) -> bool {
        self.governance_functions.iter().any(|sig| self.has_function_signature(sig))
    }

    fn has_flash_loan_vulnerable_tokens(&self) -> bool {
        // Check if governance tokens can be borrowed (simplified heuristic)
        let erc20_transfer = [0xa9, 0x05, 0x9c, 0xbb]; // transfer()
        let approve = [0x09, 0x5e, 0xa7, 0xb3]; // approve()
        self.has_function_signature(&erc20_transfer) && self.has_function_signature(&approve)
    }

    fn has_low_quorum_threshold(&self) -> bool {
        // Heuristic: look for low constants that might be quorum thresholds
        for i in 0..self.bytecode.len().saturating_sub(4) {
            if self.bytecode[i] == 0x60 { // PUSH1
                let value = self.bytecode[i + 1];
                if value > 0 && value < 20 { // Very low threshold (< 20%)
                    return true;
                }
            }
        }
        false
    }

    fn has_predictable_proposal_timing(&self) -> bool {
        // Look for timestamp-based logic without randomization
        for i in 0..self.bytecode.len().saturating_sub(2) {
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                return true; // Simplified: any timestamp usage
            }
        }
        false
    }

    fn has_emergency_functions(&self) -> bool {
        self.admin_functions.iter().any(|sig| self.has_function_signature(sig))
    }

    fn has_multi_sig_protection(&self) -> bool {
        // Look for multi-sig patterns (simplified)
        let multi_sig_sigs = [
            [0x5c, 0x60, 0xda, 0x1b], // executeTransaction() - Gnosis Safe
            [0x6a, 0x76, 0x13, 0x48], // confirmTransaction() - MultiSig
        ];
        multi_sig_sigs.iter().any(|sig| self.has_function_signature(sig))
    }

    fn has_manipulable_voting_tokens(&self) -> bool {
        // Check if voting tokens are standard ERC20 (transferable)
        let transfer = [0xa9, 0x05, 0x9c, 0xbb]; // transfer()
        let transfer_from = [0x23, 0xb8, 0x72, 0xdd]; // transferFrom()
        self.has_function_signature(&transfer) && self.has_function_signature(&transfer_from)
    }

    fn has_centralized_admin_control(&self) -> bool {
        // Look for owner-only functions without multi-sig
        let owner_functions = [
            [0xf2, 0xfd, 0xe3, 0x8b], // transferOwnership()
            [0x8d, 0xa5, 0xcb, 0x5b], // pause()
        ];
        owner_functions.iter().any(|sig| self.has_function_signature(sig)) && !self.has_multi_sig_protection()
    }

    fn has_function_signature(&self, signature: &[u8; 4]) -> bool {
        for i in 0..self.bytecode.len().saturating_sub(4) {
            let sig = [self.bytecode[i], self.bytecode[i+1], self.bytecode[i+2], self.bytecode[i+3]];
            if sig == *signature {
                return true;
            }
        }
        false
    }

    /// Main method that comprehensive analyzer calls
    pub fn detect_governance_attacks(&mut self) -> Vec<GovernanceVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Detect flash loan governance attacks
        vulnerabilities.extend(self.detect_flash_loan_governance_attacks());

        // Detect quorum manipulation
        vulnerabilities.extend(self.detect_quorum_manipulation());

        // Detect emergency function bypass
        vulnerabilities.extend(self.detect_emergency_bypass_exploits());

        vulnerabilities
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flash_loan_governance_attack_detection() {
        let bytecode = vec![
            // propose() signature
            0x40, 0xe5, 0x8e, 0xe5,
            // transfer() signature (ERC20)
            0xa9, 0x05, 0x9c, 0xbb,
            // approve() signature
            0x09, 0x5e, 0xa7, 0xb3,
        ];

        let detector = GovernanceAttackDetector::new(bytecode);
        let vulnerabilities = detector.detect_governance_vulnerabilities();

        assert!(!vulnerabilities.is_empty());
        assert!(vulnerabilities.iter().any(|v| matches!(v.attack_type, GovernanceAttackType::FlashLoanGovernanceAttack)));
    }

    #[test]
    fn test_emergency_bypass_detection() {
        let bytecode = vec![
            // pause() signature
            0x8d, 0xa5, 0xcb, 0x5b,
            // transferOwnership() signature
            0xf2, 0xfd, 0xe3, 0x8b,
        ];

        let detector = GovernanceAttackDetector::new(bytecode);
        let vulnerabilities = detector.detect_governance_vulnerabilities();

        assert!(vulnerabilities.iter().any(|v| matches!(v.attack_type, GovernanceAttackType::EmergencyBypassExploit)));
    }
}
