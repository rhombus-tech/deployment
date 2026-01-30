// Optimistic Rollup Fraud Proof DOS Detector
// Detects challenge period griefing and fraud proof denial-of-service attacks

use crate::bytecode::security::{SecuritySeverity, SecurityWarning};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimisticRollupVulnerability {
    pub location: usize,
    pub vulnerability_type: OptimisticRollupVulnerabilityType,
    pub severity: SecuritySeverity,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OptimisticRollupVulnerabilityType {
    ChallengeWindowGriefing,       // Spam challenges to DOS withdrawals
    ProofVerificationExhaustion,   // Expensive proof verification DOS
    BondSlashingManipulation,      // Manipulate bond requirements
    DisputeGameExploitation,       // Game the dispute resolution mechanism
    WithdrawalDelayAttack,         // Extend withdrawal delay indefinitely
    ValidatorSetCensorship,        // Censor fraud proofs from validators
}

pub struct OptimisticRollupDetector {
    bytecode: Vec<u8>,
}

impl OptimisticRollupDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<OptimisticRollupVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_challenge_window_griefing() {
            vulnerabilities.push(OptimisticRollupVulnerability {
                location: loc,
                vulnerability_type: OptimisticRollupVulnerabilityType::ChallengeWindowGriefing,
                severity: SecuritySeverity::High,
                description: "Challenge submission lacks rate limiting or bond escalation. Attacker \
                             can spam challenges to delay withdrawals during challenge window.".to_string(),
                confidence: 0.89,
            });
        }

        if let Some(loc) = self.detect_proof_verification_exhaustion() {
            vulnerabilities.push(OptimisticRollupVulnerability {
                location: loc,
                vulnerability_type: OptimisticRollupVulnerabilityType::ProofVerificationExhaustion,
                severity: SecuritySeverity::Critical,
                description: "Fraud proof verification unbounded or lacks gas limits. Adversarial \
                             proofs can exhaust validator resources.".to_string(),
                confidence: 0.92,
            });
        }

        if let Some(loc) = self.detect_bond_slashing_manipulation() {
            vulnerabilities.push(OptimisticRollupVulnerability {
                location: loc,
                vulnerability_type: OptimisticRollupVulnerabilityType::BondSlashingManipulation,
                severity: SecuritySeverity::High,
                description: "Bond amount insufficient or slashing logic bypassable. Low-cost \
                             challenges can be submitted without adequate deterrent.".to_string(),
                confidence: 0.86,
            });
        }

        if let Some(loc) = self.detect_dispute_game_exploitation() {
            vulnerabilities.push(OptimisticRollupVulnerability {
                location: loc,
                vulnerability_type: OptimisticRollupVulnerabilityType::DisputeGameExploitation,
                severity: SecuritySeverity::High,
                description: "Dispute resolution mechanism exploitable. Bisection game can be \
                             manipulated or forced into unresolvable states.".to_string(),
                confidence: 0.84,
            });
        }

        if let Some(loc) = self.detect_withdrawal_delay_attack() {
            vulnerabilities.push(OptimisticRollupVulnerability {
                location: loc,
                vulnerability_type: OptimisticRollupVulnerabilityType::WithdrawalDelayAttack,
                severity: SecuritySeverity::Critical,
                description: "Withdrawal finalization can be delayed indefinitely through repeated \
                             challenges. No upper bound on challenge duration.".to_string(),
                confidence: 0.90,
            });
        }

        if let Some(loc) = self.detect_validator_set_censorship() {
            vulnerabilities.push(OptimisticRollupVulnerability {
                location: loc,
                vulnerability_type: OptimisticRollupVulnerabilityType::ValidatorSetCensorship,
                severity: SecuritySeverity::Critical,
                description: "Validator set can censor fraud proofs. Centralized validator list \
                             without fallback allows proof suppression.".to_string(),
                confidence: 0.88,
            });
        }

        vulnerabilities
    }

    fn detect_challenge_window_griefing(&self) -> Option<usize> {
        // Pattern: Challenge submission without rate limiting or escalating bonds
        // No SLOAD to check recent challenge count or bond increase
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x33 {  // CALLER (challenger)
                let mut has_challenge = false;
                let mut checks_rate_limit = false;
                
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    // Challenge submission (SSTORE)
                    if self.bytecode[j] == 0x55 {
                        has_challenge = true;
                    }
                    
                    // Rate limit check: SLOAD previous challenge timestamp
                    if self.bytecode[j] == 0x54 {
                        for k in j+1..(j+8).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x42 {  // TIMESTAMP comparison
                                checks_rate_limit = true;
                            }
                        }
                    }
                }
                
                if has_challenge && !checks_rate_limit {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_proof_verification_exhaustion(&self) -> Option<usize> {
        // Pattern: Unbounded proof verification without gas checks
        // Loop or recursive verification without GAS opcode
        
        for i in 0..self.bytecode.len().saturating_sub(35) {
            // Look for loop pattern (JUMPDEST with backward JUMP)
            if self.bytecode[i] == 0x5B {  // JUMPDEST
                let mut has_verification = false;
                let mut has_gas_check = false;
                
                for j in i+1..(i+30).min(self.bytecode.len()) {
                    // Verification operation (STATICCALL or complex computation)
                    if self.bytecode[j] == 0xFA || self.bytecode[j] == 0x20 {  // STATICCALL or SHA3
                        has_verification = true;
                    }
                    
                    // Gas limit check
                    if self.bytecode[j] == 0x5A {  // GAS
                        has_gas_check = true;
                    }
                    
                    // Backward jump (loop)
                    if self.bytecode[j] == 0x56 {  // JUMP
                        if has_verification && !has_gas_check {
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn detect_bond_slashing_manipulation(&self) -> Option<usize> {
        // Pattern: Bond requirement too low or bypassable
        // Small PUSH value for bond with no escalation
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            // Bond requirement check
            if self.bytecode[i] == 0x60 || self.bytecode[i] == 0x61 {  // PUSH1 or PUSH2
                let bond_size = if self.bytecode[i] == 0x60 { 1 } else { 2 };
                let mut has_comparison = false;
                let mut has_escalation = false;
                
                // Check if this is compared against caller's balance
                for j in i+bond_size+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 {  // LT/GT
                        has_comparison = true;
                    }
                    
                    // Escalation: bond increases with challenge count
                    if self.bytecode[j] == 0x02 {  // MUL (escalation)
                        has_escalation = true;
                    }
                }
                
                // Small bond without escalation
                if has_comparison && !has_escalation && bond_size == 1 {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_dispute_game_exploitation(&self) -> Option<usize> {
        // Pattern: Bisection game without depth limit or timeout
        // Recursive dispute resolution without bounds
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x03 {  // SUB (bisection split)
                let mut is_bisection = false;
                let mut has_depth_limit = false;
                
                // Check for division by 2 (bisection)
                for j in i+1..(i+10).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x04 {  // DIV
                        is_bisection = true;
                    }
                }
                
                // Check for depth counter or maximum iterations
                for j in (i.saturating_sub(15))..i {
                    if self.bytecode[j] == 0x54 {  // SLOAD (depth counter)
                        for k in j+1..(j+10).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x10 {  // LT (max depth check)
                                has_depth_limit = true;
                            }
                        }
                    }
                }
                
                if is_bisection && !has_depth_limit {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_withdrawal_delay_attack(&self) -> Option<usize> {
        // Pattern: No maximum challenge count or total delay cap
        // Withdrawal can be challenged repeatedly without bound
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x54 {  // SLOAD (challenge count)
                let mut has_finalization = false;
                let mut has_max_challenges = false;
                
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    // Withdrawal finalization check
                    if self.bytecode[j] == 0x55 {  // SSTORE (mark finalized)
                        has_finalization = true;
                    }
                    
                    // Maximum challenge count check
                    if self.bytecode[j] == 0x10 {  // LT (challenge count < max)
                        has_max_challenges = true;
                    }
                }
                
                if has_finalization && !has_max_challenges {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_validator_set_censorship(&self) -> Option<usize> {
        // Pattern: Centralized validator whitelist without fallback
        // Single validator list with no permissionless fallback
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x33 {  // CALLER (validator)
                let mut has_whitelist = false;
                let mut has_fallback = false;
                
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    // Whitelist check (single SLOAD)
                    if self.bytecode[j] == 0x54 {  // SLOAD (validator whitelist)
                        has_whitelist = true;
                    }
                    
                    // Fallback mechanism: OR condition with time-based permissionless
                    if self.bytecode[j] == 0x17 {  // OR (fallback condition)
                        has_fallback = true;
                    }
                }
                
                if has_whitelist && !has_fallback {
                    return Some(i);
                }
            }
        }
        None
    }

    pub fn to_security_warnings(&self) -> Vec<SecurityWarning> {
        self.detect()
            .into_iter()
            .map(|v| SecurityWarning {
                kind: crate::bytecode::security::SecurityWarningKind::Other(
                    format!("OptimisticRollup{:?}", v.vulnerability_type)
                ),
                severity: v.severity,
                pc: v.location as u64,
                description: format!(
                    "Optimistic Rollup {:?}: {}",
                    v.vulnerability_type, v.description
                ),
                operations: Vec::new(),
                remediation: "Implement challenge rate limiting, bond escalation, proof gas limits, \
                             and maximum challenge duration caps".to_string(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge_window_griefing() {
        let bytecode = vec![
            0x33, // CALLER
            0x60, 0x00, // PUSH1 0
            0x55, // SSTORE (submit challenge without rate limit)
        ];
        
        let detector = OptimisticRollupDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, OptimisticRollupVulnerabilityType::ChallengeWindowGriefing)));
    }

    #[test]
    fn test_proof_verification_exhaustion() {
        let bytecode = vec![
            0x5B, // JUMPDEST (loop start)
            0x60, 0x00, // PUSH1 0
            0xFA, // STATICCALL (verification)
            0x56, // JUMP (loop back - no gas check)
        ];
        
        let detector = OptimisticRollupDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, OptimisticRollupVulnerabilityType::ProofVerificationExhaustion)));
    }
}
