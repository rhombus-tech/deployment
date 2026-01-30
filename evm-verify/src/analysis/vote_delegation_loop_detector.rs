// Vote Delegation Loop Detector
// Detects circular delegation attacks and delegation chain exploits

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteDelegationLoopVulnerability {
    pub location: usize,
    pub vulnerability_type: VoteDelegationLoopType,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VoteDelegationLoopType {
    CircularDelegation,              // A→B→C→A delegation loop
    DelegationChainExhaustion,       // Unbounded delegation chain length
    VotingPowerAmplification,        // Multiple counting through loops
    DelegationCycleGriefing,         // DOS through circular paths
    ProxyVotingManipulation,         // Delegate manipulation patterns
    DelegationDepthExploitation,     // Exploit deep delegation chains
}

pub struct VoteDelegationLoopDetector {
    bytecode: Vec<u8>,
}

impl VoteDelegationLoopDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<VoteDelegationLoopVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_circular_delegation() {
            vulnerabilities.push(VoteDelegationLoopVulnerability {
                location: loc,
                vulnerability_type: VoteDelegationLoopType::CircularDelegation,
                severity: "Critical".to_string(),
                description: "Delegation loop detection missing. Circular delegations (A→B→C→A) \
                             can amplify voting power or cause infinite loops.".to_string(),
                confidence: 0.92,
            });
        }

        if let Some(loc) = self.detect_delegation_chain_exhaustion() {
            vulnerabilities.push(VoteDelegationLoopVulnerability {
                location: loc,
                vulnerability_type: VoteDelegationLoopType::DelegationChainExhaustion,
                severity: "High".to_string(),
                description: "Delegation chain length unbounded. Deep chains can cause gas \
                             exhaustion during voting power calculation.".to_string(),
                confidence: 0.89,
            });
        }

        if let Some(loc) = self.detect_voting_power_amplification() {
            vulnerabilities.push(VoteDelegationLoopVulnerability {
                location: loc,
                vulnerability_type: VoteDelegationLoopType::VotingPowerAmplification,
                severity: "Critical".to_string(),
                description: "Voting power calculation lacks cycle detection. Loops can cause \
                             votes to be counted multiple times.".to_string(),
                confidence: 0.91,
            });
        }

        if let Some(loc) = self.detect_delegation_cycle_griefing() {
            vulnerabilities.push(VoteDelegationLoopVulnerability {
                location: loc,
                vulnerability_type: VoteDelegationLoopType::DelegationCycleGriefing,
                severity: "High".to_string(),
                description: "Delegation resolution can be griefed through intentional cycles. \
                             No timeout or iteration limit enforced.".to_string(),
                confidence: 0.86,
            });
        }

        if let Some(loc) = self.detect_proxy_voting_manipulation() {
            vulnerabilities.push(VoteDelegationLoopVulnerability {
                location: loc,
                vulnerability_type: VoteDelegationLoopType::ProxyVotingManipulation,
                severity: "Medium".to_string(),
                description: "Delegate can be changed during active proposal without restrictions. \
                             Vote manipulation possible through strategic redelegation.".to_string(),
                confidence: 0.82,
            });
        }

        if let Some(loc) = self.detect_delegation_depth_exploitation() {
            vulnerabilities.push(VoteDelegationLoopVulnerability {
                location: loc,
                vulnerability_type: VoteDelegationLoopType::DelegationDepthExploitation,
                severity: "High".to_string(),
                description: "Maximum delegation depth not enforced. Attacker can create \
                             arbitrarily deep chains for gas griefing.".to_string(),
                confidence: 0.88,
            });
        }

        vulnerabilities
    }

    fn detect_circular_delegation(&self) -> Option<usize> {
        // Pattern: Delegation update without cycle detection
        // SSTORE delegate without checking if target delegates back
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x55 {  // SSTORE (set delegate)
                let mut is_delegation = false;
                let mut has_cycle_check = false;
                
                // Check if this is delegation storage (preceded by address operations)
                for j in (i.saturating_sub(15))..i {
                    if self.bytecode[j] == 0x33 {  // CALLER (delegator)
                        is_delegation = true;
                    }
                }
                
                // Check for cycle detection (recursive SLOAD checking delegation chain)
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x54 {  // SLOAD (check delegate's delegate)
                        for k in j+1..(j+10).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x14 {  // EQ (compare with original)
                                has_cycle_check = true;
                            }
                        }
                    }
                }
                
                if is_delegation && !has_cycle_check {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_delegation_chain_exhaustion(&self) -> Option<usize> {
        // Pattern: Recursive delegation resolution without depth limit
        // Loop through delegation chain without iteration counter
        
        for i in 0..self.bytecode.len().saturating_sub(35) {
            if self.bytecode[i] == 0x5B {  // JUMPDEST (loop start)
                let mut has_delegation_load = false;
                let mut has_depth_limit = false;
                
                for j in i+1..(i+30).min(self.bytecode.len()) {
                    // Delegation chain traversal
                    if self.bytecode[j] == 0x54 {  // SLOAD (load delegate)
                        has_delegation_load = true;
                    }
                    
                    // Depth counter check
                    if self.bytecode[j] == 0x10 {  // LT (depth < max)
                        has_depth_limit = true;
                    }
                    
                    // Backward jump (loop)
                    if self.bytecode[j] == 0x56 && has_delegation_load && !has_depth_limit {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_voting_power_amplification(&self) -> Option<usize> {
        // Pattern: Voting power calculation without visited tracking
        // Accumulating votes without marking addresses as counted
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x01 {  // ADD (accumulate voting power)
                let mut is_vote_calc = false;
                let mut tracks_visited = false;
                
                // Check if this is voting power calculation
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x54 {  // SLOAD (balance/power)
                        is_vote_calc = true;
                    }
                }
                
                // Check for visited tracking (bitmap or set)
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x55 {  // SSTORE (mark visited)
                        tracks_visited = true;
                    }
                }
                
                if is_vote_calc && !tracks_visited {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_delegation_cycle_griefing(&self) -> Option<usize> {
        // Pattern: Delegation resolution without timeout
        // No gas limit or maximum iterations on delegation traversal
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x54 {  // SLOAD (delegation lookup)
                let mut has_loop = false;
                let mut has_timeout = false;
                
                // Check for loop pattern
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x56 {  // JUMP (potential loop)
                        has_loop = true;
                    }
                }
                
                // Check for gas or iteration limit
                for j in (i.saturating_sub(15))..i {
                    if self.bytecode[j] == 0x5A {  // GAS (check remaining)
                        has_timeout = true;
                    }
                }
                
                if has_loop && !has_timeout {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_proxy_voting_manipulation(&self) -> Option<usize> {
        // Pattern: Delegation change during active proposal
        // No checkpoint or snapshot enforcement
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x55 {  // SSTORE (update delegation)
                let mut is_delegate_change = false;
                let mut checks_proposal_active = false;
                
                // Check if delegation storage
                for j in (i.saturating_sub(15))..i {
                    if self.bytecode[j] == 0x33 {  // CALLER
                        is_delegate_change = true;
                    }
                }
                
                // Check for active proposal verification
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x54 {  // SLOAD (proposal state)
                        for k in j+1..(j+8).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x14 {  // EQ (check active)
                                checks_proposal_active = true;
                            }
                        }
                    }
                }
                
                if is_delegate_change && !checks_proposal_active {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_delegation_depth_exploitation(&self) -> Option<usize> {
        // Pattern: No maximum depth limit on delegation chains
        // Recursive traversal without bound
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Look for recursive delegation pattern
            if self.bytecode[i] == 0x54 {  // SLOAD (delegate)
                let mut has_recursion = false;
                let mut has_max_depth = false;
                
                // Check for recursive pattern (SLOAD in loop)
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x54 {  // Another SLOAD
                        has_recursion = true;
                    }
                }
                
                // Check for depth limit constant
                for j in (i.saturating_sub(15))..i {
                    if self.bytecode[j] == 0x60 || self.bytecode[j] == 0x61 {  // PUSH (max depth)
                        for k in j+1..(j+10).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x10 {  // LT (check depth)
                                has_max_depth = true;
                            }
                        }
                    }
                }
                
                if has_recursion && !has_max_depth {
                    return Some(i);
                }
            }
        }
        None
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circular_delegation() {
        let bytecode = vec![
            0x33, // CALLER
            0x60, 0x00, // PUSH1 0
            0x55, // SSTORE (set delegate without cycle check)
        ];
        
        let detector = VoteDelegationLoopDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, VoteDelegationLoopType::CircularDelegation)));
    }

    #[test]
    fn test_delegation_chain_exhaustion() {
        let bytecode = vec![
            0x5B, // JUMPDEST
            0x60, 0x00, // PUSH1 0
            0x54, // SLOAD (delegation lookup)
            0x56, // JUMP (loop back - no depth limit)
        ];
        
        let detector = VoteDelegationLoopDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, VoteDelegationLoopType::DelegationChainExhaustion)));
    }
}
