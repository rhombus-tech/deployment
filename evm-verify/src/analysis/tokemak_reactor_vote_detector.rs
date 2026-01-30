use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use ethers::types::U256;

/// Tokemak Reactor Vote Manipulation Detector
/// 
/// Detects vulnerabilities in Tokemak's liquidity director voting system where
/// votes can be gamed to control treasury allocations and reactor liquidity deployment.
/// 
/// **Tokemak Context**:
/// Tokemak uses "Reactors" for liquidity deployment controlled by TOKE holders.
/// Liquidity directors vote to direct protocol-owned liquidity to specific DeFi protocols.
/// 
/// **Attack Patterns**:
/// 1. Vote buying/bribing to control liquidity direction
/// 2. Vote aggregation manipulation to amplify influence
/// 3. Last-minute vote swing attacks
/// 4. Reactor allocation gaming via coordinated votes
/// 5. Cycle voting to maximize rewards without commitment
/// 
/// **Detection Strategy**:
/// - Identifies vote weight calculations without Sybil protection
/// - Detects missing vote commitment mechanisms
/// - Flags vote aggregation without validation
/// - Checks for last-minute vote change exploits
/// - Validates reactor allocation fairness
pub struct TokemakReactorVoteDetector {
    bytecode: Vec<u8>,
}

impl TokemakReactorVoteDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityWarning> {
        let mut warnings = Vec::new();

        if self.has_vote_buying_vulnerability() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "Liquidity director votes vulnerable to buying/bribing - Tokemak pattern".to_string(),
                operations: Vec::new(),
                remediation: "Add vote commitment periods and prevent vote transfers during active cycles".to_string(),
            });
        }

        if self.has_vote_aggregation_manipulation() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Vote aggregation can be manipulated to amplify voting power".to_string(),
                operations: Vec::new(),
                remediation: "Implement quadratic voting or vote weight caps to prevent aggregation gaming".to_string(),
            });
        }

        if self.has_last_minute_vote_swing() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Votes can be changed at last minute causing unexpected allocation swings".to_string(),
                operations: Vec::new(),
                remediation: "Add vote locking period before cycle end (e.g., final 24 hours)".to_string(),
            });
        }

        if self.has_reactor_allocation_gaming() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::Medium,
                pc: 0,
                description: "Reactor liquidity allocation vulnerable to coordinated vote gaming".to_string(),
                operations: Vec::new(),
                remediation: "Implement allocation smoothing and maximum per-reactor limits".to_string(),
            });
        }

        warnings
    }

    fn has_vote_buying_vulnerability(&self) -> bool {
        // Pattern: vote() function without transfer restrictions during cycle
        let vote_selector = [0xc9, 0xd2, 0x7a, 0xfe]; // vote()
        
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == vote_selector {
                    let window = &self.bytecode[i..i+50.min(self.bytecode.len())];
                    
                    // Check for vote weight storage
                    let stores_vote = window.contains(&0x55); // SSTORE
                    
                    // Check for vote commitment (prevents immediate transfer)
                    let has_commitment = window.windows(12).any(|w| {
                        // Pattern: store vote + lock tokens
                        w.iter().filter(|&&op| op == 0x55).count() >= 2 && // Multiple SSTORE (vote + lock)
                        w.iter().any(|&op| op == 0x42) // TIMESTAMP (lock duration)
                    });
                    
                    // Check for transfer restriction during vote
                    let restricts_transfers = window.windows(10).any(|w| {
                        // Check if voting sets a flag that blocks transfers
                        w.iter().any(|&op| op == 0x20) && // KECCAK256 (voting flag)
                        w.iter().any(|&op| op == 0x55) // SSTORE (set flag)
                    });
                    
                    if stores_vote && !has_commitment && !restricts_transfers {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_vote_aggregation_manipulation(&self) -> bool {
        // Pattern: vote tallying without aggregation limits
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x01 { // ADD (aggregate votes)
                let window = &self.bytecode[i.saturating_sub(30)..i+10.min(self.bytecode.len())];
                
                // Check for vote aggregation
                let aggregates_votes = window.windows(12).any(|w| {
                    w.iter().filter(|&&op| op == 0x54).count() >= 2 && // Multiple SLOAD (read votes)
                    w.iter().any(|&op| op == 0x01) // ADD (sum votes)
                });
                
                // Check for quadratic voting (sqrt to prevent aggregation)
                let uses_quadratic = window.windows(8).any(|w| {
                    // Square root operation or equivalent
                    w.iter().any(|&op| op == 0x0a) || // EXP (for sqrt)
                    w.iter().any(|&op| op == 0xfa) // STATICCALL (to sqrt lib)
                });
                
                // Check for vote weight cap
                let has_weight_cap = window.windows(6).any(|w| {
                    w.iter().any(|&op| op >= 0x60 && op <= 0x7f) && // PUSH (max weight)
                    w.iter().any(|&op| op == 0x10) // LT (cap check)
                });
                
                if aggregates_votes && !uses_quadratic && !has_weight_cap {
                    return true;
                }
            }
        }
        false
    }

    fn has_last_minute_vote_swing(&self) -> bool {
        // Pattern: vote change allowed until cycle end
        let change_vote = [0x5c, 0x19, 0xa9, 0x5c]; // changeVote() or similar
        
        for i in 0..self.bytecode.len().saturating_sub(45) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == change_vote {
                    let window = &self.bytecode[i..i+45.min(self.bytecode.len())];
                    
                    // Check for vote update
                    let updates_vote = window.contains(&0x55); // SSTORE
                    
                    // Check for voting deadline (lock before cycle end)
                    let has_deadline = window.windows(12).any(|w| {
                        // Pattern: TIMESTAMP + lockPeriod < cycleEnd
                        w.iter().any(|&op| op == 0x42) && // TIMESTAMP
                        w.iter().any(|&op| op == 0x01) && // ADD (+ lock period)
                        w.iter().any(|&op| op == 0x54) && // SLOAD (cycle end)
                        w.iter().any(|&op| op == 0x10) // LT (check if before deadline)
                    });
                    
                    if updates_vote && !has_deadline {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_reactor_allocation_gaming(&self) -> bool {
        // Pattern: allocation calculation without smoothing or limits
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x04 { // DIV (allocation = votes / total)
                let window = &self.bytecode[i.saturating_sub(40)..i+10.min(self.bytecode.len())];
                
                // Check for reactor allocation calculation
                let calculates_allocation = window.windows(15).any(|w| {
                    w.iter().filter(|&&op| op == 0x54).count() >= 2 && // Load reactor votes + total
                    w.iter().any(|&op| op == 0x02) // MUL (votes * totalLiquidity)
                });
                
                // Check for allocation smoothing (TWAP-style)
                let has_smoothing = window.windows(12).any(|w| {
                    w.iter().any(|&op| op == 0x42) && // TIMESTAMP
                    w.iter().filter(|&&op| op == 0x54).count() >= 3 // Historical allocations
                });
                
                // Check for maximum allocation per reactor
                let has_max_allocation = window.windows(8).any(|w| {
                    w.iter().any(|&op| op >= 0x60 && op <= 0x7f) && // PUSH (max %)
                    w.iter().any(|&op| op == 0x10) // LT
                });
                
                if calculates_allocation && !has_smoothing && !has_max_allocation {
                    return true;
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tokemak_vote_buying() {
        let vulnerable_bytecode = vec![
            0x63, 0xc9, 0xd2, 0x7a, 0xfe, // vote()
            0x55, // SSTORE (vote without commitment!)
        ];

        let detector = TokemakReactorVoteDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        
        assert!(!warnings.is_empty());
        assert!(warnings.iter().any(|w| w.description.contains("vote") || w.description.contains("buying")));
    }
}
