// Governance Token Lending Detector
// Detects borrowed voting power and flash loan governance exploits

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceTokenLendingVulnerability {
    pub location: usize,
    pub vulnerability_type: GovernanceLendingType,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GovernanceLendingType {
    BorrowedVotingPower,             // Vote with borrowed tokens
    FlashLoanGovernance,             // Flash loan attack on voting
    VotingPowerRental,               // Rent voting power for proposals
    DoubleVotingExploit,             // Vote then transfer to vote again
    CollateralizedGovernance,        // Use collateral for governance
    LendingProtocolAbuse,            // Exploit lending integration
}

pub struct GovernanceTokenLendingDetector {
    bytecode: Vec<u8>,
}

impl GovernanceTokenLendingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<GovernanceTokenLendingVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_borrowed_voting_power() {
            vulnerabilities.push(GovernanceTokenLendingVulnerability {
                location: loc,
                vulnerability_type: GovernanceLendingType::BorrowedVotingPower,
                severity: "Critical".to_string(),
                description: "Voting power calculated from current balance without checking borrowed \
                             tokens. Users can borrow tokens to amplify voting power artificially.".to_string(),
                confidence: 0.92,
            });
        }

        if let Some(loc) = self.detect_flash_loan_governance() {
            vulnerabilities.push(GovernanceTokenLendingVulnerability {
                location: loc,
                vulnerability_type: GovernanceLendingType::FlashLoanGovernance,
                severity: "Critical".to_string(),
                description: "Proposal or voting allows same-transaction execution. Flash loans can \
                             temporarily inflate voting power for malicious proposals.".to_string(),
                confidence: 0.94,
            });
        }

        if let Some(loc) = self.detect_voting_power_rental() {
            vulnerabilities.push(GovernanceTokenLendingVulnerability {
                location: loc,
                vulnerability_type: GovernanceLendingType::VotingPowerRental,
                severity: "High".to_string(),
                description: "No restrictions on token transfers during voting period. Voting power \
                             can be rented or sold to manipulate outcomes.".to_string(),
                confidence: 0.88,
            });
        }

        if let Some(loc) = self.detect_double_voting_exploit() {
            vulnerabilities.push(GovernanceTokenLendingVulnerability {
                location: loc,
                vulnerability_type: GovernanceLendingType::DoubleVotingExploit,
                severity: "High".to_string(),
                description: "Voting not locked after casting vote. User can vote, transfer tokens, \
                             and vote again from another address doubling voting power.".to_string(),
                confidence: 0.90,
            });
        }

        if let Some(loc) = self.detect_collateralized_governance() {
            vulnerabilities.push(GovernanceTokenLendingVulnerability {
                location: loc,
                vulnerability_type: GovernanceLendingType::CollateralizedGovernance,
                severity: "Medium".to_string(),
                description: "Collateralized tokens count toward voting power. Deposited collateral \
                             can be used for governance without economic commitment.".to_string(),
                confidence: 0.83,
            });
        }

        if let Some(loc) = self.detect_lending_protocol_abuse() {
            vulnerabilities.push(GovernanceTokenLendingVulnerability {
                location: loc,
                vulnerability_type: GovernanceLendingType::LendingProtocolAbuse,
                severity: "High".to_string(),
                description: "Integration with lending protocol allows voting with borrowed funds. \
                             Lending market can be manipulated to concentrate governance power.".to_string(),
                confidence: 0.86,
            });
        }

        vulnerabilities
    }

    fn detect_borrowed_voting_power(&self) -> Option<usize> {
        // Pattern: Voting power from balance without debt check
        // Uses balanceOf without checking if tokens are borrowed
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x54 {  // SLOAD (balance for voting)
                let mut used_for_voting = false;
                let mut checks_debt = false;
                
                // Check if used in voting calculation
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x55 {  // SSTORE (record vote)
                        used_for_voting = true;
                    }
                }
                
                // Check for debt verification (borrowed amount check)
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x54 {  // SLOAD (debt amount)
                        for k in j+1..(j+5).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x03 {  // SUB (balance - debt)
                                checks_debt = true;
                            }
                        }
                    }
                }
                
                if used_for_voting && !checks_debt {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_flash_loan_governance(&self) -> Option<usize> {
        // Pattern: Vote or proposal in same transaction as token receipt
        // No delay between token acquisition and voting
        
        for i in 0..self.bytecode.len().saturating_sub(35) {
            if self.bytecode[i] == 0x55 {  // SSTORE (vote or proposal)
                let mut is_governance = false;
                let mut has_delay_check = false;
                
                // Check if governance operation
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x33 {  // CALLER
                        is_governance = true;
                    }
                }
                
                // Check for block delay requirement
                for j in (i.saturating_sub(25))..i {
                    if self.bytecode[j] == 0x43 {  // NUMBER (block number)
                        for k in j+1..(j+10).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x03 {  // SUB (blocks since action)
                                for m in k+1..(k+5).min(self.bytecode.len()) {
                                    if self.bytecode[m] == 0x10 {  // LT (enough blocks)
                                        has_delay_check = true;
                                    }
                                }
                            }
                        }
                    }
                }
                
                if is_governance && !has_delay_check {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_voting_power_rental(&self) -> Option<usize> {
        // Pattern: Transfers allowed during active voting period
        // Token transfer not blocked when user has active votes
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x55 {  // SSTORE (transfer tokens)
                let mut is_transfer = false;
                let mut checks_active_votes = false;
                
                // Check if token transfer (balance updates)
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x03 {  // SUB (reduce balance)
                        is_transfer = true;
                    }
                }
                
                // Check for active vote verification
                for j in (i.saturating_sub(25))..i {
                    if self.bytecode[j] == 0x54 {  // SLOAD (active votes)
                        for k in j+1..(j+8).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x15 {  // ISZERO (no active votes)
                                checks_active_votes = true;
                            }
                        }
                    }
                }
                
                if is_transfer && !checks_active_votes {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_double_voting_exploit(&self) -> Option<usize> {
        // Pattern: Vote recording without locking tokens
        // Can vote then transfer to vote again
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x55 {  // SSTORE (record vote)
                let mut is_vote = false;
                let mut locks_tokens = false;
                
                // Check if voting operation
                for j in (i.saturating_sub(15))..i {
                    if self.bytecode[j] == 0x33 {  // CALLER
                        is_vote = true;
                    }
                }
                
                // Check for token locking (setting locked balance)
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x55 {  // SSTORE (lock amount)
                        locks_tokens = true;
                    }
                }
                
                if is_vote && !locks_tokens {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_collateralized_governance(&self) -> Option<usize> {
        // Pattern: Collateral balance counted in voting power
        // Deposited tokens used for voting without distinction
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x54 {  // SLOAD (token balance)
                let mut includes_collateral = false;
                let mut distinguishes_types = false;
                
                // Check if balance includes collateral (multiple balance types added)
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x01 {  // ADD (combine balances)
                        includes_collateral = true;
                    }
                }
                
                // Check for balance type distinction (different weights or exclusions)
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x02 {  // MUL (weight different balance types)
                        distinguishes_types = true;
                    }
                }
                
                if includes_collateral && !distinguishes_types {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_lending_protocol_abuse(&self) -> Option<usize> {
        // Pattern: External lending protocol balance counted for voting
        // STATICCALL to lending protocol for balance check
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0xFA {  // STATICCALL (external balance check)
                let mut is_lending_protocol = false;
                let mut validates_ownership = false;
                
                // Check if lending protocol (checking balance/collateral)
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x54 {  // SLOAD (use result for voting)
                        is_lending_protocol = true;
                    }
                }
                
                // Check for ownership validation (not borrowed)
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0xFA {  // Another STATICCALL (check debt)
                        validates_ownership = true;
                    }
                }
                
                if is_lending_protocol && !validates_ownership {
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
    fn test_borrowed_voting_power() {
        let bytecode = vec![
            0x60, 0x00, // PUSH1 0
            0x54, // SLOAD (balance without debt check)
            0x60, 0x01, // PUSH1 1
            0x55, // SSTORE (vote with borrowed tokens)
        ];
        
        let detector = GovernanceTokenLendingDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, GovernanceLendingType::BorrowedVotingPower)));
    }

    #[test]
    fn test_flash_loan_governance() {
        let bytecode = vec![
            0x33, // CALLER
            0x60, 0x00, // PUSH1 0
            0x55, // SSTORE (vote in same transaction - no block delay)
        ];
        
        let detector = GovernanceTokenLendingDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, GovernanceLendingType::FlashLoanGovernance)));
    }
}
