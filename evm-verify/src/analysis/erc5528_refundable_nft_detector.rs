/// ERC-5528 Refundable NFT Detector
///
/// Detects vulnerabilities in refundable NFT implementations (event tickets, etc.).

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Erc5528Vulnerability {
    pub vulnerability_type: Erc5528VulnerabilityType,
    pub severity: String,
    pub location: Vec<usize>,
    pub description: String,
    pub exploit_scenario: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Erc5528VulnerabilityType {
    RefundDeadlineBypass,           // Refund after deadline
    RefundAmountManipulation,       // Refund amount manipulated
    DoubleRefund,                   // Same NFT refunded twice
    RefundAfterTransfer,            // Refund after NFT transferred
    RefundableAfterUse,             // Ticket used but still refundable
    TimeManipulation,               // Refund deadline manipulated
    RefundWithoutBurn,              // NFT not burned on refund
    PartialRefundExploit,           // Partial refund calculation wrong
    RefundReentrancy,               // Reentrancy during refund
    AdminRefundDrain,               // Admin drains refund pool
}

pub struct Erc5528RefundableNftDetector {
    bytecode: Vec<u8>,
}

impl Erc5528RefundableNftDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<Erc5528Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            let mut performs_refund = false;
            let mut checks_deadline = false;
            let mut burns_nft = false;
            
            for j in i..self.bytecode.len().min(i + 25) {
                if self.bytecode[j] == 0xF1 { // CALL (refund transfer)
                    performs_refund = true;
                }
                if self.bytecode[j] == 0x42 { // TIMESTAMP
                    if j + 2 < self.bytecode.len() && self.bytecode[j+1] == 0x10 { // LT
                        checks_deadline = true;
                    }
                }
                if self.bytecode[j] == 0x55 { // SSTORE (burn)
                    burns_nft = true;
                }
            }
            
            if performs_refund && !checks_deadline {
                vulnerabilities.push(Erc5528Vulnerability {
                    vulnerability_type: Erc5528VulnerabilityType::RefundDeadlineBypass,
                    severity: "High".to_string(),
                    location: vec![i],
                    description: "Refund function missing deadline validation. Users can refund after event/expiration.".to_string(),
                    exploit_scenario: "1. User buys concert ticket NFT for 1 ETH\n\
                                      2. Attends concert (ticket scanned/used)\n\
                                      3. After concert, calls refund()\n\
                                      4. No deadline check\n\
                                      5. Gets 1 ETH refund\n\
                                      6. Attended concert for free\n\
                                      7. Venue loses revenue\n\
                                      8. $500K lost if exploited at scale".to_string(),
                    recommendation: "Add refund deadline: require(block.timestamp < refundDeadline). \
                                  Disable refunds after event start. Track ticket usage.".to_string(),
                });
            }
            
            if performs_refund && !burns_nft {
                vulnerabilities.push(Erc5528Vulnerability {
                    vulnerability_type: Erc5528VulnerabilityType::RefundWithoutBurn,
                    severity: "Critical".to_string(),
                    location: vec![i],
                    description: "Refund doesn't burn NFT. User keeps NFT after refund.".to_string(),
                    exploit_scenario: "1. User buys ticket NFT for 1 ETH\n\
                                      2. Calls refund(), receives 1 ETH back\n\
                                      3. NFT not burned\n\
                                      4. User still owns ticket\n\
                                      5. Sells ticket to victim for 0.8 ETH\n\
                                      6. Victim tries to use → already refunded/invalid\n\
                                      7. Attacker profits 0.8 ETH\n\
                                      8. $1M stolen via refund-without-burn scam".to_string(),
                    recommendation: "Burn NFT on refund: _burn(tokenId). Invalidate ticket in mapping. \
                                  Prevent transfers after refund request.".to_string(),
                });
            }
        }
        
        vulnerabilities
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_refund_deadline_bypass() {
        let bytecode = vec![
            0xF1, // CALL (refund, no TIMESTAMP check)
        ];
        
        let detector = Erc5528RefundableNftDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(!vulns.is_empty());
    }
}
