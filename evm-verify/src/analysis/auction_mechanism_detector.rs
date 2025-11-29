use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AuctionVulnerabilityType {
    DutchAuctionManipulation,
    EnglishAuctionSniping,
    SealedBidLeakage,
    BidFrontRunning,
    AuctionEndTimeManipulation,
    MinimumBidBypass,
    RefundReentrancy,
    WinnerDeterminationFlaw,
    ReserveBypass,
    LastMinuteBidDOS,
    CommitRevealWeakness,
    AuctionCancellationAbuse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecuritySeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuctionVulnerability {
    pub vulnerability_type: AuctionVulnerabilityType,
    pub severity: SecuritySeverity,
    pub location: usize,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
}

pub struct AuctionMechanismDetector {
    bytecode: Vec<u8>,
}

impl AuctionMechanismDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<AuctionVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_dutch_auction_manipulation());
        vulnerabilities.extend(self.detect_english_auction_sniping());
        vulnerabilities.extend(self.detect_sealed_bid_leakage());
        vulnerabilities.extend(self.detect_bid_front_running());
        vulnerabilities.extend(self.detect_refund_reentrancy());
        vulnerabilities.extend(self.detect_commit_reveal_weakness());

        vulnerabilities
    }

    fn detect_auction_pattern(&self) -> bool {
        // Look for auction-related function signatures
        let auction_sigs = [
            &[0x1f, 0x0b, 0xdc, 0xea][..], // bid()
            &[0x19, 0x14, 0x80, 0xfa][..], // placeBid()
            &[0xee, 0x22, 0xa2, 0x5e][..], // endAuction()
        ];

        auction_sigs.iter().any(|&sig| {
            self.bytecode.windows(sig.len()).any(|w| w == sig)
        })
    }

    fn detect_dutch_auction_manipulation(&self) -> Vec<AuctionVulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.detect_auction_pattern() {
            return vulnerabilities;
        }

        // Dutch auction: price decreases over time
        // Look for price calculation based on time
        let price_calc_pattern = self.bytecode.windows(10).enumerate().any(|(pos, w)| {
            w.contains(&0x42) && // TIMESTAMP
            w.contains(&0x03) && // SUB (price decreases)
            w.contains(&0x04)    // DIV (calculate rate)
        });

        if price_calc_pattern {
            // Check if timestamp can be manipulated
            let has_timestamp_validation = self.bytecode.windows(5).any(|w| {
                w[0] == 0x42 && // TIMESTAMP
                w[1] == 0x54 && // SLOAD (start time)
                w[2] == 0x11 && // GT
                w[3] == 0x15 && // ISZERO
                w[4] == 0x57    // JUMPI (revert if timestamp invalid)
            });

            if !has_timestamp_validation {
                vulnerabilities.push(AuctionVulnerability {
                    vulnerability_type: AuctionVulnerabilityType::DutchAuctionManipulation,
                    severity: SecuritySeverity::High,
                    location: 0,
                    description: "Dutch auction price calculation vulnerable to timestamp manipulation".to_string(),
                    exploit_scenario: "Miner/validator can manipulate block.timestamp to get favorable auction price".to_string(),
                    remediation: "Add timestamp bounds validation and use block numbers for more reliable time tracking".to_string(),
                });
            }
        }

        vulnerabilities
    }

    fn detect_english_auction_sniping(&self) -> Vec<AuctionVulnerability> {
        let mut vulnerabilities = Vec::new();

        // English auction: highest bidder wins
        // Look for endAuction() or finalize() function
        let end_sig = &[0xee, 0x22, 0xa2, 0x5e][..]; // endAuction()
        
        if let Some(pos) = self.bytecode.windows(end_sig.len()).position(|w| w == end_sig) {
            let function_section = &self.bytecode[pos..pos.saturating_add(80).min(self.bytecode.len())];
            
            // Check if auction end time is immediately checkable
            let has_immediate_end = function_section.windows(3).any(|w| {
                w[0] == 0x42 && // TIMESTAMP
                w[1] == 0x54 && // SLOAD (end time)
                w[2] == 0x10    // LT (check if ended)
            });

            // Check for extension mechanism (anti-snipe)
            let has_extension = self.bytecode.windows(6).any(|w| {
                w.contains(&0x42) && // TIMESTAMP
                w.contains(&0x01) && // ADD (extend time)
                w.contains(&0x55)    // SSTORE (update end time)
            });

            if has_immediate_end && !has_extension {
                vulnerabilities.push(AuctionVulnerability {
                    vulnerability_type: AuctionVulnerabilityType::EnglishAuctionSniping,
                    severity: SecuritySeverity::Medium,
                    location: pos,
                    description: "English auction vulnerable to last-second sniping".to_string(),
                    exploit_scenario: "Attacker waits until final block to submit highest bid, preventing counter-bids".to_string(),
                    remediation: "Implement time extension if bid placed near end (e.g., extend by 10 minutes if bid in last 5 min)".to_string(),
                });
            }
        }

        vulnerabilities
    }

    fn detect_sealed_bid_leakage(&self) -> Vec<AuctionVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for commit/reveal pattern
        let commit_sig = &[0xf1, 0x4f, 0xcb, 0xc8][..]; // commit(bytes32)
        let reveal_sig = &[0x4f, 0xaa, 0x06, 0xbe][..]; // reveal(uint256,bytes32)
        
        let has_commit = self.bytecode.windows(commit_sig.len()).any(|w| w == commit_sig);
        let has_reveal = self.bytecode.windows(reveal_sig.len()).any(|w| w == reveal_sig);

        if has_commit && has_reveal {
            // Check if commitment uses proper hashing (SHA3/KECCAK256)
            let has_secure_hash = self.bytecode.contains(&0x20); // SHA3

            if !has_secure_hash {
                vulnerabilities.push(AuctionVulnerability {
                    vulnerability_type: AuctionVulnerabilityType::SealedBidLeakage,
                    severity: SecuritySeverity::Critical,
                    location: 0,
                    description: "Sealed bid auction doesn't use cryptographic hashing".to_string(),
                    exploit_scenario: "Bids can be leaked or predicted before reveal phase, allowing bid manipulation".to_string(),
                    remediation: "Use keccak256(abi.encodePacked(amount, salt, bidder)) for commitments".to_string(),
                });
            }

            // Check if there's a reveal deadline
            let has_reveal_deadline = self.bytecode.windows(4).any(|w| {
                w[0] == 0x42 && // TIMESTAMP
                w[1] == 0x54 && // SLOAD (reveal deadline)
                w[2] == 0x10 && // LT
                w[3] == 0x57    // JUMPI (revert if past deadline)
            });

            if !has_reveal_deadline {
                vulnerabilities.push(AuctionVulnerability {
                    vulnerability_type: AuctionVulnerabilityType::CommitRevealWeakness,
                    severity: SecuritySeverity::Medium,
                    location: 0,
                    description: "No reveal deadline enforcement".to_string(),
                    exploit_scenario: "Winners may choose not to reveal, causing auction to fail".to_string(),
                    remediation: "Implement strict reveal deadline with penalties for non-reveal".to_string(),
                });
            }
        }

        vulnerabilities
    }

    fn detect_bid_front_running(&self) -> Vec<AuctionVulnerability> {
        let mut vulnerabilities = Vec::new();

        let bid_sig = &[0x1f, 0x0b, 0xdc, 0xea][..]; // bid()
        
        if let Some(pos) = self.bytecode.windows(bid_sig.len()).position(|w| w == bid_sig) {
            let function_section = &self.bytecode[pos..pos.saturating_add(100).min(self.bytecode.len())];
            
            // Check if bid amount is taken from calldata (public)
            let uses_calldata = function_section.contains(&0x35); // CALLDATALOAD
            
            // Check for minimum increment requirement
            let has_min_increment = function_section.windows(4).any(|w| {
                w[0] == 0x54 && // SLOAD (current bid)
                w[1] == 0x01 && // ADD (minimum increment)
                w[2] == 0x10 && // LT
                w[3] == 0x57    // JUMPI (require new bid > current + increment)
            });

            if uses_calldata && !has_min_increment {
                vulnerabilities.push(AuctionVulnerability {
                    vulnerability_type: AuctionVulnerabilityType::BidFrontRunning,
                    severity: SecuritySeverity::High,
                    location: pos,
                    description: "Auction bids can be front-run without minimum increment".to_string(),
                    exploit_scenario: "Attacker sees pending bid in mempool, front-runs with slightly higher bid (e.g., +1 wei)".to_string(),
                    remediation: "Implement meaningful minimum bid increment (e.g., 5% higher than current bid)".to_string(),
                });
            }

            // Check for gas price manipulation protection
            let has_gas_protection = function_section.contains(&0x3a); // GASPRICE check

            if !has_gas_protection {
                vulnerabilities.push(AuctionVulnerability {
                    vulnerability_type: AuctionVulnerabilityType::LastMinuteBidDOS,
                    severity: SecuritySeverity::Medium,
                    location: pos,
                    description: "No protection against gas price manipulation DOS".to_string(),
                    exploit_scenario: "Attacker can use extremely high gas to ensure their bid is processed first".to_string(),
                    remediation: "Consider using commit-reveal scheme or batch auction instead of continuous bidding".to_string(),
                });
            }
        }

        vulnerabilities
    }

    fn detect_refund_reentrancy(&self) -> Vec<AuctionVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for refund mechanism when outbid
        let bid_sig = &[0x1f, 0x0b, 0xdc, 0xea][..]; // bid()
        
        if let Some(pos) = self.bytecode.windows(bid_sig.len()).position(|w| w == bid_sig) {
            let function_section = &self.bytecode[pos..pos.saturating_add(150).min(self.bytecode.len())];
            
            // Check for CALL (refund) before SSTORE (state update)
            let call_pos = function_section.iter().position(|&b| b == 0xf1); // CALL
            let sstore_pos = function_section.iter().position(|&b| b == 0x55); // SSTORE

            if let (Some(call), Some(store)) = (call_pos, sstore_pos) {
                if call < store {
                    vulnerabilities.push(AuctionVulnerability {
                        vulnerability_type: AuctionVulnerabilityType::RefundReentrancy,
                        severity: SecuritySeverity::Critical,
                        location: pos,
                        description: "Auction refund mechanism vulnerable to reentrancy".to_string(),
                        exploit_scenario: "Previous bidder can reenter during refund and manipulate auction state or drain funds".to_string(),
                        remediation: "Update state before external calls (CEI pattern) or use ReentrancyGuard".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_commit_reveal_weakness(&self) -> Vec<AuctionVulnerability> {
        let mut vulnerabilities = Vec::new();

        let reveal_sig = &[0x4f, 0xaa, 0x06, 0xbe][..]; // reveal()
        
        if let Some(pos) = self.bytecode.windows(reveal_sig.len()).position(|w| w == reveal_sig) {
            let function_section = &self.bytecode[pos..pos.saturating_add(100).min(self.bytecode.len())];
            
            // Check if reveal validates against stored commitment
            let has_commitment_check = function_section.windows(5).any(|w| {
                w[0] == 0x54 && // SLOAD (stored commitment)
                w[1] == 0x20 && // SHA3 (hash of revealed values)
                w[2] == 0x14 && // EQ
                w[3] == 0x15 && // ISZERO
                w[4] == 0x57    // JUMPI (revert if mismatch)
            });

            if !has_commitment_check {
                vulnerabilities.push(AuctionVulnerability {
                    vulnerability_type: AuctionVulnerabilityType::CommitRevealWeakness,
                    severity: SecuritySeverity::Critical,
                    location: pos,
                    description: "Reveal phase doesn't properly validate commitment".to_string(),
                    exploit_scenario: "Bidders can reveal different values than committed, cheating the auction".to_string(),
                    remediation: "Strictly validate: require(keccak256(revealed) == storedCommitment)".to_string(),
                });
            }

            // Check for deposit/penalty mechanism
            let has_deposit = self.bytecode.windows(3).any(|w| {
                w[0] == 0x34 && // CALLVALUE
                w[1] == 0x10 && // LT (check value >= minimum)
                w[2] == 0x57    // JUMPI
            });

            if !has_deposit {
                vulnerabilities.push(AuctionVulnerability {
                    vulnerability_type: AuctionVulnerabilityType::CommitRevealWeakness,
                    severity: SecuritySeverity::Medium,
                    location: pos,
                    description: "No deposit requirement for commitment".to_string(),
                    exploit_scenario: "Bidders can spam fake commitments with no cost, griefing the auction".to_string(),
                    remediation: "Require deposit at commit phase, refund upon proper reveal".to_string(),
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
    fn test_detect_auction_pattern() {
        let bytecode = vec![
            0x1f, 0x0b, 0xdc, 0xea, // bid() signature
        ];
        
        let detector = AuctionMechanismDetector::new(bytecode);
        assert!(detector.detect_auction_pattern());
    }

    #[test]
    fn test_dutch_auction_vulnerability() {
        let bytecode = vec![
            0x1f, 0x0b, 0xdc, 0xea, // bid()
            0x42, // TIMESTAMP
            0x03, // SUB
            0x04, // DIV (price calculation)
        ];
        
        let detector = AuctionMechanismDetector::new(bytecode);
        let vulns = detector.detect_dutch_auction_manipulation();
        assert!(!vulns.is_empty());
    }

    #[test]
    fn test_refund_reentrancy() {
        let bytecode = vec![
            0x1f, 0x0b, 0xdc, 0xea, // bid()
            0xf1, // CALL (refund before state update)
            0x55, // SSTORE
        ];
        
        let detector = AuctionMechanismDetector::new(bytecode);
        let vulns = detector.detect_refund_reentrancy();
        assert!(!vulns.is_empty());
    }
}
