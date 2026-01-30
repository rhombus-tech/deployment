use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Vote Buying and Dark DAO Detection
/// 
/// Detects patterns indicating vote buying or dark DAO activity:
/// 1. Vote delegation followed by immediate token transfers
/// 2. Flash loan + vote + repay patterns
/// 3. Vote rental marketplaces
/// 4. Bribe distribution patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VoteBuyingVulnerability {
    /// Critical: Flash loan vote manipulation
    FlashLoanVotePattern {
        description: String,
        location: usize,
        confidence: f32,
    },
    /// High: Delegation followed by payment
    DelegationWithPayment {
        description: String,
        location: usize,
        payment_detected: bool,
    },
    /// High: Bribe marketplace pattern
    BribeMarketplace {
        description: String,
        location: usize,
        bribe_mechanism: String,
    },
    /// Medium: Vote escrow transferability
    VoteEscrowTransferable {
        description: String,
        location: usize,
    },
    /// Critical: Convex/Votium gauge bribery
    ConvexVotiumBribery {
        description: String,
        location: usize,
        protocol: String,
        bribe_amount_manipulable: bool,
    },
    /// High: Curve gauge vote manipulation
    CurveGaugeVoteManipulation {
        description: String,
        location: usize,
        gauge_address: String,
    },
}

pub struct VoteBuyingDetectionDetector {
    bytecode: Vec<u8>,
}

impl VoteBuyingDetectionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<VoteBuyingVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern 1: Flash loan + vote + repay in single transaction
        for i in 0..self.bytecode.len().saturating_sub(300) {
            if self.is_flash_loan_start(i) {
                let has_vote = self.has_vote_cast_in_range(i, i + 300);
                let has_repay = self.has_flash_loan_repay(i + 100, i + 300);
                
                if has_vote && has_repay {
                    vulnerabilities.push(VoteBuyingVulnerability::FlashLoanVotePattern {
                        description: "Flash loan -> vote -> repay pattern detected".to_string(),
                        location: i,
                        confidence: 0.90,
                    });
                }
            }
        }
        
        // Pattern 2: Delegate function followed by token transfer
        for i in 0..self.bytecode.len().saturating_sub(150) {
            if self.is_delegate_function(i) {
                // Check if there's a token transfer shortly after
                let payment_detected = self.has_token_transfer_after(i, i + 150);
                
                if payment_detected {
                    vulnerabilities.push(VoteBuyingVulnerability::DelegationWithPayment {
                        description: "Vote delegation followed by token transfer (potential bribe)".to_string(),
                        location: i,
                        payment_detected,
                    });
                }
            }
        }
        
        // Pattern 3: Bribe marketplace mechanics
        // Look for: claimBribes, distributeBribes, votingRewards patterns
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.is_bribe_distribution(i) {
                let mechanism = self.classify_bribe_mechanism(i);
                
                vulnerabilities.push(VoteBuyingVulnerability::BribeMarketplace {
                    description: format!("Bribe distribution mechanism detected: {}", mechanism),
                    location: i,
                    bribe_mechanism: mechanism,
                });
            }
        }
        
        // Pattern 4: Vote escrow (veToken) transferability
        // veTokens should be non-transferable, but check for transfer loopholes
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.is_ve_token_contract(i) {
                if self.has_transfer_function(i, i + 50) {
                    vulnerabilities.push(VoteBuyingVulnerability::VoteEscrowTransferable {
                        description: "Vote escrow token has transfer functionality".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        // Pattern 5: Convex/Votium-specific gauge bribery
        for i in 0..self.bytecode.len().saturating_sub(200) {
            if let Some((protocol, manipulable)) = self.detect_convex_votium_bribery(i) {
                vulnerabilities.push(VoteBuyingVulnerability::ConvexVotiumBribery {
                    description: format!("{} gauge bribery mechanism detected with manipulable amounts", protocol),
                    location: i,
                    protocol,
                    bribe_amount_manipulable: manipulable,
                });
            }
        }
        
        // Pattern 6: Curve gauge weight vote manipulation
        for i in 0..self.bytecode.len().saturating_sub(150) {
            if let Some(gauge_addr) = self.detect_curve_gauge_manipulation(i) {
                vulnerabilities.push(VoteBuyingVulnerability::CurveGaugeVoteManipulation {
                    description: "Curve gauge vote weight manipulation via bribes".to_string(),
                    location: i,
                    gauge_address: gauge_addr,
                });
            }
        }
        
        vulnerabilities
    }
    
    fn is_flash_loan_start(&self, location: usize) -> bool {
        if location + 30 > self.bytecode.len() {
            return false;
        }
        
        // Flash loan patterns:
        // 1. flashLoan selector: 0x5cffe9de
        // 2. Balancer flashLoan: 0xab9c4b5d
        // 3. AAVE flashLoan: 0xab9c4b5d
        
        self.bytecode[location..location + 30].windows(4).any(|w| {
            (w[0] == 0x63 && w[1] == 0x5c && w[2] == 0xff) || // flashLoan
            (w[0] == 0x63 && w[1] == 0xab && w[2] == 0x9c)    // AAVE/Balancer
        })
    }
    
    fn has_vote_cast_in_range(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return false;
        }
        
        // Look for vote casting function selectors:
        // - castVote: 0x56781388
        // - castVoteWithReason: 0x7b3c71d3
        // - vote: 0xc9d27afe
        
        self.bytecode[start..range_end].windows(4).any(|w| {
            (w[0] == 0x63 && w[1] == 0x56 && w[2] == 0x78) || // castVote
            (w[0] == 0x63 && w[1] == 0x7b && w[2] == 0x3c) || // castVoteWithReason
            (w[0] == 0x63 && w[1] == 0xc9 && w[2] == 0xd2)    // vote
        })
    }
    
    fn has_flash_loan_repay(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return false;
        }
        
        // Flash loans must be repaid in same tx
        // Look for token transfer back + callback return
        let has_transfer = self.bytecode[start..range_end]
            .windows(4)
            .any(|w| w[0] == 0x63 && w[1] == 0xa9 && w[2] == 0x05); // transfer selector
        
        let has_return = self.bytecode[start..range_end]
            .iter()
            .any(|&b| b == 0xf3); // RETURN
        
        has_transfer && has_return
    }
    
    fn is_delegate_function(&self, location: usize) -> bool {
        if location + 20 > self.bytecode.len() {
            return false;
        }
        
        // Delegate function selector: 0x5c19a95c
        self.bytecode[location..location + 20].windows(4).any(|w| {
            w[0] == 0x63 && w[1] == 0x5c && w[2] == 0x19 && w[3] == 0xa9
        })
    }
    
    fn has_token_transfer_after(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return false;
        }
        
        // Look for ERC20 transfer or ETH transfer after delegation
        self.bytecode[start..range_end].windows(4).any(|w| {
            // transfer(address,uint256): 0xa9059cbb
            (w[0] == 0x63 && w[1] == 0xa9 && w[2] == 0x05 && w[3] == 0x9c)
        }) || self.bytecode[start..range_end].iter().any(|&b| b == 0xf1) // CALL (ETH transfer)
    }
    
    fn is_bribe_distribution(&self, location: usize) -> bool {
        if location + 30 > self.bytecode.len() {
            return false;
        }
        
        // Bribe-related function selectors:
        // - claimBribes
        // - distributeBribes
        // - getReward
        // - notifyRewardAmount
        
        self.bytecode[location..location + 30].windows(4).any(|w| {
            w[0] == 0x63 && (
                (w[1] == 0x3d && w[2] == 0x18) || // claimBribes pattern
                (w[1] == 0xc0 && w[2] == 0x0e) || // getReward
                (w[1] == 0x3c && w[2] == 0x6b)    // notifyRewardAmount
            )
        })
    }
    
    fn classify_bribe_mechanism(&self, location: usize) -> String {
        let search_end = (location + 100).min(self.bytecode.len());
        
        // Check characteristics of the bribe mechanism
        let has_gauge = self.bytecode[location..search_end]
            .windows(4)
            .any(|w| w[0] == 0x60 && w.iter().any(|&b| b == 0x67)); // "gauge" related
        
        let has_epoch = self.bytecode[location..search_end]
            .windows(2)
            .any(|w| w[0] == 0x42 || w[0] == 0x43); // TIMESTAMP or NUMBER (epoch based)
        
        let has_merkle = self.bytecode[location..search_end]
            .iter()
            .filter(|&&b| b == 0x20) // SHA3
            .count() > 2;
        
        if has_gauge && has_epoch {
            "gauge_bribe_marketplace".to_string()
        } else if has_merkle {
            "merkle_bribe_distribution".to_string()
        } else {
            "direct_bribe_payment".to_string()
        }
    }
    
    fn is_ve_token_contract(&self, location: usize) -> bool {
        if location + 50 > self.bytecode.len() {
            return false;
        }
        
        // Check for veToken characteristics:
        // 1. Has locked() function
        // 2. Has create_lock() or increase_lock()
        // 3. Stores lock end times
        
        let has_lock_function = self.bytecode[location..location + 50]
            .windows(4)
            .any(|w| w[0] == 0x63 && w[1] == 0xf8); // locked() selector pattern
        
        let has_timestamp_logic = self.bytecode[location..location + 50]
            .iter()
            .any(|&b| b == 0x42); // TIMESTAMP
        
        has_lock_function && has_timestamp_logic
    }
    
    fn has_transfer_function(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return false;
        }
        
        // Check for transfer() or transferFrom() functions
        self.bytecode[start..range_end].windows(4).any(|w| {
            w[0] == 0x63 && (
                (w[1] == 0xa9 && w[2] == 0x05) || // transfer
                (w[1] == 0x23 && w[2] == 0xb8)    // transferFrom
            )
        })
    }
    
    fn detect_convex_votium_bribery(&self, location: usize) -> Option<(String, bool)> {
        if location + 200 > self.bytecode.len() {
            return None;
        }
        
        let window = &self.bytecode[location..location + 200];
        
        // Convex vlCVX bribe patterns
        // - depositBribe(): 0x3f4b0d16
        // - claimBribes(): used with Votium
        let has_vlcvx = window.windows(4).any(|w| {
            w[0] == 0x63 && w[1] == 0x3f && w[2] == 0x4b // depositBribe
        });
        
        // Votium snapshot-based bribery
        let has_votium_snapshot = window.windows(10).any(|w| {
            // Merkle root storage for Votium claims
            w.iter().filter(|&&b| b == 0x20).count() >= 2 && // Multiple KECCAK256
            w.iter().any(|&b| b == 0x55) // SSTORE merkle root
        });
        
        // Curve gauge controller interaction
        let has_gauge_controller = window.windows(4).any(|w| {
            // vote_for_gauge_weights(): 0x0f3a9f65
            w[0] == 0x63 && w[1] == 0x0f && w[2] == 0x3a
        });
        
        // Check if bribe amount is manipulable (no bounds)
        let bribe_amount_manipulable = window.windows(20).any(|w| {
            let has_amount_load = w.iter().any(|&b| b == 0x35); // CALLDATALOAD (bribe amount)
            let has_transfer = w.iter().any(|&b| b == 0xf1); // CALL (transfer bribe)
            let has_bounds_check = w.windows(5).any(|check| {
                check.iter().any(|&b| b == 0x10 || b == 0x11) && // LT/GT
                check.iter().any(|&b| b == 0xfd) // REVERT
            });
            
            has_amount_load && has_transfer && !has_bounds_check
        });
        
        if has_vlcvx || (has_votium_snapshot && has_gauge_controller) {
            let protocol = if has_vlcvx {
                "Convex".to_string()
            } else {
                "Votium".to_string()
            };
            return Some((protocol, bribe_amount_manipulable));
        }
        
        None
    }
    
    fn detect_curve_gauge_manipulation(&self, location: usize) -> Option<String> {
        if location + 150 > self.bytecode.len() {
            return None;
        }
        
        let window = &self.bytecode[location..location + 150];
        
        // Curve gauge voting patterns
        // vote_for_gauge_weights(address gauge, uint256 weight)
        let has_gauge_vote = window.windows(4).any(|w| {
            w[0] == 0x63 && w[1] == 0x0f && w[2] == 0x3a && w[3] == 0x9f
        });
        
        // Check for vote weight without time-lock or cooldown
        let has_vote_weight_manipulation = window.windows(30).any(|w| {
            let has_weight_param = w.iter().any(|&b| b == 0x35); // CALLDATALOAD (weight)
            let has_gauge_call = w.iter().any(|&b| b == 0xf1 || b == 0xfa); // CALL to gauge
            
            // Check for missing cooldown
            let has_cooldown = w.windows(8).any(|check| {
                check.iter().any(|&b| b == 0x42) && // TIMESTAMP
                check.iter().any(|&b| b == 0x54) && // SLOAD (last vote time)
                check.iter().any(|&b| b == 0x10) // LT (time check)
            });
            
            has_weight_param && has_gauge_call && !has_cooldown
        });
        
        // Detect if bribes are given for specific gauge votes
        let has_conditional_bribe = window.windows(40).any(|w| {
            let has_vote = w.windows(4).any(|v| v[0] == 0x63 && v[1] == 0x0f);
            let has_bribe_transfer = w.windows(20).any(|t| {
                t.iter().any(|&b| b == 0xf1) && // CALL (transfer)
                t.windows(4).any(|s| s[0] == 0x63 && s[1] == 0xa9) // transfer selector
            });
            
            has_vote && has_bribe_transfer
        });
        
        if has_gauge_vote && (has_vote_weight_manipulation || has_conditional_bribe) {
            // Extract gauge address if possible (simplified)
            return Some("gauge_vote_manipulation_detected".to_string());
        }
        
        None
    }
}
