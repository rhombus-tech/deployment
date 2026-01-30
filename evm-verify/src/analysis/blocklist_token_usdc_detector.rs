use serde::{Deserialize, Serialize};

/// USDC/USDT Blocklist Integration Detection
/// 
/// Detects risks when integrating USDC/USDT with blocklist functionality:
/// 1. Blocked address can lock contract funds
/// 2. No blocklist validation before critical operations
/// 3. Withdrawal path can be permanently blocked
/// 4. Collateral with blocklisted address
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlocklistTokenUsdcVulnerability {
    /// Critical: Blocked address locks contract funds
    BlockedAddressLocksContractFunds {
        description: String,
        location: usize,
        can_bypass: bool,
        confidence: f32,
    },
    /// High: No blocklist check before accepting funds
    NoBlocklistValidation {
        description: String,
        deposit_function: usize,
    },
    /// Critical: Withdrawal permanently blocked
    WithdrawalPermanentlyBlocked {
        description: String,
        withdrawal_location: usize,
    },
    /// High: Collateral can be frozen
    CollateralFreezeable {
        description: String,
        location: usize,
        affects_liquidation: bool,
    },
}

pub struct BlocklistTokenUsdcDetector {
    bytecode: Vec<u8>,
}

impl BlocklistTokenUsdcDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<BlocklistTokenUsdcVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern 1: Contract receives tokens but transfers can be blocked
        for i in 0..self.bytecode.len().saturating_sub(150) {
            if self.is_token_receive_function(i) {
                let checks_blocklist = self.has_blocklist_check(i, i + 150);
                let can_bypass = self.has_bypass_mechanism(i, i + 150);
                
                if !checks_blocklist {
                    let has_locked_transfer = self.has_subsequent_transfer_requirement(i, i + 150);
                    
                    if has_locked_transfer {
                        vulnerabilities.push(BlocklistTokenUsdcVulnerability::BlockedAddressLocksContractFunds {
                            description: "Contract can receive tokens from address that later gets blocklisted".to_string(),
                            location: i,
                            can_bypass,
                            confidence: 0.85,
                        });
                    }
                }
            }
        }
        
        // Pattern 2: Deposit functions without blocklist validation
        for i in 0..self.bytecode.len().saturating_sub(120) {
            if self.is_deposit_function(i) {
                let validates_blocklist = self.validates_sender_blocklist_status(i, i + 120);
                
                if !validates_blocklist {
                    vulnerabilities.push(BlocklistTokenUsdcVulnerability::NoBlocklistValidation {
                        description: "Deposit function accepts funds without validating sender blocklist status".to_string(),
                        deposit_function: i,
                    });
                }
            }
        }
        
        // Pattern 3: Withdrawal to user-specified address
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.is_withdrawal_function(i) {
                let destination_user_controlled = self.destination_is_user_controlled(i, i + 100);
                let has_alternative_path = self.has_alternative_withdrawal_path(i, i + 100);
                
                if destination_user_controlled && !has_alternative_path {
                    vulnerabilities.push(BlocklistTokenUsdcVulnerability::WithdrawalPermanentlyBlocked {
                        description: "Withdrawal to user address can be permanently blocked if address is blocklisted".to_string(),
                        withdrawal_location: i,
                    });
                }
            }
        }
        
        // Pattern 4: Collateral system with blocklist tokens
        for i in 0..self.bytecode.len().saturating_sub(200) {
            if self.is_collateral_system(i) {
                let uses_blocklist_token = self.uses_usdc_or_usdt(i, i + 200);
                let affects_liquidation = self.collateral_affects_liquidation(i, i + 200);
                
                if uses_blocklist_token {
                    vulnerabilities.push(BlocklistTokenUsdcVulnerability::CollateralFreezeable {
                        description: "Collateral can be frozen via blocklist, affecting liquidation process".to_string(),
                        location: i,
                        affects_liquidation,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_token_receive_function(&self, location: usize) -> bool {
        if location + 30 > self.bytecode.len() {
            return false;
        }
        
        // transferFrom selector: 0x23b872dd (receiving tokens)
        self.bytecode[location..location + 30].windows(4).any(|w| {
            w[0] == 0x63 && w[1] == 0x23 && w[2] == 0xb8 && w[3] == 0x72
        })
    }
    
    fn has_blocklist_check(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return false;
        }
        
        // USDC blocklist check patterns:
        // 1. Call to isBlacklisted(address) - USDC specific
        // 2. Or custom blocklist storage check
        
        // isBlacklisted selector: 0xfe575a87
        let has_blocklist_call = self.bytecode[start..range_end]
            .windows(4)
            .any(|w| {
                w[0] == 0x63 && w[1] == 0xfe && w[2] == 0x57 && w[3] == 0x5a
            });
        
        // Custom blocklist SLOAD
        let has_custom_check = self.bytecode[start..range_end]
            .windows(5)
            .any(|w| {
                w[0] == 0x33 && // CALLER
                w[1] == 0x60 && // PUSH1 (blocklist slot)
                w[3] == 0x54 && // SLOAD
                w[4] == 0x15    // ISZERO (not blocklisted)
            });
        
        has_blocklist_call || has_custom_check
    }
    
    fn has_bypass_mechanism(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return false;
        }
        
        // Bypass mechanisms:
        // 1. Admin can force transfer
        // 2. Alternative token swap path
        
        let has_admin_force = self.bytecode[start..range_end]
            .windows(4)
            .any(|w| {
                w[0] == 0x33 && // CALLER
                w.iter().skip(1).any(|&b| b == 0x14) // Owner check
            });
        
        let has_swap_path = self.bytecode[start..range_end]
            .windows(4)
            .filter(|w| w[0] == 0x63 && w[1] == 0x12) // swap selector
            .count() > 0;
        
        has_admin_force || has_swap_path
    }
    
    fn has_subsequent_transfer_requirement(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return false;
        }
        
        // Check if received tokens need to be transferred out later
        // Look for transfer calls after the receive
        
        self.bytecode[start..range_end]
            .windows(4)
            .filter(|w| {
                w[0] == 0x63 && w[1] == 0xa9 && w[2] == 0x05 // transfer selector
            })
            .count() > 0
    }
    
    fn is_deposit_function(&self, location: usize) -> bool {
        if location + 30 > self.bytecode.len() {
            return false;
        }
        
        // deposit() selector: 0xd0e30db0 or similar
        self.bytecode[location..location + 30].windows(4).any(|w| {
            w[0] == 0x63 && (
                (w[1] == 0xd0 && w[2] == 0xe3) || // deposit
                (w[1] == 0x47 && w[2] == 0xe7)    // depositFor
            )
        })
    }
    
    fn validates_sender_blocklist_status(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return false;
        }
        
        // Check if sender's blocklist status is validated
        // Pattern: CALLER -> isBlacklisted -> REVERT if true
        
        self.bytecode[start..range_end]
            .windows(5)
            .any(|w| {
                w[0] == 0x33 && // CALLER
                w.iter().skip(1).any(|&b| b == 0xfa || b == 0xf1) && // STATICCALL to check
                w.iter().any(|&b| b == 0xfd) // REVERT if blocklisted
            })
    }
    
    fn is_withdrawal_function(&self, location: usize) -> bool {
        if location + 30 > self.bytecode.len() {
            return false;
        }
        
        // withdraw() selector: 0x2e1a7d4d
        self.bytecode[location..location + 30].windows(4).any(|w| {
            w[0] == 0x63 && w[1] == 0x2e && w[2] == 0x1a
        })
    }
    
    fn destination_is_user_controlled(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return false;
        }
        
        // Check if withdrawal destination comes from calldata or msg.sender
        let uses_calldata = self.bytecode[start..range_end]
            .iter()
            .any(|&b| b == 0x35); // CALLDATALOAD
        
        let uses_sender = self.bytecode[start..range_end]
            .iter()
            .any(|&b| b == 0x33); // CALLER
        
        uses_calldata || uses_sender
    }
    
    fn has_alternative_withdrawal_path(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return false;
        }
        
        // Alternative paths:
        // 1. Admin can withdraw to safe address
        // 2. Token swap before withdrawal
        
        let has_admin_withdrawal = self.bytecode[start..range_end]
            .windows(6)
            .any(|w| {
                w.iter().any(|&b| b == 0x33) && // CALLER check
                w.iter().any(|&b| b == 0x14) && // EQ (owner check)
                w.iter().any(|&b| b == 0xa9)    // transfer
            });
        
        let has_swap_option = self.bytecode[start..range_end]
            .windows(4)
            .any(|w| w[0] == 0x63 && w[1] == 0x12); // swap
        
        has_admin_withdrawal || has_swap_option
    }
    
    fn is_collateral_system(&self, location: usize) -> bool {
        if location + 50 > self.bytecode.len() {
            return false;
        }
        
        // Collateral systems have:
        // 1. Collateral tracking (storage)
        // 2. Liquidation functions
        // 3. Health factor calculations
        
        let has_collateral_tracking = self.bytecode[location..location + 50]
            .iter()
            .filter(|&&b| b == 0x55) // SSTORE
            .count() > 1;
        
        let has_liquidation_ref = self.bytecode[location..location + 50]
            .windows(4)
            .any(|w| w[0] == 0x63 && (w[1] == 0x96 || w[1] == 0x5a));
        
        has_collateral_tracking && has_liquidation_ref
    }
    
    fn uses_usdc_or_usdt(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Check for USDC/USDT contract addresses
        // USDC mainnet: 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48
        // USDT mainnet: 0xdAC17F958D2ee523a2206206994597C13D831ec7
        
        // Look for these addresses being used
        for i in start..range_end {
            if self.bytecode[i] == 0x73 && i + 20 < range_end { // PUSH20
                // Check if it matches known USDC/USDT addresses
                // Simplified: any PUSH20 in collateral context
                return true;
            }
        }
        
        false
    }
    
    fn collateral_affects_liquidation(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return false;
        }
        
        // Check if collateral value is used in liquidation logic
        self.bytecode[start..range_end]
            .windows(10)
            .any(|w| {
                w.iter().any(|&b| b == 0x54) && // SLOAD (collateral)
                w.iter().any(|&b| b == 0x04) && // DIV (ratio calculation)
                w.iter().any(|&b| b == 0x10)    // LT (threshold check)
            })
    }
}
