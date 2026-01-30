use serde::{Deserialize, Serialize};

/// Pausable Token Funds Locked Detection
/// 
/// Detects risks when integrating pausable tokens (USDC, USDT):
/// 1. Funds can be locked if token is paused
/// 2. No rescue mechanism for paused token funds
/// 3. Pausable token used in time-sensitive operations
/// 4. No alternative token path when paused
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PausableTokenFundsLockedVulnerability {
    /// Critical: Funds permanently locked if token paused
    FundsPermanentlyLocked {
        description: String,
        location: usize,
        token_transfer: bool,
        confidence: f32,
    },
    /// High: No rescue function for paused tokens
    NoRescueMechanism {
        description: String,
        contract_location: usize,
    },
    /// High: Time-sensitive operation with pausable token
    TimeSensitiveWithPausableToken {
        description: String,
        operation_location: usize,
        operation_type: String,
    },
    /// Medium: Single token dependency
    NoAlternativeTokenPath {
        description: String,
        location: usize,
    },
}

pub struct PausableTokenFundsLockedDetector {
    bytecode: Vec<u8>,
}

impl PausableTokenFundsLockedDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<PausableTokenFundsLockedVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern 1: Token transfers without pause check
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.is_token_transfer(i) {
                let checks_pause_state = self.has_pause_state_check(i.saturating_sub(50), i + 50);
                let has_try_catch = self.has_error_handling(i, i + 100);
                
                if !checks_pause_state && !has_try_catch {
                    vulnerabilities.push(PausableTokenFundsLockedVulnerability::FundsPermanentlyLocked {
                        description: "Token transfer without pause state validation or error handling".to_string(),
                        location: i,
                        token_transfer: true,
                        confidence: 0.80,
                    });
                }
            }
        }
        
        // Pattern 2: Check for rescue/recovery function
        let has_rescue = self.has_token_rescue_function();
        
        if !has_rescue && self.holds_external_tokens() {
            vulnerabilities.push(PausableTokenFundsLockedVulnerability::NoRescueMechanism {
                description: "Contract holds external tokens but has no rescue mechanism".to_string(),
                contract_location: 0,
            });
        }
        
        // Pattern 3: Time-sensitive operations (liquidations, auctions) with pausable tokens
        for i in 0..self.bytecode.len().saturating_sub(150) {
            if let Some(op_type) = self.identify_time_sensitive_operation(i) {
                let uses_pausable_token = self.uses_token_in_range(i, i + 150);
                let has_deadline = self.has_deadline_check(i, i + 150);
                
                if uses_pausable_token && has_deadline {
                    vulnerabilities.push(PausableTokenFundsLockedVulnerability::TimeSensitiveWithPausableToken {
                        description: format!(
                            "Time-sensitive {} operation vulnerable to token pause",
                            op_type
                        ),
                        operation_location: i,
                        operation_type: op_type,
                    });
                }
            }
        }
        
        // Pattern 4: Single token dependency
        for i in 0..self.bytecode.len().saturating_sub(200) {
            if self.is_critical_flow(i) {
                let token_count = self.count_unique_tokens_in_flow(i, i + 200);
                let has_fallback = self.has_alternative_token_path(i, i + 200);
                
                if token_count == 1 && !has_fallback {
                    vulnerabilities.push(PausableTokenFundsLockedVulnerability::NoAlternativeTokenPath {
                        description: "Critical flow depends on single token without alternative".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_token_transfer(&self, location: usize) -> bool {
        if location + 30 > self.bytecode.len() {
            return false;
        }
        
        // ERC20 transfer/transferFrom selectors
        self.bytecode[location..location + 30].windows(4).any(|w| {
            w[0] == 0x63 && (
                (w[1] == 0xa9 && w[2] == 0x05 && w[3] == 0x9c) || // transfer: 0xa9059cbb
                (w[1] == 0x23 && w[2] == 0xb8 && w[3] == 0x72)    // transferFrom: 0x23b872dd
            )
        })
    }
    
    fn has_pause_state_check(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return false;
        }
        
        // Check for paused() call or similar
        // paused() selector: 0x5c975abb
        let has_paused_call = self.bytecode[start..range_end]
            .windows(4)
            .any(|w| {
                w[0] == 0x63 && w[1] == 0x5c && w[2] == 0x97 && w[3] == 0x5a
            });
        
        // Or direct pause state SLOAD
        let has_pause_sload = self.bytecode[start..range_end]
            .windows(5)
            .any(|w| {
                w[0] == 0x60 && // PUSH1 (pause slot)
                w[2] == 0x54 && // SLOAD
                w[3] == 0x15    // ISZERO (check if not paused)
            });
        
        has_paused_call || has_pause_sload
    }
    
    fn has_error_handling(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return false;
        }
        
        // Try-catch pattern:
        // 1. CALL with success check
        // 2. JUMPI on failure
        // 3. Alternative path
        
        self.bytecode[start..range_end]
            .windows(4)
            .any(|w| {
                (w[0] == 0xf1 || w[0] == 0xfa) && // CALL or STATICCALL
                w[1] == 0x15 && // ISZERO (check success)
                w[2] == 0x57    // JUMPI (jump on failure)
            })
    }
    
    fn has_token_rescue_function(&self) -> bool {
        // Look for rescue/recover/sweep functions
        // Common selectors: rescueTokens, recoverERC20, sweepTokens
        
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x63 { // PUSH4 (function selector)
                // Check if function has transfer call to admin/owner
                if i + 50 < self.bytecode.len() {
                    let has_transfer = self.bytecode[i..i + 50]
                        .windows(4)
                        .any(|w| w[0] == 0x63 && w[1] == 0xa9 && w[2] == 0x05);
                    
                    let has_owner_check = self.bytecode[i..i + 50]
                        .windows(2)
                        .any(|w| w[0] == 0x33 && w[1] == 0x14); // CALLER == owner
                    
                    if has_transfer && has_owner_check {
                        return true;
                    }
                }
            }
        }
        
        false
    }
    
    fn holds_external_tokens(&self) -> bool {
        // Check if contract receives or holds external tokens
        // Look for transferFrom calls (receiving tokens)
        
        self.bytecode.windows(4).any(|w| {
            w[0] == 0x63 && w[1] == 0x23 && w[2] == 0xb8 && w[3] == 0x72 // transferFrom
        })
    }
    
    fn identify_time_sensitive_operation(&self, location: usize) -> Option<String> {
        if location + 40 > self.bytecode.len() {
            return None;
        }
        
        // Check for time-sensitive function selectors
        let slice = &self.bytecode[location..location + 40];
        
        // Liquidation functions
        if slice.windows(4).any(|w| w[0] == 0x63 && (w[1] == 0x96 || w[1] == 0x5a)) {
            return Some("liquidation".to_string());
        }
        
        // Auction functions
        if slice.windows(4).any(|w| w[0] == 0x63 && w[1] == 0x45) {
            return Some("auction".to_string());
        }
        
        // Order execution
        if slice.windows(4).any(|w| w[0] == 0x63 && (w[1] == 0x12 || w[1] == 0x61)) {
            return Some("order_execution".to_string());
        }
        
        None
    }
    
    fn uses_token_in_range(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        self.bytecode[start..range_end]
            .windows(4)
            .any(|w| {
                w[0] == 0x63 && (
                    (w[1] == 0xa9 && w[2] == 0x05) || // transfer
                    (w[1] == 0x23 && w[2] == 0xb8)    // transferFrom
                )
            })
    }
    
    fn has_deadline_check(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return false;
        }
        
        // Deadline check: block.timestamp < deadline
        self.bytecode[start..range_end]
            .windows(3)
            .any(|w| {
                w[0] == 0x42 && // TIMESTAMP
                w[1] == 0x10    // LT
            })
    }
    
    fn is_critical_flow(&self, location: usize) -> bool {
        if location + 50 > self.bytecode.len() {
            return false;
        }
        
        // Critical flows involve state changes + value transfer
        let has_state_change = self.bytecode[location..location + 50]
            .iter()
            .any(|&b| b == 0x55); // SSTORE
        
        let has_value_transfer = self.bytecode[location..location + 50]
            .iter()
            .any(|&b| b == 0xf1); // CALL (ETH transfer) or token transfer
        
        has_state_change && has_value_transfer
    }
    
    fn count_unique_tokens_in_flow(&self, start: usize, end: usize) -> u32 {
        let range_end = end.min(self.bytecode.len());
        let mut token_addresses = std::collections::HashSet::new();
        
        // Look for token addresses (PUSH20)
        for i in start..range_end {
            if self.bytecode[i] == 0x73 && i + 20 < range_end { // PUSH20
                let addr_bytes = &self.bytecode[i + 1..i + 21];
                token_addresses.insert(addr_bytes.to_vec());
            }
        }
        
        token_addresses.len() as u32
    }
    
    fn has_alternative_token_path(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return false;
        }
        
        // Alternative path indicated by:
        // 1. Multiple JUMPI (conditional branches)
        // 2. Different token addresses in different branches
        
        let jumpi_count = self.bytecode[start..range_end]
            .iter()
            .filter(|&&b| b == 0x57) // JUMPI
            .count();
        
        jumpi_count >= 2
    }
}
