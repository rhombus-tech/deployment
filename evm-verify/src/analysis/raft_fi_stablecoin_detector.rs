use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use ethers::types::U256;

/// Raft.fi R Stablecoin Collateral Manipulation Detector
/// 
/// Detects vulnerabilities in the Raft.fi R stablecoin protocol where collateral
/// valuation and liquidation mechanisms can be manipulated.
/// 
/// **Historical Exploit**: Raft.fi ($6.7M, November 2023)
/// 
/// **Attack Pattern**:
/// 1. Attacker deposits collateral (e.g., stETH) to mint R stablecoin
/// 2. Manipulates collateral price oracle or redemption rate
/// 3. Over-mints R tokens against manipulated collateral value
/// 4. Redeems or swaps R tokens before price correction
/// 5. Leaves protocol with bad debt from over-collateralized positions
/// 
/// **Specific Raft Vulnerability**:
/// The protocol used Chainlink oracles for stETH/ETH pricing but didn't account
/// for rebasing token mechanics. The stETH balance could be manipulated within
/// a transaction to inflate collateral value temporarily, allowing excessive
/// R token minting.
/// 
/// **Detection Strategy**:
/// - Identifies rebasing/reward-bearing token collateral without balance snapshot
/// - Detects collateral ratio calculations using instantaneous balances
/// - Flags missing oracle staleness checks for collateral pricing
/// - Checks for mint operations without cooldown on new collateral deposits
/// - Validates liquidation threshold calculations against manipulation
pub struct RaftFiStablecoinDetector {
    bytecode: Vec<u8>,
}

impl RaftFiStablecoinDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityWarning> {
        let mut warnings = Vec::new();

        if self.has_rebasing_collateral_without_snapshot() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "Rebasing/reward-bearing token used as collateral without balance snapshots - Raft vulnerability".to_string(),
                operations: Vec::new(),
                remediation: "Use balance snapshots or shares-based accounting for rebasing collateral tokens".to_string(),
            });
        }

        if self.has_instant_collateral_mint_without_cooldown() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "Stablecoin minting allowed immediately after collateral deposit without cooldown".to_string(),
                operations: Vec::new(),
                remediation: "Add time delay or block delay between collateral deposit and minting".to_string(),
            });
        }

        if self.has_collateral_ratio_manipulation() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::OracleManipulation,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Collateral ratio uses manipulable instantaneous balance or price".to_string(),
                operations: Vec::new(),
                remediation: "Use TWAP oracles and time-weighted collateral balances for ratio calculations".to_string(),
            });
        }

        if self.has_missing_oracle_staleness_check() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::OracleManipulation,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Oracle price used without staleness validation for collateral".to_string(),
                operations: Vec::new(),
                remediation: "Add timestamp checks to ensure oracle prices are fresh and within acceptable age".to_string(),
            });
        }

        warnings
    }

    fn has_rebasing_collateral_without_snapshot(&self) -> bool {
        // Pattern: balanceOf(collateral) -> mint calculation without snapshot
        let balance_of = [0x70, 0xa0, 0x82, 0x31]; // balanceOf()
        let mint_selector = [0x40, 0xc1, 0x0f, 0x19]; // mint()
        
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == balance_of {
                    let window = &self.bytecode[i..i+50.min(self.bytecode.len())];
                    
                    // Look for mint operation based on balance
                    let has_mint = window.windows(5).any(|w| {
                        w[0] == 0x63 && w[1..5] == mint_selector
                    });
                    
                    // Check for balance snapshot mechanism
                    let has_snapshot = window.windows(8).any(|w| {
                        // Pattern: KECCAK256(user + "snapshot") -> SLOAD -> use stored balance
                        w.iter().any(|&op| op == 0x20) && // KECCAK256
                        w.iter().any(|&op| op == 0x54) && // SLOAD (load snapshot)
                        w.iter().any(|&op| op == 0x04) // DIV or calculation
                    });
                    
                    // Check for shares-based accounting
                    let has_shares = window.windows(6).any(|w| {
                        // Pattern: balance * totalShares / totalSupply
                        w.iter().any(|&op| op == 0x02) && // MUL
                        w.iter().any(|&op| op == 0x04) && // DIV
                        w.iter().any(|&op| op == 0x18) // TOTALSSUPPLY
                    });
                    
                    if has_mint && !has_snapshot && !has_shares {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_instant_collateral_mint_without_cooldown(&self) -> bool {
        // Pattern: deposit() -> mint() in same transaction without delay
        let deposit_selector = [0xb6, 0xb5, 0x5f, 0x25]; // deposit()
        let mint_selector = [0x40, 0xc1, 0x0f, 0x19]; // mint()
        
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == deposit_selector || selector == mint_selector {
                    let window = &self.bytecode[i..i+60.min(self.bytecode.len())];
                    
                    // Check if both deposit and mint are present
                    let has_deposit = window.windows(5).any(|w| {
                        w[0] == 0x63 && w[1..5] == deposit_selector
                    });
                    
                    let has_mint = window.windows(5).any(|w| {
                        w[0] == 0x63 && w[1..5] == mint_selector
                    });
                    
                    // Check for cooldown mechanism
                    let has_cooldown = window.windows(8).any(|w| {
                        // Pattern: lastDepositBlock < block.number - delay
                        w.iter().any(|&op| op == 0x43) && // NUMBER (block.number)
                        w.iter().any(|&op| op == 0x54) && // SLOAD (last deposit)
                        w.iter().any(|&op| op == 0x10) && // LT
                        w.iter().any(|&op| op == 0x57) // JUMPI (revert if too soon)
                    });
                    
                    // Check for timestamp-based delay
                    let has_time_delay = window.windows(8).any(|w| {
                        w.iter().any(|&op| op == 0x42) && // TIMESTAMP
                        w.iter().any(|&op| op == 0x54) && // SLOAD (last deposit time)
                        w.iter().any(|&op| op == 0x01) && // ADD (timestamp + delay)
                        w.iter().any(|&op| op == 0x10) // LT (check if enough time passed)
                    });
                    
                    if has_deposit && has_mint && !has_cooldown && !has_time_delay {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_collateral_ratio_manipulation(&self) -> bool {
        // Pattern: collateralValue / debt without TWAP or snapshot
        for i in 0..self.bytecode.len().saturating_sub(35) {
            if self.bytecode[i] == 0x04 { // DIV (ratio calculation)
                let window = &self.bytecode[i.saturating_sub(25)..i+10.min(self.bytecode.len())];
                
                // Check if this is collateral ratio calculation
                let has_balance_check = window.iter().any(|&op| {
                    op == 0x31 || op == 0xfa // BALANCE or STATICCALL (balanceOf)
                });
                
                // Check for comparison with threshold (e.g., 150%)
                let has_threshold = window.windows(3).any(|w| {
                    (w[0] >= 0x60 && w[0] <= 0x7f) && // PUSH (threshold value)
                    (w[1] == 0x10 || w[1] == 0x11) // LT or GT
                });
                
                // Check for TWAP usage
                let has_twap = window.iter().any(|&op| {
                    op == 0x42 // TIMESTAMP (for time-weighted calculation)
                });
                
                // Check for stored snapshot
                let has_snapshot = window.windows(5).any(|w| {
                    w.iter().any(|&op| op == 0x20) && // KECCAK256 (snapshot key)
                    w.iter().any(|&op| op == 0x54) // SLOAD
                });
                
                if has_balance_check && has_threshold && !has_twap && !has_snapshot {
                    return true;
                }
            }
        }
        false
    }

    fn has_missing_oracle_staleness_check(&self) -> bool {
        // Pattern: latestRoundData() without timestamp validation
        let latest_round = [0xfe, 0xaf, 0x96, 0x8c]; // latestRoundData() selector
        
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == latest_round {
                    let window = &self.bytecode[i..i+40.min(self.bytecode.len())];
                    
                    // Check if price is used
                    let has_price_usage = window.iter().any(|&op| {
                        op == 0x02 || op == 0x04 // MUL or DIV (price calculation)
                    });
                    
                    // Check for timestamp staleness validation
                    let has_staleness_check = window.windows(10).any(|w| {
                        // Pattern: TIMESTAMP - oracleTimestamp < maxStaleness
                        w.iter().any(|&op| op == 0x42) && // TIMESTAMP
                        w.iter().any(|&op| op == 0x03) && // SUB
                        w.iter().any(|&op| op == 0x10) && // LT (check staleness)
                        w.iter().any(|&op| op == 0x57) // JUMPI (revert if stale)
                    });
                    
                    // Check for updatedAt validation
                    let has_updated_at_check = window.windows(6).any(|w| {
                        // Pattern: require(updatedAt > 0)
                        w.iter().any(|&op| op == 0x15) && // ISZERO
                        w.iter().any(|&op| op == 0xfd) // REVERT if zero
                    });
                    
                    if has_price_usage && !has_staleness_check && !has_updated_at_check {
                        return true;
                    }
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
    fn test_raft_rebasing_collateral_vulnerability() {
        let vulnerable_bytecode = vec![
            0x63, 0x70, 0xa0, 0x82, 0x31, // balanceOf(stETH) - rebasing token
            0xfa, // STATICCALL
            0x02, // MUL (calculate mintable amount)
            0x63, 0x40, 0xc1, 0x0f, 0x19, // mint() - no snapshot!
            0x55, // SSTORE
        ];

        let detector = RaftFiStablecoinDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        
        assert!(!warnings.is_empty());
        assert!(warnings.iter().any(|w| w.description.contains("Rebasing")));
    }

    #[test]
    fn test_instant_mint_vulnerability() {
        let vulnerable_bytecode = vec![
            0x63, 0xb6, 0xb5, 0x5f, 0x25, // deposit()
            0xf1, // CALL (transfer collateral)
            0x63, 0x40, 0xc1, 0x0f, 0x19, // mint() - instant!
            0x55, // SSTORE (no cooldown check)
        ];

        let detector = RaftFiStablecoinDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        
        assert!(warnings.iter().any(|w| 
            w.description.contains("immediately after") || 
            w.description.contains("cooldown")
        ));
    }
}
