use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use ethers::types::U256;

/// Merlin DEX TVL/Liquidity Manipulation Detector
/// 
/// Detects vulnerabilities in DEX protocols where Total Value Locked (TVL)
/// or liquidity metrics can be manipulated to exploit reward mechanisms.
/// 
/// **Historical Exploit**: Merlin DEX ($1.82M, April 2023)
/// **Attack Pattern**:
/// 1. Attacker inflates TVL through flash loans or fake deposits
/// 2. Reward calculation based on manipulated TVL/liquidity shares
/// 3. Attacker claims disproportionate rewards
/// 4. Withdraw initial capital and profit
/// 
/// **Detection Strategy**:
/// - Identifies TVL calculations without manipulation resistance
/// - Detects reward distribution based on instant liquidity
/// - Flags missing time-weighted or snapshot-based calculations
/// - Checks for flash loan + deposit patterns
pub struct MerlinDexTvlManipulationDetector {
    bytecode: Vec<u8>,
}

impl MerlinDexTvlManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityWarning> {
        let mut warnings = Vec::new();

        if self.has_instant_tvl_reward_calculation() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::OracleManipulation,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "Reward calculation uses instant TVL - Merlin DEX vulnerability".to_string(),
                operations: Vec::new(),
                remediation: "Use time-weighted TVL calculations or snapshot-based mechanisms".to_string(),
            });
        }

        if self.has_flash_loan_deposit_pattern() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::FlashLoanAttackVector,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Flash loan + deposit pattern can manipulate TVL/liquidity".to_string(),
                operations: Vec::new(),
                remediation: "Add flash loan protection and minimum lock period for deposits".to_string(),
            });
        }

        if self.has_missing_time_weighted_calculation() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Liquidity-based calculation without time-weighting or snapshots".to_string(),
                operations: Vec::new(),
                remediation: "Implement time-weighted calculations or use stored snapshots".to_string(),
            });
        }

        warnings
    }

    fn has_instant_tvl_reward_calculation(&self) -> bool {
        // Pattern: balanceOf() -> reward calculation without delay
        let balance_of_selector = [0x70, 0xa0, 0x82, 0x31]; // balanceOf()
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == balance_of_selector {
                    let window = &self.bytecode[i..i+25.min(self.bytecode.len())];
                    
                    // Check for reward calculation (MUL/DIV)
                    let has_reward_calc = window.iter().any(|&op| {
                        op == 0x02 || op == 0x04 // MUL or DIV
                    });
                    
                    // Check for time delay (TIMESTAMP comparison)
                    let has_time_delay = window.iter().any(|&op| {
                        op == 0x42 // TIMESTAMP
                    });
                    
                    if has_reward_calc && !has_time_delay {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_flash_loan_deposit_pattern(&self) -> bool {
        // Pattern: flash loan callback -> deposit/stake -> claim
        let flash_callback = [0x23, 0xe3, 0x0c, 0x8b]; // onFlashLoan
        let deposit_selector = [0xb6, 0xb5, 0x5f, 0x25]; // deposit()
        
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == flash_callback {
                    let window = &self.bytecode[i..i+40.min(self.bytecode.len())];
                    
                    // Look for deposit call
                    let has_deposit = window.windows(5).any(|w| {
                        w[0] == 0x63 && w[1..5] == deposit_selector
                    });
                    
                    if has_deposit {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_missing_time_weighted_calculation(&self) -> bool {
        // Look for totalSupply or balance-based calculations without timestamps
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x18 { // TOTALSSUPPLY
                let window = &self.bytecode[i..i+20.min(self.bytecode.len())];
                
                // Check if used in calculation
                let has_calculation = window.iter().any(|&op| {
                    op == 0x02 || op == 0x04 // MUL or DIV
                });
                
                // Check for time weighting
                let has_time_weight = window.iter().any(|&op| {
                    op == 0x42 || // TIMESTAMP
                    op == 0x54    // SLOAD (stored snapshots)
                });
                
                if has_calculation && !has_time_weight {
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
    fn test_merlin_dex_tvl_manipulation() {
        let vulnerable_bytecode = vec![
            0x63, 0x70, 0xa0, 0x82, 0x31, // balanceOf()
            0xfa, // STATICCALL
            0x02, // MUL (reward calculation)
            0x55, // SSTORE (update rewards)
        ];

        let detector = MerlinDexTvlManipulationDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        assert!(!warnings.is_empty());
    }
}
