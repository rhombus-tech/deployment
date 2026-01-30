use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use ethers::types::U256;

/// Popsicle/Visor Liquidity Manager Reentrancy Detector
/// 
/// Detects reentrancy vulnerabilities in concentrated liquidity managers where
/// callbacks during liquidity operations can reenter before position updates.
/// 
/// **Attack Pattern**:
/// 1. Attacker deposits/withdraws from liquidity position
/// 2. Callback during Uniswap V3 mint/burn triggers reentrancy
/// 3. Protocol state not updated before callback
/// 4. Attacker manipulates position accounting
/// 
/// **Detection Strategy**:
/// - Identifies Uniswap V3 mint/burn/collect operations
/// - Detects missing guards on liquidity management functions
/// - Flags position state updates after callbacks
/// - Checks for share calculation vulnerabilities
pub struct PopsicleVisorLiquidityManagerReentrancyDetector {
    bytecode: Vec<u8>,
}

impl PopsicleVisorLiquidityManagerReentrancyDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityWarning> {
        let mut warnings = Vec::new();

        if self.has_unguarded_uniswap_v3_callback() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::Reentrancy,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "Uniswap V3 callback without reentrancy guard - Popsicle/Visor vulnerability".to_string(),
                operations: Vec::new(),
                remediation: "Add reentrancy guard to Uniswap V3 callback functions".to_string(),
            });
        }

        if self.has_position_update_after_callback() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::Reentrancy,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "Position accounting updated after liquidity callback".to_string(),
                operations: Vec::new(),
                remediation: "Update position accounting before callback execution".to_string(),
            });
        }

        if self.has_share_calculation_reentrancy() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::Reentrancy,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Share calculation vulnerable during liquidity operations".to_string(),
                operations: Vec::new(),
                remediation: "Lock share calculations during liquidity operations".to_string(),
            });
        }

        warnings
    }

    fn has_unguarded_uniswap_v3_callback(&self) -> bool {
        // Uniswap V3 callback selectors:
        // uniswapV3MintCallback: 0xd3487997
        // uniswapV3SwapCallback: 0xfa461e33
        let mint_callback = [0xd3, 0x48, 0x79, 0x97];
        let swap_callback = [0xfa, 0x46, 0x1e, 0x33];
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == mint_callback || selector == swap_callback {
                    let window = &self.bytecode[i..i+30.min(self.bytecode.len())];
                    
                    let has_guard = window.windows(3).any(|w| {
                        w[0] == 0x54 && w[1] == 0x15 && w[2] == 0x57
                    });
                    
                    if !has_guard {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_position_update_after_callback(&self) -> bool {
        // Pattern: mint/burn -> CALL (to UniV3) -> SSTORE (position update)
        let mint_selector = [0x88, 0x31, 0x64, 0x56]; // mint()
        let burn_selector = [0x89, 0xaf, 0xcb, 0x44]; // burn()
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == mint_selector || selector == burn_selector {
                    let window = &self.bytecode[i..i+25.min(self.bytecode.len())];
                    
                    if let Some(call_pos) = window.iter().position(|&op| op == 0xf1) {
                        let after_call = &window[call_pos+1..];
                        if after_call.contains(&0x55) {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    fn has_share_calculation_reentrancy(&self) -> bool {
        // Pattern: CALL (liquidity operation) -> DIV (share calc) -> SSTORE
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0xf1 { // CALL
                let window = &self.bytecode[i..i+20.min(self.bytecode.len())];
                
                // Look for share calculation (totalSupply DIV)
                let has_share_calc = window.windows(3).any(|w| {
                    w[0] == 0x18 && // TOTALSSUPPLY
                    w[1] == 0x04    // DIV
                });
                
                if has_share_calc && window.contains(&0x55) {
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
    fn test_popsicle_visor_reentrancy() {
        let vulnerable_bytecode = vec![
            0x63, 0xd3, 0x48, 0x79, 0x97, // uniswapV3MintCallback
            0xf1, // CALL
            0x18, // TOTALSSUPPLY
            0x04, // DIV (share calculation)
            0x55, // SSTORE
        ];

        let detector = PopsicleVisorLiquidityManagerReentrancyDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        assert!(!warnings.is_empty());
    }
}
