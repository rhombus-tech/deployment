use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use ethers::types::U256;

/// XCarnival NFT Collateral Valuation Detector
/// 
/// Detects vulnerabilities in NFT-collateralized lending where floor price
/// oracles can be manipulated to over-borrow against NFT collateral.
/// 
/// **Historical Exploit**: XCarnival ($3.8M, June 2022)
/// **Attack Pattern**:
/// 1. Manipulate NFT floor price oracle through wash trading
/// 2. Deposit NFT at inflated valuation
/// 3. Borrow maximum against manipulated collateral value
/// 4. Default on loan, profit from over-borrowing
/// 
/// **Detection Strategy**:
/// - Identifies NFT floor price calculations without manipulation resistance
/// - Detects missing time-weighted average floor prices
/// - Flags instant borrowing against freshly deposited NFTs
/// - Checks for collateral factor bounds
pub struct XcarnivalNftCollateralValuationDetector {
    bytecode: Vec<u8>,
}

impl XcarnivalNftCollateralValuationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityWarning> {
        let mut warnings = Vec::new();

        if self.has_manipulable_nft_floor_price() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::OracleManipulation,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "NFT floor price oracle manipulable - XCarnival vulnerability".to_string(),
                operations: Vec::new(),
                remediation: "Use time-weighted average floor prices with multiple data sources".to_string(),
            });
        }

        if self.has_instant_borrow_against_nft() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Instant borrowing allowed against freshly deposited NFT collateral".to_string(),
                operations: Vec::new(),
                remediation: "Implement time delay between NFT deposit and borrowing".to_string(),
            });
        }

        if self.has_unchecked_collateral_factor() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "NFT collateral factor calculation without safety bounds".to_string(),
                operations: Vec::new(),
                remediation: "Add bounds validation for NFT collateral factors".to_string(),
            });
        }

        warnings
    }

    fn has_manipulable_nft_floor_price(&self) -> bool {
        // Pattern: getFloorPrice() without TWAP
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0xfa { // STATICCALL (to oracle)
                let window = &self.bytecode[i..i+30.min(self.bytecode.len())];
                
                // Check if result used for collateral calculation
                let has_collateral_calc = window.iter().any(|&op| {
                    op == 0x02 || op == 0x04 // MUL or DIV
                });
                
                // Check for TWAP (multiple observations)
                let has_twap = window.iter().any(|&op| {
                    op == 0x54 // SLOAD (stored observations)
                });
                
                // Check for borrow operation
                let has_borrow = window.contains(&0x55); // SSTORE
                
                if has_collateral_calc && has_borrow && !has_twap {
                    return true;
                }
            }
        }
        false
    }

    fn has_instant_borrow_against_nft(&self) -> bool {
        // Pattern: NFT deposit -> immediate borrow without delay
        let transfer_from_selector = [0x23, 0xb8, 0x72, 0xdd]; // transferFrom
        let borrow_selector = [0xc5, 0xea, 0xbe, 0xec]; // borrow()
        
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == transfer_from_selector {
                    let window = &self.bytecode[i..i+40.min(self.bytecode.len())];
                    
                    // Check for borrow in same transaction window
                    let has_borrow = window.windows(5).any(|w| {
                        w[0] == 0x63 && w[1..5] == borrow_selector
                    });
                    
                    // Check for time delay
                    let has_delay = window.iter().any(|&op| {
                        op == 0x42 // TIMESTAMP
                    });
                    
                    if has_borrow && !has_delay {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_unchecked_collateral_factor(&self) -> bool {
        // Pattern: NFT value * collateral_factor without bounds
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x02 { // MUL (collateral calculation)
                let window = &self.bytecode[i..i+20.min(self.bytecode.len())];
                
                // Check for bounds validation
                let has_bounds = window.iter().any(|&op| {
                    op == 0x10 || op == 0x11 || op == 0xfd // LT, GT, REVERT
                });
                
                // Check if result used for borrowing
                let has_borrow = window.contains(&0x55); // SSTORE
                
                if has_borrow && !has_bounds {
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
    fn test_xcarnival_nft_collateral() {
        let vulnerable_bytecode = vec![
            0xfa, // STATICCALL (get floor price)
            0x02, // MUL (collateral calc, no bounds!)
            0x63, 0xc5, 0xea, 0xbe, 0xec, // borrow()
            0x55, // SSTORE
        ];

        let detector = XcarnivalNftCollateralValuationDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        assert!(!warnings.is_empty());
    }
}
