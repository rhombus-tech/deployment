use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use ethers::types::U256;

/// Revest Finance Financial NFT Wrapping Detector
/// 
/// Detects vulnerabilities in financial NFT protocols where wrapped assets
/// can be exploited through valuation manipulation or access control issues.
/// 
/// **Attack Patterns**:
/// 1. NFT valuation manipulation through oracle attacks
/// 2. Double-wrapping or unwrapping exploits
/// 3. Access control bypass in wrapper contracts
/// 4. Time-locked asset premature release
/// 
/// **Detection Strategy**:
/// - Identifies NFT wrapping without proper valuation checks
/// - Detects missing lock period validation
/// - Flags reentrancy in wrap/unwrap operations
/// - Checks for double-claim vulnerabilities
pub struct RevestFinanceNftWrappingDetector {
    bytecode: Vec<u8>,
}

impl RevestFinanceNftWrappingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityWarning> {
        let mut warnings = Vec::new();

        if self.has_unchecked_nft_valuation() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::OracleManipulation,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Financial NFT wrapping without proper valuation checks".to_string(),
                operations: Vec::new(),
                remediation: "Implement oracle-based valuation checks before wrapping NFTs".to_string(),
            });
        }

        if self.has_timelock_bypass_vulnerability() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "Time-locked assets can be released prematurely".to_string(),
                operations: Vec::new(),
                remediation: "Add strict timestamp validation with proper conditional checks".to_string(),
            });
        }

        if self.has_wrap_unwrap_reentrancy() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::Reentrancy,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Wrap/unwrap operations vulnerable to reentrancy".to_string(),
                operations: Vec::new(),
                remediation: "Add reentrancy guards to all wrap/unwrap functions".to_string(),
            });
        }

        warnings
    }

    fn has_unchecked_nft_valuation(&self) -> bool {
        // wrap() or mintFNFT() patterns
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Look for safeTransferFrom (receiving NFT)
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == [0x42, 0x84, 0x2e, 0x0e] { // safeTransferFrom
                    let window = &self.bytecode[i..i+30.min(self.bytecode.len())];
                    
                    // Check for valuation call
                    let has_valuation = window.iter().any(|&op| {
                        op == 0xfa // STATICCALL (to oracle/valuator)
                    });
                    
                    // Check for minting wrapped NFT
                    let has_mint = window.contains(&0x55); // SSTORE
                    
                    if has_mint && !has_valuation {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_timelock_bypass_vulnerability(&self) -> bool {
        // Pattern: unlock/withdraw without proper timestamp check
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                let window = &self.bytecode[i..i+25.min(self.bytecode.len())];
                
                // Look for comparison
                let has_comparison = window.iter().any(|&op| {
                    op == 0x10 || op == 0x11 // LT or GT
                });
                
                // Look for JUMPI (conditional)
                let has_conditional = window.contains(&0x57);
                
                // Look for transfer after timestamp
                let has_transfer = window.iter().any(|&op| {
                    op == 0xf1 || op == 0xf4 // CALL or DELEGATECALL
                });
                
                // Vulnerable if transfer happens without proper conditional check
                if has_transfer && (!has_comparison || !has_conditional) {
                    return true;
                }
            }
        }
        false
    }

    fn has_wrap_unwrap_reentrancy(&self) -> bool {
        // Pattern: NFT transfer (callback) -> state update
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                // safeTransferFrom triggers callback
                if selector == [0x42, 0x84, 0x2e, 0x0e] {
                    let window = &self.bytecode[i..i+20.min(self.bytecode.len())];
                    
                    // Check for SSTORE after transfer
                    if window.contains(&0x55) {
                        // Check for reentrancy guard
                        let has_guard = window.windows(3).any(|w| {
                            w[0] == 0x54 && w[1] == 0x15 && w[2] == 0x57
                        });
                        
                        if !has_guard {
                            return true;
                        }
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
    fn test_revest_nft_wrapping() {
        let vulnerable_bytecode = vec![
            0x63, 0x42, 0x84, 0x2e, 0x0e, // safeTransferFrom
            0xf1, // CALL
            0x55, // SSTORE (mint wrapped NFT without valuation)
        ];

        let detector = RevestFinanceNftWrappingDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        assert!(!warnings.is_empty());
    }
}
