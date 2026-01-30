use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use ethers::types::U256;

/// Midas Capital Isolated Pool Contamination Detector
/// 
/// Detects vulnerabilities in isolated lending pools where contamination
/// from one pool can affect others through shared components or oracles.
/// 
/// **Attack Pattern**:
/// 1. Exploit vulnerability in one isolated pool
/// 2. Contamination spreads through shared oracle or reward system
/// 3. Other isolated pools become affected
/// 4. System-wide contagion despite isolation design
/// 
/// **Detection Strategy**:
/// - Identifies shared state between "isolated" pools
/// - Detects shared oracle dependencies
/// - Flags cross-pool reward contamination
/// - Checks for proper pool isolation boundaries
pub struct MidasCapitalIsolatedPoolContaminationDetector {
    bytecode: Vec<u8>,
}

impl MidasCapitalIsolatedPoolContaminationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityWarning> {
        let mut warnings = Vec::new();

        if self.has_shared_state_between_pools() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "Isolated pools share state - Midas Capital contamination risk".to_string(),
                operations: Vec::new(),
                remediation: "Ensure complete state isolation between pools using pool-specific storage keys".to_string(),
            });
        }

        if self.has_shared_oracle_vulnerability() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::OracleManipulation,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Isolated pools use shared oracle, contamination possible".to_string(),
                operations: Vec::new(),
                remediation: "Use pool-specific oracles or implement oracle isolation".to_string(),
            });
        }

        if self.has_cross_pool_reward_contamination() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Reward system allows cross-pool contamination".to_string(),
                operations: Vec::new(),
                remediation: "Isolate reward calculations per pool to prevent contamination".to_string(),
            });
        }

        warnings
    }

    fn has_shared_state_between_pools(&self) -> bool {
        // Pattern: SSTORE using pool-independent key
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x55 { // SSTORE
                let window = &self.bytecode[i.saturating_sub(15)..i];
                
                // Check if storage key includes pool ID
                let has_pool_id = window.iter().any(|&op| {
                    op == 0x20 // KECCAK256 (should hash pool ID into key)
                });
                
                // Check if this is a critical state variable
                let has_critical_state = window.windows(5).any(|w| {
                    // Look for totalSupply, totalBorrow, or similar patterns
                    w.iter().any(|&op| op == 0x18) // TOTALSSUPPLY nearby
                });
                
                if has_critical_state && !has_pool_id {
                    return true;
                }
            }
        }
        false
    }

    fn has_shared_oracle_vulnerability(&self) -> bool {
        // Pattern: oracle call without pool-specific validation
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0xfa { // STATICCALL (to oracle)
                let window = &self.bytecode[i..i+30.min(self.bytecode.len())];
                
                // Check if oracle result used in multiple pools
                let has_pool_selection = window.iter().any(|&op| {
                    op == 0x35 || op == 0x54 // CALLDATALOAD or SLOAD (pool ID)
                });
                
                // Check if result affects pool-specific calculations
                let has_pool_calc = window.iter().any(|&op| {
                    op == 0x02 || op == 0x04 // MUL or DIV
                });
                
                // Check for pool-specific validation after oracle call
                let has_pool_validation = window.windows(5).any(|w| {
                    w[0] == 0x20 && // KECCAK256 (pool-specific check)
                    w.iter().any(|&op| op == 0x54) // SLOAD
                });
                
                if has_pool_calc && !has_pool_selection && !has_pool_validation {
                    return true;
                }
            }
        }
        false
    }

    fn has_cross_pool_reward_contamination(&self) -> bool {
        // Pattern: reward distribution without pool isolation
        for i in 0..self.bytecode.len().saturating_sub(25) {
            // Look for reward minting/distribution
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                // Common reward function selectors
                if selector[0] == 0x40 || selector[0] == 0x1e { // mint() or related
                    let window = &self.bytecode[i..i+25.min(self.bytecode.len())];
                    
                    // Check for pool ID in calculation
                    let has_pool_isolation = window.iter().any(|&op| {
                        op == 0x20 // KECCAK256 (pool-specific key)
                    });
                    
                    // Check for reward amount calculation
                    let has_reward_calc = window.iter().any(|&op| {
                        op == 0x02 || op == 0x04 // MUL or DIV
                    });
                    
                    if has_reward_calc && !has_pool_isolation {
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
    fn test_midas_pool_contamination() {
        let vulnerable_bytecode = vec![
            0x18, // TOTALSSUPPLY (global, not pool-specific!)
            0x55, // SSTORE (shared state)
            0xfa, // STATICCALL (shared oracle)
            0x02, // MUL (affects all pools)
        ];

        let detector = MidasCapitalIsolatedPoolContaminationDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        assert!(!warnings.is_empty());
    }
}
