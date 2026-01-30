use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use ethers::types::U256;

/// Tracer Perpetual Insurance Pool Gaming Detector
/// 
/// Detects vulnerabilities in decentralized perpetual futures with pooled insurance
/// where the insurance fund can be drained or socialized losses exploited.
/// 
/// **Tracer Context**:
/// Decentralized perpetuals use pooled insurance funds to cover underwater positions.
/// Insurance fund absorbs losses when liquidations don't cover debt.
/// 
/// **Attack Patterns**:
/// 1. Insurance fund draining via coordinated underwater positions
/// 2. Socialized loss exploitation (getting paid from others' losses)
/// 3. Funding rate manipulation affecting insurance
/// 4. Liquidation gaming to drain insurance
/// 5. Insurance pool contribution gaming
/// 
/// **Detection Strategy**:
/// - Identifies insurance payouts without proper validation
/// - Detects missing insurance fund depletion protection
/// - Flags socialized loss calculations without caps
/// - Checks for funding rate manipulation vectors
/// - Validates liquidation-insurance interaction
pub struct TracerPerpetualInsuranceDetector {
    bytecode: Vec<u8>,
}

impl TracerPerpetualInsuranceDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityWarning> {
        let mut warnings = Vec::new();

        if self.has_insurance_drain_vulnerability() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "Insurance pool can be drained via coordinated underwater positions - Tracer pattern".to_string(),
                operations: Vec::new(),
                remediation: "Add insurance payout caps per epoch and monitor for coordinated attacks".to_string(),
            });
        }

        if self.has_socialized_loss_exploitation() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Socialized loss distribution can be exploited for profit".to_string(),
                operations: Vec::new(),
                remediation: "Implement caps on socialized losses per user and circuit breakers".to_string(),
            });
        }

        if self.has_funding_rate_insurance_manipulation() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Funding rate can be manipulated to affect insurance payouts".to_string(),
                operations: Vec::new(),
                remediation: "Use TWAP for funding rate and add deviation limits".to_string(),
            });
        }

        if self.has_liquidation_insurance_gaming() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::Medium,
                pc: 0,
                description: "Liquidation timing can be gamed to maximize insurance extraction".to_string(),
                operations: Vec::new(),
                remediation: "Add liquidation delays and price snapshots to prevent gaming".to_string(),
            });
        }

        warnings
    }

    fn has_insurance_drain_vulnerability(&self) -> bool {
        // Pattern: insurance payout without depletion protection
        for i in 0..self.bytecode.len().saturating_sub(55) {
            // Look for insurance fund transfer
            if self.bytecode[i] == 0xf1 { // CALL (transfer from insurance)
                let window = &self.bytecode[i.saturating_sub(45)..i+10.min(self.bytecode.len())];
                
                // Check if this is insurance payout
                let is_insurance_payout = window.windows(15).any(|w| {
                    // Pattern: load insurance balance -> transfer
                    w.iter().any(|&op| op == 0x31 || op == 0x54) && // BALANCE or SLOAD
                    w.iter().any(|&op| op == 0xf1) // CALL
                });
                
                // Check for payout cap
                let has_payout_cap = window.windows(10).any(|w| {
                    w.iter().any(|&op| op >= 0x60 && op <= 0x7f) && // PUSH (max payout)
                    w.iter().any(|&op| op == 0x10) // LT (check cap)
                });
                
                // Check for minimum insurance reserve
                let has_min_reserve = window.windows(12).any(|w| {
                    // Ensure insurance > minimum before payout
                    w.iter().any(|&op| op == 0x31) && // BALANCE
                    w.iter().any(|&op| op == 0x03) && // SUB (after payout)
                    w.iter().any(|&op| op == 0x11) // GT (> minimum)
                });
                
                // Check for epoch-based limits
                let has_epoch_limit = window.windows(15).any(|w| {
                    w.iter().any(|&op| op == 0x42) && // TIMESTAMP
                    w.iter().any(|&op| op == 0x54) && // SLOAD (epoch total)
                    w.iter().any(|&op| op == 0x11) // GT (check limit)
                });
                
                if is_insurance_payout && !has_payout_cap && !has_min_reserve && !has_epoch_limit {
                    return true;
                }
            }
        }
        false
    }

    fn has_socialized_loss_exploitation(&self) -> bool {
        // Pattern: socialized loss distribution without caps
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x04 { // DIV (loss distribution)
                let window = &self.bytecode[i.saturating_sub(40)..i+10.min(self.bytecode.len())];
                
                // Check for socialized loss calculation
                let calculates_socialized_loss = window.windows(15).any(|w| {
                    // Pattern: totalLoss / totalPositions
                    w.iter().filter(|&&op| op == 0x54).count() >= 2 && // Multiple SLOAD
                    w.iter().any(|&op| op == 0x04) // DIV
                });
                
                // Check for per-user loss cap
                let has_user_cap = window.windows(10).any(|w| {
                    w.iter().any(|&op| op >= 0x60 && op <= 0x7f) && // PUSH (max loss per user)
                    w.iter().any(|&op| op == 0x10) // LT
                });
                
                // Check for circuit breaker
                let has_circuit_breaker = window.windows(12).any(|w| {
                    // Halt if socialized loss too high
                    w.iter().any(|&op| op == 0x11) && // GT (check threshold)
                    w.iter().any(|&op| op == 0x55) && // SSTORE (halt flag)
                    w.iter().any(|&op| op == 0xfd) // REVERT
                });
                
                if calculates_socialized_loss && !has_user_cap && !has_circuit_breaker {
                    return true;
                }
            }
        }
        false
    }

    fn has_funding_rate_insurance_manipulation(&self) -> bool {
        // Pattern: funding rate affects insurance without TWAP
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x03 { // SUB (funding rate calculation)
                let window = &self.bytecode[i.saturating_sub(40)..i+10.min(self.bytecode.len())];
                
                // Check for funding rate calculation
                let calculates_funding = window.windows(15).any(|w| {
                    // Pattern: long - short positions
                    w.iter().filter(|&&op| op == 0x54).count() >= 2 && // Load long/short
                    w.iter().any(|&op| op == 0x03) // SUB
                });
                
                // Check if used for insurance
                let affects_insurance = window.windows(20).any(|w| {
                    w.iter().any(|&op| op == 0x02) && // MUL (funding * position)
                    w.iter().any(|&op| op == 0x55) // SSTORE (insurance impact)
                });
                
                if calculates_funding && affects_insurance {
                    // Check for TWAP
                    let uses_twap = window.windows(12).any(|w| {
                        w.iter().any(|&op| op == 0x42) && // TIMESTAMP
                        w.iter().filter(|&&op| op == 0x54).count() >= 3 // Historical values
                    });
                    
                    if !uses_twap {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_liquidation_insurance_gaming(&self) -> bool {
        // Pattern: liquidation triggers insurance without delay
        let liquidate_selector = [0x96, 0xcd, 0x41, 0x23]; // liquidate()
        
        for i in 0..self.bytecode.len().saturating_sub(55) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == liquidate_selector {
                    let window = &self.bytecode[i..i+55.min(self.bytecode.len())];
                    
                    // Check for insurance usage
                    let uses_insurance = window.windows(20).any(|w| {
                        // Pattern: if liquidation shortfall -> insurance payout
                        w.iter().any(|&op| op == 0x03) && // SUB (shortfall)
                        w.iter().any(|&op| op == 0xf1) // CALL (insurance transfer)
                    });
                    
                    // Check for liquidation delay
                    let has_delay = window.windows(12).any(|w| {
                        w.iter().any(|&op| op == 0x42) && // TIMESTAMP
                        w.iter().any(|&op| op == 0x01) && // ADD (+ delay)
                        w.iter().any(|&op| op == 0x10) // LT
                    });
                    
                    // Check for price snapshot
                    let uses_snapshot = window.windows(10).any(|w| {
                        w.iter().any(|&op| op == 0x20) && // KECCAK256 (snapshot key)
                        w.iter().any(|&op| op == 0x54) // SLOAD (historical price)
                    });
                    
                    if uses_insurance && !has_delay && !uses_snapshot {
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
    fn test_tracer_insurance_drain() {
        let vulnerable_bytecode = vec![
            0x31, // BALANCE (insurance fund)
            0xf1, // CALL (payout - no cap!)
        ];

        let detector = TracerPerpetualInsuranceDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        
        assert!(!warnings.is_empty());
        assert!(warnings.iter().any(|w| w.description.contains("insurance") || w.description.contains("drain")));
    }
}
