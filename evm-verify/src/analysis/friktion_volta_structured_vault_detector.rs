// Friktion Volta Structured Vault Detector
// Detects manipulation in automated options strategies (covered calls, CSPs, straddles)

use crate::bytecode::security::{SecuritySeverity, SecurityWarning, SecurityWarningKind};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FriktionVaultVulnerability {
    pub location: usize,
    pub vulnerability_type: FriktionVulnerabilityType,
    pub severity: SecuritySeverity,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FriktionVulnerabilityType {
    VoltStrategyManipulation,      // Strategy parameters manipulated mid-cycle
    OptionStrikeGaming,            // Strike selection gaming for favorable fills
    PremiumDistributionUnfair,     // Unfair premium allocation to depositors
    WithdrawalQueueFrontRunning,   // Front-run withdrawal processing
    RebalancingSlippageExploit,    // High slippage during vault rebalancing
    YieldCalculationError,         // Incorrect APY calculation
    EpochTransitionRaceCondition,  // Race condition during epoch settlement
}

pub struct FriktionVaultDetector {
    bytecode: Vec<u8>,
}

impl FriktionVaultDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<FriktionVaultVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_strategy_manipulation() {
            vulnerabilities.push(FriktionVaultVulnerability {
                location: loc,
                vulnerability_type: FriktionVulnerabilityType::VoltStrategyManipulation,
                severity: SecuritySeverity::Critical,
                description: "Volt strategy parameters (strike, expiry) can be modified after deposits. \
                             Manager can change strategy mid-cycle to extract value from depositors.".to_string(),
                confidence: 0.88,
            });
        }

        if let Some(loc) = self.detect_strike_gaming() {
            vulnerabilities.push(FriktionVaultVulnerability {
                location: loc,
                vulnerability_type: FriktionVulnerabilityType::OptionStrikeGaming,
                severity: SecuritySeverity::High,
                description: "Strike selection uses single oracle price without volatility adjustment. \
                             Manager can time strike selection to maximize own profit at depositor expense.".to_string(),
                confidence: 0.83,
            });
        }

        if let Some(loc) = self.detect_premium_distribution_unfair() {
            vulnerabilities.push(FriktionVaultVulnerability {
                location: loc,
                vulnerability_type: FriktionVulnerabilityType::PremiumDistributionUnfair,
                severity: SecuritySeverity::High,
                description: "Premium distribution rounds down systematically. Late depositors in epoch \
                             receive disproportionately less premium due to rounding errors.".to_string(),
                confidence: 0.79,
            });
        }

        if let Some(loc) = self.detect_withdrawal_frontrunning() {
            vulnerabilities.push(FriktionVaultVulnerability {
                location: loc,
                vulnerability_type: FriktionVulnerabilityType::WithdrawalQueueFrontRunning,
                severity: SecuritySeverity::Medium,
                description: "Withdrawal processing order depends on transaction ordering. MEV can \
                             front-run withdrawal queue to exit before losses are realized.".to_string(),
                confidence: 0.75,
            });
        }

        if let Some(loc) = self.detect_rebalancing_slippage() {
            vulnerabilities.push(FriktionVaultVulnerability {
                location: loc,
                vulnerability_type: FriktionVulnerabilityType::RebalancingSlippageExploit,
                severity: SecuritySeverity::High,
                description: "Vault rebalancing lacks slippage protection. Large rebalances can be \
                             sandwiched to extract value during strategy adjustments.".to_string(),
                confidence: 0.81,
            });
        }

        if let Some(loc) = self.detect_yield_calculation_error() {
            vulnerabilities.push(FriktionVaultVulnerability {
                location: loc,
                vulnerability_type: FriktionVulnerabilityType::YieldCalculationError,
                severity: SecuritySeverity::Medium,
                description: "APY calculation uses simple division without compounding. Displayed \
                             yield is misleading, especially for short epochs.".to_string(),
                confidence: 0.72,
            });
        }

        if let Some(loc) = self.detect_epoch_race_condition() {
            vulnerabilities.push(FriktionVaultVulnerability {
                location: loc,
                vulnerability_type: FriktionVulnerabilityType::EpochTransitionRaceCondition,
                severity: SecuritySeverity::High,
                description: "Epoch settlement can be front-run. Depositor can deposit after seeing \
                             profitable epoch results but before settlement completes.".to_string(),
                confidence: 0.77,
            });
        }

        vulnerabilities
    }

    fn detect_strategy_manipulation(&self) -> Option<usize> {
        // Pattern: Strategy params mutable after deposits
        // SLOAD (deposits) → check → SSTORE (strategy params) without access control
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x54 {  // SLOAD (check deposits)
                let mut has_deposits_check = false;
                let mut has_access_control = false;
                
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x11 || self.bytecode[j] == 0x10 {  // GT/LT (deposits > 0)
                        has_deposits_check = true;
                    }
                    
                    // Access control: CALLER → EQ
                    if self.bytecode[j] == 0x33 {  // CALLER
                        for k in j+1..(j+5).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x14 {  // EQ
                                has_access_control = true;
                            }
                        }
                    }
                    
                    // Strategy param update without access control
                    if has_deposits_check && !has_access_control && self.bytecode[j] == 0x55 {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_strike_gaming(&self) -> Option<usize> {
        // Pattern: Strike selection from single oracle without vol adjustment
        // CALL (oracle) → MUL/DIV (strike calc) → SSTORE without additional oracle calls
        
        for i in 0..self.bytecode.len().saturating_sub(35) {
            if self.bytecode[i] == 0xF1 || self.bytecode[i] == 0xFA {  // CALL (oracle)
                let mut oracle_calls = 1;
                let mut has_strike_calc = false;
                
                for j in i+1..(i+30).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0xF1 || self.bytecode[j] == 0xFA {
                        oracle_calls += 1;
                    }
                    
                    if self.bytecode[j] == 0x02 || self.bytecode[j] == 0x04 {  // MUL/DIV
                        has_strike_calc = true;
                    }
                    
                    // Single oracle used for strike
                    if has_strike_calc && oracle_calls == 1 && self.bytecode[j] == 0x55 {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_premium_distribution_unfair(&self) -> Option<usize> {
        // Pattern: Premium division without remainder tracking
        // Loop with DIV for distribution without MOD accumulation
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x5B {  // JUMPDEST (loop start)
                let mut has_division = false;
                let mut has_mod_tracking = false;
                
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x04 {  // DIV
                        has_division = true;
                    }
                    
                    // Check for MOD followed by SSTORE (remainder tracking)
                    if self.bytecode[j] == 0x06 {  // MOD
                        for k in j+1..(j+5).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x55 {  // SSTORE
                                has_mod_tracking = true;
                            }
                        }
                    }
                    
                    if has_division && !has_mod_tracking && self.bytecode[j] == 0x57 {  // JUMPI
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_withdrawal_frontrunning(&self) -> Option<usize> {
        // Pattern: Withdrawal processing without commit-reveal or fairness queue
        // CALL (process withdrawal) without prior SLOAD (commitment hash)
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0xF1 {  // CALL (withdrawal)
                let mut has_commit_check = false;
                
                // Check if there's a commitment hash loaded before
                for j in (i.saturating_sub(15))..i {
                    if self.bytecode[j] == 0x54 {  // SLOAD
                        // Check if followed by ISZERO (hash existence check)
                        for k in j+1..(j+5).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x15 {  // ISZERO
                                has_commit_check = true;
                            }
                        }
                    }
                }
                
                if !has_commit_check {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_rebalancing_slippage(&self) -> Option<usize> {
        // Pattern: Swap without slippage check
        // CALL (swap/rebalance) without prior LT (min amount out)
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0xF1 {  // CALL (likely swap)
                let mut has_min_amount_check = false;
                
                // Look for slippage check before call
                for j in (i.saturating_sub(15))..i {
                    if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 {  // LT/GT
                        has_min_amount_check = true;
                    }
                }
                
                // Check if this looks like a rebalance (multiple SLOADs/SSTOREs nearby)
                let mut storage_ops = 0;
                for j in i+1..(i+15).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x54 || self.bytecode[j] == 0x55 {
                        storage_ops += 1;
                    }
                }
                
                if storage_ops >= 2 && !has_min_amount_check {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_yield_calculation_error(&self) -> Option<usize> {
        // Pattern: Yield calculation with simple DIV, no exponentiation for compounding
        // MUL (balance) → DIV (time) → SSTORE without EXP
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x02 {  // MUL
                let mut has_time_division = false;
                let mut has_compounding = false;
                
                for j in i+1..(i+15).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x04 {  // DIV (time)
                        has_time_division = true;
                    }
                    
                    if self.bytecode[j] == 0x0A {  // EXP (compounding)
                        has_compounding = true;
                    }
                    
                    // Simple yield calc without compounding
                    if has_time_division && !has_compounding && self.bytecode[j] == 0x55 {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_epoch_race_condition(&self) -> Option<usize> {
        // Pattern: Deposit allowed during settlement
        // TIMESTAMP → comparison (epoch check) → SSTORE (deposit) without lock
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x42 {  // TIMESTAMP
                let mut has_epoch_check = false;
                let mut has_settlement_lock = false;
                
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 {  // LT/GT (epoch boundary)
                        has_epoch_check = true;
                    }
                    
                    // Settlement lock: SLOAD checking settlement flag
                    if self.bytecode[j] == 0x54 {
                        for k in j+1..(j+5).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x15 {  // ISZERO (check not settling)
                                has_settlement_lock = true;
                            }
                        }
                    }
                    
                    // Deposit during settlement possible
                    if has_epoch_check && !has_settlement_lock && self.bytecode[j] == 0x55 {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    pub fn to_security_warnings(&self) -> Vec<SecurityWarning> {
        self.detect()
            .into_iter()
            .map(|v| SecurityWarning {
                kind: SecurityWarningKind::FriktiónVolta,
                severity: v.severity,
                description: format!(
                    "Friktion Volt {:?} at PC {}: {}",
                    v.vulnerability_type, v.location, v.description
                ),
                pc: v.location as u64,
                operations: Vec::new(),
                remediation: "Review protocol-specific security measures".to_string(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strategy_manipulation() {
        let bytecode = vec![
            0x54, // SLOAD (deposits)
            0x60, 0x00, // PUSH1 0
            0x11, // GT (deposits > 0)
            0x60, 0x01, // PUSH1 1
            0x55, // SSTORE (update strategy without access control)
        ];
        
        let detector = FriktionVaultDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, FriktionVulnerabilityType::VoltStrategyManipulation)));
    }

    #[test]
    fn test_yield_calculation_simple() {
        let bytecode = vec![
            0x02, // MUL (balance * rate)
            0x60, 0x64, // PUSH1 100
            0x04, // DIV (time division)
            0x60, 0x00, // PUSH1 0
            0x55, // SSTORE (no EXP for compounding)
        ];
        
        let detector = FriktionVaultDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, FriktionVulnerabilityType::YieldCalculationError)));
    }
}
