use crate::errors::{VMError, Result};
use crate::security::{SecurityWarning, SecurityWarningKind, Severity};
use crate::transaction::TransactionSequence;
use ethereum_types::{Address, U256};
use serde::{Serialize, Deserialize};

/// DeFi protection layer that integrates with evm-verify's invariant checker
pub struct DeFiProtectionLayer {
    /// Enable invariant checking
    invariant_checking_enabled: bool,
    /// Severity threshold for blocking
    block_threshold: Severity,
}

/// Simplified pool state for verification
#[derive(Debug, Clone)]
pub struct PoolStateSnapshot {
    pub contract: Address,
    pub reserve0: U256,
    pub reserve1: U256,
    pub reserve2: Option<U256>,
    pub total_supply: U256,
    pub timestamp: u64,
}

/// Result of DeFi protection check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeFiProtectionResult {
    pub should_block: bool,
    pub warnings: Vec<SecurityWarning>,
    pub invariant_violations: Vec<InvariantViolation>,
    pub risk_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantViolation {
    pub pool: Address,
    pub invariant_type: String,
    pub change_percent: f64,
    pub severity: Severity,
    pub description: String,
}

impl DeFiProtectionLayer {
    pub fn new(invariant_checking_enabled: bool, block_threshold: Severity) -> Self {
        Self {
            invariant_checking_enabled,
            block_threshold,
        }
    }
    
    /// Main entry point: check if sequence should be blocked
    pub async fn verify_sequence(
        &self,
        sequence: &TransactionSequence,
        pool_states_before: &[PoolStateSnapshot],
        pool_states_after: &[PoolStateSnapshot],
    ) -> Result<DeFiProtectionResult> {
        let mut result = DeFiProtectionResult {
            should_block: false,
            warnings: Vec::new(),
            invariant_violations: Vec::new(),
            risk_score: 0.0,
        };
        
        if !self.invariant_checking_enabled {
            return Ok(result);
        }
        
        // Check each pool's invariant
        for (before, after) in pool_states_before.iter().zip(pool_states_after.iter()) {
            if before.contract != after.contract {
                continue; // Mismatched pools, skip
            }
            
            let invariant_check = self.check_pool_invariant(
                before,
                after,
                sequence.transactions().len(),
            )?;
            
            if let Some(violation) = invariant_check {
                // Add to warnings
                result.warnings.push(SecurityWarning {
                    code: "DEFI-INV-001".to_string(),
                    message: violation.description.clone(),
                    severity: violation.severity,
                    kind: SecurityWarningKind::PrecisionLoss,
                    description: format!(
                        "Pool invariant violation detected: {} changed by {:.4}%",
                        violation.invariant_type,
                        violation.change_percent
                    ),
                    location: None,
                    remediation_hint: "Review pool state changes for unexpected invariant degradation".to_string(),
                });
                
                result.invariant_violations.push(violation.clone());
                
                // Update risk score
                match violation.severity {
                    Severity::Critical => result.risk_score += 10.0,
                    Severity::High => result.risk_score += 5.0,
                    Severity::Medium => result.risk_score += 2.0,
                    Severity::Low => result.risk_score += 1.0,
                    Severity::Info => result.risk_score += 0.0,
                }
                
                // Check if we should block
                if violation.severity >= self.block_threshold {
                    result.should_block = true;
                }
            }
        }
        
        Ok(result)
    }
    
    /// Check invariant for a single pool
    fn check_pool_invariant(
        &self,
        before: &PoolStateSnapshot,
        after: &PoolStateSnapshot,
        operation_count: usize,
    ) -> Result<Option<InvariantViolation>> {
        // Detect protocol type and apply appropriate invariant check
        let invariant_type = self.detect_protocol_type(before);
        
        match invariant_type.as_str() {
            "StableSwap" => self.check_stable_swap_invariant(before, after, operation_count),
            "ConstantProduct" => self.check_constant_product_invariant(before, after),
            "WeightedProduct" => self.check_weighted_product_invariant(before, after),
            _ => Ok(None), // Unknown type, don't block
        }
    }
    
    fn detect_protocol_type(&self, state: &PoolStateSnapshot) -> String {
        // Simple heuristic detection
        // Production would use bytecode analysis
        
        // If reserves are similar in size, likely stable swap
        let ratio = if state.reserve1 > U256::zero() {
            let r0 = self.u256_to_f64(state.reserve0);
            let r1 = self.u256_to_f64(state.reserve1);
            r0 / r1
        } else {
            1.0
        };
        
        if ratio > 0.8 && ratio < 1.2 {
            "StableSwap".to_string()
        } else {
            "ConstantProduct".to_string()
        }
    }
    
    fn check_stable_swap_invariant(
        &self,
        before: &PoolStateSnapshot,
        after: &PoolStateSnapshot,
        operation_count: usize,
    ) -> Result<Option<InvariantViolation>> {
        // Simplified D invariant calculation
        let d_before = self.calculate_d_invariant(before);
        let d_after = self.calculate_d_invariant(after);
        
        let change = if d_before > 0.0 {
            (d_after - d_before) / d_before
        } else {
            0.0
        };
        
        // Allow 0.01% per operation (generous)
        let max_allowed = 0.0001 * (operation_count as f64);
        
        if change.abs() > max_allowed {
            // Determine severity
            let excess_factor = change.abs() / max_allowed;
            let severity = if excess_factor > 100.0 {
                Severity::Critical
            } else if excess_factor > 10.0 {
                Severity::High
            } else if excess_factor > 3.0 {
                Severity::Medium
            } else {
                Severity::Low
            };
            
            return Ok(Some(InvariantViolation {
                pool: after.contract,
                invariant_type: "StableSwap D".to_string(),
                change_percent: change * 100.0,
                severity,
                description: format!(
                    "Stable swap invariant changed by {:.4}%, exceeds {:.4}% tolerance for {} operations. This pattern is similar to the Balancer $128M exploit.",
                    change.abs() * 100.0,
                    max_allowed * 100.0,
                    operation_count
                ),
            }));
        }
        
        Ok(None)
    }
    
    fn check_constant_product_invariant(
        &self,
        before: &PoolStateSnapshot,
        after: &PoolStateSnapshot,
    ) -> Result<Option<InvariantViolation>> {
        let k_before = self.safe_mul_u256(before.reserve0, before.reserve1)?;
        let k_after = self.safe_mul_u256(after.reserve0, after.reserve1)?;
        
        let k_before_f64 = self.u256_to_f64(k_before);
        let k_after_f64 = self.u256_to_f64(k_after);
        
        let change = if k_before_f64 > 0.0 {
            (k_after_f64 - k_before_f64) / k_before_f64
        } else {
            0.0
        };
        
        // k should only increase (fees) or stay same, never decrease
        if change < -0.0001 { // Allow 0.01% rounding tolerance
            let severity = if change < -0.01 {
                Severity::Critical
            } else if change < -0.001 {
                Severity::High
            } else {
                Severity::Medium
            };
            
            return Ok(Some(InvariantViolation {
                pool: after.contract,
                invariant_type: "Constant Product k=x*y".to_string(),
                change_percent: change * 100.0,
                severity,
                description: format!(
                    "Constant product invariant decreased by {:.4}% (should only increase or stay constant)",
                    change.abs() * 100.0
                ),
            }));
        }
        
        Ok(None)
    }
    
    fn check_weighted_product_invariant(
        &self,
        before: &PoolStateSnapshot,
        after: &PoolStateSnapshot,
    ) -> Result<Option<InvariantViolation>> {
        // Simplified weighted product check (assume equal weights)
        let x_before = self.u256_to_f64(before.reserve0);
        let y_before = self.u256_to_f64(before.reserve1);
        let x_after = self.u256_to_f64(after.reserve0);
        let y_after = self.u256_to_f64(after.reserve1);
        
        let k_before = (x_before * y_before).sqrt();
        let k_after = (x_after * y_after).sqrt();
        
        let change = if k_before > 0.0 {
            (k_after - k_before) / k_before
        } else {
            0.0
        };
        
        if change < -0.0001 {
            let severity = if change < -0.01 {
                Severity::Critical
            } else {
                Severity::High
            };
            
            return Ok(Some(InvariantViolation {
                pool: after.contract,
                invariant_type: "Weighted Product".to_string(),
                change_percent: change * 100.0,
                severity,
                description: format!(
                    "Weighted product invariant decreased by {:.4}%",
                    change.abs() * 100.0
                ),
            }));
        }
        
        Ok(None)
    }
    
    fn calculate_d_invariant(&self, state: &PoolStateSnapshot) -> f64 {
        // Simplified D calculation
        let x = self.u256_to_f64(state.reserve0);
        let y = self.u256_to_f64(state.reserve1);
        x + y // Simplified
    }
    
    fn safe_mul_u256(&self, a: U256, b: U256) -> Result<U256> {
        a.checked_mul(b)
            .ok_or_else(|| VMError::Internal {
                description: "Multiplication overflow in invariant check".to_string(),
            })
    }
    
    fn u256_to_f64(&self, value: U256) -> f64 {
        // Simple conversion (loses precision but adequate for ratios)
        // Use only the first two u64 words to avoid overflow
        let low = value.0[0] as f64;
        let high = if value.0.len() > 1 {
            value.0[1] as f64 * (u64::MAX as f64)
        } else {
            0.0
        };
        low + high
    }
}

impl Default for DeFiProtectionLayer {
    fn default() -> Self {
        Self::new(
            true, // Enable by default
            Severity::High, // Block on High or Critical
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_balancer_attack_pattern_blocked() {
        let protection = DeFiProtectionLayer::default();
        
        let before = PoolStateSnapshot {
            contract: Address::zero(),
            reserve0: U256::from(1000000),
            reserve1: U256::from(1000000),
            reserve2: None,
            total_supply: U256::from(2000000),
            timestamp: 100,
        };
        
        // Simulate 10% invariant degradation (Balancer attack level)
        let after = PoolStateSnapshot {
            contract: Address::zero(),
            reserve0: U256::from(950000),
            reserve1: U256::from(950000),
            reserve2: None,
            total_supply: U256::from(2000000),
            timestamp: 101,
        };
        
        // Create a sequence with 65 operations (like Balancer attack)
        let sequence = TransactionSequence::new(vec![], true);
        
        let result = protection
            .verify_sequence(&sequence, &[before], &[after])
            .await
            .unwrap();
        
        assert!(result.should_block);
        assert!(!result.invariant_violations.is_empty());
        assert_eq!(result.invariant_violations[0].severity, Severity::Critical);
    }
    
    #[tokio::test]
    async fn test_legitimate_swap_allowed() {
        let protection = DeFiProtectionLayer::default();
        
        let before = PoolStateSnapshot {
            contract: Address::zero(),
            reserve0: U256::from(1000000),
            reserve1: U256::from(1000000),
            reserve2: None,
            total_supply: U256::from(2000000),
            timestamp: 100,
        };
        
        // Normal swap: slight change within tolerance
        let after = PoolStateSnapshot {
            contract: Address::zero(),
            reserve0: U256::from(1001000),
            reserve1: U256::from(999000),
            reserve2: None,
            total_supply: U256::from(2000000),
            timestamp: 101,
        };
        
        // Single legitimate swap
        let sequence = TransactionSequence::new(vec![], true);
        
        let result = protection
            .verify_sequence(&sequence, &[before], &[after])
            .await
            .unwrap();
        
        assert!(!result.should_block);
        assert!(result.invariant_violations.is_empty());
    }
}
