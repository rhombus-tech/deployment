use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use ethereum_types::{Address, U256};
use std::collections::HashMap;

/// DeFi protocol invariant checker - neutral, math-based verification
pub struct DeFiInvariantChecker {
    /// Cache of detected invariant types per contract
    invariant_cache: HashMap<Address, InvariantType>,
}

/// Types of mathematical invariants used by DeFi protocols
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvariantType {
    /// Constant product: k = x * y (Uniswap V2, etc.)
    ConstantProduct,
    /// Stable swap: D invariant (Curve, Balancer stable pools)
    StableSwap,
    /// Weighted product: Balancer weighted pools
    WeightedProduct,
    /// Concentrated liquidity: Uniswap V3
    ConcentratedLiquidity,
    /// Unknown invariant type
    Unknown,
}

/// Result of invariant verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantCheckResult {
    pub is_valid: bool,
    pub invariant_type: InvariantType,
    pub value_before: f64,
    pub value_after: f64,
    pub change_percent: f64,
    pub severity: SecuritySeverity,
    pub description: String,
}

/// Pool state snapshot for verification
#[derive(Debug, Clone)]
pub struct PoolState {
    pub reserve0: U256,
    pub reserve1: U256,
    pub reserve2: Option<U256>, // For multi-asset pools
    pub total_supply: U256,
    pub amplification_parameter: Option<u32>,
    pub fee_percent: f64,
}

impl DeFiInvariantChecker {
    pub fn new() -> Self {
        Self {
            invariant_cache: HashMap::new(),
        }
    }
    
    /// Main entry point: verify invariant holds across state transition
    pub fn verify_invariant(
        &mut self,
        contract: Address,
        state_before: &PoolState,
        state_after: &PoolState,
        operation_count: usize,
    ) -> Result<InvariantCheckResult> {
        // Detect or retrieve cached invariant type
        let invariant_type = self.detect_invariant_type(contract)?;
        
        // Verify based on type
        match invariant_type {
            InvariantType::ConstantProduct => {
                self.verify_constant_product(state_before, state_after)
            },
            InvariantType::StableSwap => {
                self.verify_stable_swap(state_before, state_after, operation_count)
            },
            InvariantType::WeightedProduct => {
                self.verify_weighted_product(state_before, state_after)
            },
            InvariantType::ConcentratedLiquidity => {
                self.verify_concentrated_liquidity(state_before, state_after)
            },
            InvariantType::Unknown => {
                // Can't verify unknown protocols, but don't block
                Ok(InvariantCheckResult {
                    is_valid: true,
                    invariant_type: InvariantType::Unknown,
                    value_before: 0.0,
                    value_after: 0.0,
                    change_percent: 0.0,
                    severity: SecuritySeverity::Info,
                    description: "Unknown protocol type - cannot verify invariant".to_string(),
                })
            },
        }
    }
    
    /// Detect invariant type from contract bytecode/behavior
    fn detect_invariant_type(&mut self, contract: Address) -> Result<InvariantType> {
        // Check cache first
        if let Some(&cached_type) = self.invariant_cache.get(&contract) {
            return Ok(cached_type);
        }
        
        // Would detect from bytecode patterns in production
        // For now, return Unknown and let it pass
        let detected_type = InvariantType::Unknown;
        
        self.invariant_cache.insert(contract, detected_type);
        Ok(detected_type)
    }
    
    /// Verify constant product invariant (k = x * y)
    fn verify_constant_product(
        &self,
        before: &PoolState,
        after: &PoolState,
    ) -> Result<InvariantCheckResult> {
        // Calculate k before and after
        let k_before = self.safe_mul(before.reserve0, before.reserve1)?;
        let k_after = self.safe_mul(after.reserve0, after.reserve1)?;
        
        // Convert to f64 for percentage calculation
        let k_before_f64 = self.u256_to_f64(k_before);
        let k_after_f64 = self.u256_to_f64(k_after);
        
        // Calculate change
        let change = if k_before_f64 > 0.0 {
            (k_after_f64 - k_before_f64) / k_before_f64
        } else {
            0.0
        };
        
        // Constant product should only increase (due to fees) or stay same
        // Never decrease more than rounding error (0.01%)
        let is_valid = change >= -0.0001;
        
        let severity = if !is_valid {
            if change < -0.01 { // >1% decrease
                SecuritySeverity::Critical
            } else if change < -0.001 { // >0.1% decrease  
                SecuritySeverity::High
            } else {
                SecuritySeverity::Medium
            }
        } else {
            SecuritySeverity::Info
        };
        
        Ok(InvariantCheckResult {
            is_valid,
            invariant_type: InvariantType::ConstantProduct,
            value_before: k_before_f64,
            value_after: k_after_f64,
            change_percent: change * 100.0,
            severity,
            description: if !is_valid {
                format!("Constant product invariant decreased by {:.4}% (should only increase or stay constant)", change.abs() * 100.0)
            } else {
                "Constant product invariant maintained".to_string()
            },
        })
    }
    
    /// Verify stable swap invariant (D)
    fn verify_stable_swap(
        &self,
        before: &PoolState,
        after: &PoolState,
        operation_count: usize,
    ) -> Result<InvariantCheckResult> {
        // Calculate D invariant before and after
        let d_before = self.calculate_stable_invariant_d(before)?;
        let d_after = self.calculate_stable_invariant_d(after)?;
        
        // Calculate change percentage
        let change = if d_before > 0.0 {
            (d_after - d_before) / d_before
        } else {
            0.0
        };
        
        // For stable pools, invariant should stay very stable
        // Allow 0.01% per operation as maximum (generous tolerance)
        let max_allowed_change = 0.0001 * (operation_count as f64);
        
        let is_valid = change.abs() <= max_allowed_change;
        
        // Severity based on how far outside bounds
        let severity = if !is_valid {
            let excess_factor = change.abs() / max_allowed_change;
            if excess_factor > 100.0 { // >100x tolerance = Balancer attack level
                SecuritySeverity::Critical
            } else if excess_factor > 10.0 {
                SecuritySeverity::High
            } else if excess_factor > 3.0 {
                SecuritySeverity::Medium
            } else {
                SecuritySeverity::Low
            }
        } else {
            SecuritySeverity::Info
        };
        
        Ok(InvariantCheckResult {
            is_valid,
            invariant_type: InvariantType::StableSwap,
            value_before: d_before,
            value_after: d_after,
            change_percent: change * 100.0,
            severity,
            description: if !is_valid {
                format!(
                    "Stable swap invariant changed by {:.4}%, exceeds {:.4}% tolerance for {} operations (possible precision attack)",
                    change.abs() * 100.0,
                    max_allowed_change * 100.0,
                    operation_count
                )
            } else {
                "Stable swap invariant maintained within tolerance".to_string()
            },
        })
    }
    
    /// Calculate stable swap D invariant (simplified Curve/Balancer formula)
    fn calculate_stable_invariant_d(&self, state: &PoolState) -> Result<f64> {
        // Simplified calculation - production would use full StableSwap formula
        let x = self.u256_to_f64(state.reserve0);
        let y = self.u256_to_f64(state.reserve1);
        
        // Get amplification parameter (default 100 if not specified)
        let a = state.amplification_parameter.unwrap_or(100) as f64;
        
        // Simplified D calculation
        // Real formula: An^n * sum(x_i) + D = An^n*D + D^(n+1)/(n^n * prod(x_i))
        // This is simplified for demonstration
        let sum = x + y;
        let product = x * y;
        
        if product <= 0.0 {
            return Ok(sum);
        }
        
        // Approximate D
        let d = sum * (1.0 + a / 10000.0);
        
        Ok(d)
    }
    
    /// Verify weighted product invariant (Balancer weighted pools)
    fn verify_weighted_product(
        &self,
        before: &PoolState,
        after: &PoolState,
    ) -> Result<InvariantCheckResult> {
        // Weighted product: k = x^w1 * y^w2
        // Simplified check - production would use actual weights
        
        let x_before = self.u256_to_f64(before.reserve0);
        let y_before = self.u256_to_f64(before.reserve1);
        let x_after = self.u256_to_f64(after.reserve0);
        let y_after = self.u256_to_f64(after.reserve1);
        
        // Assume equal weights (0.5, 0.5) for simplification
        let k_before = (x_before * y_before).sqrt();
        let k_after = (x_after * y_after).sqrt();
        
        let change = if k_before > 0.0 {
            (k_after - k_before) / k_before
        } else {
            0.0
        };
        
        // Similar to constant product, should only increase or stay same
        let is_valid = change >= -0.0001;
        
        let severity = if !is_valid {
            if change < -0.01 {
                SecuritySeverity::Critical
            } else if change < -0.001 {
                SecuritySeverity::High
            } else {
                SecuritySeverity::Medium
            }
        } else {
            SecuritySeverity::Info
        };
        
        Ok(InvariantCheckResult {
            is_valid,
            invariant_type: InvariantType::WeightedProduct,
            value_before: k_before,
            value_after: k_after,
            change_percent: change * 100.0,
            severity,
            description: if !is_valid {
                format!("Weighted product invariant decreased by {:.4}%", change.abs() * 100.0)
            } else {
                "Weighted product invariant maintained".to_string()
            },
        })
    }
    
    /// Verify concentrated liquidity invariant (Uniswap V3)
    fn verify_concentrated_liquidity(
        &self,
        before: &PoolState,
        after: &PoolState,
    ) -> Result<InvariantCheckResult> {
        // Simplified check for concentrated liquidity
        // Real implementation would verify sqrt price and liquidity
        
        let x_before = self.u256_to_f64(before.reserve0);
        let y_before = self.u256_to_f64(before.reserve1);
        let x_after = self.u256_to_f64(after.reserve0);
        let y_after = self.u256_to_f64(after.reserve1);
        
        // Virtual reserves (simplified)
        let l_before = (x_before * y_before).sqrt();
        let l_after = (x_after * y_after).sqrt();
        
        let change = if l_before > 0.0 {
            (l_after - l_before) / l_before
        } else {
            0.0
        };
        
        // Liquidity should only increase (fees) or stay same
        let is_valid = change >= -0.0001;
        
        Ok(InvariantCheckResult {
            is_valid,
            invariant_type: InvariantType::ConcentratedLiquidity,
            value_before: l_before,
            value_after: l_after,
            change_percent: change * 100.0,
            severity: if !is_valid { SecuritySeverity::High } else { SecuritySeverity::Info },
            description: if !is_valid {
                format!("Concentrated liquidity invariant decreased by {:.4}%", change.abs() * 100.0)
            } else {
                "Concentrated liquidity invariant maintained".to_string()
            },
        })
    }
    
    // Helper methods
    
    fn safe_mul(&self, a: U256, b: U256) -> Result<U256> {
        a.checked_mul(b)
            .ok_or_else(|| anyhow!("Multiplication overflow"))
    }
    
    fn u256_to_f64(&self, value: U256) -> f64 {
        // Convert U256 to f64 (loses precision for very large numbers, but adequate for ratios)
        let mut result = 0.0;
        let mut multiplier = 1.0;
        
        for i in 0..4 { // Use first 4 u64 words
            if let Some(word) = value.0.get(i) {
                result += (*word as f64) * multiplier;
                multiplier *= (u64::MAX as f64);
            }
        }
        
        result
    }
}

impl Default for DeFiInvariantChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_constant_product_valid() {
        let checker = DeFiInvariantChecker::new();
        
        let before = PoolState {
            reserve0: U256::from(1000000),
            reserve1: U256::from(1000000),
            reserve2: None,
            total_supply: U256::from(1000000),
            amplification_parameter: None,
            fee_percent: 0.3,
        };
        
        let after = PoolState {
            reserve0: U256::from(1001000), // Slightly increased (fees)
            reserve1: U256::from(999000),
            reserve2: None,
            total_supply: U256::from(1000000),
            amplification_parameter: None,
            fee_percent: 0.3,
        };
        
        let result = checker.verify_constant_product(&before, &after).unwrap();
        assert!(result.is_valid);
    }
    
    #[test]
    fn test_constant_product_attack() {
        let checker = DeFiInvariantChecker::new();
        
        let before = PoolState {
            reserve0: U256::from(1000000),
            reserve1: U256::from(1000000),
            reserve2: None,
            total_supply: U256::from(1000000),
            amplification_parameter: None,
            fee_percent: 0.3,
        };
        
        let after = PoolState {
            reserve0: U256::from(1100000),
            reserve1: U256::from(800000), // k decreased significantly
            reserve2: None,
            total_supply: U256::from(1000000),
            amplification_parameter: None,
            fee_percent: 0.3,
        };
        
        let result = checker.verify_constant_product(&before, &after).unwrap();
        assert!(!result.is_valid);
        assert_eq!(result.severity, SecuritySeverity::Critical);
    }
    
    #[test]
    fn test_stable_swap_within_tolerance() {
        let checker = DeFiInvariantChecker::new();
        
        let before = PoolState {
            reserve0: U256::from(1000000),
            reserve1: U256::from(1000000),
            reserve2: None,
            total_supply: U256::from(2000000),
            amplification_parameter: Some(100),
            fee_percent: 0.04,
        };
        
        let after = PoolState {
            reserve0: U256::from(1000100),
            reserve1: U256::from(999900),
            reserve2: None,
            total_supply: U256::from(2000000),
            amplification_parameter: Some(100),
            fee_percent: 0.04,
        };
        
        let result = checker.verify_stable_swap(&before, &after, 1).unwrap();
        assert!(result.is_valid);
    }
    
    #[test]
    fn test_stable_swap_balancer_attack_pattern() {
        let checker = DeFiInvariantChecker::new();
        
        let before = PoolState {
            reserve0: U256::from(1000000),
            reserve1: U256::from(1000000),
            reserve2: None,
            total_supply: U256::from(2000000),
            amplification_parameter: Some(100),
            fee_percent: 0.04,
        };
        
        // Simulate 10% invariant degradation like Balancer attack
        let after = PoolState {
            reserve0: U256::from(950000),
            reserve1: U256::from(950000),
            reserve2: None,
            total_supply: U256::from(2000000),
            amplification_parameter: Some(100),
            fee_percent: 0.04,
        };
        
        let result = checker.verify_stable_swap(&before, &after, 65).unwrap();
        assert!(!result.is_valid);
        assert_eq!(result.severity, SecuritySeverity::Critical);
        assert!(result.description.contains("precision attack"));
    }
}
