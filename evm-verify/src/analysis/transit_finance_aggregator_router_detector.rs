use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use ethers::types::U256;

/// Transit Finance Aggregator Router Detector
/// 
/// Detects vulnerabilities in DEX aggregator routers where routing logic
/// can be exploited through path manipulation or unchecked external calls.
/// 
/// **Attack Patterns**:
/// 1. Malicious routing path with manipulated intermediate swaps
/// 2. Unchecked external calls to untrusted DEX contracts
/// 3. Slippage bypass through custom router implementations
/// 4. Front-running of aggregated multi-hop trades
/// 
/// **Detection Strategy**:
/// - Identifies unchecked DEX router calls
/// - Detects missing path validation
/// - Flags inadequate slippage protection in aggregation
/// - Checks for whitelist of approved routers
pub struct TransitFinanceAggregatorRouterDetector {
    bytecode: Vec<u8>,
}

impl TransitFinanceAggregatorRouterDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityWarning> {
        let mut warnings = Vec::new();

        if self.has_unchecked_router_call() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::UncheckedExternalCall,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "Unchecked call to external DEX router - Transit Finance vulnerability".to_string(),
                operations: Vec::new(),
                remediation: "Implement whitelist for approved DEX routers and validate all calls".to_string(),
            });
        }

        if self.has_unvalidated_swap_path() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Swap path not validated, allows malicious intermediate tokens".to_string(),
                operations: Vec::new(),
                remediation: "Validate all tokens in swap path against approved list".to_string(),
            });
        }

        if self.has_aggregation_slippage_bypass() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Aggregated swap lacks proper slippage protection".to_string(),
                operations: Vec::new(),
                remediation: "Add comprehensive slippage checks for aggregated swaps".to_string(),
            });
        }

        warnings
    }

    fn has_unchecked_router_call(&self) -> bool {
        // Pattern: CALL to variable address without whitelist check
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0xf1 { // CALL
                let window = &self.bytecode[i.saturating_sub(15)..i+5.min(self.bytecode.len())];
                
                // Check if target address is dynamic (from calldata or storage)
                let has_dynamic_target = window.iter().any(|&op| {
                    op == 0x35 || op == 0x54 // CALLDATALOAD or SLOAD
                });
                
                // Check for whitelist validation
                let has_whitelist = window.windows(4).any(|w| {
                    w[0] == 0x54 && // SLOAD (whitelist)
                    w[1] == 0x15 && // ISZERO
                    w[2] == 0x15 && // ISZERO (double negative = must be whitelisted)
                    w[3] == 0x57    // JUMPI
                });
                
                // Check for return value check
                let has_return_check = window.iter().skip(i).any(|&op| {
                    op == 0x15 || op == 0xfd // ISZERO or REVERT
                });
                
                if has_dynamic_target && !has_whitelist && !has_return_check {
                    return true;
                }
            }
        }
        false
    }

    fn has_unvalidated_swap_path(&self) -> bool {
        // Pattern: multi-hop swap without path validation
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Look for array/path processing
            if self.bytecode[i] == 0x35 { // CALLDATALOAD (path data)
                let window = &self.bytecode[i..i+30.min(self.bytecode.len())];
                
                // Check for loop over path (multi-hop)
                let has_loop = window.iter().any(|&op| {
                    op == 0x57 // JUMPI (loop)
                });
                
                // Check for token validation in path
                let has_token_check = window.windows(3).any(|w| {
                    w[0] == 0x54 && // SLOAD (token whitelist)
                    w[1] == 0x15 && // ISZERO
                    w[2] == 0x57    // JUMPI (reject if not whitelisted)
                });
                
                // Check for swap execution
                let has_swap = window.iter().any(|&op| {
                    op == 0xf1 // CALL
                });
                
                if has_loop && has_swap && !has_token_check {
                    return true;
                }
            }
        }
        false
    }

    fn has_aggregation_slippage_bypass(&self) -> bool {
        // Pattern: multiple swaps without cumulative slippage check
        let mut swap_count = 0;
        let mut has_slippage_check = false;
        
        for i in 0..self.bytecode.len().saturating_sub(15) {
            if self.bytecode[i] == 0xf1 { // CALL (swap)
                swap_count += 1;
            }
            
            // Check for slippage validation (amountOut >= minAmountOut)
            if self.bytecode[i] == 0x11 || self.bytecode[i] == 0x10 { // GT or LT
                let window = &self.bytecode[i..i+5.min(self.bytecode.len())];
                if window.contains(&0xfd) { // REVERT on slippage
                    has_slippage_check = true;
                }
            }
        }
        
        // Multiple swaps without proper slippage validation
        swap_count >= 2 && !has_slippage_check
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transit_aggregator_router() {
        let vulnerable_bytecode = vec![
            0x35, // CALLDATALOAD (router address)
            0xf1, // CALL (no whitelist check!)
            0x35, // CALLDATALOAD (path)
            0x57, // JUMPI (multi-hop)
            0xf1, // CALL (swap, no token validation)
        ];

        let detector = TransitFinanceAggregatorRouterDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        assert!(!warnings.is_empty());
    }
}
