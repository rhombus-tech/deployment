use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use ethers::types::U256;

/// Swap Route Path Dependency & Optimization Gaming Detector
/// 
/// Detects vulnerabilities in DEX aggregators and routers where route path selection
/// can be gamed to manipulate liquidity, extract value, or cause unfavorable execution.
/// 
/// **Attack Patterns**:
/// 1. **Route Optimization Gaming**: Force router to select suboptimal path benefiting attacker
/// 2. **Path Dependency MEV**: Front-run to manipulate which route gets selected
/// 3. **Circular Route Exploitation**: Create routes that loop through attacker's contracts
/// 4. **Hop Limit Bypass**: Exceed hop limits to drain gas or create complex attack chains
/// 5. **Sandwich via Route Manipulation**: Force victim through specific pools for sandwich
/// 
/// **Detection Strategy**:
/// - Identifies unconstrained route path selection
/// - Detects missing hop count limits
/// - Flags routes without intermediate pool validation
/// - Checks for circular path detection
/// - Validates route selection criteria against manipulation
pub struct SwapRoutePathDependencyDetector {
    bytecode: Vec<u8>,
}

impl SwapRoutePathDependencyDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityWarning> {
        let mut warnings = Vec::new();

        if self.has_unconstrained_route_selection() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "Route path selection unconstrained - can be gamed for MEV extraction".to_string(),
                operations: Vec::new(),
                remediation: "Add constraints on route selection including hop limits and pool whitelisting".to_string(),
            });
        }

        if self.has_missing_hop_limit() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "No maximum hop limit on routing paths - enables complex attack chains".to_string(),
                operations: Vec::new(),
                remediation: "Implement strict maximum hop count (e.g., 3-5 hops) for swap routes".to_string(),
            });
        }

        if self.has_unvalidated_intermediate_pools() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::UncheckedExternalCall,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Intermediate pools in route not validated - can route through malicious contracts".to_string(),
                operations: Vec::new(),
                remediation: "Validate all intermediate pools against whitelist or factory verification".to_string(),
            });
        }

        if self.has_circular_route_risk() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "No circular path detection - route can loop through same pools".to_string(),
                operations: Vec::new(),
                remediation: "Add circular path detection to prevent routes visiting same pool twice".to_string(),
            });
        }

        if self.has_manipulable_route_optimization() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::Medium,
                pc: 0,
                description: "Route optimization criteria can be manipulated to force suboptimal paths".to_string(),
                operations: Vec::new(),
                remediation: "Use robust route selection with slippage protection and price impact limits".to_string(),
            });
        }

        warnings
    }

    fn has_unconstrained_route_selection(&self) -> bool {
        // Pattern: swap() with route array from calldata without validation
        let swap_selector = [0x12, 0x8a, 0xcb, 0x08]; // swap() or swapExactTokensForTokens
        
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == swap_selector {
                    let window = &self.bytecode[i..i+60.min(self.bytecode.len())];
                    
                    // Check for calldata route loading
                    let has_route_from_calldata = window.iter().any(|&op| {
                        op == 0x36 // CALLDATACOPY (load route array)
                    });
                    
                    // Check for hop count validation
                    let has_hop_limit = window.windows(6).any(|w| {
                        // Pattern: route.length -> PUSH(maxHops) -> GT -> REVERT
                        w.iter().any(|&op| op >= 0x60 && op <= 0x7f) && // PUSH max hops
                        w.iter().any(|&op| op == 0x11) && // GT
                        w.iter().any(|&op| op == 0xfd) // REVERT if exceeded
                    });
                    
                    // Check for pool validation loop
                    let has_pool_validation = window.windows(10).any(|w| {
                        // Pattern: loop through route -> validate each pool
                        w.iter().any(|&op| op == 0x56) && // JUMP (loop)
                        w.iter().any(|&op| op == 0x54) && // SLOAD (whitelist check)
                        w.iter().any(|&op| op == 0x3b) // EXTCODESIZE (verify pool exists)
                    });
                    
                    // Check for route constraints
                    let has_constraints = window.windows(8).any(|w| {
                        // Pattern: minOutput check or slippage protection
                        w.iter().any(|&op| op == 0x10 || op == 0x11) && // LT/GT
                        w.iter().any(|&op| op == 0xfd) // REVERT if constraint violated
                    });
                    
                    if has_route_from_calldata && !has_hop_limit && !has_pool_validation && !has_constraints {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_missing_hop_limit(&self) -> bool {
        // Pattern: route iteration without max hop check
        for i in 0..self.bytecode.len().saturating_sub(40) {
            // Look for loop pattern (route iteration)
            if self.bytecode[i] == 0x56 { // JUMP (start of loop)
                let window = &self.bytecode[i.saturating_sub(30)..i+10.min(self.bytecode.len())];
                
                // Check if this is a route iteration loop
                let has_array_access = window.iter().any(|&op| {
                    op == 0x35 // CALLDATALOAD (access route element)
                });
                
                // Check for swap calls in loop
                let has_swap_logic = window.iter().any(|&op| {
                    op == 0xf1 || op == 0xfa // CALL or STATICCALL (to pools)
                });
                
                // Check for iteration counter limit
                let has_max_iterations = window.windows(5).any(|w: &[u8]| {
                    // Pattern: counter > maxHops -> exit
                    w.iter().any(|&op| op >= 0x60 && op <= 0x7f) && // PUSH limit
                    w.iter().any(|&op| op == 0x11) // GT (compare)
                });
                
                if has_array_access && has_swap_logic && !has_max_iterations {
                    return true;
                }
            }
        }
        false
    }

    fn has_unvalidated_intermediate_pools(&self) -> bool {
        // Pattern: swap call to pool address without validation
        for i in 0..self.bytecode.len().saturating_sub(35) {
            if self.bytecode[i] == 0xf1 || self.bytecode[i] == 0xfa { // CALL or STATICCALL
                let window = &self.bytecode[i.saturating_sub(25)..i];
                
                // Check if target comes from route array
                let has_route_address = window.iter().any(|&op| {
                    op == 0x35 || op == 0x36 // CALLDATALOAD or CALLDATACOPY
                });
                
                // Check for pool validation
                let has_factory_check = window.windows(8).any(|w| {
                    // Pattern: call factory.getPair(tokenA, tokenB) -> compare with pool address
                    w.iter().any(|&op| op == 0xfa) && // STATICCALL
                    w.iter().any(|&op| op == 0x14) && // EQ (verify address)
                    w.iter().any(|&op| op == 0xfd) // REVERT if mismatch
                });
                
                // Check for whitelist validation
                let has_whitelist = window.windows(6).any(|w| {
                    w.iter().any(|&op| op == 0x20) && // KECCAK256 (pool address hash)
                    w.iter().any(|&op| op == 0x54) && // SLOAD (whitelist)
                    w.iter().any(|&op| op == 0x15) // ISZERO (check if whitelisted)
                });
                
                // Check for code existence
                let has_existence_check = window.iter().any(|&op| {
                    op == 0x3b // EXTCODESIZE
                });
                
                if has_route_address && !has_factory_check && !has_whitelist && !has_existence_check {
                    return true;
                }
            }
        }
        false
    }

    fn has_circular_route_risk(&self) -> bool {
        // Pattern: route processing without duplicate detection
        for i in 0..self.bytecode.len().saturating_sub(50) {
            // Look for route iteration with pool calls
            if self.bytecode[i] == 0x56 { // JUMP (loop)
                let window = &self.bytecode[i.saturating_sub(40)..i+10.min(self.bytecode.len())];
                
                // Check for route element loading
                let has_route_loading = window.iter().any(|&op| {
                    op == 0x35 // CALLDATALOAD (get pool address from route)
                });
                
                // Check for pool interaction
                let has_pool_call = window.iter().any(|&op| {
                    op == 0xf1 // CALL (swap)
                });
                
                // Check for visited pools tracking
                let has_duplicate_check = window.windows(10).any(|w| {
                    // Pattern: store visited pools and check before calling
                    w.iter().any(|&op| op == 0x55) && // SSTORE (mark as visited)
                    w.iter().any(|&op| op == 0x54) && // SLOAD (check if visited)
                    w.iter().any(|&op| op == 0x15) // ISZERO (require not visited)
                });
                
                // Check for token pair tracking (alternative circular detection)
                let has_pair_tracking = window.windows(8).any(|w| {
                    // Track token A -> token B conversions
                    w.iter().filter(|&&op| op == 0x20).count() >= 2 // Multiple KECCAK256 (track pairs)
                });
                
                if has_route_loading && has_pool_call && !has_duplicate_check && !has_pair_tracking {
                    return true;
                }
            }
        }
        false
    }

    fn has_manipulable_route_optimization(&self) -> bool {
        // Pattern: route selection based on price without bounds
        for i in 0..self.bytecode.len().saturating_sub(45) {
            // Look for comparison in route selection
            if self.bytecode[i] == 0x10 || self.bytecode[i] == 0x11 { // LT or GT
                let window = &self.bytecode[i.saturating_sub(35)..i+10.min(self.bytecode.len())];
                
                // Check for price/output comparison
                let has_output_comparison = window.windows(10).any(|w| {
                    w.iter().any(|&op| op == 0xfa) && // STATICCALL (getAmountOut)
                    w.iter().any(|&op| op == 0x10 || op == 0x11) // Compare outputs
                });
                
                // Check for slippage protection
                let has_slippage_check = window.windows(6).any(|w| {
                    // Pattern: amountOut * (100 - slippage) / 100 > minAmount
                    w.iter().any(|&op| op == 0x02) && // MUL
                    w.iter().any(|&op| op == 0x04) && // DIV
                    w.iter().any(|&op| op == 0x11) // GT
                });
                
                // Check for price impact limits
                let has_impact_limit = window.windows(8).any(|w| {
                    // Pattern: (spotPrice - executionPrice) / spotPrice < maxImpact
                    w.iter().any(|&op| op == 0x03) && // SUB
                    w.iter().any(|&op| op == 0x04) && // DIV
                    w.iter().any(|&op| op == 0x10) // LT (check impact)
                });
                
                if has_output_comparison && !has_slippage_check && !has_impact_limit {
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
    fn test_unconstrained_route() {
        let vulnerable_bytecode = vec![
            0x63, 0x12, 0x8a, 0xcb, 0x08, // swap()
            0x36, // CALLDATACOPY (load route without validation)
            0x56, // JUMP (loop through route)
            0xf1, // CALL (swap on each hop - no limits!)
        ];

        let detector = SwapRoutePathDependencyDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        
        assert!(!warnings.is_empty());
        assert!(warnings.iter().any(|w| w.description.contains("route")));
    }

    #[test]
    fn test_circular_path_vulnerability() {
        let vulnerable_bytecode = vec![
            0x35, // CALLDATALOAD (pool from route)
            0xf1, // CALL (swap - no circular detection)
            0x56, // JUMP (loop back for next hop)
        ];

        let detector = SwapRoutePathDependencyDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        
        assert!(warnings.iter().any(|w| 
            w.description.contains("circular") || 
            w.description.contains("loop")
        ));
    }
}
