use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use ethers::types::U256;

/// Socket Multi-Chain Router Exploits Detector
/// 
/// Detects vulnerabilities specific to Socket's multi-chain routing infrastructure
/// where cross-chain message manipulation or routing logic can be exploited.
/// 
/// **Socket Gateway Context**:
/// Socket is a cross-chain interoperability protocol that routes messages and tokens
/// across multiple blockchains. The routing logic determines paths and validates
/// cross-chain operations.
/// 
/// **Attack Patterns**:
/// 1. **Route Manipulation**: Attacker manipulates routing paths to bypass security checks
/// 2. **Destination Chain Spoofing**: Fake destination to redirect funds
/// 3. **Bridge Selector Manipulation**: Choose vulnerable bridge for cross-chain transfer
/// 4. **Route Optimization Gaming**: Exploit route selection to drain liquidity
/// 5. **Cross-Chain Reentrancy**: Reenter via different chain during routing
/// 
/// **Detection Strategy**:
/// - Identifies unvalidated routing path parameters
/// - Detects missing destination chain verification
/// - Flags unchecked bridge/connector selection
/// - Checks for route optimization manipulation vectors
/// - Validates cross-chain message authentication
pub struct SocketMultichainRouterDetector {
    bytecode: Vec<u8>,
}

impl SocketMultichainRouterDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityWarning> {
        let mut warnings = Vec::new();

        if self.has_unvalidated_routing_path() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::UncheckedExternalCall,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "Cross-chain routing path not validated - Socket vulnerability".to_string(),
                operations: Vec::new(),
                remediation: "Validate all routing paths against whitelist and check intermediate hops".to_string(),
            });
        }

        if self.has_destination_chain_spoofing_risk() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "Destination chain ID can be manipulated to redirect funds".to_string(),
                operations: Vec::new(),
                remediation: "Validate destination chain against supported chains and verify bridge compatibility".to_string(),
            });
        }

        if self.has_bridge_selector_manipulation() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::AccessControl,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Bridge/connector selection not restricted - can route through vulnerable bridges".to_string(),
                operations: Vec::new(),
                remediation: "Implement bridge whitelist and validate security properties of selected bridges".to_string(),
            });
        }

        if self.has_route_optimization_gaming() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Route optimization can be gamed to manipulate liquidity or fees".to_string(),
                operations: Vec::new(),
                remediation: "Add bounds checking on route optimization and prevent extreme paths".to_string(),
            });
        }

        if self.has_cross_chain_reentrancy_risk() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::Reentrancy,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Cross-chain routing vulnerable to reentrancy via different chains".to_string(),
                operations: Vec::new(),
                remediation: "Implement cross-chain reentrancy guards and message nonce tracking".to_string(),
            });
        }

        warnings
    }

    fn has_unvalidated_routing_path(&self) -> bool {
        // Pattern: route() or bridge() function with calldata-driven path
        let route_selector = [0x8d, 0x8f, 0x69, 0x26]; // route()
        let bridge_selector = [0x38, 0x09, 0x5c, 0xd6]; // bridge()
        
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == route_selector || selector == bridge_selector {
                    let window = &self.bytecode[i..i+50.min(self.bytecode.len())];
                    
                    // Check if path comes from calldata
                    let has_calldata_path = window.iter().any(|&op| {
                        op == 0x35 || op == 0x36 // CALLDATALOAD or CALLDATACOPY
                    });
                    
                    // Check for path validation (whitelist check)
                    let has_path_validation = window.windows(6).any(|w| {
                        // Pattern: KECCAK256(path) -> SLOAD(whitelist) -> check
                        w[0] == 0x20 && // KECCAK256
                        w.iter().any(|&op| op == 0x54) && // SLOAD
                        w.iter().any(|&op| op == 0x15) && // ISZERO
                        w.iter().any(|&op| op == 0x57) // JUMPI
                    });
                    
                    // Check for hop count validation
                    let has_hop_limit = window.windows(4).any(|w| {
                        w[0] == 0x60 && // PUSH (max hops)
                        (w[1] == 0x10 || w[1] == 0x11) // LT or GT
                    });
                    
                    if has_calldata_path && !has_path_validation && !has_hop_limit {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_destination_chain_spoofing_risk(&self) -> bool {
        // Pattern: destinationChainId from calldata without validation
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x35 { // CALLDATALOAD (chain ID)
                let window = &self.bytecode[i..i+30.min(self.bytecode.len())];
                
                // Check if used in bridge call
                let has_bridge_call = window.iter().any(|&op| {
                    op == 0xf1 || op == 0xf4 // CALL or DELEGATECALL
                });
                
                // Check for chain ID validation
                let has_chain_validation = window.windows(5).any(|w| {
                    // Pattern: chainId -> SLOAD(supported chains) -> EQ check
                    w.iter().any(|&op| op == 0x54) && // SLOAD
                    w.iter().any(|&op| op == 0x14) && // EQ
                    w.iter().any(|&op| op == 0x57) // JUMPI
                });
                
                // Check for bridge compatibility validation
                let has_bridge_check = window.windows(4).any(|w| {
                    w[0] == 0x20 && // KECCAK256 (chain + bridge mapping)
                    w.iter().any(|&op| op == 0x54) // SLOAD
                });
                
                if has_bridge_call && !has_chain_validation && !has_bridge_check {
                    return true;
                }
            }
        }
        false
    }

    fn has_bridge_selector_manipulation(&self) -> bool {
        // Pattern: bridge selector from user input without whitelist
        for i in 0..self.bytecode.len().saturating_sub(40) {
            // Look for CALLDATALOAD of bridge address/ID
            if self.bytecode[i] == 0x35 {
                let window = &self.bytecode[i..i+40.min(self.bytecode.len())];
                
                // Check if used as call target
                let has_dynamic_call = window.windows(3).any(|w| {
                    w[0] == 0xf1 || w[0] == 0xf4 || w[0] == 0xfa // CALL/DELEGATECALL/STATICCALL
                });
                
                // Check for bridge whitelist validation
                let has_whitelist_check = window.windows(7).any(|w| {
                    // Pattern: bridge address -> mapping(address => bool) -> require(isWhitelisted)
                    w.iter().any(|&op| op == 0x20) && // KECCAK256
                    w.iter().any(|&op| op == 0x54) && // SLOAD
                    w.iter().any(|&op| op == 0x15) && // ISZERO
                    w.iter().any(|&op| op == 0xfd) // REVERT if not whitelisted
                });
                
                if has_dynamic_call && !has_whitelist_check {
                    return true;
                }
            }
        }
        false
    }

    fn has_route_optimization_gaming(&self) -> bool {
        // Pattern: route selection based on fees/slippage without bounds
        for i in 0..self.bytecode.len().saturating_sub(35) {
            // Look for route comparison (fee or slippage)
            if self.bytecode[i] == 0x10 || self.bytecode[i] == 0x11 { // LT or GT
                let window = &self.bytecode[i.saturating_sub(20)..i+15.min(self.bytecode.len())];
                
                // Check for route selection loop
                let has_route_iteration = window.iter().any(|&op| {
                    op == 0x56 // JUMP (loop)
                });
                
                // Check for external call based on selection
                let has_route_execution = window.iter().any(|&op| {
                    op == 0xf1 // CALL
                });
                
                // Check for bounds on route parameters
                let has_bounds_check = window.windows(5).any(|w| {
                    // Pattern: PUSH(maxFee) -> GT/LT -> REVERT
                    w.iter().any(|&op| op >= 0x60 && op <= 0x7f) && // PUSH
                    w.iter().any(|&op| op == 0x10 || op == 0x11) && // GT/LT
                    w.iter().any(|&op| op == 0xfd) // REVERT
                });
                
                if has_route_iteration && has_route_execution && !has_bounds_check {
                    return true;
                }
            }
        }
        false
    }

    fn has_cross_chain_reentrancy_risk(&self) -> bool {
        // Pattern: cross-chain message receive without reentrancy guard
        let receive_message = [0x57, 0x2b, 0x6c, 0x16]; // receiveMessage() or similar
        
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == receive_message {
                    let window = &self.bytecode[i..i+40.min(self.bytecode.len())];
                    
                    // Check for state updates
                    let has_state_update = window.contains(&0x55); // SSTORE
                    
                    // Check for reentrancy guard
                    let has_reentrancy_guard = window.windows(5).any(|w| {
                        // Pattern: SLOAD(guard) -> ISZERO -> require -> SSTORE(lock)
                        w[0] == 0x54 && // SLOAD
                        w.iter().any(|&op| op == 0x15) && // ISZERO
                        w.iter().any(|&op| op == 0x55) // SSTORE (set lock)
                    });
                    
                    // Check for message nonce validation
                    let has_nonce_check = window.windows(6).any(|w| {
                        // Pattern: CALLDATALOAD(nonce) -> SLOAD(lastNonce) -> GT -> require
                        w.iter().any(|&op| op == 0x35) && // CALLDATALOAD
                        w.iter().any(|&op| op == 0x54) && // SLOAD
                        w.iter().any(|&op| op == 0x11) // GT
                    });
                    
                    if has_state_update && !has_reentrancy_guard && !has_nonce_check {
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
    fn test_socket_routing_manipulation() {
        let vulnerable_bytecode = vec![
            0x63, 0x8d, 0x8f, 0x69, 0x26, // route() selector
            0x35, // CALLDATALOAD (get routing path)
            0xf1, // CALL (execute route without validation)
            0x55, // SSTORE (update state)
        ];

        let detector = SocketMultichainRouterDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        
        assert!(!warnings.is_empty());
        assert!(warnings.iter().any(|w| w.description.contains("routing path")));
    }

    #[test]
    fn test_destination_chain_spoofing() {
        let vulnerable_bytecode = vec![
            0x35, // CALLDATALOAD (destination chain ID - unvalidated)
            0x60, 0x00, // PUSH0 (prepare for call)
            0xf1, // CALL (bridge to unvalidated chain)
        ];

        let detector = SocketMultichainRouterDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        
        assert!(warnings.iter().any(|w| 
            w.description.contains("Destination chain") || 
            w.description.contains("chain ID")
        ));
    }
}
