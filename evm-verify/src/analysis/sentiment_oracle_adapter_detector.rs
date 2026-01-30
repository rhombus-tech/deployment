use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use ethers::types::U256;

/// Sentiment XYZ Custom Oracle Adapter Bypass Detector
/// 
/// Detects vulnerabilities in custom oracle adapters where price feed
/// manipulation or adapter bypass can lead to incorrect asset valuations.
/// 
/// **Sentiment Protocol Context**:
/// Sentiment is a lending protocol that uses custom oracle adapters to price
/// various assets. Each adapter translates external price feeds into a format
/// the protocol can use. Vulnerabilities arise when adapters can be bypassed
/// or manipulated.
/// 
/// **Attack Patterns**:
/// 1. **Adapter Bypass**: Attacker provides custom adapter that reports fake prices
/// 2. **Price Feed Manipulation**: Exploit adapter's price aggregation logic
/// 3. **Staleness Bypass**: Use stale prices by bypassing freshness checks
/// 4. **Fallback Exploitation**: Trigger fallback mechanism to use manipulable source
/// 5. **Decimal Mismatch**: Exploit decimal conversion errors in adapter
/// 
/// **Detection Strategy**:
/// - Identifies custom oracle adapter registration without validation
/// - Detects missing price sanity checks in adapters
/// - Flags adapters without staleness validation
/// - Checks for decimal conversion vulnerabilities
/// - Validates adapter authorization and immutability
pub struct SentimentOracleAdapterDetector {
    bytecode: Vec<u8>,
}

impl SentimentOracleAdapterDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityWarning> {
        let mut warnings = Vec::new();

        if self.has_unvalidated_custom_adapter() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::OracleManipulation,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "Custom oracle adapter can be registered without validation - Sentiment vulnerability".to_string(),
                operations: Vec::new(),
                remediation: "Implement adapter whitelist and validate adapter implementation before registration".to_string(),
            });
        }

        if self.has_missing_price_sanity_checks() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::OracleManipulation,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "Oracle adapter lacks price sanity checks (bounds, deviation limits)".to_string(),
                operations: Vec::new(),
                remediation: "Add price range validation and maximum deviation checks in adapter".to_string(),
            });
        }

        if self.has_adapter_staleness_bypass() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::OracleManipulation,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Oracle adapter doesn't validate price freshness/staleness".to_string(),
                operations: Vec::new(),
                remediation: "Implement timestamp checks to reject stale prices from adapters".to_string(),
            });
        }

        if self.has_decimal_conversion_vulnerability() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Decimal conversion in oracle adapter vulnerable to precision loss or overflow".to_string(),
                operations: Vec::new(),
                remediation: "Use safe decimal conversion with proper scaling and overflow checks".to_string(),
            });
        }

        if self.has_mutable_adapter_configuration() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::AccessControl,
                severity: SecuritySeverity::Medium,
                pc: 0,
                description: "Oracle adapter configuration can be changed without timelock".to_string(),
                operations: Vec::new(),
                remediation: "Make critical adapter parameters immutable or require timelock for changes".to_string(),
            });
        }

        warnings
    }

    fn has_unvalidated_custom_adapter(&self) -> bool {
        // Pattern: setAdapter() or addAdapter() without implementation validation
        let set_adapter = [0x1b, 0x6b, 0xa5, 0xe0]; // setAdapter()
        let add_adapter = [0x7a, 0x9a, 0x72, 0xce]; // addAdapter()
        
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == set_adapter || selector == add_adapter {
                    let window = &self.bytecode[i..i+50.min(self.bytecode.len())];
                    
                    // Check for adapter storage
                    let has_adapter_storage = window.contains(&0x55); // SSTORE
                    
                    // Check for adapter validation (interface check)
                    let has_interface_check = window.windows(8).any(|w| {
                        // Pattern: STATICCALL to supportsInterface or similar
                        w.iter().any(|&op| op == 0xfa) && // STATICCALL
                        w.iter().any(|&op| op == 0x15) && // ISZERO
                        w.iter().any(|&op| op == 0xfd) // REVERT if invalid
                    });
                    
                    // Check for whitelist validation
                    let has_whitelist = window.windows(6).any(|w| {
                        w.iter().any(|&op| op == 0x54) && // SLOAD (whitelist)
                        w.iter().any(|&op| op == 0x14) && // EQ
                        w.iter().any(|&op| op == 0x57) // JUMPI
                    });
                    
                    if has_adapter_storage && !has_interface_check && !has_whitelist {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_missing_price_sanity_checks(&self) -> bool {
        // Pattern: getPrice() returns value without bounds checking
        let get_price = [0x41, 0x97, 0x6e, 0x09]; // getPrice()
        
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == get_price {
                    let window = &self.bytecode[i..i+40.min(self.bytecode.len())];
                    
                    // Check for external call to price source
                    let has_price_fetch = window.iter().any(|&op| {
                        op == 0xfa || op == 0xf1 // STATICCALL or CALL
                    });
                    
                    // Check for minimum price validation
                    let has_min_check = window.windows(5).any(|w| {
                        w.iter().any(|&op| op >= 0x60 && op <= 0x7f) && // PUSH (min price)
                        w.iter().any(|&op| op == 0x11) && // GT (price > min)
                        w.iter().any(|&op| op == 0x57) // JUMPI
                    });
                    
                    // Check for maximum price validation
                    let has_max_check = window.windows(5).any(|w| {
                        w.iter().any(|&op| op >= 0x60 && op <= 0x7f) && // PUSH (max price)
                        w.iter().any(|&op| op == 0x10) && // LT (price < max)
                        w.iter().any(|&op| op == 0x57) // JUMPI
                    });
                    
                    // Check for deviation validation
                    let has_deviation_check = window.windows(8).any(|w| {
                        w.iter().any(|&op| op == 0x54) && // SLOAD (last price)
                        w.iter().any(|&op| op == 0x03) && // SUB (difference)
                        w.iter().any(|&op| op == 0x10 || op == 0x11) // LT/GT (check deviation)
                    });
                    
                    if has_price_fetch && !has_min_check && !has_max_check && !has_deviation_check {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_adapter_staleness_bypass(&self) -> bool {
        // Pattern: price returned without timestamp validation
        for i in 0..self.bytecode.len().saturating_sub(35) {
            // Look for price fetch (STATICCALL to oracle)
            if self.bytecode[i] == 0xfa { // STATICCALL
                let window = &self.bytecode[i..i+35.min(self.bytecode.len())];
                
                // Check if return value is used as price
                let has_price_usage = window.iter().any(|&op| {
                    op == 0x02 || op == 0x04 // MUL or DIV (price calculation)
                });
                
                // Check for timestamp validation
                let has_timestamp_check = window.windows(8).any(|w| {
                    // Pattern: TIMESTAMP - updatedAt < maxStaleness
                    w.iter().any(|&op| op == 0x42) && // TIMESTAMP
                    w.iter().any(|&op| op == 0x03) && // SUB
                    w.iter().any(|&op| op == 0x10) && // LT
                    w.iter().any(|&op| op == 0xfd) // REVERT if stale
                });
                
                // Check for updatedAt field usage
                let has_updated_at = window.windows(4).any(|w| {
                    // Look for tuple element access (updatedAt from latestRoundData)
                    w.iter().any(|&op| op == 0x60) && // PUSH offset
                    w.iter().any(|&op| op == 0x35) // CALLDATALOAD
                });
                
                if has_price_usage && !has_timestamp_check && !has_updated_at {
                    return true;
                }
            }
        }
        false
    }

    fn has_decimal_conversion_vulnerability(&self) -> bool {
        // Pattern: decimal conversion without overflow protection
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Look for power of 10 operations (10 ** decimals)
            if self.bytecode[i] == 0x0a { // EXP (exponentiation for 10^n)
                let window = &self.bytecode[i.saturating_sub(10)..i+20.min(self.bytecode.len())];
                
                // Check if used for decimal conversion
                let has_decimal_mul = window.iter().any(|&op| {
                    op == 0x02 // MUL (scale by 10^decimals)
                });
                
                let has_decimal_div = window.iter().any(|&op| {
                    op == 0x04 // DIV (scale down by 10^decimals)
                });
                
                // Check for overflow protection
                let has_overflow_check = window.windows(5).any(|w| {
                    // Pattern: check if result > MAX or division by zero
                    w.iter().any(|&op| op == 0x15) && // ISZERO
                    w.iter().any(|&op| op == 0xfd) // REVERT
                });
                
                // Check for safe math library
                let has_safe_math = window.windows(6).any(|w| {
                    // Pattern: STATICCALL to SafeMath or checked operations
                    w.iter().any(|&op| op == 0xfa) // STATICCALL
                });
                
                if (has_decimal_mul || has_decimal_div) && !has_overflow_check && !has_safe_math {
                    return true;
                }
            }
        }
        false
    }

    fn has_mutable_adapter_configuration(&self) -> bool {
        // Pattern: adapter config update without timelock
        let update_config = [0x9d, 0x6f, 0x41, 0x9a]; // updateConfig() or similar
        
        for i in 0..self.bytecode.len().saturating_sub(35) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == update_config {
                    let window = &self.bytecode[i..i+35.min(self.bytecode.len())];
                    
                    // Check for config storage update
                    let has_config_update = window.contains(&0x55); // SSTORE
                    
                    // Check for timelock mechanism
                    let has_timelock = window.windows(10).any(|w| {
                        // Pattern: proposedTime + delay < TIMESTAMP
                        w.iter().any(|&op| op == 0x54) && // SLOAD (proposed time)
                        w.iter().any(|&op| op == 0x01) && // ADD (+ delay)
                        w.iter().any(|&op| op == 0x42) && // TIMESTAMP
                        w.iter().any(|&op| op == 0x10) // LT (check if delay passed)
                    });
                    
                    // Check for multi-sig requirement
                    let has_multisig = window.windows(8).any(|w| {
                        // Pattern: multiple signature verifications
                        w.iter().filter(|&&op| op == 0x20).count() >= 2 // Multiple KECCAK256 (sig checks)
                    });
                    
                    if has_config_update && !has_timelock && !has_multisig {
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
    fn test_sentiment_adapter_bypass() {
        let vulnerable_bytecode = vec![
            0x63, 0x1b, 0x6b, 0xa5, 0xe0, // setAdapter()
            0x35, // CALLDATALOAD (get adapter address)
            0x55, // SSTORE (store adapter without validation!)
        ];

        let detector = SentimentOracleAdapterDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        
        assert!(!warnings.is_empty());
        assert!(warnings.iter().any(|w| w.description.contains("adapter")));
    }

    #[test]
    fn test_missing_price_sanity_checks() {
        let vulnerable_bytecode = vec![
            0x63, 0x41, 0x97, 0x6e, 0x09, // getPrice()
            0xfa, // STATICCALL (fetch price)
            0xf3, // RETURN (return price without bounds checking!)
        ];

        let detector = SentimentOracleAdapterDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        
        assert!(warnings.iter().any(|w| 
            w.description.contains("sanity") || 
            w.description.contains("bounds")
        ));
    }
}
