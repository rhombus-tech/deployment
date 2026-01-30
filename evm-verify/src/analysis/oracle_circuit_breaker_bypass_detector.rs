use serde::{Deserialize, Serialize};

/// Oracle Circuit Breaker Bypass Detection
/// 
/// Detects vulnerabilities in oracle circuit breaker mechanisms:
/// 1. Circuit breaker can be bypassed
/// 2. Price bounds too wide or missing
/// 3. Circuit breaker reset without validation
/// 4. Emergency oracle override without protection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OracleCircuitBreakerBypassVulnerability {
    /// Critical: Circuit breaker can be bypassed
    CircuitBreakerBypass {
        description: String,
        location: usize,
        bypass_method: String,
        confidence: f32,
    },
    /// High: Missing or insufficient price bounds
    MissingPriceBounds {
        description: String,
        oracle_call: usize,
    },
    /// High: Circuit breaker reset without proper validation
    UnsafeCircuitBreakerReset {
        description: String,
        reset_location: usize,
        missing_checks: Vec<String>,
    },
    /// Critical: Emergency oracle override without timelock
    EmergencyOracleOverride {
        description: String,
        location: usize,
    },
}

pub struct OracleCircuitBreakerBypassDetector {
    bytecode: Vec<u8>,
}

impl OracleCircuitBreakerBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<OracleCircuitBreakerBypassVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern 1: Find oracle calls and check for circuit breaker
        for i in 0..self.bytecode.len().saturating_sub(150) {
            if self.is_oracle_price_fetch(i) {
                let has_circuit_breaker = self.has_circuit_breaker_check(i, i + 150);
                let bypass_method = self.find_circuit_breaker_bypass(i, i + 150);
                
                if !has_circuit_breaker || !bypass_method.is_empty() {
                    vulnerabilities.push(OracleCircuitBreakerBypassVulnerability::CircuitBreakerBypass {
                        description: if bypass_method.is_empty() {
                            "Oracle price used without circuit breaker protection".to_string()
                        } else {
                            format!("Circuit breaker can be bypassed via: {}", bypass_method)
                        },
                        location: i,
                        bypass_method,
                        confidence: 0.85,
                    });
                }
                
                // Check for price bounds
                let has_bounds = self.has_price_bounds_check(i, i + 150);
                if !has_bounds {
                    vulnerabilities.push(OracleCircuitBreakerBypassVulnerability::MissingPriceBounds {
                        description: "Oracle price not validated against min/max bounds".to_string(),
                        oracle_call: i,
                    });
                }
            }
        }
        
        // Pattern 2: Circuit breaker reset functions
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.is_circuit_breaker_reset_function(i) {
                let missing_checks = self.validate_reset_requirements(i, i + 100);
                
                if !missing_checks.is_empty() {
                    vulnerabilities.push(OracleCircuitBreakerBypassVulnerability::UnsafeCircuitBreakerReset {
                        description: "Circuit breaker reset lacks proper validation".to_string(),
                        reset_location: i,
                        missing_checks,
                    });
                }
            }
        }
        
        // Pattern 3: Emergency oracle override
        for i in 0..self.bytecode.len().saturating_sub(120) {
            if self.is_emergency_oracle_function(i) {
                let has_timelock = self.has_timelock_protection(i, i + 120);
                let has_multisig = self.has_multisig_requirement(i, i + 120);
                
                if !has_timelock && !has_multisig {
                    vulnerabilities.push(OracleCircuitBreakerBypassVulnerability::EmergencyOracleOverride {
                        description: "Emergency oracle override without timelock or multisig".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_oracle_price_fetch(&self, location: usize) -> bool {
        if location + 30 > self.bytecode.len() {
            return false;
        }
        
        // Oracle price fetch selectors
        self.bytecode[location..location + 30].windows(4).any(|w| {
            w[0] == 0x63 && (
                (w[1] == 0xfe && w[2] == 0xaf) || // latestRoundData
                (w[1] == 0x50 && w[2] == 0xd2) || // latestAnswer
                (w[1] == 0x41 && w[2] == 0x97)    // getPrice
            )
        })
    }
    
    fn has_circuit_breaker_check(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return false;
        }
        
        // Circuit breaker patterns:
        // 1. Check if price changed too much: abs(newPrice - oldPrice) > threshold
        // 2. Check if circuit is tripped (SLOAD from breaker state)
        // 3. REVERT if tripped
        
        let has_price_delta = self.bytecode[start..range_end]
            .windows(2)
            .any(|w| w[0] == 0x03 && w[1] == 0x02); // SUB then MUL (for percentage)
        
        let has_breaker_state_check = self.bytecode[start..range_end]
            .windows(3)
            .any(|w| {
                w[0] == 0x54 && // SLOAD (circuit breaker state)
                w[1] == 0x15 && // ISZERO
                w[2] == 0xfd    // REVERT if tripped
            });
        
        has_price_delta || has_breaker_state_check
    }
    
    fn find_circuit_breaker_bypass(&self, start: usize, end: usize) -> String {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return String::new();
        }
        
        // Check for bypass methods:
        
        // 1. Admin can disable circuit breaker
        let admin_disable = self.bytecode[start..range_end]
            .windows(5)
            .any(|w| {
                w[0] == 0x33 && // CALLER
                w.iter().any(|&b| b == 0x55) // SSTORE (changing breaker state)
            });
        
        if admin_disable {
            return "admin_disable".to_string();
        }
        
        // 2. Timeout allows automatic reset
        let auto_timeout = self.bytecode[start..range_end]
            .windows(4)
            .any(|w| {
                w[0] == 0x42 && // TIMESTAMP
                w[1] == 0x10 && // LT
                w[2] == 0x57    // JUMPI (skip if timeout passed)
            });
        
        if auto_timeout {
            return "timeout_reset".to_string();
        }
        
        // 3. Alternative oracle path without breaker
        let alt_oracle = self.bytecode[start..range_end]
            .windows(2)
            .filter(|w| w[0] == 0x63 && w[1] == 0x41) // getPrice calls
            .count() > 1;
        
        if alt_oracle {
            return "alternative_oracle_path".to_string();
        }
        
        String::new()
    }
    
    fn has_price_bounds_check(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return false;
        }
        
        // Price bounds check pattern:
        // 1. price > MIN_PRICE
        // 2. price < MAX_PRICE
        // 3. REVERT if out of bounds
        
        let gt_checks = self.bytecode[start..range_end]
            .iter()
            .filter(|&&b| b == 0x11) // GT
            .count();
        
        let lt_checks = self.bytecode[start..range_end]
            .iter()
            .filter(|&&b| b == 0x10) // LT
            .count();
        
        let has_revert = self.bytecode[start..range_end]
            .iter()
            .any(|&b| b == 0xfd); // REVERT
        
        gt_checks > 0 && lt_checks > 0 && has_revert
    }
    
    fn is_circuit_breaker_reset_function(&self, location: usize) -> bool {
        if location + 30 > self.bytecode.len() {
            return false;
        }
        
        // Reset function patterns:
        // resetCircuitBreaker(), unpause(), etc.
        // Look for function that sets breaker state to false
        
        self.bytecode[location..location + 30].windows(6).any(|w| {
            w[0] == 0x63 && // Function selector
            w.iter().skip(4).any(|&b| b == 0x60) && // PUSH1 false
            w.iter().any(|&b| b == 0x55) // SSTORE
        })
    }
    
    fn validate_reset_requirements(&self, start: usize, end: usize) -> Vec<String> {
        let range_end = end.min(self.bytecode.len());
        let mut missing = Vec::new();
        
        if start >= range_end {
            return missing;
        }
        
        // Check required validations for reset:
        
        // 1. Cooldown period check
        let has_cooldown = self.bytecode[start..range_end]
            .windows(3)
            .any(|w| {
                w[0] == 0x42 && // TIMESTAMP
                w[1] == 0x10    // LT
            });
        
        if !has_cooldown {
            missing.push("cooldown_period".to_string());
        }
        
        // 2. Oracle price stabilization check
        let has_stability_check = self.bytecode[start..range_end]
            .iter()
            .filter(|&&b| b == 0x03) // SUB (price delta)
            .count() > 0;
        
        if !has_stability_check {
            missing.push("price_stability".to_string());
        }
        
        // 3. Multi-sig or governance approval
        let has_multisig = self.bytecode[start..range_end]
            .iter()
            .filter(|&&b| b == 0x33) // CALLER
            .count() > 1;
        
        if !has_multisig {
            missing.push("multisig_approval".to_string());
        }
        
        missing
    }
    
    fn is_emergency_oracle_function(&self, location: usize) -> bool {
        if location + 30 > self.bytecode.len() {
            return false;
        }
        
        // Emergency functions: setEmergencyOracle, updateOracleManually, etc.
        // Look for functions that directly SSTORE oracle address or price
        
        self.bytecode[location..location + 30].windows(4).any(|w| {
            w[0] == 0x63 && // Function selector
            w.iter().skip(4).take(20).any(|&b| b == 0x55) // SSTORE within function
        })
    }
    
    fn has_timelock_protection(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return false;
        }
        
        // Timelock pattern: queued time + delay < current time
        self.bytecode[start..range_end]
            .windows(4)
            .any(|w| {
                w[0] == 0x42 && // TIMESTAMP
                w[1] == 0x10 && // LT
                w[2] == 0x15 && // ISZERO
                w[3] == 0xfd    // REVERT
            })
    }
    
    fn has_multisig_requirement(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return false;
        }
        
        // Multisig: multiple CALLER checks and approval tracking
        let caller_checks = self.bytecode[start..range_end]
            .iter()
            .filter(|&&b| b == 0x33) // CALLER
            .count();
        
        let has_approval_count = self.bytecode[start..range_end]
            .windows(3)
            .any(|w| {
                w[0] == 0x54 && // SLOAD (approval count)
                w[1] == 0x10    // LT (check threshold)
            });
        
        caller_checks >= 2 && has_approval_count
    }
}
