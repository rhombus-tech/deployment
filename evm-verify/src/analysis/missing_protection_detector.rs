/// Missing Protection Detector
/// 
/// Meta-detector: Identifies when critical functions SHOULD have protections but don't
/// Examples:
/// - Functions that modify state without reentrancy guard
/// - Admin functions without timelock
/// - Price updates without staleness check
/// - Withdrawals without pause mechanism
/// - DEX swaps without slippage protection

use crate::bytecode::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissingProtectionVulnerability {
    pub location: usize,
    pub severity: SecuritySeverity,
    pub missing_protection: ProtectionType,
    pub function_type: String,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProtectionType {
    ReentrancyGuard,      // External call without nonReentrant
    Timelock,             // Admin function without delay
    PauseMechanism,       // Critical function can't be paused
    SlippageProtection,   // Swap without min output check
    DeadlineCheck,        // No expiration on transaction
    StalenessCheck,       // Oracle without staleness validation
    CircuitBreaker,       // No emergency stop for anomalies
    RateLimiting,         // No limits on repeated calls
    AccessControl,        // Public function should be restricted
    InputValidation,      // No bounds checking
}

pub struct MissingProtectionDetector {
    bytecode: Vec<u8>,
}

impl MissingProtectionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<MissingProtectionVulnerability> {
        let mut vulnerabilities = Vec::new();

        // 1. External calls without reentrancy guard
        vulnerabilities.extend(self.detect_missing_reentrancy_guard());

        // 2. Admin functions without timelock
        vulnerabilities.extend(self.detect_missing_timelock());

        // 3. Critical functions without pause mechanism
        vulnerabilities.extend(self.detect_missing_pause());

        // 4. Swaps without slippage protection
        vulnerabilities.extend(self.detect_missing_slippage_protection());

        // 5. Operations without deadline check
        vulnerabilities.extend(self.detect_missing_deadline());

        // 6. Oracle reads without staleness check
        vulnerabilities.extend(self.detect_missing_staleness_check());

        // 7. No circuit breaker for anomalies
        vulnerabilities.extend(self.detect_missing_circuit_breaker());

        vulnerabilities
    }

    fn detect_missing_reentrancy_guard(&self) -> Vec<MissingProtectionVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: CALL/DELEGATECALL followed by SSTORE (state change after external call)
            // without reentrancy lock check
            if self.has_external_call_with_state_change(pc) && !self.has_reentrancy_lock(pc) {
                vulns.push(MissingProtectionVulnerability {
                    location: pc,
                    severity: SecuritySeverity::Critical,
                    missing_protection: ProtectionType::ReentrancyGuard,
                    function_type: "State-changing function with external call".to_string(),
                    description: "Function makes external call then modifies state without reentrancy guard".to_string(),
                    exploit_scenario: "function withdraw(uint amount) {\n\
                        // No nonReentrant modifier\n\
                        balances[msg.sender] -= amount;\n\
                        (bool success,) = msg.sender.call{value: amount}(\"\"); // External call\n\
                        // State changed after call - vulnerable to reentrancy\n\
                        // Attacker can reenter and drain funds\n\
                        }".to_string(),
                    remediation: "Add nonReentrant modifier or use Checks-Effects-Interactions pattern".to_string(),
                    confidence: 0.85,
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_missing_timelock(&self) -> Vec<MissingProtectionVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: Owner/admin check followed by critical state change
            // without timelock delay check
            if self.has_admin_function(pc) && !self.has_timelock_check(pc) {
                vulns.push(MissingProtectionVulnerability {
                    location: pc,
                    severity: SecuritySeverity::High,
                    missing_protection: ProtectionType::Timelock,
                    function_type: "Admin function".to_string(),
                    description: "Admin function can execute immediately without timelock delay".to_string(),
                    exploit_scenario: "function setFeeRecipient(address newRecipient) onlyOwner {\n\
                        // No timelock - instant execution\n\
                        feeRecipient = newRecipient;\n\
                        // Compromised admin key = instant rug pull\n\
                        // Users have no time to exit before malicious change\n\
                        }".to_string(),
                    remediation: "Add timelock: require(block.timestamp >= proposedTime + DELAY)".to_string(),
                    confidence: 0.78,
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_missing_pause(&self) -> Vec<MissingProtectionVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: Critical function (transfer, withdraw, swap) without pause check
            if self.has_critical_function(pc) && !self.has_pause_check(pc) {
                vulns.push(MissingProtectionVulnerability {
                    location: pc,
                    severity: SecuritySeverity::High,
                    missing_protection: ProtectionType::PauseMechanism,
                    function_type: "Critical financial function".to_string(),
                    description: "Critical function cannot be paused in emergency".to_string(),
                    exploit_scenario: "function withdraw(uint amount) {\n\
                        // No whenNotPaused modifier\n\
                        // Bug discovered in protocol\n\
                        // Cannot stop withdrawals to fix issue\n\
                        // All funds at risk, no emergency stop\n\
                        _transfer(msg.sender, amount);\n\
                        }".to_string(),
                    remediation: "Add whenNotPaused modifier for emergency control".to_string(),
                    confidence: 0.72,
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_missing_slippage_protection(&self) -> Vec<MissingProtectionVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: Swap/exchange without minimum output check
            if self.has_swap_function(pc) && !self.has_slippage_check(pc) {
                vulns.push(MissingProtectionVulnerability {
                    location: pc,
                    severity: SecuritySeverity::Critical,
                    missing_protection: ProtectionType::SlippageProtection,
                    function_type: "Token swap function".to_string(),
                    description: "Swap function accepts any output amount without minimum check".to_string(),
                    exploit_scenario: "function swap(uint amountIn) {\n\
                        // No minAmountOut parameter\n\
                        uint amountOut = getAmountOut(amountIn);\n\
                        // Sandwiched by MEV bot:\n\
                        // 1. Bot front-runs, manipulates price\n\
                        // 2. User swap executes at terrible price\n\
                        // 3. Bot back-runs, profits from user's loss\n\
                        _executeSwap(amountIn, amountOut);\n\
                        }".to_string(),
                    remediation: "Add minAmountOut parameter: require(amountOut >= minAmountOut)".to_string(),
                    confidence: 0.82,
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_missing_deadline(&self) -> Vec<MissingProtectionVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: Time-sensitive operation without deadline check
            if self.has_time_sensitive_operation(pc) && !self.has_deadline_check(pc) {
                vulns.push(MissingProtectionVulnerability {
                    location: pc,
                    severity: SecuritySeverity::High,
                    missing_protection: ProtectionType::DeadlineCheck,
                    function_type: "Time-sensitive operation".to_string(),
                    description: "Operation has no expiration deadline".to_string(),
                    exploit_scenario: "function swap(uint amountIn) {\n\
                        // No deadline parameter\n\
                        // Transaction sits in mempool for hours\n\
                        // Price moves significantly\n\
                        // Transaction finally executes at stale price\n\
                        // User receives much less than expected\n\
                        _swap(amountIn);\n\
                        }".to_string(),
                    remediation: "Add deadline: require(block.timestamp <= deadline)".to_string(),
                    confidence: 0.75,
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_missing_staleness_check(&self) -> Vec<MissingProtectionVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: Oracle read without timestamp validation
            if self.has_oracle_read(pc) && !self.has_staleness_validation(pc) {
                vulns.push(MissingProtectionVulnerability {
                    location: pc,
                    severity: SecuritySeverity::Critical,
                    missing_protection: ProtectionType::StalenessCheck,
                    function_type: "Oracle price read".to_string(),
                    description: "Oracle price used without checking if data is fresh".to_string(),
                    exploit_scenario: "function liquidate(address user) {\n\
                        uint price = oracle.getPrice(); // No staleness check\n\
                        // Oracle offline for 2 hours\n\
                        // Price stale, doesn't reflect market\n\
                        // Attacker liquidates using stale favorable price\n\
                        // Protocol suffers bad debt\n\
                        }".to_string(),
                    remediation: "Check updatedAt: require(block.timestamp - updatedAt < MAX_DELAY)".to_string(),
                    confidence: 0.80,
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_missing_circuit_breaker(&self) -> Vec<MissingProtectionVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: Large value operations without bounds checking
            if self.has_large_value_operation(pc) && !self.has_circuit_breaker(pc) {
                vulns.push(MissingProtectionVulnerability {
                    location: pc,
                    severity: SecuritySeverity::High,
                    missing_protection: ProtectionType::CircuitBreaker,
                    function_type: "Large value operation".to_string(),
                    description: "Operation allows extreme values without circuit breaker".to_string(),
                    exploit_scenario: "function withdraw(uint amount) {\n\
                        // No maximum withdrawal limit\n\
                        // Bug or exploit allows amount = type(uint).max\n\
                        // Entire protocol drained in one transaction\n\
                        // No circuit breaker to detect anomaly\n\
                        _transfer(msg.sender, amount);\n\
                        }".to_string(),
                    remediation: "Add bounds: require(amount <= maxWithdrawal) or use rate limiting".to_string(),
                    confidence: 0.70,
                });
            }

            pc += 1;
        }

        vulns
    }

    // Helper functions

    fn has_external_call_with_state_change(&self, start: usize) -> bool {
        if start + 30 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 30];
        
        // Look for CALL/DELEGATECALL followed by SSTORE
        let call_pos = window.iter().position(|&b| b == 0xF1 || b == 0xF4);
        let sstore_pos = window.iter().position(|&b| b == 0x55);

        matches!((call_pos, sstore_pos), (Some(c), Some(s)) if s > c)
    }

    fn has_reentrancy_lock(&self, start: usize) -> bool {
        if start < 20 || start + 20 > self.bytecode.len() {
            return false;
        }

        // Check for reentrancy lock pattern: SLOAD(lock_slot) → check → SSTORE(lock_slot)
        let check_before = &self.bytecode[start.saturating_sub(20)..start];
        let check_after = &self.bytecode[start..start.min(start + 20)];

        let has_lock_check = check_before.windows(3).any(|w| {
            w[0] == 0x54 && // SLOAD
            w[1] == 0x15 && // ISZERO (check if unlocked)
            w[2] == 0x57    // JUMPI
        });

        let has_lock_set = check_after.iter().any(|&b| b == 0x55); // SSTORE to set lock

        has_lock_check && has_lock_set
    }

    fn has_admin_function(&self, start: usize) -> bool {
        if start + 15 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 15];
        
        // Pattern: CALLER → SLOAD(owner) → EQ check
        window.windows(4).any(|w| {
            w[0] == 0x33 && // CALLER
            w[1] == 0x54 && // SLOAD
            w[2] == 0x14 && // EQ
            w[3] == 0x57    // JUMPI
        })
    }

    fn has_timelock_check(&self, start: usize) -> bool {
        if start + 25 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 25];
        
        // Pattern: TIMESTAMP → SLOAD(time) → comparison
        window.windows(3).any(|w| {
            w[0] == 0x42 && // TIMESTAMP
            w[1] == 0x54 && // SLOAD
            (w[2] == 0x10 || w[2] == 0x11) // LT or GT
        })
    }

    fn has_critical_function(&self, start: usize) -> bool {
        if start + 20 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 20];
        
        // Look for transfer/withdrawal patterns (CALL with value or SSTORE with balance change)
        window.windows(2).any(|w| {
            (w[0] == 0xF1 && w[1] == 0x50) || // CALL (transfer ETH)
            (w[0] == 0x55)                     // SSTORE (update balances)
        })
    }

    fn has_pause_check(&self, start: usize) -> bool {
        if start < 15 {
            return false;
        }

        let window = &self.bytecode[start.saturating_sub(15)..start.min(start + 10)];
        
        // Pattern: SLOAD(paused) → ISZERO → require
        window.windows(3).any(|w| {
            w[0] == 0x54 && // SLOAD
            w[1] == 0x15 && // ISZERO
            w[2] == 0x57    // JUMPI (revert if paused)
        })
    }

    fn has_swap_function(&self, start: usize) -> bool {
        if start + 30 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 30];
        
        // Look for mul/div operations (price calculations) followed by transfer
        let has_math = window.iter().any(|&b| b == 0x02 || b == 0x04); // MUL or DIV
        let has_transfer = window.windows(4).any(|w| w == [0xa9, 0x05, 0x9c, 0xbb]); // transfer()

        has_math && has_transfer
    }

    fn has_slippage_check(&self, start: usize) -> bool {
        if start + 25 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 25];
        
        // Pattern: CALLDATALOAD(minOut) → calculated amount → GT check
        window.windows(3).any(|w| {
            w[0] == 0x35 && // CALLDATALOAD
            w[1] == 0x11 && // GT (amount > min)
            w[2] == 0x57    // JUMPI (revert if too low)
        })
    }

    fn has_time_sensitive_operation(&self, start: usize) -> bool {
        self.has_swap_function(start) || self.has_oracle_read(start)
    }

    fn has_deadline_check(&self, start: usize) -> bool {
        if start + 20 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 20];
        
        // Pattern: TIMESTAMP → CALLDATALOAD(deadline) → LT check
        window.windows(3).any(|w| {
            w[0] == 0x42 && // TIMESTAMP
            w[1] == 0x35 && // CALLDATALOAD
            w[2] == 0x10    // LT (timestamp < deadline)
        })
    }

    fn has_oracle_read(&self, start: usize) -> bool {
        if start + 25 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 25];
        
        // Look for STATICCALL (oracle read)
        window.iter().any(|&b| b == 0xFA) // STATICCALL
    }

    fn has_staleness_validation(&self, start: usize) -> bool {
        if start + 30 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 30];
        
        // Pattern: TIMESTAMP → updatedAt → SUB → comparison to threshold
        window.windows(4).any(|w| {
            w[0] == 0x42 && // TIMESTAMP
            w[1] == 0x03 && // SUB
            w[2] == 0x10 && // LT (check freshness)
            w[3] == 0x57    // JUMPI
        })
    }

    fn has_large_value_operation(&self, start: usize) -> bool {
        if start + 20 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 20];
        
        // Look for operations involving large amounts (SSTORE or transfer)
        window.iter().any(|&b| b == 0x55 || b == 0xF1) // SSTORE or CALL
    }

    fn has_circuit_breaker(&self, start: usize) -> bool {
        if start + 20 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 20];
        
        // Pattern: Amount comparison to maximum threshold
        window.windows(3).any(|w| {
            w[0] == 0x10 && // LT (amount < max)
            w[1] == 0x15 && // ISZERO
            w[2] == 0x57    // JUMPI (revert if exceeded)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_missing_reentrancy_guard() {
        let bytecode = vec![
            0xF1, // CALL (external)
            0x55, // SSTORE (state change after call)
            // No reentrancy lock pattern
        ];
        
        let detector = MissingProtectionDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.missing_protection, ProtectionType::ReentrancyGuard)));
    }
}
