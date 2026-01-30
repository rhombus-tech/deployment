/// Default Parameter Danger Detector
/// 
/// Detects when functions accept dangerous default parameter values
/// Examples:
/// - slippage = 100% (user loses everything to sandwich attack)
/// - deadline = type(uint).max (transaction never expires)
/// - minOutput = 0 (accept any output amount)
/// - maxFee = type(uint).max (unlimited fees)

use crate::bytecode::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultParameterDangerVulnerability {
    pub location: usize,
    pub severity: SecuritySeverity,
    pub danger_type: DangerousDefaultType,
    pub parameter_name: String,
    pub dangerous_value: String,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DangerousDefaultType {
    UnlimitedSlippage,    // Accepts slippage >= 100%
    InfiniteDeadline,     // Accepts deadline = max uint
    ZeroMinimum,          // Accepts minOutput = 0
    UnlimitedFee,         // Accepts fee = max value
    MaxApproval,          // Approves type(uint).max
    NoGasLimit,           // Gas limit = unlimited
    ZeroValidation,       // Allows amount = 0 bypass
}

pub struct DefaultParameterDangerDetector {
    bytecode: Vec<u8>,
}

impl DefaultParameterDangerDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<DefaultParameterDangerVulnerability> {
        let mut vulnerabilities = Vec::new();

        // 1. Unlimited slippage acceptance (slippage >= 100%)
        vulnerabilities.extend(self.detect_unlimited_slippage());

        // 2. Infinite deadline acceptance (deadline = type(uint).max)
        vulnerabilities.extend(self.detect_infinite_deadline());

        // 3. Zero minimum output (minOut = 0)
        vulnerabilities.extend(self.detect_zero_minimum());

        // 4. Unlimited fee acceptance
        vulnerabilities.extend(self.detect_unlimited_fees());

        // 5. Max approval patterns
        vulnerabilities.extend(self.detect_max_approval());

        // 6. Zero amount bypass
        vulnerabilities.extend(self.detect_zero_bypass());

        vulnerabilities
    }

    fn detect_unlimited_slippage(&self) -> Vec<DefaultParameterDangerVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: Slippage parameter that allows 100% or more
            // Look for: slippage check that accepts values up to 10000 (100%)
            if self.accepts_unlimited_slippage(pc) {
                vulns.push(DefaultParameterDangerVulnerability {
                    location: pc,
                    severity: SecuritySeverity::Critical,
                    danger_type: DangerousDefaultType::UnlimitedSlippage,
                    parameter_name: "slippageBps".to_string(),
                    dangerous_value: "10000 (100%)".to_string(),
                    description: "Function accepts slippage of 100%, allowing complete MEV extraction".to_string(),
                    exploit_scenario: "function swap(uint amountIn, uint slippageBps) {\n\
                        require(slippageBps <= 10000); // Allows 100%!\n\
                        uint minOut = amountIn * (10000 - slippageBps) / 10000;\n\
                        // User calls with slippageBps = 10000\n\
                        // minOut = 0, accepts ANY output\n\
                        // MEV bot sandwiches:\n\
                        //   1. Front-run: manipulate price down\n\
                        //   2. User gets 0.01% of expected output\n\
                        //   3. Back-run: restore price, bot profits\n\
                        // User loses 99.99% of funds\n\
                        }".to_string(),
                    remediation: "Cap slippage: require(slippageBps <= 500) // Max 5% slippage".to_string(),
                    confidence: 0.88,
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_infinite_deadline(&self) -> Vec<DefaultParameterDangerVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: Deadline check that accepts type(uint).max
            if self.accepts_infinite_deadline(pc) {
                vulns.push(DefaultParameterDangerVulnerability {
                    location: pc,
                    severity: SecuritySeverity::High,
                    danger_type: DangerousDefaultType::InfiniteDeadline,
                    parameter_name: "deadline".to_string(),
                    dangerous_value: "type(uint256).max".to_string(),
                    description: "Function accepts infinite deadline, transaction never expires".to_string(),
                    exploit_scenario: "function swap(uint amountIn, uint deadline) {\n\
                        require(block.timestamp <= deadline);\n\
                        // User sets deadline = type(uint).max (common pattern)\n\
                        // Transaction stuck in mempool for hours\n\
                        // Price moves dramatically\n\
                        // Transaction executes at terrible price\n\
                        // No protection against stale transactions\n\
                        }".to_string(),
                    remediation: "Reject infinite deadline: require(deadline < block.timestamp + MAX_DELAY)".to_string(),
                    confidence: 0.82,
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_zero_minimum(&self) -> Vec<DefaultParameterDangerVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: minOut = 0 is allowed
            if self.accepts_zero_minimum(pc) {
                vulns.push(DefaultParameterDangerVulnerability {
                    location: pc,
                    severity: SecuritySeverity::Critical,
                    danger_type: DangerousDefaultType::ZeroMinimum,
                    parameter_name: "minAmountOut".to_string(),
                    dangerous_value: "0".to_string(),
                    description: "Function accepts minAmountOut = 0, no slippage protection".to_string(),
                    exploit_scenario: "function swap(uint amountIn, uint minAmountOut) {\n\
                        uint amountOut = getAmountOut(amountIn);\n\
                        require(amountOut >= minAmountOut); // Allows 0!\n\
                        // User sets minAmountOut = 0\n\
                        // MEV bot sandwiches trade\n\
                        // User receives 0.001 tokens instead of 1000\n\
                        // Check passes (0.001 >= 0)\n\
                        // User loses 99.9999% of funds\n\
                        }".to_string(),
                    remediation: "Reject zero: require(minAmountOut > 0) and suggest reasonable minimum".to_string(),
                    confidence: 0.90,
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_unlimited_fees(&self) -> Vec<DefaultParameterDangerVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: Fee parameter without reasonable cap
            if self.accepts_unlimited_fees(pc) {
                vulns.push(DefaultParameterDangerVulnerability {
                    location: pc,
                    severity: SecuritySeverity::High,
                    danger_type: DangerousDefaultType::UnlimitedFee,
                    parameter_name: "feeBps".to_string(),
                    dangerous_value: "> 10000 (>100%)".to_string(),
                    description: "Function accepts fees over 100% of transaction value".to_string(),
                    exploit_scenario: "function setProtocolFee(uint feeBps) onlyOwner {\n\
                        require(feeBps <= type(uint).max); // No real check\n\
                        protocolFee = feeBps;\n\
                        // Malicious owner sets fee = 50000 (500%)\n\
                        // Users pay 5x transaction value in fees\n\
                        // Protocol drains user funds via fees\n\
                        }".to_string(),
                    remediation: "Cap fees: require(feeBps <= 1000) // Max 10% fee".to_string(),
                    confidence: 0.75,
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_max_approval(&self) -> Vec<DefaultParameterDangerVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: Approve with type(uint).max
            if self.has_max_approval(pc) {
                vulns.push(DefaultParameterDangerVulnerability {
                    location: pc,
                    severity: SecuritySeverity::Medium,
                    danger_type: DangerousDefaultType::MaxApproval,
                    parameter_name: "amount (approve)".to_string(),
                    dangerous_value: "type(uint256).max".to_string(),
                    description: "Contract approves unlimited token amount".to_string(),
                    exploit_scenario: "function depositFor(address token, uint amount) {\n\
                        IERC20(token).approve(vault, type(uint).max);\n\
                        // Gives vault unlimited access to all future deposits\n\
                        // If vault is compromised or upgradeable:\n\
                        //   - All tokens can be drained\n\
                        //   - Users lose funds they haven't even deposited yet\n\
                        }".to_string(),
                    remediation: "Approve exact amount: approve(vault, amount) instead of max".to_string(),
                    confidence: 0.78,
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_zero_bypass(&self) -> Vec<DefaultParameterDangerVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: Amount = 0 bypasses validation
            if self.has_zero_bypass(pc) {
                vulns.push(DefaultParameterDangerVulnerability {
                    location: pc,
                    severity: SecuritySeverity::High,
                    danger_type: DangerousDefaultType::ZeroValidation,
                    parameter_name: "amount".to_string(),
                    dangerous_value: "0".to_string(),
                    description: "Amount = 0 bypasses validation checks".to_string(),
                    exploit_scenario: "function transfer(uint amount) {\n\
                        if (amount > 0) {\n\
                            require(balances[msg.sender] >= amount);\n\
                        }\n\
                        // amount = 0 bypasses balance check!\n\
                        _updateState(); // Still executes state changes\n\
                        // Attacker can trigger state changes without balance\n\
                        // Could manipulate accounting, rewards, etc.\n\
                        }".to_string(),
                    remediation: "Always check: require(amount > 0) at function start".to_string(),
                    confidence: 0.72,
                });
            }

            pc += 1;
        }

        vulns
    }

    // Helper functions

    fn accepts_unlimited_slippage(&self, start: usize) -> bool {
        if start + 30 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 30];

        // Look for: slippage <= 10000 check (10000 basis points = 100%)
        // Pattern: PUSH 10000 (0x2710) → LE check
        self.has_constant_check(window, 0x2710, 0x10) // 10000, LT
    }

    fn accepts_infinite_deadline(&self, start: usize) -> bool {
        if start + 25 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 25];

        // Look for: deadline check without upper bound validation
        // Pattern: TIMESTAMP → deadline → LE check (but no max check)
        let has_timestamp_check = window.windows(3).any(|w| {
            w[0] == 0x42 && // TIMESTAMP
            w[1] == 0x10 && // LT (timestamp < deadline)
            w[2] == 0x57    // JUMPI
        });

        // Check if there's NO maximum deadline validation
        let has_max_check = window.windows(2).any(|w| {
            w[0] == 0x11 && // GT (deadline > max)
            w[1] == 0x57    // JUMPI revert
        });

        has_timestamp_check && !has_max_check
    }

    fn accepts_zero_minimum(&self, start: usize) -> bool {
        if start + 25 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 25];

        // Look for: minOut check that doesn't reject zero
        // Pattern: amountOut >= minOut check without minOut > 0 check
        let has_min_check = window.windows(3).any(|w| {
            w[0] == 0x11 && // GT (amountOut > minOut)
            w[1] == 0x15 && // ISZERO
            w[2] == 0x57    // JUMPI revert
        });

        // Check if there's NO zero rejection for minOut
        let rejects_zero = window.windows(3).any(|w| {
            w[0] == 0x15 && // ISZERO (minOut == 0)
            w[1] == 0x57    // JUMPI revert if zero
        });

        has_min_check && !rejects_zero
    }

    fn accepts_unlimited_fees(&self, start: usize) -> bool {
        if start + 30 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 30];

        // Look for: fee check that allows > 100%
        // No check for fee <= 10000, or check allows larger values
        let has_fee_validation = window.iter().any(|&b| b == 0x10 || b == 0x11); // LT or GT

        if has_fee_validation {
            // Check if the cap is above 10000 (100%)
            !self.has_constant_check(window, 0x2710, 0x10) // Not checking <= 10000
        } else {
            false
        }
    }

    fn has_max_approval(&self, start: usize) -> bool {
        if start + 30 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 30];

        // Look for: approve() call with type(uint).max
        // approve selector: 0x095ea7b3
        let has_approve = window.windows(4).any(|w| w == [0x09, 0x5e, 0xa7, 0xb3]);

        if has_approve {
            // Check for max uint256 constant
            let max_uint = 0xFFFFFFFFFFFFFFFFu64;
            self.has_constant_in_window(window, max_uint)
        } else {
            false
        }
    }

    fn has_zero_bypass(&self, start: usize) -> bool {
        if start + 30 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 30];

        // Pattern: if (amount > 0) { check } else { no check }
        // Look for: GT 0 → JUMPI (conditional check)
        window.windows(4).any(|w| {
            w[0] == 0x60 && // PUSH1 0
            w[1] == 0x00 &&
            w[2] == 0x11 && // GT (amount > 0)
            w[3] == 0x57    // JUMPI (skip check if zero)
        })
    }

    fn has_constant_check(&self, window: &[u8], constant: u16, comparison: u8) -> bool {
        let constant_bytes = constant.to_be_bytes();
        
        window.windows(4).any(|w| {
            w[0] == 0x61 && // PUSH2
            w[1] == constant_bytes[0] &&
            w[2] == constant_bytes[1] &&
            w[3] == comparison
        })
    }

    fn has_constant_in_window(&self, window: &[u8], constant: u64) -> bool {
        let bytes = constant.to_be_bytes();
        window.windows(8).any(|w| w == bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unlimited_slippage() {
        // Accepts slippage <= 10000 (100%)
        let bytecode = vec![
            0x61, 0x27, 0x10, // PUSH2 10000
            0x10,             // LT (slippage < 10000)
            0x57,             // JUMPI
        ];
        
        let detector = DefaultParameterDangerDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.danger_type, DangerousDefaultType::UnlimitedSlippage)));
    }

    #[test]
    fn test_zero_minimum() {
        // Allows minOut >= 0 (including zero)
        let bytecode = vec![
            0x11, // GT (amountOut > minOut)
            0x15, // ISZERO
            0x57, // JUMPI revert
            // No zero rejection for minOut
        ];
        
        let detector = DefaultParameterDangerDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.danger_type, DangerousDefaultType::ZeroMinimum)));
    }
}
