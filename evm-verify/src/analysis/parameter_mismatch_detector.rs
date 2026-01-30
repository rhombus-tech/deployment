/// Parameter Mismatch Detector
/// 
/// Detects when function validates one parameter but uses a different one
/// Pattern: require(param A), then use param B
/// 
/// Example:
/// ```solidity
/// function transfer(address to, uint amount) {
///     require(balances[msg.sender] >= amount);  // Validates 'amount'
///     balances[to] += msg.value;                 // Uses 'msg.value'!
/// }
/// ```

use crate::bytecode::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterMismatchVulnerability {
    pub location: usize,
    pub severity: SecuritySeverity,
    pub mismatch_type: MismatchType,
    pub checked_parameter: String,
    pub used_parameter: String,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MismatchType {
    AmountVsValue,           // Check amount param, use msg.value
    AddressVsOrigin,         // Check to address, use tx.origin
    TokenVsImplicit,         // Check token param, use hardcoded token
    LengthVsActual,          // Check array.length, use different array
    IndexVsOffset,           // Check index, use offset
    CallerVsParameter,       // Check msg.sender, use address parameter
}

pub struct ParameterMismatchDetector {
    bytecode: Vec<u8>,
}

impl ParameterMismatchDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<ParameterMismatchVulnerability> {
        let mut vulnerabilities = Vec::new();

        // 1. Amount parameter vs msg.value
        vulnerabilities.extend(self.detect_amount_vs_value());

        // 2. Address parameter vs tx.origin
        vulnerabilities.extend(self.detect_address_vs_origin());

        // 3. CALLDATALOAD offset mismatches
        vulnerabilities.extend(self.detect_calldataload_mismatch());

        // 4. Array length vs array access mismatch
        vulnerabilities.extend(self.detect_array_mismatch());

        // 5. msg.sender vs address parameter
        vulnerabilities.extend(self.detect_caller_vs_parameter());

        vulnerabilities
    }

    fn detect_amount_vs_value(&self) -> Vec<ParameterMismatchVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: CALLDATALOAD (amount) → validation → CALLVALUE → use
            if self.has_amount_value_mismatch(pc) {
                vulns.push(ParameterMismatchVulnerability {
                    location: pc,
                    severity: SecuritySeverity::Critical,
                    mismatch_type: MismatchType::AmountVsValue,
                    checked_parameter: "amount (calldata)".to_string(),
                    used_parameter: "msg.value".to_string(),
                    description: "Function validates 'amount' parameter but uses 'msg.value'".to_string(),
                    exploit_scenario: "function deposit(uint amount) {\n\
                        require(amount <= maxDeposit);    // Check amount=0\n\
                        balance += msg.value;             // Use msg.value=1M ETH\n\
                        }\n\
                        Attacker calls with amount=0, msg.value=1M\n\
                        Validation passes, deposits unlimited".to_string(),
                    remediation: "Use the same parameter for both validation and execution: require(msg.value <= maxDeposit)".to_string(),
                    confidence: 0.90,
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_address_vs_origin(&self) -> Vec<ParameterMismatchVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: CALLDATALOAD (address) → validation → ORIGIN → use
            if self.has_address_origin_mismatch(pc) {
                vulns.push(ParameterMismatchVulnerability {
                    location: pc,
                    severity: SecuritySeverity::High,
                    mismatch_type: MismatchType::AddressVsOrigin,
                    checked_parameter: "to (address parameter)".to_string(),
                    used_parameter: "tx.origin".to_string(),
                    description: "Function validates address parameter but uses tx.origin".to_string(),
                    exploit_scenario: "function transferTo(address to, uint amount) {\n\
                        require(to != address(0));     // Check 'to' parameter\n\
                        _transfer(tx.origin, amount);  // Use tx.origin instead!\n\
                        }\n\
                        Funds sent to transaction originator, not 'to' address".to_string(),
                    remediation: "Use the address parameter consistently: _transfer(to, amount)".to_string(),
                    confidence: 0.85,
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_calldataload_mismatch(&self) -> Vec<ParameterMismatchVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: CALLDATALOAD offset X → validate → CALLDATALOAD offset Y → use
            if let Some(offsets) = self.find_different_calldataload_offsets(pc) {
                vulns.push(ParameterMismatchVulnerability {
                    location: pc,
                    severity: SecuritySeverity::Critical,
                    mismatch_type: MismatchType::IndexVsOffset,
                    checked_parameter: format!("parameter at offset {}", offsets.0),
                    used_parameter: format!("parameter at offset {}", offsets.1),
                    description: "Function validates parameter at one calldata offset but uses different offset".to_string(),
                    exploit_scenario: "Function signature: transfer(address to, uint amount, bytes data)\n\
                        Validates: amount at offset 0x44\n\
                        Uses: amount at offset 0x24\n\
                        Attacker can bypass validation by manipulating calldata layout".to_string(),
                    remediation: "Use consistent calldata offsets for validation and execution".to_string(),
                    confidence: 0.80,
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_array_mismatch(&self) -> Vec<ParameterMismatchVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: MLOAD (array A length) → validate → MLOAD (array B) → use
            if self.has_array_length_mismatch(pc) {
                vulns.push(ParameterMismatchVulnerability {
                    location: pc,
                    severity: SecuritySeverity::High,
                    mismatch_type: MismatchType::LengthVsActual,
                    checked_parameter: "array A length".to_string(),
                    used_parameter: "array B elements".to_string(),
                    description: "Function validates length of one array but iterates over different array".to_string(),
                    exploit_scenario: "function batchTransfer(address[] recipients, uint[] amounts) {\n\
                        require(recipients.length <= 100);  // Check recipients\n\
                        for (uint i = 0; i < amounts.length; i++) { // Loop over amounts!\n\
                            transfer(recipients[i], amounts[i]); // OOB if amounts.length > recipients.length\n\
                        }\n\
                        }".to_string(),
                    remediation: "Validate and use the same array: require(recipients.length == amounts.length)".to_string(),
                    confidence: 0.75,
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_caller_vs_parameter(&self) -> Vec<ParameterMismatchVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: CALLER → validate → CALLDATALOAD (address) → use
            if self.has_caller_parameter_mismatch(pc) {
                vulns.push(ParameterMismatchVulnerability {
                    location: pc,
                    severity: SecuritySeverity::Critical,
                    mismatch_type: MismatchType::CallerVsParameter,
                    checked_parameter: "msg.sender".to_string(),
                    used_parameter: "from (address parameter)".to_string(),
                    description: "Function validates msg.sender but uses address parameter".to_string(),
                    exploit_scenario: "function withdraw(address from, uint amount) {\n\
                        require(balances[msg.sender] >= amount);  // Check msg.sender balance\n\
                        balances[from] -= amount;                  // Deduct from 'from' address!\n\
                        }\n\
                        Attacker steals from any address by passing it as 'from'".to_string(),
                    remediation: "Use msg.sender consistently or validate the from parameter matches msg.sender".to_string(),
                    confidence: 0.88,
                });
            }

            pc += 1;
        }

        vulns
    }

    // Helper functions

    fn has_amount_value_mismatch(&self, start: usize) -> bool {
        if start + 30 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 30];

        // Look for: CALLDATALOAD → validation → CALLVALUE → use
        let has_calldataload = window.iter().position(|&b| b == 0x35); // CALLDATALOAD
        let has_callvalue = window.iter().position(|&b| b == 0x34);     // CALLVALUE

        if let (Some(cdl_pos), Some(cv_pos)) = (has_calldataload, has_callvalue) {
            // CALLVALUE comes after CALLDATALOAD, with validation between
            cv_pos > cdl_pos && self.has_comparison_between(window, cdl_pos, cv_pos)
        } else {
            false
        }
    }

    fn has_address_origin_mismatch(&self, start: usize) -> bool {
        if start + 30 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 30];

        // Look for: CALLDATALOAD → validation → ORIGIN → use
        let has_calldataload = window.iter().position(|&b| b == 0x35); // CALLDATALOAD
        let has_origin = window.iter().position(|&b| b == 0x32);        // ORIGIN

        if let (Some(cdl_pos), Some(origin_pos)) = (has_calldataload, has_origin) {
            origin_pos > cdl_pos && self.has_comparison_between(window, cdl_pos, origin_pos)
        } else {
            false
        }
    }

    fn find_different_calldataload_offsets(&self, start: usize) -> Option<(u8, u8)> {
        if start + 40 > self.bytecode.len() {
            return None;
        }

        let window = &self.bytecode[start..start + 40];
        
        // Find all CALLDATALOAD instructions with their preceding PUSH offset
        let mut offsets = Vec::new();
        for i in 0..window.len() - 2 {
            if window[i] == 0x60 && window[i + 2] == 0x35 { // PUSH1 offset, CALLDATALOAD
                offsets.push(window[i + 1]);
            }
        }

        // If we have 2+ different offsets
        if offsets.len() >= 2 && offsets[0] != offsets[1] {
            Some((offsets[0], offsets[1]))
        } else {
            None
        }
    }

    fn has_array_length_mismatch(&self, start: usize) -> bool {
        if start + 35 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 35];

        // Look for: MLOAD (length) → validate → different MLOAD → loop
        let mload_positions: Vec<usize> = window
            .iter()
            .enumerate()
            .filter(|(_, &b)| b == 0x51) // MLOAD
            .map(|(i, _)| i)
            .collect();

        // If we have 2+ MLOADs at different memory locations
        mload_positions.len() >= 2 && window.iter().any(|&b| b == 0x56) // JUMP (loop)
    }

    fn has_caller_parameter_mismatch(&self, start: usize) -> bool {
        if start + 30 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 30];

        // Look for: CALLER → validation → CALLDATALOAD → use
        let has_caller = window.iter().position(|&b| b == 0x33);        // CALLER
        let has_calldataload = window.iter().position(|&b| b == 0x35); // CALLDATALOAD

        if let (Some(caller_pos), Some(cdl_pos)) = (has_caller, has_calldataload) {
            cdl_pos > caller_pos && window[caller_pos..cdl_pos].iter().any(|&b| b == 0x14 || b == 0x10) // EQ or LT
        } else {
            false
        }
    }

    fn has_comparison_between(&self, window: &[u8], start: usize, end: usize) -> bool {
        window[start..end].iter().any(|&b| {
            b == 0x10 || // LT
            b == 0x11 || // GT
            b == 0x14 || // EQ
            b == 0x12 || // SLT
            b == 0x13    // SGT
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_amount_vs_value() {
        let bytecode = vec![
            0x35, // CALLDATALOAD (amount)
            0x10, // LT (validate)
            0x34, // CALLVALUE (use msg.value instead!)
            0x55, // SSTORE
        ];
        
        let detector = ParameterMismatchDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.mismatch_type, MismatchType::AmountVsValue)));
    }
}
