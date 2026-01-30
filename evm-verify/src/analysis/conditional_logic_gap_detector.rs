/// Conditional Logic Gap Detector
/// 
/// Detects if/else if chains with missing else clauses that allow bypass
/// Real exploit: DeltaPrime $4.85M (2024) - parameter validation bypass
/// 
/// Pattern: Function validates some cases but leaves gaps
/// Example:
/// ```solidity
/// function withdraw(uint amount, address token) {
///     if (token == USDC) require(balance[msg.sender] >= amount);
///     else if (token == DAI) require(balance[msg.sender] >= amount);
///     // Missing: else clause - other tokens bypass check!
///     IERC20(token).transfer(msg.sender, amount);
/// }
/// ```

use crate::bytecode::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConditionalLogicGapVulnerability {
    pub location: usize,
    pub severity: SecuritySeverity,
    pub gap_type: ConditionalGapType,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConditionalGapType {
    MissingElseClause,           // if/else if without final else
    ParameterValidationBypass,   // Check parameter A, use parameter B
    StateCheckGap,               // Check state X, but state Y not checked
    RoleCheckGap,                // Check role for some cases, not others
    TokenTypeGap,                // Validate some tokens, not others
    AmountRangeGap,              // Check some amounts, gap in range
}

pub struct ConditionalLogicGapDetector {
    bytecode: Vec<u8>,
}

impl ConditionalLogicGapDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<ConditionalLogicGapVulnerability> {
        let mut vulnerabilities = Vec::new();

        // 1. Detect if/else if chains without final else
        vulnerabilities.extend(self.detect_missing_else_clause());

        // 2. Detect parameter validation vs usage mismatch
        vulnerabilities.extend(self.detect_parameter_validation_bypass());

        // 3. Detect incomplete state validation
        vulnerabilities.extend(self.detect_state_check_gaps());

        // 4. Detect role-based access gaps
        vulnerabilities.extend(self.detect_role_check_gaps());

        // 5. Detect token type validation gaps
        vulnerabilities.extend(self.detect_token_type_gaps());

        vulnerabilities
    }

    fn detect_missing_else_clause(&self) -> Vec<ConditionalLogicGapVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: Multiple JUMPI (if/else if) without final catch-all REVERT
            // JUMPI = conditional jump (if statement)
            // Multiple JUMPI in sequence = if/else if chain
            
            if self.has_if_else_chain_without_default(pc) {
                vulns.push(ConditionalLogicGapVulnerability {
                    location: pc,
                    severity: SecuritySeverity::Critical,
                    gap_type: ConditionalGapType::MissingElseClause,
                    description: "If/else if chain without default else clause allows bypass".to_string(),
                    exploit_scenario: "DeltaPrime-style exploit:\n\
                        Function validates specific token addresses (USDC, DAI)\n\
                        Attacker calls with different token address\n\
                        Validation bypassed, arbitrary token withdrawn\n\
                        $4.85M stolen via parameter bypass".to_string(),
                    remediation: "Add final else clause that reverts or has default validation".to_string(),
                    confidence: 0.85,
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_parameter_validation_bypass(&self) -> Vec<ConditionalLogicGapVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: CALLDATALOAD (load parameter) → validation → 
            //          Different CALLDATALOAD (use different parameter)
            
            if self.has_parameter_mismatch(pc) {
                vulns.push(ConditionalLogicGapVulnerability {
                    location: pc,
                    severity: SecuritySeverity::Critical,
                    gap_type: ConditionalGapType::ParameterValidationBypass,
                    description: "Function validates one parameter but uses another".to_string(),
                    exploit_scenario: "function transfer(address to, uint amount) {\n\
                        require(balances[msg.sender] >= amount); // Check 'amount'\n\
                        balances[to] += msg.value;                // Use 'msg.value'!\n\
                        }\n\
                        Attacker sends amount=0, msg.value=1M\n\
                        Check passes (amount=0), but transfers msg.value".to_string(),
                    remediation: "Ensure validated parameter matches used parameter".to_string(),
                    confidence: 0.80,
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_state_check_gaps(&self) -> Vec<ConditionalLogicGapVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: Check state variable A, modify state variable B
            //          without checking B
            
            if self.has_unchecked_state_modification(pc) {
                vulns.push(ConditionalLogicGapVulnerability {
                    location: pc,
                    severity: SecuritySeverity::High,
                    gap_type: ConditionalGapType::StateCheckGap,
                    description: "Function checks one state variable but modifies unchecked state".to_string(),
                    exploit_scenario: "function claim() {\n\
                        require(claimable[msg.sender] > 0);  // Check claimable\n\
                        totalClaimed += 1000;                 // Modify totalClaimed (unchecked!)\n\
                        }\n\
                        totalClaimed overflows, protocol state corrupted".to_string(),
                    remediation: "Validate all state variables that will be modified".to_string(),
                    confidence: 0.75,
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_role_check_gaps(&self) -> Vec<ConditionalLogicGapVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: Role check for some code paths, missing for others
            // CALLER → SLOAD (role) → EQ → JUMPI (role branch)
            // Followed by code without role check
            
            if self.has_conditional_role_check(pc) {
                vulns.push(ConditionalLogicGapVulnerability {
                    location: pc,
                    severity: SecuritySeverity::Critical,
                    gap_type: ConditionalGapType::RoleCheckGap,
                    description: "Access control check missing in some code paths".to_string(),
                    exploit_scenario: "function adminFunction(bool special) {\n\
                        if (special) {\n\
                            require(hasRole(ADMIN_ROLE, msg.sender)); // ✓ Check\n\
                            // admin action\n\
                        } // ✗ No else check!\n\
                        criticalAction(); // Anyone can call with special=false\n\
                        }".to_string(),
                    remediation: "Apply access control to all code paths, not just conditional branches".to_string(),
                    confidence: 0.82,
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_token_type_gaps(&self) -> Vec<ConditionalLogicGapVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: Token address comparison → validation
            //          Multiple token addresses checked, but gap exists
            
            if self.has_token_whitelist_gap(pc) {
                vulns.push(ConditionalLogicGapVulnerability {
                    location: pc,
                    severity: SecuritySeverity::High,
                    gap_type: ConditionalGapType::TokenTypeGap,
                    description: "Token validation applies to some tokens but not all".to_string(),
                    exploit_scenario: "function swap(address tokenIn, uint amount) {\n\
                        if (tokenIn == USDC) require(amount <= 1M);\n\
                        else if (tokenIn == DAI) require(amount <= 1M);\n\
                        // No validation for other tokens!\n\
                        _swap(tokenIn, amount); // Attacker uses WETH, unlimited amount\n\
                        }".to_string(),
                    remediation: "Use whitelist with explicit revert for unknown tokens, or validate all".to_string(),
                    confidence: 0.78,
                });
            }

            pc += 1;
        }

        vulns
    }

    // Helper functions for pattern detection

    fn has_if_else_chain_without_default(&self, start: usize) -> bool {
        if start + 50 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 50];
        
        // Count JUMPI instructions (conditional jumps)
        let jumpi_count = window.iter().filter(|&&b| b == 0x57).count();
        
        // Look for pattern: Multiple JUMPI without final REVERT
        if jumpi_count >= 2 {
            // Check if there's a catch-all REVERT after the JUMPI chain
            let has_final_revert = window[30..].iter().any(|&b| b == 0xFD || b == 0xFE);
            
            !has_final_revert && self.has_storage_write_after(start + 30)
        } else {
            false
        }
    }

    fn has_parameter_mismatch(&self, start: usize) -> bool {
        if start + 40 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 40];
        
        // Pattern: CALLDATALOAD at offset X → validate → CALLDATALOAD at offset Y → use
        let calldataload_positions: Vec<usize> = window
            .iter()
            .enumerate()
            .filter(|(_, &b)| b == 0x35) // CALLDATALOAD
            .map(|(i, _)| i)
            .collect();

        // If we see 2+ CALLDATALOAD in sequence with different offsets
        if calldataload_positions.len() >= 2 {
            // Check if there's a comparison between them (validation)
            let has_validation_between = window[calldataload_positions[0]..calldataload_positions[1]]
                .iter()
                .any(|&b| b == 0x10 || b == 0x11 || b == 0x14); // LT, GT, EQ

            has_validation_between
        } else {
            false
        }
    }

    fn has_unchecked_state_modification(&self, start: usize) -> bool {
        if start + 30 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 30];
        
        // Pattern: SLOAD (read state) → validation → SSTORE (write different slot)
        let has_sload = window.iter().any(|&b| b == 0x54);
        let has_sstore = window.iter().any(|&b| b == 0x55);
        
        has_sload && has_sstore && self.has_conditional_jump_between(window)
    }

    fn has_conditional_role_check(&self, start: usize) -> bool {
        if start + 35 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 35];
        
        // Pattern: CALLER → SLOAD → EQ → JUMPI (conditional role check)
        //          Followed by code without CALLER check
        let has_role_pattern = window.windows(4).any(|w| {
            w[0] == 0x33 && // CALLER
            w[1] == 0x54 && // SLOAD (role storage)
            w[2] == 0x14 && // EQ
            w[3] == 0x57    // JUMPI (conditional)
        });

        if has_role_pattern {
            // Check if code after JUMPI lacks role check
            !window[20..].windows(2).any(|w| w[0] == 0x33 && w[1] == 0x54)
        } else {
            false
        }
    }

    fn has_token_whitelist_gap(&self, start: usize) -> bool {
        if start + 40 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 40];
        
        // Pattern: Multiple address comparisons (token checks)
        let eq_count = window.iter().filter(|&&b| b == 0x14).count(); // EQ
        let jumpi_count = window.iter().filter(|&&b| b == 0x57).count(); // JUMPI
        
        // If we have multiple comparisons but no final catch-all
        eq_count >= 2 && jumpi_count >= 2 && !window[30..].iter().any(|&b| b == 0xFD)
    }

    fn has_storage_write_after(&self, start: usize) -> bool {
        if start + 20 > self.bytecode.len() {
            return false;
        }
        
        self.bytecode[start..start + 20].iter().any(|&b| b == 0x55) // SSTORE
    }

    fn has_conditional_jump_between(&self, window: &[u8]) -> bool {
        window.iter().any(|&b| b == 0x57) // JUMPI
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_missing_else_clause() {
        // Bytecode with if/else if pattern without final else
        let bytecode = vec![
            0x57, // JUMPI (if)
            0x60, 0x00, // PUSH1 0
            0x57, // JUMPI (else if)
            0x60, 0x01, // PUSH1 1
            // No REVERT here (gap!)
            0x55, // SSTORE (state change)
        ];
        
        let detector = ConditionalLogicGapDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(!vulns.is_empty());
        assert!(vulns.iter().any(|v| matches!(v.gap_type, ConditionalGapType::MissingElseClause)));
    }

    #[test]
    fn test_parameter_mismatch() {
        // Bytecode that validates one param but uses another
        let bytecode = vec![
            0x35, // CALLDATALOAD (param 1)
            0x10, // LT (validate)
            0x35, // CALLDATALOAD (param 2 - different!)
            0x55, // SSTORE (use param 2)
        ];
        
        let detector = ConditionalLogicGapDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.gap_type, ConditionalGapType::ParameterValidationBypass)));
    }
}
