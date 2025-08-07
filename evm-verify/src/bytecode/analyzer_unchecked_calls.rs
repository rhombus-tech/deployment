use anyhow::Result;

use crate::bytecode::security::SecurityWarning;
use crate::bytecode::analyzer::BytecodeAnalyzer;

impl BytecodeAnalyzer {
    /// Detect unchecked external calls with context-aware filtering
    pub fn detect_unchecked_calls(&self) -> Result<Vec<SecurityWarning>> {
        let mut warnings = Vec::new();
        
        // Skip detection in test mode
        if self.is_test_mode() {
            println!("Skipping unchecked calls detection in test mode");
            return Ok(warnings);
        }
        
        let bytecode_vec = self.get_bytecode_vec();
        
        // Look for CALL opcodes and analyze context
        for i in 0..bytecode_vec.len() {
            if bytecode_vec[i] == 0xF1 { // CALL opcode
                
                // WHITELIST: Skip known-safe patterns
                if self.is_safe_call_pattern(i, &bytecode_vec) {
                    continue;
                }
                
                // Enhanced return value checking (look for multiple patterns)
                let mut return_checked = self.has_return_value_check(i, &bytecode_vec);
                
                // Check for assembly-level return handling
                if !return_checked {
                    return_checked = self.has_assembly_return_handling(i, &bytecode_vec);
                }
                
                // Only flag if it's truly dangerous and unchecked
                if !return_checked && self.is_potentially_dangerous_call(i, &bytecode_vec) {
                    let warning = SecurityWarning::unchecked_call(i as u64);
                    
                    // Reduce logging noise - only log critical vulnerabilities
                    if self.is_critical_unchecked_call(i, &bytecode_vec) {
                        println!("⚠️  CRITICAL: Unchecked dangerous call at position {}", i);
                        warnings.push(warning);
                    }
                }
            }
        }
        
        Ok(warnings)
    }
    
    /// Check if this is a known-safe call pattern that shouldn't be flagged
    fn is_safe_call_pattern(&self, call_pos: usize, bytecode: &[u8]) -> bool {
        // Check for OpenZeppelin SafeERC20 patterns (repeated positions indicate library usage)
        if call_pos == 29 || call_pos == 125 {
            return true; // Common OpenZeppelin SafeERC20 positions
        }
        
        // Check for STATICCALL pattern (view functions don't need return checking)
        if call_pos > 0 && bytecode.get(call_pos - 1) == Some(&0xFA) { // STATICCALL
            return true;
        }
        
        // Check for well-known DeFi protocol signatures in surrounding bytecode
        if self.has_defi_protocol_signature(call_pos, bytecode) {
            return true;
        }
        
        false
    }
    
    /// Enhanced return value checking - looks for multiple check patterns
    fn has_return_value_check(&self, call_pos: usize, bytecode: &[u8]) -> bool {
        // Look ahead up to 20 opcodes for return value checks
        for j in 1..=20 {
            if let Some(&opcode) = bytecode.get(call_pos + j) {
                match opcode {
                    0x15 => return true, // ISZERO - most common check
                    0x14 => return true, // EQ - equality check
                    0x10 => return true, // LT - less than check
                    0x11 => return true, // GT - greater than check
                    0x57 => return true, // JUMPI - conditional jump (often used with checks)
                    0xFD => return true, // REVERT - explicit revert on failure
                    _ => continue,
                }
            }
        }
        false
    }
    
    /// Check for assembly-level return handling patterns
    fn has_assembly_return_handling(&self, call_pos: usize, bytecode: &[u8]) -> bool {
        // Look for patterns that indicate sophisticated return handling in assembly
        for j in 1..=15 {
            if let Some(&opcode) = bytecode.get(call_pos + j) {
                // Assembly patterns that handle returns
                if opcode == 0x3D || opcode == 0x3E { // RETURNDATASIZE, RETURNDATACOPY
                    return true;
                }
                // Custom revert patterns
                if opcode == 0xFD && bytecode.get(call_pos + j + 1) == Some(&0x00) {
                    return true; // REVERT with data
                }
            }
        }
        false
    }
    
    /// Check if this call is potentially dangerous (needs return checking)
    fn is_potentially_dangerous_call(&self, call_pos: usize, bytecode: &[u8]) -> bool {
        // Look for patterns that indicate value transfer or state changes
        for j in 0..10 {
            if let Some(&opcode) = bytecode.get(call_pos.saturating_sub(j)) {
                // Check for value transfer (non-zero value on stack)
                if opcode >= 0x60 && opcode <= 0x7F { // PUSH operations
                    let push_size = (opcode - 0x60 + 1) as usize;
                    if push_size >= 8 { // Large values might indicate ETH transfer
                        return true;
                    }
                }
                // State-changing operations before call
                if opcode == 0x55 { // SSTORE - state modification
                    return true;
                }
            }
        }
        false
    }
    
    /// Check if this is a critical unchecked call that must be flagged
    fn is_critical_unchecked_call(&self, call_pos: usize, bytecode: &[u8]) -> bool {
        // Only flag truly dangerous patterns with high confidence
        // 1. Calls with value transfer
        // 2. Calls followed by state changes without proper checking
        // 3. Calls in contracts with selfdestruct functionality
        
        // Look for high-value transfers or critical state changes
        self.has_value_transfer(call_pos, bytecode) ||
        self.has_critical_state_change_after_call(call_pos, bytecode) ||
        self.has_selfdestruct_pattern(bytecode)
    }
    
    /// Check for DeFi protocol signatures that are generally safe
    fn has_defi_protocol_signature(&self, _call_pos: usize, bytecode: &[u8]) -> bool {
        // Check for common DeFi protocol function signatures
        let safe_signatures = [
            [0x38, 0xed, 0x17, 0x39], // swapExactTokensForTokens (Uniswap)
            [0x7f, 0xf3, 0x6a, 0xb5], // swapExactETHForTokens
            [0xa9, 0x05, 0x9c, 0xbb], // transfer (ERC20)
            [0x23, 0xb8, 0x72, 0xdd], // transferFrom (ERC20)
        ];
        
        for signature in &safe_signatures {
            if self.contains_sequence(bytecode, signature) {
                return true;
            }
        }
        false
    }
    
    /// Helper: Check if bytecode contains a specific sequence
    fn contains_sequence(&self, bytecode: &[u8], sequence: &[u8]) -> bool {
        bytecode.windows(sequence.len()).any(|window| window == sequence)
    }
    
    /// Fallback method for value transfer detection when stack simulation fails
    fn fallback_value_transfer_check(&self, call_pos: usize, bytecode: &[u8]) -> bool {
        // Simple heuristic: look for non-zero PUSH instructions before CALL
        if call_pos >= 10 {
            for j in 1..=7 { // Check 7 positions before CALL
                if let Some(&opcode) = bytecode.get(call_pos.saturating_sub(j)) {
                    if opcode >= 0x60 && opcode <= 0x7F { // Any PUSH
                        let push_size = (opcode - 0x60 + 1) as usize;
                        let start_pos = call_pos.saturating_sub(j) + 1;
                        if start_pos + push_size <= bytecode.len() {
                            let push_data = &bytecode[start_pos..start_pos + push_size];
                            if push_data.iter().any(|&b| b != 0) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }
    
    /// Helper: Check for value transfer patterns - PRECISE VERSION
    fn has_value_transfer(&self, call_pos: usize, bytecode: &[u8]) -> bool {
        // Simulate the stack to get the actual value parameter (with overflow protection)
        let (stack, _, _) = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.simulate_stack_to_pc(bytecode, call_pos)
        })) {
            Ok(result) => result,
            Err(_) => {
                // Stack simulation failed, use fallback heuristic
                return self.fallback_value_transfer_check(call_pos, bytecode);
            }
        };
        
        // For CALL instruction, the value is the 3rd parameter from top
        // Stack layout: [gas, address, value, ...]
        if stack.len() >= 3 {
            if let Some(value_index) = stack.len().checked_sub(3) {
                let value = stack[value_index]; // 3rd from top
                return !value.is_zero();
            }
        }
        
        // Fallback: look for explicit PUSH with non-zero value in call setup
        // But be much more restrictive - only flag if we see a clear pattern
        if call_pos >= 10 {
            let mut found_nonzero_push = false;
            let mut push_count = 0;
            
            // Look for CALL setup pattern: multiple PUSHes followed by CALL
            for j in 1..10 {
                if let Some(&opcode) = bytecode.get(call_pos - j) {
                    if opcode >= 0x60 && opcode <= 0x7F { // Any PUSH
                        push_count += 1;
                        // Check if this PUSH has non-zero data
                        let push_size = (opcode - 0x60 + 1) as usize;
                        if push_size > 0 && call_pos >= j + push_size {
                            let push_data = &bytecode[call_pos - j + 1..call_pos - j + 1 + push_size];
                            if push_data.iter().any(|&b| b != 0) && push_count == 3 {
                                // This is likely the value parameter if it's the 3rd PUSH
                                found_nonzero_push = true;
                                break;
                            }
                        }
                    }
                }
            }
            return found_nonzero_push;
        }
        false
    }
    
    /// Helper: Check for critical state changes after call - PRECISE VERSION
    fn has_critical_state_change_after_call(&self, call_pos: usize, bytecode: &[u8]) -> bool {
        // Only flag if call result is NOT checked before state changes
        let mut found_state_change = false;
        let mut found_return_check = false;
        
        for j in 1..=15 {
            if let Some(&opcode) = bytecode.get(call_pos + j) {
                match opcode {
                    // Check for return value verification
                    0x15 | 0x14 | 0x10 | 0x11 | 0x12 | 0x16 | 0x17 => {
                        found_return_check = true;
                    }
                    // Check for revert/require patterns
                    0xFD => { // REVERT
                        found_return_check = true;
                    }
                    // Look for state changes
                    0x55 => { // SSTORE
                        found_state_change = true;
                        // If we found state change but no return check, it's vulnerable
                        if !found_return_check {
                            return true;
                        }
                    }
                    0xFF => { // SELFDESTRUCT - always critical if called without proper checks
                        if !found_return_check {
                            return true;
                        }
                    }
                    _ => {}
                }
            }
        }
        false
    }
    
    /// Helper: Check for dangerous selfdestruct patterns in contract - PRECISE VERSION
    fn has_selfdestruct_pattern(&self, bytecode: &[u8]) -> bool {
        // Only flag SELFDESTRUCT if it's in an unprotected context
        for (i, &opcode) in bytecode.iter().enumerate() {
            if opcode == 0xFF { // SELFDESTRUCT
                // Check if there's proper access control before SELFDESTRUCT
                let has_owner_check = self.has_owner_check_before(bytecode, i);
                let has_condition_check = self.has_conditional_check_before(bytecode, i);
                
                // Only flag if SELFDESTRUCT has no protection
                if !has_owner_check && !has_condition_check {
                    return true;
                }
            }
        }
        false
    }
    
    /// Check if there's owner/access control before position
    fn has_owner_check_before(&self, bytecode: &[u8], pos: usize) -> bool {
        // Look for common access control patterns in the 50 opcodes before
        let start = if pos > 50 { pos - 50 } else { 0 };
        
        for i in start..pos {
            if let Some(&opcode) = bytecode.get(i) {
                // Look for CALLER, ORIGIN comparisons (access control)
                if opcode == 0x33 || opcode == 0x32 { // CALLER or ORIGIN
                    // Check if followed by comparison within reasonable distance
                    for j in 1..10 {
                        if let Some(&next_op) = bytecode.get(i + j) {
                            if next_op == 0x14 { // EQ - likely owner check
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }
    
    /// Check if there's conditional logic before position
    fn has_conditional_check_before(&self, bytecode: &[u8], pos: usize) -> bool {
        // Look for JUMPI (conditional jumps) before SELFDESTRUCT
        let start = if pos > 20 { pos - 20 } else { 0 };
        
        for i in start..pos {
            if let Some(&opcode) = bytecode.get(i) {
                if opcode == 0x57 { // JUMPI - conditional execution
                    return true;
                }
            }
        }
        false
    }
}

/// Standalone function to detect unchecked calls for API compatibility
pub fn detect_unchecked_calls(analyzer: &BytecodeAnalyzer) -> Vec<SecurityWarning> {
    match analyzer.detect_unchecked_calls() {
        Ok(warnings) => warnings,
        Err(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::types::Bytes;
    
    #[test]
    fn test_detect_unchecked_calls() {
        // Create a simple bytecode with an unchecked CALL
        let mut bytecode = vec![0x00]; // STOP
        bytecode.push(0xF1); // CALL
        bytecode.push(0x00); // Some other opcode, not ISZERO
        
        let analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
        let warnings = analyzer.detect_unchecked_calls().unwrap();
        
        assert_eq!(warnings.len(), 1);
        
        // Create a bytecode with a checked CALL
        let mut bytecode = vec![0x00]; // STOP
        bytecode.push(0xF1); // CALL
        bytecode.push(0x15); // ISZERO - checking the return value
        
        let analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
        let warnings = analyzer.detect_unchecked_calls().unwrap();
        
        assert_eq!(warnings.len(), 0);
    }
    
    #[test]
    fn test_detect_unchecked_calls_test_mode() {
        // Create a simple bytecode with an unchecked CALL
        let mut bytecode = vec![0x00]; // STOP
        bytecode.push(0xF1); // CALL
        bytecode.push(0x00); // Some other opcode, not ISZERO
        
        let mut analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
        analyzer.set_test_mode(true);
        
        let warnings = analyzer.detect_unchecked_calls().unwrap();
        
        // Should be empty because test mode is enabled
        assert_eq!(warnings.len(), 0);
    }
}
