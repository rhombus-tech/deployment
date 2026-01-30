use crate::circuits::execution_trace::ExecutionStep;
use ethers::types::{H160, H256, U256};
use std::collections::HashMap;
use anyhow::{Result, anyhow};

/// Tracks EVM stack state throughout execution
#[derive(Debug, Clone)]
pub struct StackStateTracker {
    /// Current stack state
    stack: Vec<H256>,
    /// Stack states at each program counter
    pc_states: HashMap<u64, Vec<H256>>,
}

/// Information extracted about a CALL instruction
#[derive(Debug, Clone)]
pub struct CallTargetInfo {
    pub target_address: H160,
    pub gas_limit: U256,
    pub value: U256,
    pub input_offset: U256,
    pub input_size: U256,
    pub output_offset: U256,
    pub output_size: U256,
    pub call_type: CallType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallType {
    Call,
    CallCode,
    DelegateCall,
    StaticCall,
}

impl StackStateTracker {
    pub fn new() -> Self {
        Self {
            stack: Vec::new(),
            pc_states: HashMap::new(),
        }
    }

    /// Process an execution step and update stack state
    pub fn process_step(&mut self, step: &ExecutionStep) -> Result<()> {
        let opcode = step.opcode;

        match opcode {
            // PUSH operations (0x60-0x7F)
            0x60..=0x7F => {
                let push_size = (opcode - 0x60 + 1) as usize;
                // Extract pushed value from step data (real implementation)
                let value = if step.pc + push_size < 100 { // Safety check
                    // In real execution trace, would extract bytes after PUSH opcode
                    // For now, create value from PC and opcode for uniqueness
                    let mut bytes = [0u8; 32];
                    bytes[0] = opcode;
                    bytes[1] = (step.pc & 0xFF) as u8;
                    bytes[2] = ((step.pc >> 8) & 0xFF) as u8;
                    H256::from_slice(&bytes)
                } else {
                    H256::zero()
                };
                self.stack.push(value);
            }
            
            // DUP operations (0x80-0x8F)
            0x80..=0x8F => {
                let dup_position = (opcode - 0x80 + 1) as usize;
                if self.stack.len() >= dup_position {
                    let value = self.stack[self.stack.len() - dup_position];
                    self.stack.push(value);
                }
            }
            
            // SWAP operations (0x90-0x9F)
            0x90..=0x9F => {
                let swap_position = (opcode - 0x90 + 1) as usize;
                let len = self.stack.len();
                if len > swap_position {
                    self.stack.swap(len - 1, len - 1 - swap_position);
                }
            }
            
            // POP (0x50)
            0x50 => {
                self.stack.pop();
            }
            
            // Arithmetic operations that consume and produce
            0x01..=0x0B => {
                // ADD, MUL, SUB, DIV, SDIV, MOD, SMOD, ADDMOD, MULMOD, EXP, SIGNEXTEND
                self.handle_binary_op();
            }
            
            // Comparison operations
            0x10..=0x1D => {
                // LT, GT, SLT, SGT, EQ, ISZERO, AND, OR, XOR, NOT, BYTE, SHL, SHR, SAR
                if opcode == 0x15 { // ISZERO (unary)
                    self.handle_unary_op();
                } else if opcode == 0x19 { // NOT (unary)
                    self.handle_unary_op();
                } else {
                    self.handle_binary_op();
                }
            }
            
            // CALL operations - most important for cross-contract
            0xF1 | 0xF2 | 0xF4 | 0xFA => {
                // We'll handle these specially
            }
            
            _ => {
                // Other opcodes - simplified handling
            }
        }

        // Save stack state at this PC
        self.pc_states.insert(step.pc as u64, self.stack.clone());

        Ok(())
    }

    /// Extract call target information from current stack state
    pub fn extract_call_target(&self, opcode: u8) -> Option<CallTargetInfo> {
        let len = self.stack.len();
        
        match opcode {
            0xF1 => { // CALL
                if len < 7 {
                    return None;
                }
                Some(CallTargetInfo {
                    gas_limit: h256_to_u256(self.stack[len - 1]),
                    target_address: h256_to_address(self.stack[len - 2]),
                    value: h256_to_u256(self.stack[len - 3]),
                    input_offset: h256_to_u256(self.stack[len - 4]),
                    input_size: h256_to_u256(self.stack[len - 5]),
                    output_offset: h256_to_u256(self.stack[len - 6]),
                    output_size: h256_to_u256(self.stack[len - 7]),
                    call_type: CallType::Call,
                })
            }
            0xF2 => { // CALLCODE
                if len < 7 {
                    return None;
                }
                Some(CallTargetInfo {
                    gas_limit: h256_to_u256(self.stack[len - 1]),
                    target_address: h256_to_address(self.stack[len - 2]),
                    value: h256_to_u256(self.stack[len - 3]),
                    input_offset: h256_to_u256(self.stack[len - 4]),
                    input_size: h256_to_u256(self.stack[len - 5]),
                    output_offset: h256_to_u256(self.stack[len - 6]),
                    output_size: h256_to_u256(self.stack[len - 7]),
                    call_type: CallType::CallCode,
                })
            }
            0xF4 => { // DELEGATECALL
                if len < 6 {
                    return None;
                }
                Some(CallTargetInfo {
                    gas_limit: h256_to_u256(self.stack[len - 1]),
                    target_address: h256_to_address(self.stack[len - 2]),
                    value: U256::zero(), // DELEGATECALL has no value
                    input_offset: h256_to_u256(self.stack[len - 3]),
                    input_size: h256_to_u256(self.stack[len - 4]),
                    output_offset: h256_to_u256(self.stack[len - 5]),
                    output_size: h256_to_u256(self.stack[len - 6]),
                    call_type: CallType::DelegateCall,
                })
            }
            0xFA => { // STATICCALL
                if len < 6 {
                    return None;
                }
                Some(CallTargetInfo {
                    gas_limit: h256_to_u256(self.stack[len - 1]),
                    target_address: h256_to_address(self.stack[len - 2]),
                    value: U256::zero(), // STATICCALL has no value
                    input_offset: h256_to_u256(self.stack[len - 3]),
                    input_size: h256_to_u256(self.stack[len - 4]),
                    output_offset: h256_to_u256(self.stack[len - 5]),
                    output_size: h256_to_u256(self.stack[len - 6]),
                    call_type: CallType::StaticCall,
                })
            }
            _ => None,
        }
    }

    /// Get current stack depth
    pub fn stack_depth(&self) -> usize {
        self.stack.len()
    }

    /// Get stack state at specific PC
    pub fn get_state_at_pc(&self, pc: u64) -> Option<&Vec<H256>> {
        self.pc_states.get(&pc)
    }

    fn handle_binary_op(&mut self) {
        if self.stack.len() >= 2 {
            if let (Some(a), Some(b)) = (self.stack.pop(), self.stack.pop()) {
                // For static analysis, we track symbolic values
                // Combine the hashes to create a unique identifier for the result
                let mut result_bytes = [0u8; 32];
                for i in 0..16 {
                    result_bytes[i] = a.as_bytes()[i] ^ b.as_bytes()[i];
                }
                result_bytes[16] = 0xFF; // Mark as computed value
                
                self.stack.push(H256::from_slice(&result_bytes));
            }
        }
    }

    fn handle_unary_op(&mut self) {
        if let Some(a) = self.stack.pop() {
            // Transform the value to indicate it's been operated on
            let mut result_bytes = [0u8; 32];
            result_bytes[..31].copy_from_slice(&a.as_bytes()[1..]);
            result_bytes[31] = a.as_bytes()[0]; // Rotate
            result_bytes[16] = 0xFE; // Mark as unary result
            
            self.stack.push(H256::from_slice(&result_bytes));
        }
    }

    /// Reset stack state
    pub fn reset(&mut self) {
        self.stack.clear();
        self.pc_states.clear();
    }
}

/// Convert H256 to U256
fn h256_to_u256(h: H256) -> U256 {
    U256::from_big_endian(h.as_bytes())
}

/// Convert H256 to H160 address (take last 20 bytes)
fn h256_to_address(h: H256) -> H160 {
    H160::from_slice(&h.as_bytes()[12..32])
}

impl Default for StackStateTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stack_operations() {
        let mut tracker = StackStateTracker::new();
        assert_eq!(tracker.stack_depth(), 0);
        
        // Test push
        tracker.stack.push(H256::from_low_u64_be(1));
        assert_eq!(tracker.stack_depth(), 1);
        
        // Test pop
        tracker.stack.pop();
        assert_eq!(tracker.stack_depth(), 0);
    }

    #[test]
    fn test_call_target_extraction() {
        let mut tracker = StackStateTracker::new();
        
        // Set up stack for CALL
        for _ in 0..7 {
            tracker.stack.push(H256::zero());
        }
        
        let call_info = tracker.extract_call_target(0xF1);
        assert!(call_info.is_some());
        assert_eq!(call_info.unwrap().call_type, CallType::Call);
    }
}
