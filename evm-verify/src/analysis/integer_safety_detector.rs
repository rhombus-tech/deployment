// Integer overflow/underflow detector
// Detects BeautyChain-style vulnerabilities and unchecked arithmetic

use crate::bytecode::security::SecuritySeverity;
use crate::analysis::contract_metadata_parser::{MetadataParser, ContractMetadata};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegerVulnerability {
    pub pc: usize,
    pub severity: SecuritySeverity,
    pub operation: ArithmeticOp,
    pub description: String,
    pub has_safe_math: bool,
    pub confidence: f32,
    pub affected_operation: String,
    pub solidity_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ArithmeticOp {
    Addition,      // ADD
    Multiplication, // MUL
    Subtraction,   // SUB
    Division,      // DIV
    Modulo,        // MOD
    Exponentiation, // EXP
}

pub struct IntegerSafetyDetector {
    bytecode: Vec<u8>,
}

impl IntegerSafetyDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<IntegerVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // CRITICAL: Parse contract metadata to detect Solidity version
        let metadata = MetadataParser::parse(&self.bytecode);
        
        // Debug: Print metadata detection results
        eprintln!("[METADATA] has_metadata={}, has_solc_0_8_plus={}, version={:?}", 
                  metadata.has_metadata, metadata.has_solc_0_8_plus, metadata.solidity_version);
        
        // If Solidity 0.8+, arithmetic is automatically checked - very low confidence
        if metadata.has_solc_0_8_plus {
            eprintln!("[METADATA] Contract has Solidity 0.8+ - skipping integer vulnerability detection");
            // Contract has built-in overflow protection - no vulnerabilities
            return vulnerabilities;
        }
        
        // Find all arithmetic operations
        let arithmetic_ops = self.find_arithmetic_operations();
        
        for op_info in arithmetic_ops {
            // CRITICAL: Check if THIS SPECIFIC operation has overflow protection
            // Don't rely on global metrics - BeautyChain had 23.8% protection but still vulnerable
            // because ONE specific MUL operation was unprotected
            let has_local_check = self.has_overflow_check_near(op_info.pc);
            
            // Only flag if THIS operation is unprotected
            if !has_local_check {
                let severity = match op_info.operation {
                    ArithmeticOp::Multiplication | ArithmeticOp::Addition => {
                        // MUL and ADD are most dangerous for overflow
                        SecuritySeverity::High
                    }
                    ArithmeticOp::Subtraction => {
                        // SUB can underflow
                        SecuritySeverity::High
                    }
                    ArithmeticOp::Exponentiation => {
                        // EXP can overflow catastrophically
                        SecuritySeverity::Critical
                    }
                    _ => SecuritySeverity::Medium,
                };
                
                // Calculate confidence based on risk factors and context
                let is_defi = self.is_defi_contract();
                let has_any_protection = self.has_any_overflow_protection();
                
                // Start with base confidence
                let mut confidence: f32 = if has_any_protection {
                    // Contract has SOME protection elsewhere, so unprotected ops might be intentional/benign
                    0.65
                } else {
                    // NO protection anywhere - higher confidence this is vulnerable
                    0.80
                };
                
                if op_info.in_loop {
                    confidence = 0.95;  // Very high confidence - arithmetic in loop is dangerous
                }
                
                // Adjust for operation type
                if matches!(op_info.operation, ArithmeticOp::Multiplication) {
                    if is_defi && has_any_protection {
                        // DeFi contract with some protection - unprotected MUL might be intentional (Uniswap)
                        confidence += 0.10;  // 65 + 10 = 75% (below threshold)
                    } else if has_any_protection {
                        // Non-DeFi contract with protection - unprotected MUL is suspicious (BeautyChain)
                        confidence += 0.20;  // 65 + 20 = 85%
                    } else {
                        // No protection anywhere - very suspicious
                        confidence += 0.15;  // 80 + 15 = 95%
                    }
                }
                
                if matches!(op_info.operation, ArithmeticOp::Exponentiation) {
                    if is_defi {
                        // DeFi EXP is often for interest calculations
                        confidence += 0.05;  // Low confidence
                    } else {
                        confidence += 0.15;  // High confidence for non-DeFi
                    }
                }
                
                // Cap at 0.95 and round to avoid floating point precision issues
                confidence = confidence.min(0.95);
                confidence = (confidence * 100.0).round() / 100.0;  // Round to 2 decimal places
                
                let description = if metadata.has_metadata {
                    format!(
                        "Unchecked {:?} at PC {}. Contract compiled with Solidity {} \
                        (pre-0.8). No SafeMath library detected and no manual validation. \
                        This operation can {} and cause unexpected behavior.",
                        op_info.operation,
                        op_info.pc,
                        metadata.solidity_version.as_ref().unwrap_or(&"unknown".to_string()),
                        match op_info.operation {
                            ArithmeticOp::Addition | ArithmeticOp::Multiplication | 
                            ArithmeticOp::Exponentiation => "overflow",
                            ArithmeticOp::Subtraction => "underflow",
                            _ => "produce invalid results",
                        }
                    )
                } else {
                    format!(
                        "Unchecked {:?} at PC {}. No SafeMath library detected, \
                        no Solidity 0.8+ overflow checks, and no manual validation. \
                        This operation can {} and cause unexpected behavior.",
                        op_info.operation,
                        op_info.pc,
                        match op_info.operation {
                            ArithmeticOp::Addition | ArithmeticOp::Multiplication | 
                            ArithmeticOp::Exponentiation => "overflow",
                            ArithmeticOp::Subtraction => "underflow",
                            _ => "produce invalid results",
                        }
                    )
                };
                
                vulnerabilities.push(IntegerVulnerability {
                    pc: op_info.pc,
                    severity,
                    operation: op_info.operation.clone(),
                    description,
                    has_safe_math: false,
                    confidence,
                    affected_operation: format!("{:?}", op_info.operation),
                    solidity_version: metadata.solidity_version.clone(),
                });
            }
        }
        
        vulnerabilities
    }
    
    fn find_arithmetic_operations(&self) -> Vec<ArithmeticOpInfo> {
        let mut ops = Vec::new();
        let mut pc = 0;
        let mut in_loop = false;
        let mut loop_start = None;
        
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // Detect loops (JUMPDEST that's jumped to)
            if opcode == 0x5B {  // JUMPDEST
                // Simple heuristic: if we see JUMPI going backwards, it's a loop
                if let Some(start) = loop_start {
                    if start == pc {
                        in_loop = true;
                    }
                }
            }
            
            // Detect arithmetic operations
            let operation = match opcode {
                0x01 => Some(ArithmeticOp::Addition),
                0x02 => Some(ArithmeticOp::Multiplication),
                0x03 => Some(ArithmeticOp::Subtraction),
                0x04 => Some(ArithmeticOp::Division),
                0x06 => Some(ArithmeticOp::Modulo),
                0x0A => Some(ArithmeticOp::Exponentiation),
                _ => None,
            };
            
            if let Some(op) = operation {
                ops.push(ArithmeticOpInfo {
                    pc,
                    operation: op,
                    in_loop,
                });
            }
            
            // Track backwards jumps (loop indicators)
            if opcode == 0x57 {  // JUMPI
                // Check if next instruction is a backward jump
                loop_start = Some(pc);
            }
            
            pc += 1;
            
            // Skip PUSH data
            if opcode >= 0x60 && opcode <= 0x7F {
                let push_bytes = (opcode - 0x5F) as usize;
                pc += push_bytes;
            }
        }
        
        ops
    }
    
    fn has_safe_math_library(&self) -> bool {
        // Look for SafeMath patterns:
        // 1. ADD followed by overflow check
        // 2. MUL followed by division check  
        // 3. SUB followed by underflow check
        // 4. Count protected arithmetic operations
        
        let mut pc = 0;
        let mut protected_ops = 0;
        let mut total_risky_ops = 0;
        
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // Track all risky arithmetic
            if matches!(opcode, 0x01 | 0x02 | 0x03) {  // ADD, MUL, SUB
                total_risky_ops += 1;
                
                // Check if this operation has overflow protection
                if self.has_revert_after(pc, 20) {
                    protected_ops += 1;
                }
            }
            
            pc += 1;
            
            // Skip PUSH data
            if opcode >= 0x60 && opcode <= 0x7F {
                let push_bytes = (opcode - 0x5F) as usize;
                pc += push_bytes;
            }
        }
        
        // If 15%+ of risky operations have protection, assume SafeMath is used
        // Lowered threshold: not all operations need protection, only the risky user-facing ones
        // Well-audited contracts like USDC have selective protection
        if total_risky_ops > 0 {
            let protection_rate = protected_ops as f32 / total_risky_ops as f32;
            
            // If any meaningful protection exists (10%+), return true
            protection_rate >= 0.10
        } else {
            false
        }
    }
    
    fn has_overflow_checks(&self) -> bool {
        // Solidity 0.8+ inserts automatic overflow checks
        // Look for pattern: arithmetic op followed by comparison and revert
        
        let mut pc = 0;
        let mut check_count = 0;
        let mut total_ops = 0;
        
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // Arithmetic operation
            if matches!(opcode, 0x01 | 0x02 | 0x03) {  // ADD, MUL, SUB
                total_ops += 1;
                // Check if there's a revert within next few instructions
                if self.has_revert_after(pc, 20) {
                    check_count += 1;
                }
            }
            
            pc += 1;
            
            // Skip PUSH data
            if opcode >= 0x60 && opcode <= 0x7F {
                let push_bytes = (opcode - 0x5F) as usize;
                pc += push_bytes;
            }
        }
        
        // If 10%+ of operations have checks, assume overflow protection is present
        if total_ops > 0 {
            let check_rate = check_count as f32 / total_ops as f32;
            check_rate >= 0.10
        } else {
            false
        }
    }
    
    fn has_overflow_check_near(&self, op_pc: usize) -> bool {
        // Check if there's overflow validation within next 20 instructions
        self.has_revert_after(op_pc, 20)
    }
    
    /// Check if contract has ANY overflow protection (for confidence adjustment)
    fn has_any_overflow_protection(&self) -> bool {
        // Quick check: does contract have SafeMath library or Solidity 0.8+ checks?
        self.has_safe_math_library() || self.has_overflow_checks()
    }
    
    fn has_revert_after(&self, start_pc: usize, window: usize) -> bool {
        let mut pc = start_pc + 1;
        let end_pc = (start_pc + window).min(self.bytecode.len());
        let mut found_comparison = false;
        let mut found_dup = false;
        
        while pc < end_pc {
            let opcode = self.bytecode[pc];
            
            // Look for DUP operations FIRST (Solidity 0.8+ pattern)
            if matches!(opcode, 0x80..=0x8F) {  // DUP1-DUP16
                found_dup = true;
            }
            
            // Look for comparison operations (indicates overflow check)
            if matches!(opcode, 0x10 | 0x11 | 0x12 | 0x13 | 0x14 | 0x15) {
                // LT, GT, SLT, SGT, EQ, ISZERO
                found_comparison = true;
            }
            
            // Look for REVERT (0xFD) or INVALID (0xFE)
            if opcode == 0xFD || opcode == 0xFE {
                return true;
            }
            
            // Solidity 0.8+ pattern: op → DUP → comparison → JUMPI
            if opcode == 0x57 {  // JUMPI
                if found_dup && found_comparison {
                    return true;  // Strong signal of overflow check
                }
                if found_comparison {
                    return true;  // SafeMath pattern without DUP
                }
            }
            
            // SWAP operations often used in overflow checks
            if matches!(opcode, 0x90..=0x9F) && found_comparison {
                return true;
            }
            
            pc += 1;
            
            // Skip PUSH data
            if opcode >= 0x60 && opcode <= 0x7F {
                let push_bytes = (opcode - 0x5F) as usize;
                pc += push_bytes;
            }
        }
        
        false
    }
    
    /// Detect if this is a complex DeFi protocol (not just a simple ERC20 token)
    /// Returns true for Uniswap, Compound, Aave, etc. - NOT for basic ERC20 tokens
    fn is_defi_contract(&self) -> bool {
        // Heuristic 1: Very large bytecode (>15KB) is usually complex DeFi
        // Uniswap V3 pools, Curve pools, etc. are massive
        if self.bytecode.len() > 15000 {
            return true;
        }
        
        // Heuristic 2: Check for ADVANCED DeFi functions (not just ERC20)
        let advanced_defi_signatures = [
            // Compound/lending (NOT in basic tokens)
            [0xb2, 0xa0, 0x2f, 0xf1], // exchangeRateCurrent()
            [0xbd, 0x6d, 0x89, 0x4f], // borrowRatePerBlock()
            [0x15, 0xf2, 0x40, 0x53], // supplyRatePerBlock()
            [0x09, 0xe3, 0x77, 0xab], // borrow()
            [0x57, 0x3e, 0xad, 0x1b], // repay()
            // Uniswap V2/AMM (NOT in basic tokens)
            [0x02, 0x2c, 0x0d, 0x9f], // swap()
            [0xe8, 0xe3, 0x37, 0x00], // addLiquidity()
            [0x44, 0x31, 0xd7, 0x94], // removeLiquidity()
            [0x09, 0x02, 0xf1, 0xac], // getReserves()
            // Uniswap V3 pool (concentrated liquidity)
            [0x12, 0x8a, 0xcb, 0x08], // swap(address,bool,int256,uint160,bytes)
            [0x6c, 0x19, 0xe7, 0x83], // mint(address,int24,int24,uint128,bytes)
            [0xa3, 0x4b, 0x03, 0xf7], // burn(int24,int24,uint128)
            [0x85, 0x26, 0xfc, 0x06], // collect(address,int24,int24,uint128,uint128)
            // Curve pools (stableswap)
            [0x5b, 0x36, 0x38, 0x9c], // exchange(int128,int128,uint256,uint256)
            [0x3d, 0xf0, 0x21, 0x24], // add_liquidity(uint256[],uint256)
            // Vault protocols (NOT in basic tokens)
            [0x99, 0x53, 0x0b, 0x06], // pricePerShare()
            [0x01, 0xe1, 0xd1, 0x14], // totalAssets()
        ];
        
        let mut matches = 0;
        for sig in &advanced_defi_signatures {
            for i in 0..self.bytecode.len().saturating_sub(4) {
                let candidate = [
                    self.bytecode[i],
                    self.bytecode[i + 1],
                    self.bytecode[i + 2],
                    self.bytecode[i + 3],
                ];
                if candidate == *sig {
                    matches += 1;
                    break;
                }
            }
        }
        
        // Require 2+ ADVANCED functions to be considered DeFi
        // This excludes simple ERC20 tokens like BeautyChain
        matches >= 2
    }
}

#[derive(Debug, Clone)]
struct ArithmeticOpInfo {
    pc: usize,
    operation: ArithmeticOp,
    in_loop: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_unchecked_add() {
        // Bytecode with unchecked ADD
        let bytecode = vec![
            0x60, 0x01,  // PUSH1 1
            0x60, 0x02,  // PUSH1 2
            0x01,        // ADD (no overflow check!)
        ];
        
        let detector = IntegerSafetyDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(!vulns.is_empty(), "Should detect unchecked addition");
        assert_eq!(vulns[0].operation, ArithmeticOp::Addition);
    }
    
    #[test]
    fn test_safe_math_pattern() {
        // Bytecode with SafeMath-style check
        let bytecode = vec![
            0x60, 0x01,  // PUSH1 1
            0x60, 0x02,  // PUSH1 2
            0x01,        // ADD
            0x80,        // DUP1
            0x10,        // LT (check overflow)
            0x15,        // ISZERO
            0xFD,        // REVERT if overflow
        ];
        
        let detector = IntegerSafetyDetector::new(bytecode);
        let has_safe = detector.has_safe_math_library();
        
        assert!(has_safe, "Should detect SafeMath pattern");
    }
}
