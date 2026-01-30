use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvmWasmTranslationVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct EvmToWasmBytecodeTranslationBugDetector {
    bytecode: Vec<u8>,
}

impl EvmToWasmBytecodeTranslationBugDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<EvmWasmTranslationVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_memory_model_mismatch());
        vulnerabilities.extend(self.detect_stack_depth_translation_error());
        vulnerabilities.extend(self.detect_gas_metering_discrepancy());

        vulnerabilities
    }

    fn detect_memory_model_mismatch(&self) -> Vec<EvmWasmTranslationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if matches!(opcode, 0x51 | 0x52 | 0x53) { // MLOAD, MSTORE, MSTORE8
                let start = if pc > 80 { pc - 80 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_large_offset = window.windows(2).any(|w| {
                    w[0] >= 0x62 && w[0] <= 0x7F // PUSH3 or larger (>64KB offset)
                });
                
                if has_large_offset {
                    vulns.push(EvmWasmTranslationVulnerability {
                        pc,
                        vulnerability_type: "MemoryModelMismatch".to_string(),
                        description: format!(
                            "Memory operation at PC {} uses large offset incompatible with WASM linear memory. \
                            EVM supports unlimited memory expansion, WASM has initial 64KB pages requiring explicit growth. \
                            Translation bug: WASM compiler may not insert memory.grow instructions for large allocations, \
                            causing out-of-bounds access. Missing: explicit memory expansion checks, page boundary validation, \
                            WASM-specific memory limits. EVM bytecode relying on automatic expansion fails on WASM.",
                            pc
                        ),
                        confidence: 0.84,
                    });
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_stack_depth_translation_error(&self) -> Vec<EvmWasmTranslationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        let mut max_stack_depth = 0;
        let mut current_depth: usize = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            match opcode {
                0x50 => current_depth = current_depth.saturating_sub(1), // POP
                0x80..=0x8F => current_depth += (opcode - 0x7F) as usize, // DUP1-DUP16
                0x90..=0x9F => {}, // SWAP doesn't change depth
                _ if opcode >= 0x60 && opcode <= 0x7F => current_depth += 1, // PUSH
                _ => {
                    let (inputs, outputs) = Self::get_opcode_stack_effect(opcode);
                    current_depth = current_depth.saturating_sub(inputs).saturating_add(outputs);
                }
            }

            max_stack_depth = max_stack_depth.max(current_depth);

            if max_stack_depth > 1000 {
                vulns.push(EvmWasmTranslationVulnerability {
                    pc,
                    vulnerability_type: "StackDepthTranslationError".to_string(),
                    description: format!(
                        "Stack depth {} at PC {} exceeds WASM local variable limits. EVM allows 1024 stack items, \
                        WASM translates to local variables with compiler-specific limits. Deep stacks cause: \
                        (1) WASM compilation failure, (2) different execution semantics, (3) local variable overflow. \
                        Missing: stack depth optimization for WASM, local variable pooling, stack-to-memory spilling. \
                        Code valid in EVM may fail or behave differently in WASM translation.",
                        max_stack_depth, pc
                    ),
                    confidence: 0.87,
                });
                break;
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_gas_metering_discrepancy(&self) -> Vec<EvmWasmTranslationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x5A { // GAS opcode
                let window_end = (pc + 60).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_comparison = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                let has_revert = window.iter().any(|&b| b == 0xFD); // REVERT
                
                if has_comparison && has_revert {
                    vulns.push(EvmWasmTranslationVulnerability {
                        pc,
                        vulnerability_type: "GasMeteringDiscrepancy".to_string(),
                        description: format!(
                            "Gas check at PC {} relies on precise EVM gas metering. WASM translation introduces \
                            metering discrepancies: (1) instruction costs differ between EVM/WASM, (2) WASM gas \
                            injection is less granular, (3) memory operations have different costs. Code using \
                            exact gas amounts for logic (e.g., `gasleft() < 2300`) breaks. Missing: WASM-compatible \
                            gas abstractions, tolerance margins, platform-agnostic gas checks. Causes DoS or logic bypass.",
                            pc
                        ),
                        confidence: 0.85,
                    });
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn get_opcode_stack_effect(opcode: u8) -> (usize, usize) {
        match opcode {
            0x00..=0x0B => (2, 1), // Arithmetic ops
            0x10..=0x1A => (2, 1), // Comparison ops
            0x20 => (2, 1), // KECCAK256
            0x30..=0x3F => (0, 1), // Environmental info
            0x40..=0x48 => (0, 1), // Block info
            0x50 => (1, 0), // POP
            0x51..=0x5F => (1, 1), // Memory/Storage ops
            0xA0..=0xA4 => (2 + (opcode - 0xA0) as usize, 0), // LOG operations
            0xF0 => (3, 1), // CREATE
            0xF1 | 0xF2 => (7, 1), // CALL, CALLCODE
            0xF3 | 0xFD => (2, 0), // RETURN, REVERT
            0xF4 => (6, 1), // DELEGATECALL
            0xFA => (6, 1), // STATICCALL
            0xF5 => (4, 1), // CREATE2
            0xFF => (1, 0), // SELFDESTRUCT
            _ => (0, 0),
        }
    }
}
