use anyhow::Result;
use std::collections::HashMap;
use std::io::{Read, Write};

/// Williams compression algorithm implementation
/// 
/// This implements a lossless compression algorithm optimized for WASM bytecode,
/// taking advantage of WASM's structured format and common patterns.
pub struct WilliamsCompressor {
    /// Dictionary for common WASM instruction patterns
    instruction_dictionary: HashMap<Vec<u8>, u16>,
    /// Dictionary for common constant values
    constant_dictionary: HashMap<i64, u8>,
    /// Dictionary for common function signatures
    signature_dictionary: HashMap<Vec<u8>, u8>,
}

impl WilliamsCompressor {
    /// Create a new Williams compressor with pre-built dictionaries
    pub fn new() -> Self {
        let mut compressor = Self {
            instruction_dictionary: HashMap::new(),
            constant_dictionary: HashMap::new(),
            signature_dictionary: HashMap::new(),
        };
        
        compressor.build_wasm_dictionaries();
        compressor
    }

    /// Compress WASM bytecode using Williams algorithm
    pub fn compress(&self, wasm_bytes: &[u8]) -> Result<Vec<u8>> {
        let mut compressed = Vec::new();
        
        // Write magic header for Williams compression
        compressed.extend_from_slice(b"WLMS"); // Williams Magic Signature
        compressed.extend_from_slice(&(wasm_bytes.len() as u32).to_le_bytes());
        
        let mut pos = 0;
        while pos < wasm_bytes.len() {
            // Try to match instruction patterns
            if let Some((pattern_len, dict_id)) = self.find_instruction_pattern(&wasm_bytes[pos..]) {
                // Write pattern marker (0xFF) followed by dictionary ID
                compressed.push(0xFF);
                compressed.extend_from_slice(&dict_id.to_le_bytes());
                pos += pattern_len;
                continue;
            }
            
            // Try to match constant patterns
            if pos + 8 <= wasm_bytes.len() {
                let potential_constant = i64::from_le_bytes(
                    wasm_bytes[pos..pos+8].try_into().unwrap_or([0; 8])
                );
                if let Some(&dict_id) = self.constant_dictionary.get(&potential_constant) {
                    // Write constant marker (0xFE) followed by dictionary ID
                    compressed.push(0xFE);
                    compressed.push(dict_id);
                    pos += 8;
                    continue;
                }
            }
            
            // Check for repeating sequences
            if let Some((repeat_len, repeat_count)) = self.find_repeating_sequence(&wasm_bytes[pos..]) {
                if repeat_len >= 4 && repeat_count >= 3 {
                    // Write repeat marker (0xFD) followed by length and count
                    compressed.push(0xFD);
                    compressed.push(repeat_len as u8);
                    compressed.push(repeat_count as u8);
                    // Write the pattern once
                    compressed.extend_from_slice(&wasm_bytes[pos..pos + repeat_len]);
                    pos += repeat_len * repeat_count;
                    continue;
                }
            }
            
            // Check for zero runs
            let zero_run_len = self.count_zero_run(&wasm_bytes[pos..]);
            if zero_run_len >= 4 {
                // Write zero run marker (0xFC) followed by length
                compressed.push(0xFC);
                compressed.extend_from_slice(&(zero_run_len as u16).to_le_bytes());
                pos += zero_run_len;
                continue;
            }
            
            // No pattern found, write byte as-is
            compressed.push(wasm_bytes[pos]);
            pos += 1;
        }
        
        Ok(compressed)
    }

    /// Decompress Williams-compressed WASM bytecode
    pub fn decompress(&self, compressed_bytes: &[u8]) -> Result<Vec<u8>> {
        if compressed_bytes.len() < 8 {
            anyhow::bail!("Invalid Williams compressed format: too short");
        }
        
        // Verify magic header
        if &compressed_bytes[0..4] != b"WLMS" {
            anyhow::bail!("Invalid Williams compressed format: bad magic");
        }
        
        let original_size = u32::from_le_bytes(
            compressed_bytes[4..8].try_into()
                .map_err(|_| anyhow::anyhow!("Invalid size header"))?
        ) as usize;
        
        let mut decompressed = Vec::with_capacity(original_size);
        let mut pos = 8; // Skip header
        
        while pos < compressed_bytes.len() {
            match compressed_bytes[pos] {
                0xFF => {
                    // Instruction pattern
                    if pos + 3 > compressed_bytes.len() {
                        anyhow::bail!("Truncated instruction pattern");
                    }
                    let dict_id = u16::from_le_bytes([compressed_bytes[pos + 1], compressed_bytes[pos + 2]]);
                    if let Some(pattern) = self.get_instruction_pattern(dict_id) {
                        decompressed.extend_from_slice(&pattern);
                    } else {
                        anyhow::bail!("Invalid instruction pattern ID: {}", dict_id);
                    }
                    pos += 3;
                }
                0xFE => {
                    // Constant pattern
                    if pos + 2 > compressed_bytes.len() {
                        anyhow::bail!("Truncated constant pattern");
                    }
                    let dict_id = compressed_bytes[pos + 1];
                    if let Some(constant) = self.get_constant_value(dict_id) {
                        decompressed.extend_from_slice(&constant.to_le_bytes());
                    } else {
                        anyhow::bail!("Invalid constant pattern ID: {}", dict_id);
                    }
                    pos += 2;
                }
                0xFD => {
                    // Repeating sequence
                    if pos + 3 > compressed_bytes.len() {
                        anyhow::bail!("Truncated repeat pattern");
                    }
                    let repeat_len = compressed_bytes[pos + 1] as usize;
                    let repeat_count = compressed_bytes[pos + 2] as usize;
                    
                    if pos + 3 + repeat_len > compressed_bytes.len() {
                        anyhow::bail!("Truncated repeat pattern data");
                    }
                    
                    let pattern = &compressed_bytes[pos + 3..pos + 3 + repeat_len];
                    for _ in 0..repeat_count {
                        decompressed.extend_from_slice(pattern);
                    }
                    pos += 3 + repeat_len;
                }
                0xFC => {
                    // Zero run
                    if pos + 3 > compressed_bytes.len() {
                        anyhow::bail!("Truncated zero run");
                    }
                    let zero_len = u16::from_le_bytes([compressed_bytes[pos + 1], compressed_bytes[pos + 2]]) as usize;
                    decompressed.extend(vec![0; zero_len]);
                    pos += 3;
                }
                byte => {
                    // Literal byte
                    decompressed.push(byte);
                    pos += 1;
                }
            }
        }
        
        if decompressed.len() != original_size {
            anyhow::bail!(
                "Decompression size mismatch: expected {}, got {}", 
                original_size, 
                decompressed.len()
            );
        }
        
        Ok(decompressed)
    }

    /// Build dictionaries for common WASM patterns
    fn build_wasm_dictionaries(&mut self) {
        // Common WASM instruction sequences
        let common_patterns = vec![
            // Function prologue patterns
            vec![0x20, 0x00], // local.get 0
            vec![0x20, 0x01], // local.get 1  
            vec![0x21, 0x00], // local.set 0
            vec![0x21, 0x01], // local.set 1
            
            // Memory operations
            vec![0x28, 0x02, 0x00], // i32.load align=2 offset=0
            vec![0x36, 0x02, 0x00], // i32.store align=2 offset=0
            
            // Control flow
            vec![0x02, 0x40], // block (void)
            vec![0x03, 0x40], // loop (void)
            vec![0x04, 0x40], // if (void)
            vec![0x05],       // else
            vec![0x0b],       // end
            
            // Arithmetic operations
            vec![0x6a],       // i32.add
            vec![0x6b],       // i32.sub
            vec![0x6c],       // i32.mul
            vec![0x41, 0x00], // i32.const 0
            vec![0x41, 0x01], // i32.const 1
        ];
        
        for (i, pattern) in common_patterns.into_iter().enumerate() {
            self.instruction_dictionary.insert(pattern, i as u16);
        }
        
        // Common constant values
        let common_constants = vec![0, 1, -1, 4, 8, 16, 32, 64, 128, 256, 1024];
        for (i, &constant) in common_constants.iter().enumerate() {
            self.constant_dictionary.insert(constant, i as u8);
        }
    }

    fn find_instruction_pattern(&self, bytes: &[u8]) -> Option<(usize, u16)> {
        // Try longest patterns first
        for pattern_len in (2..=8).rev() {
            if pattern_len > bytes.len() {
                continue;
            }
            
            let pattern = &bytes[0..pattern_len];
            if let Some(&dict_id) = self.instruction_dictionary.get(pattern) {
                return Some((pattern_len, dict_id));
            }
        }
        None
    }

    fn find_repeating_sequence(&self, bytes: &[u8]) -> Option<(usize, usize)> {
        for pattern_len in 2..=16 {
            if pattern_len * 2 > bytes.len() {
                break;
            }
            
            let pattern = &bytes[0..pattern_len];
            let mut count = 1;
            let mut pos = pattern_len;
            
            while pos + pattern_len <= bytes.len() && &bytes[pos..pos + pattern_len] == pattern {
                count += 1;
                pos += pattern_len;
            }
            
            if count >= 3 {
                return Some((pattern_len, count));
            }
        }
        None
    }

    fn count_zero_run(&self, bytes: &[u8]) -> usize {
        bytes.iter().take_while(|&&b| b == 0).count()
    }

    fn get_instruction_pattern(&self, dict_id: u16) -> Option<Vec<u8>> {
        self.instruction_dictionary
            .iter()
            .find(|(_, &id)| id == dict_id)
            .map(|(pattern, _)| pattern.clone())
    }

    fn get_constant_value(&self, dict_id: u8) -> Option<i64> {
        self.constant_dictionary
            .iter()
            .find(|(_, &id)| id == dict_id)
            .map(|(&constant, _)| constant)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_williams_compression_roundtrip() {
        let compressor = WilliamsCompressor::new();
        
        // Test with simple WASM-like bytecode
        let original = vec![
            0x00, 0x61, 0x73, 0x6d, // WASM magic
            0x01, 0x00, 0x00, 0x00, // version
            0x20, 0x00, 0x20, 0x01, // local.get patterns
            0x6a, // i32.add
            0x41, 0x00, // i32.const 0
            0x00, 0x00, 0x00, 0x00, // zero run
        ];
        
        let compressed = compressor.compress(&original).unwrap();
        let decompressed = compressor.decompress(&compressed).unwrap();
        
        assert_eq!(original, decompressed);
        println!("Compression ratio: {:.2}", original.len() as f64 / compressed.len() as f64);
    }

    #[test]
    fn test_pattern_recognition() {
        let compressor = WilliamsCompressor::new();
        
        // Test that common patterns are recognized
        let pattern_bytes = vec![0x20, 0x00]; // local.get 0
        assert!(compressor.find_instruction_pattern(&pattern_bytes).is_some());
    }

    #[test]
    fn test_zero_run_compression() {
        let compressor = WilliamsCompressor::new();
        
        let mut original = vec![0x42]; // Non-zero prefix
        original.extend(vec![0x00; 100]); // Long zero run
        original.push(0x43); // Non-zero suffix
        
        let compressed = compressor.compress(&original).unwrap();
        let decompressed = compressor.decompress(&compressed).unwrap();
        
        assert_eq!(original, decompressed);
        assert!(compressed.len() < original.len());
    }
}
