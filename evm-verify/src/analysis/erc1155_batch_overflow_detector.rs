use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Erc1155BatchOverflowVulnerability {
    BatchLengthMismatch { description: String, location: usize, confidence: f32 },
    UncheckedBatchSize { description: String, location: usize },
    BatchArrayOverflow { description: String, location: usize },
    BalanceOverflowInBatch { description: String, location: usize },
}

pub struct Erc1155BatchOverflowDetector {
    bytecode: Vec<u8>,
}

impl Erc1155BatchOverflowDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<Erc1155BatchOverflowVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(150) {
            if self.is_safe_batch_transfer(i) {
                if !self.validates_array_lengths(i, i + 150) {
                    vulnerabilities.push(Erc1155BatchOverflowVulnerability::BatchLengthMismatch {
                        description: "safeBatchTransferFrom doesn't validate ids.length == amounts.length".to_string(),
                        location: i,
                        confidence: 0.95,
                    });
                }
                
                if !self.checks_batch_size(i, i + 150) {
                    vulnerabilities.push(Erc1155BatchOverflowVulnerability::UncheckedBatchSize {
                        description: "No maximum batch size limit - DoS via huge batch".to_string(),
                        location: i,
                    });
                }
                
                if !self.has_balance_overflow_check(i, i + 150) {
                    vulnerabilities.push(Erc1155BatchOverflowVulnerability::BalanceOverflowInBatch {
                        description: "Batch transfer without balance overflow checks".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_safe_batch_transfer(&self, location: usize) -> bool {
        if location + 20 > self.bytecode.len() {
            return false;
        }
        // safeBatchTransferFrom selector: 0x2eb2c2d6
        self.bytecode[location..location + 20].windows(4).any(|w| w == [0x2e, 0xb2, 0xc2, 0xd6])
    }
    
    fn validates_array_lengths(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Must compare two array lengths with EQ
        let length_loads = self.bytecode[start..range_end]
            .iter()
            .filter(|&&b| b == 0x51) // MLOAD (to get array length)
            .count();
        
        let has_eq_check = self.bytecode[start..range_end]
            .windows(2)
            .any(|w| w[0] == 0x14 && w[1] == 0xFD); // EQ + REVERT
        
        length_loads >= 2 && has_eq_check
    }
    
    fn checks_batch_size(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Check for maximum size limit (e.g., 256 items)
        self.bytecode[start..range_end].windows(3).any(|w| {
            w[0] == 0x61 && // PUSH2
            w[1] < 0x02 && // Reasonable limit (< 512)
            w[2] == 0x10 // LT
        })
    }
    
    fn has_balance_overflow_check(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Balance updates should use checked arithmetic
        // Look for ADD followed by LT check (overflow detection)
        for i in start..range_end.saturating_sub(5) {
            if self.bytecode[i] == 0x01 { // ADD
                // Check for overflow validation after ADD
                for j in i+1..i.saturating_add(10).min(range_end) {
                    if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 { // LT or GT
                        return true;
                    }
                }
            }
        }
        
        false
    }
}
