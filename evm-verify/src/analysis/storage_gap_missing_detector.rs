use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageGapMissingVulnerability {
    MissingStorageGap {
        description: String,
        location: usize,
        contract_is_upgradeable: bool,
        confidence: f32,
    },
    InsufficientGapSize {
        description: String,
        location: usize,
        gap_size: u32,
    },
    GapNotAtEnd {
        description: String,
        location: usize,
    },
}

pub struct StorageGapMissingDetector {
    bytecode: Vec<u8>,
}

impl StorageGapMissingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<StorageGapMissingVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        let is_upgradeable = self.is_upgradeable_contract();
        
        if is_upgradeable {
            let has_gap = self.has_storage_gap();
            
            if !has_gap {
                vulnerabilities.push(StorageGapMissingVulnerability::MissingStorageGap {
                    description: "Upgradeable contract missing __gap storage array".to_string(),
                    location: 0,
                    contract_is_upgradeable: true,
                    confidence: 0.90,
                });
            } else {
                let gap_size = self.calculate_gap_size();
                if gap_size < 50 {
                    vulnerabilities.push(StorageGapMissingVulnerability::InsufficientGapSize {
                        description: format!("Storage gap of {} slots is insufficient", gap_size),
                        location: 0,
                        gap_size,
                    });
                }
                
                if !self.is_gap_at_end() {
                    vulnerabilities.push(StorageGapMissingVulnerability::GapNotAtEnd {
                        description: "Storage gap not positioned at end of storage layout".to_string(),
                        location: 0,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_upgradeable_contract(&self) -> bool {
        self.bytecode.windows(4).any(|w| w[0] == 0xf4) || // DELEGATECALL
        self.bytecode.windows(20).any(|w| {
            w.iter().any(|&b| b == 0x36) // CALLDATASIZE (proxy pattern)
        })
    }
    
    fn has_storage_gap(&self) -> bool {
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x60 && i + 1 < self.bytecode.len() {
                let value = self.bytecode[i + 1];
                if value >= 50 && value <= 100 {
                    if i + 10 < self.bytecode.len() && self.bytecode[i + 5] == 0x55 {
                        return true;
                    }
                }
            }
        }
        false
    }
    
    fn calculate_gap_size(&self) -> u32 {
        for i in 0..self.bytecode.len().saturating_sub(5) {
            if self.bytecode[i] == 0x60 {
                let value = self.bytecode[i + 1] as u32;
                if value >= 10 && value <= 200 {
                    return value;
                }
            }
        }
        0
    }
    
    fn is_gap_at_end(&self) -> bool {
        let storage_writes: Vec<usize> = self.bytecode.iter()
            .enumerate()
            .filter(|(_, &b)| b == 0x55)
            .map(|(i, _)| i)
            .collect();
        
        if storage_writes.len() < 2 {
            return false;
        }
        
        let last_write = storage_writes[storage_writes.len() - 1];
        let second_last = storage_writes[storage_writes.len() - 2];
        
        last_write > second_last + 50
    }
}
