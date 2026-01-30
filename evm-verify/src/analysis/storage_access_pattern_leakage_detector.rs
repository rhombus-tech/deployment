use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageLeakage {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct StorageAccessPatternLeakageDetector {
    bytecode: Vec<u8>,
}

impl StorageAccessPatternLeakageDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<StorageLeakage> {
        let mut vulnerabilities = Vec::new();

        // Detect conditional SLOAD revealing secret existence
        vulnerabilities.extend(self.detect_conditional_sload());
        
        // Detect sequential storage access patterns
        vulnerabilities.extend(self.detect_sequential_access());
        
        // Detect SSTORE after comparison (data-dependent writes)
        vulnerabilities.extend(self.detect_data_dependent_writes());

        vulnerabilities
    }

    fn detect_conditional_sload(&self) -> Vec<StorageLeakage> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // Look for SLOAD (0x54) preceded by conditional logic
            if opcode == 0x54 {
                // Check if preceded by JUMPI within 20 bytes (conditional branch before load)
                let start = if pc > 20 { pc - 20 } else { 0 };
                let has_conditional = self.bytecode[start..pc].iter().any(|&b| b == 0x57); // JUMPI
                
                if has_conditional {
                    vulns.push(StorageLeakage {
                        pc,
                        vulnerability_type: "ConditionalStorageLoad".to_string(),
                        description: format!(
                            "Conditional SLOAD at PC {}. Storage access pattern depends on execution path. \
                            Attackers can detect which branch was taken by observing storage reads, \
                            potentially revealing private information like user balances or permissions.",
                            pc
                        ),
                        confidence: 0.75,
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

    fn detect_sequential_access(&self) -> Vec<StorageLeakage> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        let mut sload_count = 0;
        let mut last_sload_pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            if opcode == 0x54 { // SLOAD
                if last_sload_pc > 0 && pc - last_sload_pc < 30 {
                    sload_count += 1;
                    
                    // Multiple SLOADs in close proximity suggests array/mapping iteration
                    if sload_count >= 3 {
                        vulns.push(StorageLeakage {
                            pc: last_sload_pc,
                            vulnerability_type: "SequentialStorageAccess".to_string(),
                            description: format!(
                                "Sequential storage loads detected (count: {}) starting at PC {}. \
                                Pattern suggests array or mapping iteration. Number of iterations \
                                reveals data structure size, potentially leaking sensitive information \
                                about user lists, balance distributions, or access control entries.",
                                sload_count, last_sload_pc
                            ),
                            confidence: 0.80,
                        });
                        sload_count = 0;
                    }
                } else {
                    sload_count = 1;
                }
                last_sload_pc = pc;
            }
            
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_data_dependent_writes(&self) -> Vec<StorageLeakage> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // Look for comparison followed by SSTORE
            if matches!(opcode, 0x10 | 0x11 | 0x12 | 0x13 | 0x14) { // Comparison ops
                let window_end = (pc + 25).min(self.bytecode.len());
                for check_pc in (pc + 1)..window_end {
                    if self.bytecode[check_pc] == 0x55 { // SSTORE
                        vulns.push(StorageLeakage {
                            pc,
                            vulnerability_type: "DataDependentWrite".to_string(),
                            description: format!(
                                "Comparison at PC {} followed by SSTORE at PC {}. Storage write pattern \
                                depends on compared values. Observers can infer comparison results by \
                                monitoring storage writes, potentially revealing secret thresholds, \
                                privilege levels, or authorization states.",
                                pc, check_pc
                            ),
                            confidence: 0.70,
                        });
                        break;
                    }
                }
            }
            
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }
}
