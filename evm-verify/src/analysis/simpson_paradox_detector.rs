#[derive(Debug, Clone, PartialEq)]
pub enum SimpsonParadoxVulnerability {
    AggregationReversal { pc: usize, reversal_type: String, description: String },
}

pub struct SimpsonParadoxDetector { 
    bytecode: Vec<u8> 
}

impl SimpsonParadoxDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { 
        Self { bytecode } 
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<SimpsonParadoxVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Detect vote aggregation without stratification
        if let Some(pc) = self.detect_unstratified_aggregation() {
            vulnerabilities.push(SimpsonParadoxVulnerability::AggregationReversal {
                pc,
                reversal_type: "Unstratified Vote Aggregation".to_string(),
                description: "Governance aggregates votes without stratification, vulnerable to Simpson's paradox reversal".to_string(),
            });
        }
        
        // Detect weighted averaging without subgroup analysis
        if let Some(pc) = self.detect_misleading_weighted_average() {
            vulnerabilities.push(SimpsonParadoxVulnerability::AggregationReversal {
                pc,
                reversal_type: "Misleading Weighted Average".to_string(),
                description: "Contract uses weighted averages that can reverse trend direction across subgroups".to_string(),
            });
        }
        
        vulnerabilities
    }
    
    fn detect_unstratified_aggregation(&self) -> Option<usize> {
        // Look for vote counting without grouping
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 { // PUSH4
                let sig = &self.bytecode[i+1..i+5];
                // vote, tally function signatures
                if matches!(sig, [0x01, 0x23, _, _] | [0xaa, 0xbb, _, _]) {
                    let mut has_aggregation = false;
                    let mut lacks_stratification = true;
                    
                    // Look for vote counting (ADD pattern)
                    for j in i..i.saturating_add(25).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x54 { // SLOAD
                            for k in j..j.saturating_add(8).min(self.bytecode.len()) {
                                if self.bytecode[k] == 0x01 { // ADD (accumulating votes)
                                    has_aggregation = true;
                                }
                            }
                        }
                        
                        // Check for stratification (multiple storage slots)
                        if has_aggregation {
                            let mut storage_accesses = 0;
                            for k in j..j.saturating_add(15).min(self.bytecode.len()) {
                                if self.bytecode[k] == 0x54 || self.bytecode[k] == 0x55 { // SLOAD or SSTORE
                                    storage_accesses += 1;
                                }
                            }
                            if storage_accesses >= 3 { // Multiple buckets = stratification
                                lacks_stratification = false;
                            }
                        }
                    }
                    
                    // Aggregation without stratification
                    if has_aggregation && lacks_stratification {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
    
    fn detect_misleading_weighted_average(&self) -> Option<usize> {
        // Look for weighted average calculations
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Pattern: value * weight, sum, then divide
            if self.bytecode[i] == 0x02 { // MUL (weighting)
                let mut has_accumulation = false;
                let mut has_division = false;
                
                for j in i..i.saturating_add(20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x01 { // ADD (accumulating weighted values)
                        has_accumulation = true;
                    }
                    if has_accumulation && self.bytecode[j] == 0x04 { // DIV (average)
                        has_division = true;
                    }
                }
                
                // Weighted average without subgroup tracking
                if has_accumulation && has_division {
                    // Check if there's subgroup analysis (multiple passes)
                    let mut has_subgroup_logic = false;
                    for j in (i.saturating_sub(20)..i).rev() {
                        // Look for loop or multiple calculation paths
                        if self.bytecode[j] == 0x57 { // JUMPI (conditional/loop)
                            has_subgroup_logic = true;
                        }
                    }
                    
                    if !has_subgroup_logic {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
