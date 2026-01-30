#[derive(Debug, Clone, PartialEq)]
pub enum MutualInformationVulnerability {
    CrossContractCorrelation { pc: usize, correlation_strength: f64, description: String },
}

pub struct MutualInformationLeakageDetector { 
    bytecode: Vec<u8> 
}

impl MutualInformationLeakageDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { 
        Self { bytecode } 
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<MutualInformationVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Detect correlated state changes revealing private information
        if let Some((pc, correlation)) = self.detect_correlated_state_updates() {
            vulnerabilities.push(MutualInformationVulnerability::CrossContractCorrelation {
                pc,
                correlation_strength: correlation,
                description: format!(
                    "State updates reveal mutual information through correlation (strength: {:.2}). Changes in one variable leak information about another.",
                    correlation
                ),
            });
        }
        
        // Detect event correlation leaking private data
        if let Some((pc, correlation)) = self.detect_event_correlation_leakage() {
            vulnerabilities.push(MutualInformationVulnerability::CrossContractCorrelation {
                pc,
                correlation_strength: correlation,
                description: format!(
                    "Event emissions are correlated (strength: {:.2}), leaking mutual information about private state.",
                    correlation
                ),
            });
        }
        
        vulnerabilities
    }
    
    fn detect_correlated_state_updates(&self) -> Option<(usize, f64)> {
        // Look for multiple SSTORE operations in close proximity (correlated updates)
        let mut sstore_groups = Vec::new();
        let mut current_group = Vec::new();
        
        for i in 0..self.bytecode.len() {
            if self.bytecode[i] == 0x55 { // SSTORE
                current_group.push(i);
            } else if !current_group.is_empty() && i - current_group[current_group.len() - 1] > 50 {
                if current_group.len() >= 2 {
                    sstore_groups.push(current_group.clone());
                }
                current_group.clear();
            }
        }
        
        // Check if updates depend on same input (high correlation)
        for group in sstore_groups {
            if group.len() >= 2 {
                // Check if they share common input source
                let first_store = group[0];
                let mut shared_loads = 0;
                
                for i in (first_store.saturating_sub(30)..first_store).rev() {
                    if self.bytecode[i] == 0x54 || self.bytecode[i] == 0x35 { // SLOAD or CALLDATALOAD
                        // Check if same load used for other stores
                        for &other_store in &group[1..] {
                            if i < other_store && other_store - i < 40 {
                                shared_loads += 1;
                            }
                        }
                    }
                }
                
                // High correlation if multiple stores depend on same input
                if shared_loads >= 2 {
                    let correlation = 0.7 + (shared_loads as f64 * 0.1);
                    return Some((first_store, correlation.min(1.0)));
                }
            }
        }
        
        None
    }
    
    fn detect_event_correlation_leakage(&self) -> Option<(usize, f64)> {
        // Look for multiple LOG operations with correlated data
        let mut log_positions = Vec::new();
        
        for i in 0..self.bytecode.len() {
            if (0xa0..=0xa4).contains(&self.bytecode[i]) { // LOGx
                log_positions.push(i);
            }
        }
        
        // Check for logs with shared data sources
        if log_positions.len() >= 2 {
            for window in log_positions.windows(2) {
                let first_log = window[0];
                let second_log = window[1];
                
                // If logs are close and share data preparation
                if second_log - first_log < 60 {
                    // Check for shared SLOAD between logs (correlated data)
                    let mut shared_data_ops = 0;
                    for i in first_log..second_log {
                        if self.bytecode[i] == 0x54 || self.bytecode[i] == 0x80 { // SLOAD or DUP1
                            shared_data_ops += 1;
                        }
                    }
                    
                    if shared_data_ops >= 2 {
                        let correlation = 0.6 + (shared_data_ops as f64 * 0.1);
                        return Some((first_log, correlation.min(1.0)));
                    }
                }
            }
        }
        
        None
    }
}
