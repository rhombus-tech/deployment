#[derive(Debug, Clone, PartialEq)]
pub enum FramingEffectVulnerability {
    ChoiceArchitectureExploit { pc: usize, framing_method: String, description: String },
}

pub struct FramingEffectDetector { 
    bytecode: Vec<u8> 
}

impl FramingEffectDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { 
        Self { bytecode } 
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<FramingEffectVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Detect UI manipulation patterns that frame choices
        if let Some(pc) = self.detect_default_choice_bias() {
            vulnerabilities.push(FramingEffectVulnerability::ChoiceArchitectureExploit {
                pc,
                framing_method: "Default Choice Manipulation".to_string(),
                description: "Contract uses default values or initial state that biases user choices toward disadvantageous options".to_string(),
            });
        }
        
        // Detect positive/negative framing in error messages
        if let Some(pc) = self.detect_asymmetric_error_framing() {
            vulnerabilities.push(FramingEffectVulnerability::ChoiceArchitectureExploit {
                pc,
                framing_method: "Asymmetric Error Framing".to_string(),
                description: "Contract presents errors and success messages asymmetrically to manipulate user perception".to_string(),
            });
        }
        
        // Detect choice ordering manipulation
        if let Some(pc) = self.detect_option_ordering_bias() {
            vulnerabilities.push(FramingEffectVulnerability::ChoiceArchitectureExploit {
                pc,
                framing_method: "Option Ordering Bias".to_string(),
                description: "Contract presents options in order designed to bias selection toward preferred choice".to_string(),
            });
        }
        
        vulnerabilities
    }
    
    fn detect_default_choice_bias(&self) -> Option<usize> {
        // Look for functions that use SLOAD with default values that favor the protocol
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x54 { // SLOAD
                // Check if there's a default value check (ISZERO) followed by setting a value
                for j in i..i.saturating_add(15).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x15 { // ISZERO
                        // Look for PUSH followed by conditional jump
                        for k in j..j.saturating_add(8).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x57 { // JUMPI
                                // Check if default branch has SSTORE with biased value
                                for l in k..k.saturating_add(12).min(self.bytecode.len()) {
                                    if self.bytecode[l] == 0x55 { // SSTORE
                                        // Pattern matches: default value manipulation
                                        return Some(i);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }
    
    fn detect_asymmetric_error_framing(&self) -> Option<usize> {
        // Look for REVERT patterns that have different gas costs or data sizes
        let mut revert_patterns = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0xfd { // REVERT
                // Measure size of error data (look backward for PUSH)
                let mut error_size = 0;
                for j in (i.saturating_sub(10)..i).rev() {
                    if self.bytecode[j] >= 0x60 && self.bytecode[j] <= 0x7f { // PUSH
                        error_size = (self.bytecode[j] - 0x5f) as usize;
                        break;
                    }
                }
                revert_patterns.push((i, error_size));
            }
        }
        
        // Check for significant variance in error message sizes (asymmetric framing)
        if revert_patterns.len() >= 2 {
            let sizes: Vec<usize> = revert_patterns.iter().map(|(_, s)| *s).collect();
            let max_size = sizes.iter().max().unwrap_or(&0);
            let min_size = sizes.iter().min().unwrap_or(&0);
            
            if max_size > &0 && min_size > &0 && max_size / min_size >= 3 {
                return Some(revert_patterns[0].0);
            }
        }
        
        None
    }
    
    fn detect_option_ordering_bias(&self) -> Option<usize> {
        // Look for switch/case patterns with non-uniform handling
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x35 { // CALLDATALOAD (reading function selector or params)
                let mut jump_targets = Vec::new();
                
                // Look for multiple conditional jumps (switch pattern)
                for j in i..i.saturating_add(25).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x14 { // EQ (comparing options)
                        // Look for JUMPI nearby
                        for k in j..j.saturating_add(5).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x57 { // JUMPI
                                jump_targets.push(k);
                            }
                        }
                    }
                }
                
                // If multiple branches with different gas costs (biased ordering)
                if jump_targets.len() >= 3 {
                    return Some(i);
                }
            }
        }
        None
    }
}
