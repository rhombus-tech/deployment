use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CustomErrorCollisionVulnerability {
    ErrorSelectorCollision { description: String, location: usize, confidence: f32 },
    AmbiguousErrorHandling { description: String, location: usize, confidence: f32 },
}

pub struct CustomErrorSelectorCollisionDetector {
    bytecode: Vec<u8>,
}

impl CustomErrorSelectorCollisionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<CustomErrorCollisionVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_error_selector_patterns());
        vulnerabilities
    }
    
    fn detect_error_selector_patterns(&self) -> Vec<CustomErrorCollisionVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut error_selectors = std::collections::HashMap::new();
        
        // Custom errors (Solidity 0.8.4+) use first 4 bytes of keccak256(ErrorName(types))
        // Pattern: PUSH4 selector, MSTORE, REVERT
        
        for i in 0..self.bytecode.len().saturating_sub(10) {
            // Look for PUSH4 followed by potential error revert
            if self.bytecode[i] == 0x63 { // PUSH4
                if i + 5 < self.bytecode.len() {
                    let selector = &self.bytecode[i+1..i+5];
                    let selector_u32 = u32::from_be_bytes([selector[0], selector[1], selector[2], selector[3]]);
                    
                    // Check if followed by revert pattern
                    let section = &self.bytecode[i..std::cmp::min(i + 15, self.bytecode.len())];
                    let is_error_revert = section.windows(3).any(|w| {
                        w[0] == 0x52 && // MSTORE
                        w[1] == 0x60 && // PUSH1
                        w[2] == 0xFD    // REVERT
                    });
                    
                    if is_error_revert {
                        // Track selector and location
                        if let Some(first_location) = error_selectors.get(&selector_u32) {
                            vulnerabilities.push(CustomErrorCollisionVulnerability::ErrorSelectorCollision {
                                description: format!("Custom error selector collision: 0x{:08x} appears at PC {} and {}. Solidity custom errors use 4-byte selectors → birthday paradox collisions likely. Example: `error Unauthorized()` and `error AccessDenied()` may share selector. Risk: Wrong error decoded in external contracts, tooling displays incorrect error. Use unique error names or check collision.", selector_u32, first_location, i),
                                location: i,
                                confidence: 0.92,
                            });
                        } else {
                            error_selectors.insert(selector_u32, i);
                        }
                        
                        // Check for common collision-prone selectors
                        // First 4 bytes of keccak256("Error()") = 0x08c379a0 (string error)
                        // Common custom errors often collide
                        if self.is_collision_prone_selector(selector_u32) {
                            vulnerabilities.push(CustomErrorCollisionVulnerability::AmbiguousErrorHandling {
                                description: format!("Error selector 0x{:08x} at PC {} is collision-prone. Generic names like `Error()`, `Failed()`, `Unauthorized()` have high collision probability across contracts. When calling external contracts, wrong error may be decoded. Use descriptive names: `ProtocolNameUnauthorized()` instead of `Unauthorized()`.", selector_u32, i),
                                location: i,
                                confidence: 0.86,
                            });
                        }
                    }
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_collision_prone_selector(&self, selector: u32) -> bool {
        // List of known collision-prone selectors (common error names)
        let collision_prone = vec![
            0x82b42900, // "Error()"
            0x30cd7471, // "Failed()"
            // Add more common ones
        ];
        collision_prone.contains(&selector)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_duplicate_error_selectors() {
        let bytecode = vec![
            0x63, 0x12, 0x34, 0x56, 0x78, // PUSH4 0x12345678
            0x52,       // MSTORE
            0x60, 0x04, // PUSH1 4
            0xFD,       // REVERT
            0x63, 0x12, 0x34, 0x56, 0x78, // PUSH4 0x12345678 (same selector!)
            0x52,       // MSTORE
            0x60, 0x04, // PUSH1 4
            0xFD,       // REVERT
        ];
        
        let detector = CustomErrorSelectorCollisionDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(v, CustomErrorCollisionVulnerability::ErrorSelectorCollision { .. })));
    }
}
