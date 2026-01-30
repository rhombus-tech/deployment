/// EIP-1167 Minimal Proxy Clone Detector (Dedicated)
/// Clone factory vulnerabilities

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Eip1167Vulnerability {
    pub vulnerability_type: Eip1167VulnerabilityType,
    pub severity: String,
    pub location: Vec<usize>,
    pub description: String,
    pub exploit_scenario: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Eip1167VulnerabilityType {
    UninitializedClone,             // Clone not initialized
    InitializationReentrancy,       // Reentrancy during init
    ImplementationDestruct,         // Implementation selfdestructed
    CloneCollision,                 // Clone address collision
    InitializerAccessControl,       // Anyone can initialize
}

pub struct Eip1167MinimalProxyDetector {
    bytecode: Vec<u8>,
}

impl Eip1167MinimalProxyDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<Eip1167Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // EIP-1167 minimal proxy bytecode pattern
        let minimal_proxy_pattern = [0x36, 0x3d, 0x3d, 0x37, 0x3d, 0x3d, 0x3d, 0x36, 0x3d, 0x73];
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            let mut is_clone = false;
            let mut has_initializer = false;
            let mut initializer_protected = false;
            
            // Check for minimal proxy pattern
            if i + 10 < self.bytecode.len() && &self.bytecode[i..i+10] == minimal_proxy_pattern {
                is_clone = true;
            }
            
            for j in i..self.bytecode.len().min(i + 30) {
                if self.bytecode[j] == 0x55 { // SSTORE (initialization)
                    has_initializer = true;
                }
                if self.bytecode[j] == 0x33 && j + 2 < self.bytecode.len() && self.bytecode[j+1] == 0x14 { // CALLER EQ
                    initializer_protected = true;
                }
            }
            
            if is_clone && has_initializer && !initializer_protected {
                vulnerabilities.push(Eip1167Vulnerability {
                    vulnerability_type: Eip1167VulnerabilityType::InitializerAccessControl,
                    severity: "Critical".to_string(),
                    location: vec![i],
                    description: "Clone initialization lacks access control. Anyone can initialize.".to_string(),
                    exploit_scenario: "1. Factory deploys clone at address X\n\
                                      2. Before owner calls initialize()\n\
                                      3. Attacker front-runs with initialize(attackerAsOwner)\n\
                                      4. Attacker now owns the clone\n\
                                      5. Steals all funds sent to clone\n\
                                      6. $1M+ stolen via init front-running".to_string(),
                    recommendation: "Use initialize(address owner) and set in constructor. Or use factory-only \
                                  initialization. Add onlyFactory modifier. Reference: OpenZeppelin Clones.".to_string(),
                });
            }
        }
        
        vulnerabilities
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_unprotected_init() {
        let bytecode = vec![
            0x36, 0x3d, 0x3d, 0x37, 0x3d, 0x3d, 0x3d, 0x36, 0x3d, 0x73, // Minimal proxy
            0x55, // SSTORE (no access control)
        ];
        
        let detector = Eip1167MinimalProxyDetector::new(bytecode);
        assert!(!detector.detect_vulnerabilities().is_empty());
    }
}
