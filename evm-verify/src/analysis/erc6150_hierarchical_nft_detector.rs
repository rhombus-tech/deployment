/// ERC-6150 Hierarchical NFT Detector
/// Parent/child NFT relationships

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Erc6150Vulnerability {
    pub vulnerability_type: Erc6150VulnerabilityType,
    pub severity: String,
    pub location: Vec<usize>,
    pub description: String,
    pub exploit_scenario: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Erc6150VulnerabilityType {
    OrphanedChildren,               // Parent burned but children exist
    CircularReference,              // Parent/child circular dependency
    UnauthorizedHierarchyChange,    // Anyone can modify hierarchy
    InheritanceExploit,             // Child inherits incorrect properties
    HierarchyDepthAttack,           // Unbounded depth DOS
}

pub struct Erc6150HierarchicalNftDetector {
    bytecode: Vec<u8>,
}

impl Erc6150HierarchicalNftDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<Erc6150Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            let mut burns_token = false;
            let mut updates_children = false;
            
            for j in i..self.bytecode.len().min(i + 20) {
                if self.bytecode[j] == 0x55 { burns_token = true; }
                if self.bytecode[j] == 0x54 && j + 1 < self.bytecode.len() && self.bytecode[j+1] == 0x55 {
                    updates_children = true;
                }
            }
            
            if burns_token && !updates_children {
                vulnerabilities.push(Erc6150Vulnerability {
                    vulnerability_type: Erc6150VulnerabilityType::OrphanedChildren,
                    severity: "High".to_string(),
                    location: vec![i],
                    description: "Parent NFT burned without updating child relationships.".to_string(),
                    exploit_scenario: "1. Parent NFT #1 has children #2, #3, #4\n\
                                      2. Owner burns parent #1\n\
                                      3. Children still reference parent\n\
                                      4. Orphaned NFTs with broken hierarchy\n\
                                      5. $100K in child NFTs inaccessible".to_string(),
                    recommendation: "Update child references on parent burn. Transfer children or invalidate hierarchy.".to_string(),
                });
            }
        }
        
        vulnerabilities
    }
}
